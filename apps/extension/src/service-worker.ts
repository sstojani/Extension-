import { ZodError } from "zod";
import {
  fail,
  dailyIocHuntParamsSchema,
  isAllowedOrigin,
  ok,
  parseBridgeRequest,
  threatRadarAgentConfigSchema,
  type BridgeRequest,
  type BridgeResponse
} from "@soc-watch/protocol";
import { DEFAULT_ALLOWED_ORIGINS } from "./config";
import {
  BridgeOperationError,
  analyzeThreatRadar,
  getDataView,
  getFleetAgent,
  getFleetIncomingData,
  getFleetSummary,
  getKibanaStatus,
  listAllFleetAgents,
  listDataViews,
  listFleetAgents,
  searchIOC
} from "./kibana";
import { collectDailyThreatIntel, type ThreatIntelIOC } from "./threat-intel";
import { isExcludedCandidate } from "./candidate-exclusions";

const THREAT_RADAR_AGENT_ALARM = "soc-watch-threat-radar-agent";
const THREAT_RADAR_AGENT_CONFIG_KEY = "threatRadarAgentConfig";
const THREAT_RADAR_AGENT_STATE_KEY = "threatRadarAgentState";
const THREAT_RADAR_AGENT_ALERTS_KEY = "threatRadarAgentAlerts";

type ThreatRadarAgentConfig = {
  enabled: boolean;
  intervalMinutes: number;
  indexPattern: string;
  timestampField: string;
  candidateExclusions: string[];
};

type ThreatRadarAgentFinding = {
  sourceIp: string;
  destinationIp: string;
  dangerousPorts: number[];
  actions: Array<{ key: string; count: number }>;
  latest?: { action?: string; message?: string; timestamp?: string };
  gti?: { threatScore: number; malicious: number; suspicious: number };
};

type ThreatRadarAgentReport = { suspects: ThreatRadarAgentFinding[] };

let threatRadarAgentRunning = false;

chrome.runtime.onMessageExternal.addListener((message, sender, sendResponse) => {
  void handleExternalMessage(message, sender).then(sendResponse);
  return true;
});

chrome.runtime.onConnectExternal.addListener((port) => {
  void handleLivePort(port);
});

chrome.runtime.onConnect.addListener((port) => {
  if (port.name === "soc-watch-page-relay") {
    void handleLivePort(port);
  }
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  void handleInternalMessage(message).then(sendResponse);
  return true;
});

chrome.runtime.onInstalled.addListener(() => {
  void setDisconnectedIcon();
  void ensureSocWatchRelays();
  void ensureThreatRadarAgentSchedule();
  void runThreatRadarAgent();
});

chrome.runtime.onStartup.addListener(() => {
  void ensureSocWatchRelays();
  void ensureThreatRadarAgentSchedule();
  void runThreatRadarAgent();
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === THREAT_RADAR_AGENT_ALARM) void runThreatRadarAgent();
});

void setDisconnectedIcon();
void ensureSocWatchRelays();
void ensureThreatRadarAgentSchedule();

async function handleExternalMessage(message: unknown, sender: chrome.runtime.MessageSender): Promise<BridgeResponse> {
  const started = performance.now();
  let requestId = "unknown";
  try {
    if (!isAllowedOrigin(senderUrl(sender), DEFAULT_ALLOWED_ORIGINS)) {
      return fail(requestId, "INVALID_ORIGIN", "This origin is not allowed to use SOC Watch Bridge.", elapsed(started));
    }

    const request = parseBridgeRequest(message);
    requestId = request.requestId;
    const data = await dispatch(request);
    return ok(requestId, data, elapsed(started));
  } catch (error) {
    if (error instanceof BridgeOperationError) {
      return fail(requestId, error.code, error.message, elapsed(started), error.details);
    }
    if (error instanceof ZodError) {
      return fail(requestId, "INVALID_REQUEST", "The bridge request did not match the protocol schema.", elapsed(started), error.issues);
    }
    return fail(requestId, "INTERNAL_ERROR", "SOC Watch Bridge encountered an unexpected error.", elapsed(started), {
      cause: error instanceof Error ? error.message : String(error)
    });
  }
}

async function handleLivePort(port: chrome.runtime.Port): Promise<void> {
  if (!isAllowedOrigin(senderUrl(port.sender), DEFAULT_ALLOWED_ORIGINS)) {
    safePost(port, fail("stream", "INVALID_ORIGIN", "This origin is not allowed to use SOC Watch Bridge."));
    safeDisconnect(port);
    return;
  }

  let closed = false;
  port.onDisconnect.addListener(() => {
    closed = true;
  });

  const pushSnapshot = async () => {
    if (closed) return;
    const snapshot = await collectLiveSnapshot();
    await chrome.storage.local.set({ lastConnection: snapshot });
    if (!safePost(port, { type: "soc-watch.snapshot", snapshot })) closed = true;
  };

  port.onMessage.addListener((message) => {
    if (isRelayHello(message)) return;
    if (isSnapshotRequest(message)) {
      void pushSnapshot();
      return;
    }
    void handleExternalMessage(message, port.sender ?? {}).then((response) => {
      if (!closed && !safePost(port, { type: "soc-watch.response", response })) closed = true;
    });
  });

  await pushSnapshot();
  const interval = setInterval(() => {
    if (closed) {
      clearInterval(interval);
      return;
    }
    void pushSnapshot();
  }, 10000);
}

function safePost(port: chrome.runtime.Port, message: unknown): boolean {
  try {
    port.postMessage(message);
    return true;
  } catch {
    return false;
  }
}

function safeDisconnect(port: chrome.runtime.Port): void {
  try {
    port.disconnect();
  } catch {
    // The port can disappear while Chrome is moving tabs between lifecycle states.
  }
}

async function ensureSocWatchRelays(): Promise<void> {
  const tabs = await chrome.tabs.query({
    url: ["https://socwatch.internal/*", "http://localhost/*", "http://127.0.0.1/*"]
  });

  for (const tab of tabs) {
    if (typeof tab.id !== "number") continue;
    try {
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        files: ["content-script.js"]
      });
    } catch {
      // Some tabs can be loading, discarded, or otherwise unavailable. The web app also retries from its side.
    }
  }
}

async function handleInternalMessage(message: unknown): Promise<BridgeResponse> {
  const started = performance.now();
  let requestId = "unknown";
  try {
    if (isInternalConfigMessage(message)) {
      await chrome.storage.local.set({ kibanaBaseUrl: message.kibanaBaseUrl });
      return ok(message.requestId, { saved: true }, elapsed(started));
    }

    const request = parseBridgeRequest(message);
    requestId = request.requestId;
    const data = await dispatch(request);
    await setConnectedBadge(request.action);
    if (request.action === "fleet.summary") {
      await chrome.storage.local.set({ lastConnection: { state: "connected", updatedAt: new Date().toISOString(), fleet: data } });
    }
    return ok(requestId, data, elapsed(started));
  } catch (error) {
    await setErrorBadge();
    if (error instanceof BridgeOperationError) {
      return fail(requestId, error.code, error.message, elapsed(started), error.details);
    }
    if (error instanceof ZodError) {
      return fail(requestId, "INVALID_REQUEST", "The bridge request did not match the protocol schema.", elapsed(started), error.issues);
    }
    return fail(requestId, "INTERNAL_ERROR", "SOC Watch Bridge encountered an unexpected error.", elapsed(started), {
      cause: error instanceof Error ? error.message : String(error)
    });
  }
}

async function collectLiveSnapshot(): Promise<Record<string, unknown>> {
  const updatedAt = new Date().toISOString();
  const [kibanaResult, fleetResult, agentsResult] = await Promise.allSettled([
    getKibanaStatus(),
    getFleetSummary({}),
    listAllFleetAgents()
  ]);
  const kibana = kibanaResult.status === "fulfilled" ? kibanaResult.value : { overall: "unavailable" };
  const fleet = fleetResult.status === "fulfilled"
    ? fleetResult.value
    : { online: 0, offline: 0, error: 0, inactive: 0, updating: 0, unenrolled: 0, active: 0, all: 0, other: 0 };
  const agents = agentsResult.status === "fulfilled" ? agentsResult.value : [];
  const problemAgents = agents.filter((agent) => agent.status === "offline" || agent.status === "error");
  const errors = [kibanaResult, fleetResult, agentsResult]
    .filter((result): result is PromiseRejectedResult => result.status === "rejected")
    .map((result) => bridgeErrorPayload(result.reason));

  await setConnectedIcon();
  return {
    state: "connected",
    updatedAt,
    kibana,
    fleet,
    agents,
    problemAgents,
    serviceErrors: errors
  };
}

function bridgeErrorPayload(error: unknown): { code: string; message: string; details?: unknown } {
  if (error instanceof BridgeOperationError) {
    return { code: error.code, message: error.message, details: error.details };
  }
  return {
    code: "INTERNAL_ERROR",
    message: error instanceof Error ? error.message : "Unexpected bridge error"
  };
}

function isInternalConfigMessage(message: unknown): message is { type: "soc-watch.saveConfig"; requestId: string; kibanaBaseUrl: string } {
  if (typeof message !== "object" || message === null) return false;
  const record = message as Record<string, unknown>;
  if (record.type !== "soc-watch.saveConfig") return false;
  if (typeof record.requestId !== "string") return false;
  if (typeof record.kibanaBaseUrl !== "string") return false;
  try {
    const url = new URL(record.kibanaBaseUrl);
    return (url.protocol === "https:" || url.protocol === "http:") && url.hostname === "10.10.254.202";
  } catch {
    return false;
  }
}

async function dispatch(request: BridgeRequest): Promise<unknown> {
  switch (request.action) {
    case "bridge.ping":
      return { extension: "SOC Watch Bridge", version: chrome.runtime.getManifest().version, status: "ok" };
    case "config.get":
      return getBridgeConfig();
    case "config.save":
      return saveBridgeConfig(request.params);
    case "kibana.status":
      return getKibanaStatus();
    case "fleet.summary":
      return getFleetSummary(request.params);
    case "fleet.list":
      return listFleetAgents(request.params);
    case "fleet.get":
      return getFleetAgent(request.params);
    case "fleet.incomingData":
      return getFleetIncomingData(request.params);
    case "dataViews.list":
      return listDataViews();
    case "dataViews.get":
      return getDataView(request.params);
    case "ioc.search":
      return searchIOC(request.params);
    case "threatIntel.dailyHunt":
      return runDailyIocHunt(request.params);
    case "threatRadar.analyze":
      return analyzeThreatRadar(request.params);
    case "threatRadar.agent.configure":
      return configureThreatRadarAgent(request.params);
    case "threatRadar.agent.run":
      return runThreatRadarAgent();
    default:
      throw new BridgeOperationError("INVALID_REQUEST", "This action is not implemented in the bridge yet.");
  }
}

async function getBridgeConfig(): Promise<unknown> {
  const stored = await chrome.storage.local.get(["kibanaBaseUrl", "spaceId", "threatFoxAuthKey", "malwareBazaarAuthKey", "googleThreatIntelApiKey", THREAT_RADAR_AGENT_CONFIG_KEY, THREAT_RADAR_AGENT_STATE_KEY]);
  return {
    kibanaBaseUrl: typeof stored.kibanaBaseUrl === "string" ? stored.kibanaBaseUrl : undefined,
    spaceId: typeof stored.spaceId === "string" ? stored.spaceId : undefined,
    threatFoxAuthKeySaved: typeof stored.threatFoxAuthKey === "string" && stored.threatFoxAuthKey.trim().length > 0,
    malwareBazaarAuthKeySaved: typeof stored.malwareBazaarAuthKey === "string" && stored.malwareBazaarAuthKey.trim().length > 0,
    googleThreatIntelApiKeySaved: typeof stored.googleThreatIntelApiKey === "string" && stored.googleThreatIntelApiKey.trim().length > 0,
    threatRadarAgent: readThreatRadarAgentConfig(stored[THREAT_RADAR_AGENT_CONFIG_KEY]),
    threatRadarAgentState: asRecord(stored[THREAT_RADAR_AGENT_STATE_KEY])
  };
}

async function saveBridgeConfig(params: unknown): Promise<unknown> {
  const record = asRecord(params);
  const updates: Record<string, string> = {};

  if (typeof record.threatFoxAuthKey === "string") {
    const key = record.threatFoxAuthKey.trim();
    if (key) updates.threatFoxAuthKey = key;
  }
  if (typeof record.malwareBazaarAuthKey === "string") {
    const key = record.malwareBazaarAuthKey.trim();
    if (key) updates.malwareBazaarAuthKey = key;
  }
  if (typeof record.googleThreatIntelApiKey === "string") {
    const key = record.googleThreatIntelApiKey.trim();
    if (key) updates.googleThreatIntelApiKey = key;
  }

  if (Object.keys(updates).length > 0) {
    await chrome.storage.local.set(updates);
  }

  return getBridgeConfig();
}

function readThreatRadarAgentConfig(value: unknown): ThreatRadarAgentConfig {
  const parsed = threatRadarAgentConfigSchema.safeParse(value);
  return parsed.success ? parsed.data : { enabled: true, intervalMinutes: 15, indexPattern: "logs-*", timestampField: "@timestamp", candidateExclusions: [] };
}

async function getThreatRadarAgentConfig(): Promise<ThreatRadarAgentConfig> {
  const stored = await chrome.storage.local.get(THREAT_RADAR_AGENT_CONFIG_KEY);
  return readThreatRadarAgentConfig(stored[THREAT_RADAR_AGENT_CONFIG_KEY]);
}

async function ensureThreatRadarAgentSchedule(): Promise<void> {
  const config = await getThreatRadarAgentConfig();
  await chrome.alarms.clear(THREAT_RADAR_AGENT_ALARM);
  if (!config.enabled) return;
  await chrome.alarms.create(THREAT_RADAR_AGENT_ALARM, { periodInMinutes: config.intervalMinutes });
}

async function configureThreatRadarAgent(params: unknown): Promise<unknown> {
  const config = threatRadarAgentConfigSchema.parse(params);
  await chrome.storage.local.set({ [THREAT_RADAR_AGENT_CONFIG_KEY]: config });
  await ensureThreatRadarAgentSchedule();
  const state = asRecord((await chrome.storage.local.get(THREAT_RADAR_AGENT_STATE_KEY))[THREAT_RADAR_AGENT_STATE_KEY]);
  return { config, state };
}

async function runThreatRadarAgent(): Promise<unknown> {
  const config = await getThreatRadarAgentConfig();
  if (!config.enabled) return { config, state: { status: "disabled" } };
  if (threatRadarAgentRunning) return { config, state: { status: "running" } };

  threatRadarAgentRunning = true;
  const startedAt = new Date().toISOString();
  await chrome.storage.local.set({
    [THREAT_RADAR_AGENT_STATE_KEY]: {
      status: "running",
      startedAt,
      candidates: 0,
      alertsCreated: 0
    }
  });
  try {
    const report = await analyzeThreatRadar({
      indexPattern: config.indexPattern,
      timestampField: config.timestampField,
      from: `now-${config.intervalMinutes}m`,
      to: "now",
      size: 50
    }) as ThreatRadarAgentReport;
    const candidates = report.suspects.filter(isHighConfidenceAccessCandidate);
    const alertsCreated = await notifyThreatRadarCandidates(candidates);
    const state = {
      status: "healthy",
      startedAt,
      completedAt: new Date().toISOString(),
      candidates: candidates.length,
      alertsCreated,
      report,
      lastError: undefined
    };
    await chrome.storage.local.set({ [THREAT_RADAR_AGENT_STATE_KEY]: state });
    return { config, state };
  } catch (error) {
    const state = {
      status: "error",
      startedAt,
      completedAt: new Date().toISOString(),
      candidates: 0,
      alertsCreated: 0,
      lastError: error instanceof Error ? error.message : "Threat Radar agent scan failed."
    };
    await chrome.storage.local.set({ [THREAT_RADAR_AGENT_STATE_KEY]: state });
    return { config, state };
  } finally {
    threatRadarAgentRunning = false;
  }
}

function isHighConfidenceAccessCandidate(finding: ThreatRadarAgentFinding): boolean {
  const riskyAuthenticationPorts = [22, 23, 3389, 445, 5900];
  const hasRiskyService = finding.dangerousPorts.some((port) => riskyAuthenticationPorts.includes(port));
  const failedAttempts = finding.actions
    .filter((action) => /fail|denied|blocked|drop|reject|invalid|auth/i.test(action.key))
    .reduce((total, action) => total + action.count, 0);
  const latest = `${finding.latest?.action ?? ""} ${finding.latest?.message ?? ""}`.toLowerCase();
  const successfulAuthentication = /(successful|succeeded|accepted password|authenticated|session opened)/.test(latest)
    && /(ssh|sshd|rdp|login|auth|session)/.test(latest);
  const reputationRisk = (finding.gti?.threatScore ?? 0) >= 50 || (finding.gti?.malicious ?? 0) >= 2 || (finding.gti?.suspicious ?? 0) >= 4;
  return hasRiskyService && failedAttempts >= 20 && successfulAuthentication && reputationRisk;
}

async function notifyThreatRadarCandidates(candidates: ThreatRadarAgentFinding[]): Promise<number> {
  if (candidates.length === 0) return 0;
  const stored = await chrome.storage.local.get(THREAT_RADAR_AGENT_ALERTS_KEY);
  const notified = asRecord(stored[THREAT_RADAR_AGENT_ALERTS_KEY]);
  const now = Date.now();
  let created = 0;

  for (const candidate of candidates) {
    const key = `${candidate.sourceIp}|${candidate.destinationIp}|${candidate.dangerousPorts.join(",")}`;
    const lastAlert = typeof notified[key] === "number" ? notified[key] : 0;
    if (now - lastAlert < 6 * 60 * 60 * 1000) continue;
    try {
      await chrome.notifications.create(`soc-watch-radar-${now}-${created}`, {
        type: "basic",
        iconUrl: chrome.runtime.getURL("icon-128.svg"),
        title: "SOC Watch: high-confidence access risk",
        message: `${candidate.sourceIp} reached ${candidate.destinationIp} after repeated failures on port ${candidate.dangerousPorts[0] ?? "--"}.`
      });
      notified[key] = now;
      created += 1;
    } catch {
      // The report state remains available even when Chrome suppresses a desktop notification.
    }
  }

  await chrome.storage.local.set({ [THREAT_RADAR_AGENT_ALERTS_KEY]: notified });
  return created;
}

async function runDailyIocHunt(params: unknown): Promise<unknown> {
  const parsed = dailyIocHuntParamsSchema.parse(params);
  const startedAt = new Date().toISOString();
  const collection = await collectDailyThreatIntel(parsed.maxIocs);
  const agentConfig = await getThreatRadarAgentConfig();
  const iocs = collection.iocs.filter((ioc) => !isExcludedCandidate({
    type: ioc.type,
    normalized: ioc.normalized,
    values: [ioc.malware ?? "", ioc.threatType ?? "", ...ioc.sources]
  }, agentConfig.candidateExclusions));
  const results = [];

  for (const ioc of iocs) {
    try {
      const search = await searchIOC({
        value: ioc.normalized,
        indexPattern: parsed.indexPattern,
        timestampField: parsed.timestampField,
        from: parsed.from,
        to: parsed.to,
        size: parsed.size
      });
      const summary = summarizeElasticResult(search);
      results.push({
        ioc,
        total: summary.total,
        hits: summary.hits,
        matched: summary.total > 0
      });
    } catch (error) {
      results.push({
        ioc,
        total: 0,
        hits: [],
        matched: false,
        error: error instanceof Error ? error.message : "IOC hunt search failed."
      });
    }
  }

  const matchedResults = results.filter((result) => result.total > 0);
  const providers = collection.providers.map((provider) => {
    const providerResults = results.filter((result) => result.ioc.sources.includes(provider.name));
    const providerMatches = providerResults.filter((result) => result.total > 0);
    return {
      ...provider,
      checked: providerResults.length,
      matched: providerMatches.length,
      checkedByType: countResultsByType(providerResults),
      matchedByType: countResultsByType(providerMatches)
    };
  });
  return {
    startedAt,
    completedAt: new Date().toISOString(),
    providers,
    collected: collection.iocs.length,
    hunted: results.length,
    matched: matchedResults.length,
    siemEvents: matchedResults.reduce((sum, result) => sum + result.total, 0),
    results
  };
}

function countResultsByType(results: Array<{ ioc: ThreatIntelIOC }>): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const result of results) {
    counts[result.ioc.type] = (counts[result.ioc.type] ?? 0) + 1;
  }
  return counts;
}

function summarizeElasticResult(result: unknown): {
  total: number;
  hits: Array<{ index: string; timestamp?: string; host?: string; eventAction?: string; destinationPort?: number; sourceIp?: string; destinationIp?: string; message?: string }>;
} {
  const record = asRecord(result);
  const raw = asRecord(record.raw);
  const hitsObject = asRecord(raw.hits);
  const totalObject = asRecord(hitsObject.total);
  const rawHits = Array.isArray(hitsObject.hits) ? hitsObject.hits : [];
  return {
    total: typeof totalObject.value === "number" ? totalObject.value : typeof hitsObject.total === "number" ? hitsObject.total : rawHits.length,
    hits: rawHits.slice(0, 5).map((hit) => {
      const hitRecord = asRecord(hit);
      const source = asRecord(hitRecord._source);
      const host = asRecord(source.host);
      const event = asRecord(source.event);
      const destination = asRecord(source.destination);
      const sourceInfo = asRecord(source.source);
      return {
        index: typeof hitRecord._index === "string" ? hitRecord._index : "--",
        timestamp: typeof source["@timestamp"] === "string" ? source["@timestamp"] : undefined,
        host: typeof host.name === "string" ? host.name : undefined,
        eventAction: typeof event.action === "string" ? event.action : undefined,
        destinationPort: typeof destination.port === "number" ? destination.port : undefined,
        sourceIp: typeof sourceInfo.ip === "string" ? sourceInfo.ip : undefined,
        destinationIp: typeof destination.ip === "string" ? destination.ip : undefined,
        message: typeof source.message === "string" ? source.message.slice(0, 220) : undefined
      };
    })
  };
}

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null ? (value as Record<string, unknown>) : {};
}

function elapsed(started: number): number {
  return Math.round(performance.now() - started);
}

async function setConnectedBadge(action: string): Promise<void> {
  if (action !== "fleet.summary" && action !== "kibana.status") return;
  await setConnectedIcon();
}

async function setErrorBadge(): Promise<void> {
  await setDisconnectedIcon();
}

async function setConnectedIcon(): Promise<void> {
  await chrome.action.setBadgeText({ text: "" });
  await setGeneratedIcon("#22c55e", "#0f172a");
}

async function setDisconnectedIcon(): Promise<void> {
  await chrome.action.setBadgeText({ text: "" });
  await setGeneratedIcon("#64748b", "#1f2937");
}

async function setGeneratedIcon(primary: string, background: string): Promise<void> {
  try {
    await chrome.action.setIcon({ imageData: { 128: drawIcon(primary, background) } });
  } catch {
    // Icon rendering is cosmetic; it must never break bridge operation.
  }
}

function drawIcon(primary: string, background: string): ImageData {
  const size = 128;
  const image = new ImageData(size, size);
  fill(image, background);
  fillShield(image, primary);
  fillShieldInner(image, background);
  drawLetterS(image, "#f8fafc");
  return image;
}

function fill(image: ImageData, color: string): void {
  const [red, green, blue] = hexToRgb(color);
  for (let index = 0; index < image.data.length; index += 4) {
    image.data[index] = red;
    image.data[index + 1] = green;
    image.data[index + 2] = blue;
    image.data[index + 3] = 255;
  }
}

function fillShield(image: ImageData, color: string): void {
  const points = [
    [64, 18],
    [98, 31],
    [98, 60],
    [90, 85],
    [64, 112],
    [38, 85],
    [30, 60],
    [30, 31]
  ];
  fillPolygon(image, points, color);
}

function fillShieldInner(image: ImageData, color: string): void {
  const points = [
    [64, 31],
    [85, 39],
    [85, 61],
    [78, 79],
    [64, 96],
    [50, 79],
    [43, 61],
    [43, 39]
  ];
  fillPolygon(image, points, color);
}

function drawLetterS(image: ImageData, color: string): void {
  const blocks = [
    [55, 50, 21, 8],
    [51, 58, 8, 12],
    [55, 70, 20, 8],
    [68, 78, 8, 12],
    [52, 90, 24, 8]
  ];
  for (const [x, y, width, height] of blocks) {
    fillRect(image, x, y, width, height, color);
  }
}

function fillRect(image: ImageData, x: number, y: number, width: number, height: number, color: string): void {
  const [red, green, blue] = hexToRgb(color);
  for (let row = y; row < y + height; row += 1) {
    for (let col = x; col < x + width; col += 1) {
      const index = (row * image.width + col) * 4;
      image.data[index] = red;
      image.data[index + 1] = green;
      image.data[index + 2] = blue;
      image.data[index + 3] = 255;
    }
  }
}

function fillPolygon(image: ImageData, points: number[][], color: string): void {
  const [red, green, blue] = hexToRgb(color);
  const xs = points.map((point) => point[0] ?? 0);
  const ys = points.map((point) => point[1] ?? 0);
  const minX = Math.max(0, Math.floor(Math.min(...xs)));
  const maxX = Math.min(image.width - 1, Math.ceil(Math.max(...xs)));
  const minY = Math.max(0, Math.floor(Math.min(...ys)));
  const maxY = Math.min(image.height - 1, Math.ceil(Math.max(...ys)));

  for (let y = minY; y <= maxY; y += 1) {
    for (let x = minX; x <= maxX; x += 1) {
      if (!pointInPolygon(x, y, points)) continue;
      const index = (y * image.width + x) * 4;
      image.data[index] = red;
      image.data[index + 1] = green;
      image.data[index + 2] = blue;
      image.data[index + 3] = 255;
    }
  }
}

function pointInPolygon(x: number, y: number, points: number[][]): boolean {
  let inside = false;
  for (let index = 0, previous = points.length - 1; index < points.length; previous = index, index += 1) {
    const xi = points[index]?.[0] ?? 0;
    const yi = points[index]?.[1] ?? 0;
    const xj = points[previous]?.[0] ?? 0;
    const yj = points[previous]?.[1] ?? 0;
    const intersects = yi > y !== yj > y && x < ((xj - xi) * (y - yi)) / (yj - yi || 1) + xi;
    if (intersects) inside = !inside;
  }
  return inside;
}

function hexToRgb(color: string): [number, number, number] {
  const value = color.replace("#", "");
  return [
    Number.parseInt(value.slice(0, 2), 16),
    Number.parseInt(value.slice(2, 4), 16),
    Number.parseInt(value.slice(4, 6), 16)
  ];
}

function senderUrl(sender: chrome.runtime.MessageSender | undefined): string | undefined {
  return sender?.url ?? sender?.tab?.url;
}

function isRelayHello(message: unknown): boolean {
  if (typeof message !== "object" || message === null) return false;
  return (message as Record<string, unknown>).type === "soc-watch.hello";
}

function isSnapshotRequest(message: unknown): boolean {
  if (typeof message !== "object" || message === null) return false;
  return (message as Record<string, unknown>).type === "soc-watch.requestSnapshot";
}
