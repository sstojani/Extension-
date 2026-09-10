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
  enrichThreatRadarSuspects,
  getDataView,
  getFleetAgent,
  getFleetIncomingData,
  getFleetSummary,
  getKibanaStatus,
  listAllFleetAgents,
  listDataViews,
  listFleetAgents,
  resetGtiLookupState,
  searchIOC,
  searchIOCBatch,
  type GtiCoverageSummary,
  type GtiLookupStatus,
  type ThreatRadarFinding
} from "./kibana";
import { collectDailyThreatIntel, type ThreatIntelIOC } from "./threat-intel";
import { isExcludedCandidate } from "./candidate-exclusions";
import { mergeFindingHistory } from "./threat-radar-history";
import {
  buildThreatAlertCandidates,
  normalizeAlertIndicator,
  type AlertIndicatorType,
  type ThreatAlertCandidate,
  type ThreatAlertRule
} from "./threat-alerts";

const THREAT_RADAR_AGENT_ALARM = "soc-watch-threat-radar-agent";
const THREAT_RADAR_AGENT_CONFIG_KEY = "threatRadarAgentConfig";
const THREAT_RADAR_AGENT_STATE_KEY = "threatRadarAgentState";
const THREAT_RADAR_AGENT_ALERTS_KEY = "threatRadarAgentAlerts";
const THREAT_ALERT_CONFIG_KEY = "threatAlertConfig";
const THREAT_ALERT_RULES_KEY = "threatAlertRules";
const THREAT_ALERT_HISTORY_KEY = "threatAlertHistory";

type ThreatRadarAgentConfig = {
  enabled: boolean;
  intervalMinutes: number;
  indexPattern: string;
  timestampField: string;
  candidateExclusions: string[];
};

type ThreatRadarAgentFinding = ThreatRadarFinding & {
  firstSeen?: string;
  lastSeen?: string;
  observations?: number;
  previousEvents?: number;
  eventDelta?: number;
  active?: boolean;
};

type ThreatRadarAgentReport = {
  historyVersion?: number;
  analyzedAt: string;
  suspects: ThreatRadarAgentFinding[];
  externalSources: ThreatRadarAgentFinding[];
  suspiciousDestinations: ThreatRadarAgentFinding[];
  suspiciousOutbound: ThreatRadarAgentFinding[];
  deniedActivity: ThreatRadarAgentFinding[];
  reviewCandidates?: ThreatRadarAgentFinding[];
  suspiciousIndicators?: Array<{
    value: string;
    type: "domain" | "hash";
    score: number;
    events: number;
    reasons: string[];
    matchedKeywords?: string[];
    gti?: ThreatRadarAgentFinding["gti"];
  }>;
  signals?: Array<{ key: string; label: string; count: number }>;
  analysis?: {
    strategy: "single" | "staged";
    partial: boolean;
    completedStages: string[];
    skippedStages: string[];
    candidatesEvaluated?: number;
    candidatesForReview?: number;
    candidateMethods?: string[];
    reputation?: GtiCoverageSummary;
  };
  summary: { suspects: number; critical: number; high: number; medium: number };
};

type ThreatAlertConfig = {
  browserNotifications: boolean;
  discordWebhookUrl?: string;
  telegramBotToken?: string;
  telegramChatId?: string;
  cooldownMinutes: number;
};

type ThreatAlertDelivery = {
  browser: "sent" | "disabled" | "failed";
  discord: "sent" | "disabled" | "failed";
  telegram: "sent" | "disabled" | "failed";
  errors: string[];
};

type ThreatAlertHistoryItem = ThreatAlertCandidate & {
  id: string;
  createdAt: string;
  lastSeenAt: string;
  lastNotifiedAt?: string;
  occurrences: number;
  delivery: ThreatAlertDelivery;
};

const THREAT_RADAR_HISTORY_VERSION = 6;
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
      return getBridgeConfig(request.params);
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
      return runInteractiveThreatRadar(request.params);
    case "threatRadar.agent.configure":
      return configureThreatRadarAgent(request.params);
    case "threatRadar.agent.run":
      return runThreatRadarAgent();
    case "alerts.get":
      return getThreatAlerts();
    case "alerts.configure":
      return configureThreatAlerts(request.params);
    case "alerts.rule.add":
      return addThreatAlertRule(request.params);
    case "alerts.rule.remove":
      return removeThreatAlertRule(request.params);
    case "alerts.history.clear":
      return clearThreatAlertHistory();
    default:
      throw new BridgeOperationError("INVALID_REQUEST", "This action is not implemented in the bridge yet.");
  }
}

async function getBridgeConfig(params: unknown = {}): Promise<unknown> {
  const stored = await chrome.storage.local.get(["kibanaBaseUrl", "spaceId", "threatFoxAuthKey", "malwareBazaarAuthKey", "googleThreatIntelApiKey", THREAT_RADAR_AGENT_CONFIG_KEY, THREAT_RADAR_AGENT_STATE_KEY]);
  const includeReport = asRecord(params).includeReport === true;
  const agentState = asRecord(stored[THREAT_RADAR_AGENT_STATE_KEY]);
  const { report, ...agentStateWithoutReport } = agentState;
  const storedReport = asRecord(report);
  const compatibleAgentState = storedReport.historyVersion === THREAT_RADAR_HISTORY_VERSION
    ? agentState
    : agentStateWithoutReport;
  return {
    extensionVersion: chrome.runtime.getManifest().version,
    kibanaBaseUrl: typeof stored.kibanaBaseUrl === "string" ? stored.kibanaBaseUrl : undefined,
    spaceId: typeof stored.spaceId === "string" ? stored.spaceId : undefined,
    threatFoxAuthKeySaved: typeof stored.threatFoxAuthKey === "string" && stored.threatFoxAuthKey.trim().length > 0,
    malwareBazaarAuthKeySaved: typeof stored.malwareBazaarAuthKey === "string" && stored.malwareBazaarAuthKey.trim().length > 0,
    googleThreatIntelApiKeySaved: typeof stored.googleThreatIntelApiKey === "string" && stored.googleThreatIntelApiKey.trim().length > 0,
    threatRadarAgent: readThreatRadarAgentConfig(stored[THREAT_RADAR_AGENT_CONFIG_KEY]),
    threatRadarAgentState: includeReport ? compatibleAgentState : agentStateWithoutReport
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
    if (updates.googleThreatIntelApiKey) {
      resetGtiLookupState();
      await chrome.storage.local.remove("gtiReputationCacheV1");
    }
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
  const stored = await chrome.storage.local.get(THREAT_RADAR_AGENT_STATE_KEY);
  const state = filterThreatRadarAgentState(
    asRecord(stored[THREAT_RADAR_AGENT_STATE_KEY]),
    config.candidateExclusions
  );
  await chrome.storage.local.set({
    [THREAT_RADAR_AGENT_CONFIG_KEY]: config,
    [THREAT_RADAR_AGENT_STATE_KEY]: state
  });
  await ensureThreatRadarAgentSchedule();
  return { config, state };
}

function filterThreatRadarAgentState(state: Record<string, unknown>, exclusions: string[]): Record<string, unknown> {
  const report = asRecord(state.report) as ThreatRadarAgentReport;
  if (typeof report.analyzedAt !== "string") return state;
  return { ...state, report: filterThreatRadarReport(report, exclusions) };
}

function filterThreatRadarReport(report: ThreatRadarAgentReport, exclusions: string[]): ThreatRadarAgentReport {
  const allowFinding = (finding: ThreatRadarAgentFinding) => !isExcludedCandidate({
    ip: finding.ip,
    sourceIp: finding.sourceIp,
    destinationIp: finding.destinationIp,
    values: finding.actions.map((action) => action.key),
    text: `${finding.latest?.message ?? ""} ${finding.reasons.join(" ")}`
  }, exclusions);
  const allowIndicator = (indicator: NonNullable<ThreatRadarAgentReport["suspiciousIndicators"]>[number]) => !isExcludedCandidate({
    type: indicator.type === "hash" ? "sha256" : "domain",
    normalized: indicator.value,
    text: indicator.reasons.join(" ")
  }, exclusions);
  const filterFindings = (findings: ThreatRadarAgentFinding[] | undefined) => (
    Array.isArray(findings) ? findings.filter(allowFinding) : []
  );
  const suspects = filterFindings(report.suspects);
  const suspiciousIndicators = (report.suspiciousIndicators ?? []).filter(allowIndicator);
  const keywordCounts = [...suspects.flatMap((finding) => finding.matchedKeywords), ...suspiciousIndicators.flatMap((indicator) => indicator.matchedKeywords ?? [])]
    .reduce<Record<string, number>>((counts, key) => {
      counts[key] = (counts[key] ?? 0) + 1;
      return counts;
    }, {});
  const signalCounts: Record<string, number> = {
    denied: suspects.filter((finding) => finding.role === "source" && finding.direction === "inbound" && finding.deniedEvents > 0).length,
    outbound: suspects.filter((finding) => finding.direction === "outbound").length,
    dangerous_ports: suspects.filter((finding) => finding.role === "source" && finding.direction === "inbound" && finding.dangerousPorts.length > 0).length,
    indicators: suspiciousIndicators.length,
    ...keywordCounts
  };
  const signals = (report.signals ?? [])
    .map((signal) => ({ ...signal, count: signalCounts[signal.key] ?? 0 }))
    .filter((signal) => signal.count > 0);

  const updatedReport: ThreatRadarAgentReport = {
    ...report,
    suspects,
    externalSources: filterFindings(report.externalSources),
    suspiciousDestinations: filterFindings(report.suspiciousDestinations),
    suspiciousOutbound: filterFindings(report.suspiciousOutbound),
    deniedActivity: filterFindings(report.deniedActivity),
    reviewCandidates: filterFindings(report.reviewCandidates),
    suspiciousIndicators,
    signals,
    summary: {
      suspects: suspects.length,
      critical: suspects.filter((finding) => finding.score >= 80).length,
      high: suspects.filter((finding) => finding.score >= 55 && finding.score < 80).length,
      medium: suspects.filter((finding) => finding.score >= 25 && finding.score < 55).length
    }
  };
  return updatedReport;
}

async function runInteractiveThreatRadar(params: unknown): Promise<unknown> {
  const report = await analyzeThreatRadar(params) as ThreatRadarAgentReport;
  const alertResult = await processThreatRadarAlerts(report);
  return { ...report, alertsCreated: alertResult.alertsCreated };
}

async function runThreatRadarAgent(): Promise<unknown> {
  const config = await getThreatRadarAgentConfig();
  if (!config.enabled) return { config, state: { status: "disabled" } };
  if (threatRadarAgentRunning) return { config, state: { status: "running" } };

  threatRadarAgentRunning = true;
  const startedAt = new Date().toISOString();
  const previousState = asRecord((await chrome.storage.local.get(THREAT_RADAR_AGENT_STATE_KEY))[THREAT_RADAR_AGENT_STATE_KEY]);
  const previousReport = asRecord(previousState.report) as ThreatRadarAgentReport;
  await chrome.storage.local.set({
    [THREAT_RADAR_AGENT_STATE_KEY]: {
      status: "running",
      startedAt,
      candidates: 0,
      alertsCreated: 0,
      report: previousState.report
    }
  });
  try {
    const currentReport = await analyzeThreatRadar({
      indexPattern: config.indexPattern,
      timestampField: config.timestampField,
      from: `now-${config.intervalMinutes}m`,
      to: "now",
      size: 50
    }) as ThreatRadarAgentReport;
    const alertResult = await processThreatRadarAlerts(currentReport);
    const mergedReport = mergeThreatRadarReportHistory(currentReport, previousReport);
    const report = await backfillThreatRadarReportReputation(mergedReport);
    const state = {
      status: "healthy",
      startedAt,
      completedAt: new Date().toISOString(),
      candidates: alertResult.candidates,
      alertsCreated: alertResult.alertsCreated,
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

function mergeThreatRadarReportHistory(current: ThreatRadarAgentReport, previous: ThreatRadarAgentReport): ThreatRadarAgentReport {
  const observedAt = current.analyzedAt || new Date().toISOString();
  const compatiblePrevious = previous.historyVersion === THREAT_RADAR_HISTORY_VERSION ? previous : {} as ThreatRadarAgentReport;
  const merge = (currentFindings: ThreatRadarAgentFinding[], previousFindings: ThreatRadarAgentFinding[] | undefined) => (
    mergeFindingHistory(currentFindings, Array.isArray(previousFindings) ? previousFindings : [], observedAt)
  );
  const suspects = merge(current.suspects, compatiblePrevious.suspects);
  return {
    ...current,
    historyVersion: THREAT_RADAR_HISTORY_VERSION,
    suspects,
    externalSources: merge(current.externalSources, compatiblePrevious.externalSources),
    suspiciousDestinations: merge(current.suspiciousDestinations, compatiblePrevious.suspiciousDestinations),
    suspiciousOutbound: merge(current.suspiciousOutbound, compatiblePrevious.suspiciousOutbound),
    deniedActivity: merge(current.deniedActivity, compatiblePrevious.deniedActivity),
    reviewCandidates: merge(current.reviewCandidates ?? [], compatiblePrevious.reviewCandidates),
    summary: {
      suspects: suspects.length,
      critical: suspects.filter((finding) => finding.score >= 80).length,
      high: suspects.filter((finding) => finding.score >= 55 && finding.score < 80).length,
      medium: suspects.filter((finding) => finding.score >= 25 && finding.score < 55).length
    }
  };
}

async function backfillThreatRadarReportReputation(report: ThreatRadarAgentReport): Promise<ThreatRadarAgentReport> {
  const stored = await chrome.storage.local.get("googleThreatIntelApiKey");
  const apiKey = typeof stored.googleThreatIntelApiKey === "string" ? stored.googleThreatIntelApiKey.trim() : "";
  if (!apiKey) return report;

  const candidates = [...report.suspects, ...(report.reviewCandidates ?? [])]
    .filter((finding) => !finding.gti && finding.gtiIp && finding.gtiIp !== "--")
    .sort((left, right) => Number(right.active) - Number(left.active) || right.score - left.score);
  const unique = [...new Map(candidates.map((finding) => [threatRadarFindingKey(finding), finding])).values()].slice(0, 16);
  if (unique.length === 0) return report;

  const enriched = await enrichThreatRadarSuspects(unique, apiKey);
  const enrichedByKey = new Map(enriched.map((finding) => [threatRadarFindingKey(finding), finding]));
  const replace = (findings: ThreatRadarAgentFinding[] | undefined) => (findings ?? []).map((finding) => {
    const replacement = enrichedByKey.get(threatRadarFindingKey(finding));
    if (!replacement) return finding;
    return {
      ...finding,
      ...replacement,
      firstSeen: finding.firstSeen,
      lastSeen: finding.lastSeen,
      observations: finding.observations,
      previousEvents: finding.previousEvents,
      eventDelta: finding.eventDelta,
      active: finding.active
    } as ThreatRadarAgentFinding;
  });
  const suspects = replace(report.suspects);
  const reviewCandidates = replace(report.reviewCandidates);
  const allReputationRows = [...suspects, ...reviewCandidates].filter((finding) => finding.gti || finding.gtiStatus);
  const reputation = summarizeAgentGtiCoverage(allReputationRows);

  const updatedReport: ThreatRadarAgentReport = {
    ...report,
    suspects,
    externalSources: replace(report.externalSources),
    suspiciousDestinations: replace(report.suspiciousDestinations),
    suspiciousOutbound: replace(report.suspiciousOutbound),
    deniedActivity: replace(report.deniedActivity),
    reviewCandidates
  };
  if (report.analysis) updatedReport.analysis = { ...report.analysis, reputation };
  return updatedReport;
}

function threatRadarFindingKey(finding: ThreatRadarAgentFinding): string {
  return `${finding.role}|${finding.direction}|${finding.ip || finding.sourceIp || finding.destinationIp}`;
}

function summarizeAgentGtiCoverage(findings: ThreatRadarAgentFinding[]): GtiCoverageSummary {
  const scored = findings.filter((finding) => Boolean(finding.gti)).length;
  const rateLimited = findings.filter((finding) => finding.gtiStatus === "rate_limited").length;
  const pending = findings.filter((finding) => finding.gtiStatus === "pending").length;
  const failedStatuses = new Set<GtiLookupStatus>(["not_found", "unauthorized", "unavailable"]);
  const failed = findings.filter((finding) => finding.gtiStatus && failedStatuses.has(finding.gtiStatus)).length;
  return {
    status: findings.some((finding) => finding.gtiStatus === "unauthorized" || finding.gtiStatus === "unavailable") && scored === 0
      ? "unavailable"
      : scored === findings.length ? "healthy" : "partial",
    requested: findings.length,
    scored,
    cached: findings.filter((finding) => finding.gtiCached).length,
    pending,
    rateLimited,
    failed
  };
}

function readThreatAlertConfig(value: unknown): ThreatAlertConfig {
  const record = asRecord(value);
  const config: ThreatAlertConfig = {
    browserNotifications: record.browserNotifications !== false,
    cooldownMinutes: Math.min(1440, Math.max(5, readNumber(record.cooldownMinutes) || 60))
  };
  if (typeof record.discordWebhookUrl === "string" && isDiscordWebhook(record.discordWebhookUrl)) config.discordWebhookUrl = record.discordWebhookUrl;
  if (typeof record.telegramBotToken === "string" && isTelegramToken(record.telegramBotToken)) config.telegramBotToken = record.telegramBotToken;
  if (typeof record.telegramChatId === "string" && record.telegramChatId.trim()) config.telegramChatId = record.telegramChatId.trim();
  return config;
}

function readThreatAlertRules(value: unknown): ThreatAlertRule[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item) => {
    const record = asRecord(item);
    const indicatorType = record.indicatorType;
    const indicatorValue = typeof record.indicatorValue === "string" ? normalizeAlertIndicator(record.indicatorValue) : "";
    if (!isAlertIndicatorType(indicatorType) || !indicatorValue || typeof record.id !== "string") return [];
    return [{
      id: record.id,
      name: typeof record.name === "string" && record.name.trim() ? record.name.trim().slice(0, 120) : indicatorValue,
      indicatorType,
      indicatorValue,
      minScore: Math.min(200, Math.max(0, readNumber(record.minScore))),
      enabled: record.enabled !== false,
      createdAt: typeof record.createdAt === "string" ? record.createdAt : new Date().toISOString()
    }];
  });
}

function readThreatAlertHistory(value: unknown): ThreatAlertHistoryItem[] {
  return Array.isArray(value) ? value.filter((item): item is ThreatAlertHistoryItem => typeof item === "object" && item !== null) : [];
}

async function getThreatAlerts(): Promise<unknown> {
  const stored = await chrome.storage.local.get([THREAT_ALERT_CONFIG_KEY, THREAT_ALERT_RULES_KEY, THREAT_ALERT_HISTORY_KEY]);
  const config = readThreatAlertConfig(stored[THREAT_ALERT_CONFIG_KEY]);
  return {
    config: {
      browserNotifications: config.browserNotifications,
      discordConfigured: Boolean(config.discordWebhookUrl),
      telegramConfigured: Boolean(config.telegramBotToken && config.telegramChatId),
      cooldownMinutes: config.cooldownMinutes
    },
    rules: readThreatAlertRules(stored[THREAT_ALERT_RULES_KEY]),
    history: readThreatAlertHistory(stored[THREAT_ALERT_HISTORY_KEY]).sort((left, right) => right.lastSeenAt.localeCompare(left.lastSeenAt))
  };
}

async function configureThreatAlerts(params: unknown): Promise<unknown> {
  const record = asRecord(params);
  const stored = await chrome.storage.local.get(THREAT_ALERT_CONFIG_KEY);
  const config = readThreatAlertConfig(stored[THREAT_ALERT_CONFIG_KEY]);
  if (typeof record.browserNotifications === "boolean") config.browserNotifications = record.browserNotifications;
  if (typeof record.cooldownMinutes === "number") config.cooldownMinutes = Math.min(1440, Math.max(5, Math.round(record.cooldownMinutes)));

  if (record.clearDiscord === true) delete config.discordWebhookUrl;
  if (typeof record.discordWebhookUrl === "string" && record.discordWebhookUrl.trim()) {
    const value = record.discordWebhookUrl.trim();
    if (!isDiscordWebhook(value)) throw new BridgeOperationError("INVALID_REQUEST", "Discord webhook must be an HTTPS discord.com/api/webhooks URL.");
    config.discordWebhookUrl = value;
  }

  if (record.clearTelegram === true) {
    delete config.telegramBotToken;
    delete config.telegramChatId;
  }
  if (typeof record.telegramBotToken === "string" && record.telegramBotToken.trim()) {
    const value = record.telegramBotToken.trim();
    if (!isTelegramToken(value)) throw new BridgeOperationError("INVALID_REQUEST", "Telegram bot token format is invalid.");
    config.telegramBotToken = value;
  }
  if (typeof record.telegramChatId === "string" && record.telegramChatId.trim()) config.telegramChatId = record.telegramChatId.trim();

  await chrome.storage.local.set({ [THREAT_ALERT_CONFIG_KEY]: config });
  return getThreatAlerts();
}

async function addThreatAlertRule(params: unknown): Promise<unknown> {
  const record = asRecord(params);
  if (!isAlertIndicatorType(record.indicatorType)) throw new BridgeOperationError("INVALID_IOC", "Choose IP, domain, or hash for the alert rule.");
  const indicatorValue = typeof record.indicatorValue === "string" ? normalizeAlertIndicator(record.indicatorValue) : "";
  if (!isValidAlertIndicator(record.indicatorType, indicatorValue)) throw new BridgeOperationError("INVALID_IOC", "Enter a valid IP address, domain, or MD5/SHA hash.");

  const stored = await chrome.storage.local.get(THREAT_ALERT_RULES_KEY);
  const rules = readThreatAlertRules(stored[THREAT_ALERT_RULES_KEY]);
  const duplicate = rules.find((rule) => rule.indicatorType === record.indicatorType && rule.indicatorValue === indicatorValue);
  const requestedMinScore = typeof record.minScore === "number" && Number.isFinite(record.minScore) ? record.minScore : 55;
  const rule: ThreatAlertRule = {
    id: duplicate?.id ?? crypto.randomUUID(),
    name: typeof record.name === "string" && record.name.trim() ? record.name.trim().slice(0, 120) : `Watch ${indicatorValue}`,
    indicatorType: record.indicatorType,
    indicatorValue,
    minScore: Math.min(200, Math.max(0, Math.round(requestedMinScore))),
    enabled: true,
    createdAt: duplicate?.createdAt ?? new Date().toISOString()
  };
  const nextRules = duplicate ? rules.map((item) => item.id === duplicate.id ? rule : item) : [rule, ...rules];
  await chrome.storage.local.set({ [THREAT_ALERT_RULES_KEY]: nextRules });
  return getThreatAlerts();
}

async function removeThreatAlertRule(params: unknown): Promise<unknown> {
  const id = asRecord(params).id;
  if (typeof id !== "string") throw new BridgeOperationError("INVALID_REQUEST", "Alert rule id is required.");
  const stored = await chrome.storage.local.get(THREAT_ALERT_RULES_KEY);
  const rules = readThreatAlertRules(stored[THREAT_ALERT_RULES_KEY]).filter((rule) => rule.id !== id);
  await chrome.storage.local.set({ [THREAT_ALERT_RULES_KEY]: rules });
  return getThreatAlerts();
}

async function clearThreatAlertHistory(): Promise<unknown> {
  await chrome.storage.local.set({ [THREAT_ALERT_HISTORY_KEY]: [], [THREAT_RADAR_AGENT_ALERTS_KEY]: {} });
  return getThreatAlerts();
}

async function processThreatRadarAlerts(report: ThreatRadarAgentReport): Promise<{ candidates: number; alertsCreated: number }> {
  const stored = await chrome.storage.local.get([THREAT_ALERT_CONFIG_KEY, THREAT_ALERT_RULES_KEY, THREAT_ALERT_HISTORY_KEY, THREAT_RADAR_AGENT_ALERTS_KEY]);
  const config = readThreatAlertConfig(stored[THREAT_ALERT_CONFIG_KEY]);
  const rules = readThreatAlertRules(stored[THREAT_ALERT_RULES_KEY]);
  const history = readThreatAlertHistory(stored[THREAT_ALERT_HISTORY_KEY]);
  const cooldowns = asRecord(stored[THREAT_RADAR_AGENT_ALERTS_KEY]);
  const candidates = buildThreatAlertCandidates(report, rules);
  const now = Date.now();
  const nowIso = new Date(now).toISOString();
  let alertsCreated = 0;

  for (const candidate of candidates) {
    const existingIndex = history.findIndex((item) => item.fingerprint === candidate.fingerprint);
    const existing = existingIndex >= 0 ? history[existingIndex] : undefined;
    const lastNotified = typeof cooldowns[candidate.fingerprint] === "number" ? cooldowns[candidate.fingerprint] as number : 0;
    const shouldNotify = now - lastNotified >= config.cooldownMinutes * 60 * 1000;
    const delivery = shouldNotify ? await deliverThreatAlert(candidate, config) : existing?.delivery ?? disabledDelivery();
    const item: ThreatAlertHistoryItem = {
      ...candidate,
      id: existing?.id ?? crypto.randomUUID(),
      createdAt: existing?.createdAt ?? nowIso,
      lastSeenAt: nowIso,
      occurrences: (existing?.occurrences ?? 0) + 1,
      delivery
    };
    if (shouldNotify) {
      item.lastNotifiedAt = nowIso;
      cooldowns[candidate.fingerprint] = now;
      alertsCreated += 1;
    } else if (existing?.lastNotifiedAt) {
      item.lastNotifiedAt = existing.lastNotifiedAt;
    }
    if (existingIndex >= 0) history.splice(existingIndex, 1);
    history.unshift(item);
  }

  await chrome.storage.local.set({
    [THREAT_ALERT_HISTORY_KEY]: history.slice(0, 500),
    [THREAT_RADAR_AGENT_ALERTS_KEY]: cooldowns
  });
  return { candidates: candidates.length, alertsCreated };
}

async function deliverThreatAlert(candidate: ThreatAlertCandidate, config: ThreatAlertConfig): Promise<ThreatAlertDelivery> {
  const delivery = disabledDelivery();
  const message = formatThreatAlertMessage(candidate);
  if (config.browserNotifications) {
    try {
      await chrome.notifications.create(`soc-watch-alert-${Date.now()}-${crypto.randomUUID()}`, {
        type: "basic",
        iconUrl: chrome.runtime.getURL("icon-128.svg"),
        title: `SOC Watch: ${candidate.title}`,
        message
      });
      delivery.browser = "sent";
    } catch (error) {
      delivery.browser = "failed";
      delivery.errors.push(`Browser: ${error instanceof Error ? error.message : "notification failed"}`);
    }
  }

  if (config.discordWebhookUrl) {
    try {
      const response = await fetch(config.discordWebhookUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ content: `**SOC Watch: ${candidate.title}**\n${message}`.slice(0, 1900) })
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      delivery.discord = "sent";
    } catch (error) {
      delivery.discord = "failed";
      delivery.errors.push(`Discord: ${error instanceof Error ? error.message : "delivery failed"}`);
    }
  }

  if (config.telegramBotToken && config.telegramChatId) {
    try {
      const response = await fetch(`https://api.telegram.org/bot${config.telegramBotToken}/sendMessage`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ chat_id: config.telegramChatId, text: `SOC Watch: ${candidate.title}\n${message}`.slice(0, 3900) })
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      delivery.telegram = "sent";
    } catch (error) {
      delivery.telegram = "failed";
      delivery.errors.push(`Telegram: ${error instanceof Error ? error.message : "delivery failed"}`);
    }
  }
  return delivery;
}

function disabledDelivery(): ThreatAlertDelivery {
  return { browser: "disabled", discord: "disabled", telegram: "disabled", errors: [] };
}

function formatThreatAlertMessage(candidate: ThreatAlertCandidate): string {
  const route = candidate.sourceIp || candidate.destinationIp
    ? `${candidate.sourceIp ?? "--"} -> ${candidate.destinationIp ?? "--"}`
    : candidate.indicator;
  const rule = candidate.ruleNames.length ? ` Rule: ${candidate.ruleNames.join(", ")}.` : "";
  return `${route}. Score ${candidate.score}; ${candidate.events.toLocaleString()} events. ${candidate.reasons.slice(0, 3).join("; ")}.${rule}`;
}

function isAlertIndicatorType(value: unknown): value is AlertIndicatorType {
  return value === "ip" || value === "domain" || value === "hash";
}

function isValidAlertIndicator(type: AlertIndicatorType, value: string): boolean {
  if (type === "ip") return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value) || /^[0-9a-f:]{2,}$/i.test(value);
  if (type === "domain") return /^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$/i.test(value);
  return /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(value);
}

function isDiscordWebhook(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && ["discord.com", "discordapp.com"].includes(url.hostname) && url.pathname.startsWith("/api/webhooks/");
  } catch {
    return false;
  }
}

function isTelegramToken(value: string): boolean {
  return /^\d{5,15}:[A-Za-z0-9_-]{20,}$/.test(value);
}

async function runDailyIocHunt(params: unknown): Promise<unknown> {
  const parsed = dailyIocHuntParamsSchema.parse(params);
  const startedAt = new Date().toISOString();
  const collection = await collectDailyThreatIntel(parsed.maxIocs, parsed.batchOffset);
  const agentConfig = await getThreatRadarAgentConfig();
  const iocs = collection.iocs.filter((ioc) => !isExcludedCandidate({
    type: ioc.type,
    normalized: ioc.normalized,
    values: [ioc.malware ?? "", ioc.threatType ?? "", ...ioc.sources]
  }, agentConfig.candidateExclusions));
  let results;
  try {
    const raw = await searchIOCBatch({
      iocs,
      indexPattern: parsed.indexPattern,
      timestampField: parsed.timestampField,
      from: parsed.from,
      to: parsed.to,
      size: parsed.size
    });
    const buckets = asRecord(asRecord(asRecord(raw).aggregations).ioc_matches).buckets;
    const bucketMap = asRecord(buckets);
    results = iocs.map((ioc, index) => {
      const bucket = asRecord(bucketMap[`ioc_${index}`]);
      const total = readNumber(bucket.doc_count);
      return {
        ioc,
        total,
        hits: summarizeBulkHits(bucket),
        matched: total > 0
      };
    });
  } catch (error) {
    results = iocs.map((ioc) => ({
      ioc,
      total: 0,
      hits: [],
      matched: false,
      error: error instanceof Error ? error.message : "IOC hunt search failed."
    }));
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
    batchNumber: Math.floor(collection.batchOffset / parsed.maxIocs) + 1,
    batchOffset: collection.batchOffset,
    batchSize: collection.batchSize,
    totalAvailable: collection.totalAvailable,
    nextBatchOffset: collection.batchOffset + collection.batchSize,
    hasMore: collection.hasMore,
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

function summarizeBulkHits(bucket: Record<string, unknown>): Array<{ index: string; timestamp: string | undefined; host: string | undefined; eventAction: string | undefined; destinationPort: number | undefined; sourceIp: string | undefined; destinationIp: string | undefined; message: string | undefined }> {
  const latest = asRecord(bucket.latest);
  const hitsObject = asRecord(latest.hits);
  const rawHits = Array.isArray(hitsObject.hits) ? hitsObject.hits : [];
  return rawHits.slice(0, 5).map((hit) => {
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
  });
}

function readNumber(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
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
