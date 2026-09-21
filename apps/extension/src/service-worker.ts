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
  type ThreatRadarFinding,
  type ThreatRadarIdentityAnomaly
} from "./kibana";
import { collectDailyThreatIntel, type ThreatIntelIOC } from "./threat-intel";
import { isExcludedCandidate, type CandidateException } from "./candidate-exclusions";
import { mergeFindingHistory, THREAT_RADAR_HISTORY_RETENTION_MS } from "./threat-radar-history";
import { classifyIdentityValue } from "./identity-analysis";
import { DETECTION_PACK_VERSION, type DetectionCoverageRow } from "./detection-packs";
import { suppressesAutomaticAlert, type ThreatFeedbackDisposition, type ThreatFeedbackRecord, type ThreatFeedbackTarget } from "./threat-feedback";
import { normalizeCaseRecord, type ThreatCaseRecord, type ThreatCaseSeverity, type ThreatCaseStatus } from "./case-store";
import {
  buildThreatAlertCandidates,
  normalizeAlertIndicator,
  type AlertIndicatorType,
  type ThreatAlertCandidate,
  type ThreatAlertRule
} from "./threat-alerts";
import { deriveConnectionHealth, type ConnectionState } from "./connection-health";

const THREAT_RADAR_AGENT_ALARM = "soc-watch-threat-radar-agent";
const CONNECTION_HEALTH_ALARM = "soc-watch-connection-health";
const CONNECTION_HEALTH_PERIOD_MINUTES = 1;
const THREAT_RADAR_AGENT_CONFIG_KEY = "threatRadarAgentConfig";
const THREAT_RADAR_AGENT_STATE_KEY = "threatRadarAgentState";
const THREAT_RADAR_AGENT_ALERTS_KEY = "threatRadarAgentAlerts";
const THREAT_ALERT_CONFIG_KEY = "threatAlertConfig";
const THREAT_ALERT_RULES_KEY = "threatAlertRules";
const THREAT_ALERT_HISTORY_KEY = "threatAlertHistory";
const THREAT_ALERT_BROWSER_DIAGNOSTICS_KEY = "threatAlertBrowserDiagnostics";
const THREAT_ALERT_NOTIFICATION_ICON = "icon-128.png";
const CHROME_NOTIFICATION_API_TIMEOUT_MS = 5000;

type ThreatRadarAgentConfig = {
  enabled: boolean;
  intervalMinutes: number;
  indexPattern: string;
  timestampField: string;
  candidateExclusions: string[];
  candidateExceptions: CandidateException[];
};

type ThreatRadarScanRun = {
  id: string;
  mode: "automatic" | "manual";
  status: "running" | "healthy" | "partial" | "error";
  startedAt: string;
  completedAt?: string;
  from?: string;
  to?: string;
  eventsAnalyzed: number;
  candidates: number;
  alertsCreated: number;
  notificationsSent: number;
  notificationsFailed: number;
  completedStages: string[];
  skippedStages: string[];
  error?: string;
  detectionPackVersion: string;
};

type ThreatRadarAgentFinding = ThreatRadarFinding & {
  firstSeen?: string;
  lastSeen?: string;
  observations?: number;
  previousEvents?: number;
  eventDelta?: number;
  active?: boolean;
};

type ThreatRadarAgentIdentity = ThreatRadarIdentityAnomaly & {
  observations?: number;
  previousEvents?: number;
  eventDelta?: number;
  active?: boolean;
};

type ThreatRadarAgentReport = {
  historyVersion?: number;
  analyzedAt: string;
  eventsAnalyzed: number;
  suspects: ThreatRadarAgentFinding[];
  externalSources: ThreatRadarAgentFinding[];
  suspiciousDestinations: ThreatRadarAgentFinding[];
  suspiciousOutbound: ThreatRadarAgentFinding[];
  deniedActivity: ThreatRadarAgentFinding[];
  identityAnomalies?: ThreatRadarAgentIdentity[];
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
    detectionPackVersion?: string;
    detectionCoverage?: DetectionCoverageRow[];
    scanId?: string;
    scanMode?: "automatic" | "manual";
    dataHealth?: {
      status: "healthy" | "partial" | "unavailable";
      indexPattern: string;
      from: string;
      to: string;
      events: number;
      exactEventCount: boolean;
      fields: Array<{ key: string; label: string; coverage: number; events: number }>;
      completedStages: string[];
      skippedStages: string[];
      tookMs?: number;
      message?: string;
    };
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

type BrowserNotificationPermission = "granted" | "denied" | "unavailable";

type ThreatAlertDelivery = {
  browser: "sent" | "disabled" | "failed";
  discord: "sent" | "disabled" | "failed";
  telegram: "sent" | "disabled" | "failed";
  browserPermission?: BrowserNotificationPermission;
  browserNotificationId?: string;
  browserAttemptedAt?: string;
  errors: string[];
};

type BrowserNotificationDiagnostics = {
  enabled: boolean;
  apiAvailable: boolean;
  permission: BrowserNotificationPermission;
  status: "ready" | "disabled" | "blocked" | "sent" | "failed";
  checkedAt: string;
  iconUrl: string | null;
  lastAttemptAt: string | null;
  lastSuccessAt: string | null;
  lastNotificationId: string | null;
  lastError: string | null;
};

type ThreatAlertHistoryItem = ThreatAlertCandidate & {
  id: string;
  createdAt: string;
  lastSeenAt: string;
  lastNotifiedAt?: string;
  occurrences: number;
  delivery: ThreatAlertDelivery;
};

const THREAT_RADAR_HISTORY_VERSION = 10;
const THREAT_RADAR_SCAN_HISTORY_KEY = "threatRadarScanHistory";
const THREAT_RADAR_FEEDBACK_KEY = "threatRadarFeedbackV1";
const THREAT_RADAR_CASES_KEY = "threatRadarCasesV1";
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
  void ensureConnectionHealthSchedule();
  void refreshStoredConnectionHealth();
  void ensureThreatRadarAgentSchedule();
  void runThreatRadarAgent();
});

chrome.runtime.onStartup.addListener(() => {
  void ensureSocWatchRelays();
  void ensureConnectionHealthSchedule();
  void refreshStoredConnectionHealth();
  void ensureThreatRadarAgentSchedule();
  void runThreatRadarAgent();
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === THREAT_RADAR_AGENT_ALARM) void runThreatRadarAgent();
  if (alarm.name === CONNECTION_HEALTH_ALARM) void refreshStoredConnectionHealth();
});

void setDisconnectedIcon();
void ensureSocWatchRelays();
void ensureConnectionHealthSchedule();
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
    await setConnectedBadge(request.action);
    return ok(requestId, data, elapsed(started));
  } catch (error) {
    if (error instanceof BridgeOperationError) {
      if (isKibanaConnectionError(error.code)) await setDisconnectedIcon();
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
    return ok(requestId, data, elapsed(started));
  } catch (error) {
    if (error instanceof BridgeOperationError) {
      if (isKibanaConnectionError(error.code)) await setDisconnectedIcon();
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
  let kibana: Awaited<ReturnType<typeof getKibanaStatus>>;
  try {
    kibana = await getKibanaStatus();
  } catch (error) {
    const failure = bridgeErrorPayload(error);
    const connection = deriveConnectionHealth({
      kibanaAvailable: false,
      fleetAvailable: false,
      agentsAvailable: false,
      kibanaError: failure
    });
    await setConnectionIcon(connection.state);
    return {
      state: connection.state,
      bridge: { state: "connected", version: chrome.runtime.getManifest().version },
      connection,
      updatedAt,
      kibana: { overall: "unavailable" },
      fleet: null,
      agents: [],
      problemAgents: [],
      serviceErrors: [failure],
      error: failure
    };
  }

  const [fleetResult, agentsResult] = await Promise.allSettled([
    getFleetSummary({}),
    listAllFleetAgents()
  ]);
  const fleet = fleetResult.status === "fulfilled"
    ? fleetResult.value
    : null;
  const agents = agentsResult.status === "fulfilled" ? agentsResult.value : [];
  const problemAgents = agents.filter((agent) => agent.status === "offline" || agent.status === "error");
  const errors = [fleetResult, agentsResult]
    .filter((result): result is PromiseRejectedResult => result.status === "rejected")
    .map((result) => bridgeErrorPayload(result.reason));
  const connection = deriveConnectionHealth({
    kibanaAvailable: true,
    fleetAvailable: fleetResult.status === "fulfilled",
    agentsAvailable: agentsResult.status === "fulfilled"
  });

  await setConnectionIcon(connection.state);
  return {
    state: connection.state,
    bridge: { state: "connected", version: chrome.runtime.getManifest().version },
    connection,
    updatedAt,
    kibana,
    fleet,
    agents,
    problemAgents,
    serviceErrors: errors,
    ...(errors[0] ? { error: errors[0] } : {})
  };
}

async function ensureConnectionHealthSchedule(): Promise<void> {
  const existing = await chrome.alarms.get(CONNECTION_HEALTH_ALARM);
  if (existing) return;
  chrome.alarms.create(CONNECTION_HEALTH_ALARM, { periodInMinutes: CONNECTION_HEALTH_PERIOD_MINUTES });
}

async function refreshStoredConnectionHealth(): Promise<void> {
  try {
    const snapshot = await collectLiveSnapshot();
    await chrome.storage.local.set({ lastConnection: snapshot });
  } catch {
    await setDisconnectedIcon();
  }
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

function isKibanaConnectionError(code: string): boolean {
  return code === "KIBANA_AUTH_REQUIRED"
    || code === "KIBANA_FORBIDDEN"
    || code === "KIBANA_NOT_FOUND"
    || code === "KIBANA_UNREACHABLE";
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
    case "alerts.test":
      return testThreatAlertDelivery();
    case "threatRadar.feedback.list":
      return listThreatRadarFeedback();
    case "threatRadar.feedback.save":
      return saveThreatRadarFeedback(request.params);
    case "cases.list":
      return listThreatCases();
    case "cases.create":
      return createThreatCase(request.params);
    case "cases.update":
      return updateThreatCase(request.params);
    case "cases.note":
      return addThreatCaseNote(request.params);
    default:
      throw new BridgeOperationError("INVALID_REQUEST", "This action is not implemented in the bridge yet.");
  }
}

async function getBridgeConfig(params: unknown = {}): Promise<unknown> {
  const stored = await chrome.storage.local.get(["kibanaBaseUrl", "spaceId", "threatFoxAuthKey", "malwareBazaarAuthKey", "googleThreatIntelApiKey", THREAT_RADAR_AGENT_CONFIG_KEY, THREAT_RADAR_AGENT_STATE_KEY, THREAT_RADAR_SCAN_HISTORY_KEY]);
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
    threatRadarAgentState: {
      ...(includeReport ? compatibleAgentState : agentStateWithoutReport),
      scanHistory: readThreatRadarScanHistory(stored[THREAT_RADAR_SCAN_HISTORY_KEY])
    }
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
  return parsed.success ? parsed.data : {
    enabled: true,
    intervalMinutes: 15,
    indexPattern: "logs-*",
    timestampField: "@timestamp",
    candidateExclusions: [],
    candidateExceptions: []
  };
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
    config.candidateExclusions,
    config.candidateExceptions
  );
  await chrome.storage.local.set({
    [THREAT_RADAR_AGENT_CONFIG_KEY]: config,
    [THREAT_RADAR_AGENT_STATE_KEY]: state
  });
  await ensureThreatRadarAgentSchedule();
  return { config, state };
}

function filterThreatRadarAgentState(state: Record<string, unknown>, exclusions: string[], exceptions: CandidateException[]): Record<string, unknown> {
  const report = asRecord(state.report) as ThreatRadarAgentReport;
  if (typeof report.analyzedAt !== "string") return state;
  return { ...state, report: filterThreatRadarReport(report, exclusions, exceptions) };
}

function filterThreatRadarReport(report: ThreatRadarAgentReport, exclusions: string[], exceptions: CandidateException[]): ThreatRadarAgentReport {
  const allowFinding = (finding: ThreatRadarAgentFinding) => !isExcludedCandidate({
    ip: finding.ip,
    sourceIp: finding.sourceIp,
    destinationIp: finding.destinationIp,
    values: finding.actions.map((action) => action.key),
    text: `${finding.latest?.message ?? ""} ${finding.reasons.join(" ")}`,
    fields: {
      "source.ip": finding.sourceIp,
      "destination.ip": finding.destinationIp,
      "host.name": finding.latest?.host,
      "event.action": finding.actions.map((action) => action.key),
      "data_stream.dataset": finding.datasets.map((dataset) => dataset.key)
    }
  }, exclusions, exceptions);
  const allowIndicator = (indicator: NonNullable<ThreatRadarAgentReport["suspiciousIndicators"]>[number]) => !isExcludedCandidate({
    type: indicator.type === "hash" ? "sha256" : "domain",
    normalized: indicator.value,
    text: indicator.reasons.join(" ")
  }, exclusions, exceptions);
  const allowIdentity = (identity: ThreatRadarAgentIdentity) => !isExcludedCandidate({
    type: "identity",
    normalized: identity.identity,
    sourceIp: identity.sourceIp,
    destinationIp: identity.destinationIp,
    values: [
      identity.identity,
      identity.rawIdentity,
      identity.sourceField,
      ...(identity.actions ?? []).map((action) => action.key),
      ...(identity.datasets ?? []).map((dataset) => dataset.key)
    ],
    text: identity.reasons.join(" "),
    fields: {
      [identity.sourceField]: identity.identity,
      "source.ip": identity.sourceIp,
      "destination.ip": identity.destinationIp,
      "data_stream.dataset": (identity.datasets ?? []).map((dataset) => dataset.key)
    }
  }, exclusions, exceptions);
  const filterFindings = (findings: ThreatRadarAgentFinding[] | undefined) => (
    Array.isArray(findings) ? findings.filter(allowFinding) : []
  );
  const suspects = filterFindings(report.suspects);
  const suspiciousIndicators = (report.suspiciousIndicators ?? []).filter(allowIndicator);
  const identityAnomalies = (report.identityAnomalies ?? []).filter(allowIdentity);
  const activeSuspects = suspects.filter((finding) => finding.active !== false);
  const activeIdentities = identityAnomalies.filter((identity) => identity.active !== false);
  const keywordCounts = [...activeSuspects.flatMap((finding) => finding.matchedKeywords), ...suspiciousIndicators.flatMap((indicator) => indicator.matchedKeywords ?? [])]
    .reduce<Record<string, number>>((counts, key) => {
      counts[key] = (counts[key] ?? 0) + 1;
      return counts;
    }, {});
  const signalCounts: Record<string, number> = {
    denied: activeSuspects.filter((finding) => finding.role === "source" && finding.direction === "inbound" && finding.deniedEvents > 0).length,
    outbound: activeSuspects.filter((finding) => finding.direction === "outbound").length,
    dangerous_ports: activeSuspects.filter((finding) => finding.role === "source" && finding.direction === "inbound" && finding.dangerousPorts.length > 0).length,
    indicators: suspiciousIndicators.length,
    identity_auth: activeIdentities.length,
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
    identityAnomalies,
    reviewCandidates: filterFindings(report.reviewCandidates),
    suspiciousIndicators,
    signals,
    summary: {
      suspects: activeSuspects.length + activeIdentities.filter((identity) => identity.promoted).length,
      critical: activeSuspects.filter((finding) => finding.score >= 80).length + activeIdentities.filter((identity) => identity.promoted && identity.severity === "critical").length,
      high: activeSuspects.filter((finding) => finding.score >= 55 && finding.score < 80).length + activeIdentities.filter((identity) => identity.promoted && identity.severity === "high").length,
      medium: activeSuspects.filter((finding) => finding.score >= 25 && finding.score < 55).length + activeIdentities.filter((identity) => identity.promoted && identity.severity === "medium").length
    }
  };
  return updatedReport;
}

function readThreatRadarScanHistory(value: unknown): ThreatRadarScanRun[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is ThreatRadarScanRun => {
    const record = asRecord(item);
    return typeof record.id === "string" && typeof record.startedAt === "string" && (record.mode === "automatic" || record.mode === "manual");
  }).slice(0, 50);
}

function appendThreatRadarScanRun(history: ThreatRadarScanRun[], run: ThreatRadarScanRun): ThreatRadarScanRun[] {
  return [run, ...history.filter((item) => item.id !== run.id)]
    .sort((left, right) => right.startedAt.localeCompare(left.startedAt))
    .slice(0, 50);
}

async function persistThreatRadarScanRun(run: ThreatRadarScanRun): Promise<ThreatRadarScanRun[]> {
  const stored = await chrome.storage.local.get(THREAT_RADAR_SCAN_HISTORY_KEY);
  const history = appendThreatRadarScanRun(readThreatRadarScanHistory(stored[THREAT_RADAR_SCAN_HISTORY_KEY]), run);
  await chrome.storage.local.set({ [THREAT_RADAR_SCAN_HISTORY_KEY]: history });
  return history;
}

async function runInteractiveThreatRadar(params: unknown): Promise<unknown> {
  const scanId = crypto.randomUUID();
  const startedAt = new Date().toISOString();
  const request = asRecord(params);
  const baseRun: ThreatRadarScanRun = {
    id: scanId,
    mode: "manual",
    status: "running",
    startedAt,
    ...(typeof request.from === "string" ? { from: request.from } : {}),
    ...(typeof request.to === "string" ? { to: request.to } : {}),
    eventsAnalyzed: 0,
    candidates: 0,
    alertsCreated: 0,
    notificationsSent: 0,
    notificationsFailed: 0,
    completedStages: [],
    skippedStages: [],
    detectionPackVersion: DETECTION_PACK_VERSION
  };
  await persistThreatRadarScanRun(baseRun);
  try {
    let report = await analyzeThreatRadar(params) as ThreatRadarAgentReport;
    if (report.analysis) report = { ...report, analysis: { ...report.analysis, scanId, scanMode: "manual" } };
    const alertResult = await processThreatRadarAlerts(report);
    const partial = report.analysis?.partial === true || report.analysis?.dataHealth?.status !== "healthy";
    await persistThreatRadarScanRun({
      ...baseRun,
      status: partial ? "partial" : "healthy",
      completedAt: new Date().toISOString(),
      eventsAnalyzed: report.analysis?.dataHealth?.events ?? report.eventsAnalyzed,
      candidates: alertResult.candidates,
      alertsCreated: alertResult.alertsCreated,
      notificationsSent: alertResult.notificationsSent,
      notificationsFailed: alertResult.notificationsFailed,
      completedStages: report.analysis?.completedStages ?? [],
      skippedStages: report.analysis?.skippedStages ?? []
    });
    return { ...report, alertsCreated: alertResult.alertsCreated };
  } catch (error) {
    await persistThreatRadarScanRun({
      ...baseRun,
      status: "error",
      completedAt: new Date().toISOString(),
      error: error instanceof Error ? error.message : "Threat Radar scan failed."
    });
    throw error;
  }
}

async function runThreatRadarAgent(): Promise<unknown> {
  const config = await getThreatRadarAgentConfig();
  if (!config.enabled) return { config, state: { status: "disabled" } };
  const stored = await chrome.storage.local.get([THREAT_RADAR_AGENT_STATE_KEY, THREAT_RADAR_SCAN_HISTORY_KEY]);
  const previousState = asRecord(stored[THREAT_RADAR_AGENT_STATE_KEY]);
  const previousStartedAt = typeof previousState.startedAt === "string" ? Date.parse(previousState.startedAt) : 0;
  const leaseMs = Math.max(10, config.intervalMinutes * 2) * 60 * 1000;
  if (threatRadarAgentRunning || (previousState.status === "running" && Number.isFinite(previousStartedAt) && Date.now() - previousStartedAt < leaseMs)) {
    return { config, state: { ...previousState, status: "running", scanHistory: readThreatRadarScanHistory(stored[THREAT_RADAR_SCAN_HISTORY_KEY]) } };
  }

  threatRadarAgentRunning = true;
  const scanId = crypto.randomUUID();
  const startedAt = new Date().toISOString();
  const from = `now-${config.intervalMinutes}m`;
  const previousReport = asRecord(previousState.report) as ThreatRadarAgentReport;
  const runningRun: ThreatRadarScanRun = {
    id: scanId,
    mode: "automatic",
    status: "running",
    startedAt,
    from,
    to: "now",
    eventsAnalyzed: 0,
    candidates: 0,
    alertsCreated: 0,
    notificationsSent: 0,
    notificationsFailed: 0,
    completedStages: [],
    skippedStages: [],
    detectionPackVersion: DETECTION_PACK_VERSION
  };
  const runningHistory = appendThreatRadarScanRun(readThreatRadarScanHistory(stored[THREAT_RADAR_SCAN_HISTORY_KEY]), runningRun);
  await chrome.storage.local.set({
    [THREAT_RADAR_SCAN_HISTORY_KEY]: runningHistory,
    [THREAT_RADAR_AGENT_STATE_KEY]: {
      ...previousState,
      status: "running",
      runId: scanId,
      startedAt,
      candidates: 0,
      alertsCreated: 0,
      report: previousState.report,
      scanHistory: runningHistory
    }
  });
  try {
    let currentReport = await analyzeThreatRadar({
      indexPattern: config.indexPattern,
      timestampField: config.timestampField,
      from,
      to: "now",
      size: 50
    }) as ThreatRadarAgentReport;
    if (currentReport.analysis) currentReport = { ...currentReport, analysis: { ...currentReport.analysis, scanId, scanMode: "automatic" } };
    const alertResult = await processThreatRadarAlerts(currentReport);
    const mergedReport = mergeThreatRadarReportHistory(currentReport, previousReport);
    const report = await backfillThreatRadarReportReputation(mergedReport);
    const completedAt = new Date().toISOString();
    const partial = report.analysis?.partial === true || report.analysis?.dataHealth?.status !== "healthy";
    const completedRun: ThreatRadarScanRun = {
      ...runningRun,
      status: partial ? "partial" : "healthy",
      completedAt,
      eventsAnalyzed: report.analysis?.dataHealth?.events ?? report.eventsAnalyzed,
      candidates: alertResult.candidates,
      alertsCreated: alertResult.alertsCreated,
      notificationsSent: alertResult.notificationsSent,
      notificationsFailed: alertResult.notificationsFailed,
      completedStages: report.analysis?.completedStages ?? [],
      skippedStages: report.analysis?.skippedStages ?? []
    };
    const scanHistory = appendThreatRadarScanRun(runningHistory, completedRun);
    const state = {
      status: partial ? "partial" : "healthy",
      runId: scanId,
      startedAt,
      completedAt,
      lastSuccessfulRunAt: completedAt,
      consecutiveFailures: 0,
      candidates: alertResult.candidates,
      alertsCreated: alertResult.alertsCreated,
      notificationsSent: alertResult.notificationsSent,
      notificationsFailed: alertResult.notificationsFailed,
      suppressedAlerts: alertResult.suppressed,
      report,
      scanHistory
    };
    await chrome.storage.local.set({ [THREAT_RADAR_AGENT_STATE_KEY]: state, [THREAT_RADAR_SCAN_HISTORY_KEY]: scanHistory });
    return { config, state };
  } catch (error) {
    const completedAt = new Date().toISOString();
    const message = error instanceof Error ? error.message : "Threat Radar agent scan failed.";
    const failedRun: ThreatRadarScanRun = { ...runningRun, status: "error", completedAt, error: message };
    const scanHistory = appendThreatRadarScanRun(runningHistory, failedRun);
    const state = {
      ...previousState,
      status: "error",
      runId: scanId,
      startedAt,
      completedAt,
      candidates: 0,
      alertsCreated: 0,
      consecutiveFailures: readNumber(previousState.consecutiveFailures) + 1,
      lastError: message,
      report: previousState.report,
      scanHistory
    };
    await chrome.storage.local.set({ [THREAT_RADAR_AGENT_STATE_KEY]: state, [THREAT_RADAR_SCAN_HISTORY_KEY]: scanHistory });
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
  const mergeIdentities = (currentIdentities: ThreatRadarAgentIdentity[], previousIdentities: ThreatRadarAgentIdentity[] | undefined) => {
    const previousByKey = new Map((Array.isArray(previousIdentities) ? previousIdentities : [])
      .map((identity) => [identityHistoryKey(identity), identity] as const));
    const currentKeys = new Set<string>();
    const active = currentIdentities.map((identity) => {
      const key = identityHistoryKey(identity);
      currentKeys.add(key);
      const prior = previousByKey.get(key);
      return {
        ...prior,
        ...identity,
        firstSeen: prior?.firstSeen ?? identity.firstSeen ?? observedAt,
        lastSeen: observedAt,
        observations: (prior?.observations ?? 0) + 1,
        active: true,
        ...(prior ? {
          previousEvents: prior.events,
          eventDelta: identity.events - prior.events
        } : {})
      };
    });
    const observedTime = Date.parse(observedAt);
    const cutoff = Number.isFinite(observedTime)
      ? observedTime - THREAT_RADAR_HISTORY_RETENTION_MS
      : Date.now() - THREAT_RADAR_HISTORY_RETENTION_MS;
    const retained = (Array.isArray(previousIdentities) ? previousIdentities : [])
      .filter((identity) => !currentKeys.has(identityHistoryKey(identity)))
      .filter((identity) => {
        const lastSeen = Date.parse(identity.lastSeen ?? "");
        return Number.isFinite(lastSeen) && lastSeen >= cutoff;
      })
      .map((identity) => ({ ...identity, active: false }));
    return [...active, ...retained]
      .sort((left, right) => Number(right.active) - Number(left.active) || right.score - left.score || right.events - left.events);
  };
  const suspects = merge(current.suspects, compatiblePrevious.suspects);
  const identityAnomalies = mergeIdentities(current.identityAnomalies ?? [], compatiblePrevious.identityAnomalies);
  const activeSuspects = suspects.filter((finding) => finding.active !== false);
  const activeIdentities = identityAnomalies.filter((identity) => identity.active !== false);
  return {
    ...current,
    historyVersion: THREAT_RADAR_HISTORY_VERSION,
    suspects,
    externalSources: merge(current.externalSources, compatiblePrevious.externalSources),
    suspiciousDestinations: merge(current.suspiciousDestinations, compatiblePrevious.suspiciousDestinations),
    suspiciousOutbound: merge(current.suspiciousOutbound, compatiblePrevious.suspiciousOutbound),
    deniedActivity: merge(current.deniedActivity, compatiblePrevious.deniedActivity),
    identityAnomalies,
    reviewCandidates: merge(current.reviewCandidates ?? [], compatiblePrevious.reviewCandidates),
    summary: {
      suspects: activeSuspects.length + activeIdentities.filter((identity) => identity.promoted).length,
      critical: activeSuspects.filter((finding) => finding.score >= 80).length + activeIdentities.filter((identity) => identity.promoted && identity.severity === "critical").length,
      high: activeSuspects.filter((finding) => finding.score >= 55 && finding.score < 80).length + activeIdentities.filter((identity) => identity.promoted && identity.severity === "high").length,
      medium: activeSuspects.filter((finding) => finding.score >= 25 && finding.score < 55).length + activeIdentities.filter((identity) => identity.promoted && identity.severity === "medium").length
    }
  };
}

function identityHistoryKey(identity: ThreatRadarAgentIdentity): string {
  return identity.identity.trim().toLowerCase();
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
  const notFound = findings.filter((finding) => finding.gtiStatus === "not_found").length;
  const unauthorized = findings.filter((finding) => finding.gtiStatus === "unauthorized").length;
  const unavailable = findings.filter((finding) => finding.gtiStatus === "unavailable").length;
  const failed = notFound + unauthorized + unavailable;
  return {
    status: (unauthorized > 0 || unavailable > 0) && scored === 0
      ? "unavailable"
      : pending > 0 || rateLimited > 0 || unauthorized > 0 || unavailable > 0 ? "partial" : "healthy",
    requested: findings.length,
    scored,
    cached: findings.filter((finding) => finding.gtiCached).length,
    pending,
    rateLimited,
    notFound,
    unauthorized,
    unavailable,
    failed,
    failureReasons: summarizeAgentGtiFailureReasons(findings)
  };
}

function summarizeAgentGtiFailureReasons(findings: ThreatRadarAgentFinding[]): Array<{ message: string; count: number }> {
  const counts = new Map<string, number>();
  for (const finding of findings) {
    if (finding.gtiStatus !== "unavailable" || !finding.gtiMessage) continue;
    counts.set(finding.gtiMessage, (counts.get(finding.gtiMessage) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([message, count]) => ({ message, count }))
    .sort((left, right) => right.count - left.count)
    .slice(0, 3);
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
  const stored = await chrome.storage.local.get([
    THREAT_ALERT_CONFIG_KEY,
    THREAT_ALERT_RULES_KEY,
    THREAT_ALERT_HISTORY_KEY,
    THREAT_ALERT_BROWSER_DIAGNOSTICS_KEY,
    THREAT_RADAR_FEEDBACK_KEY,
    THREAT_RADAR_CASES_KEY
  ]);
  const config = readThreatAlertConfig(stored[THREAT_ALERT_CONFIG_KEY]);
  const browserDiagnostics = await getBrowserNotificationDiagnostics(
    config.browserNotifications,
    stored[THREAT_ALERT_BROWSER_DIAGNOSTICS_KEY]
  );
  return {
    config: {
      browserNotifications: config.browserNotifications,
      discordConfigured: Boolean(config.discordWebhookUrl),
      telegramConfigured: Boolean(config.telegramBotToken && config.telegramChatId),
      cooldownMinutes: config.cooldownMinutes
    },
    diagnostics: { browser: browserDiagnostics },
    rules: readThreatAlertRules(stored[THREAT_ALERT_RULES_KEY]),
    history: readThreatAlertHistory(stored[THREAT_ALERT_HISTORY_KEY]).sort((left, right) => right.lastSeenAt.localeCompare(left.lastSeenAt)),
    feedback: readThreatRadarFeedback(stored[THREAT_RADAR_FEEDBACK_KEY]).sort((left, right) => right.createdAt.localeCompare(left.createdAt)),
    cases: readThreatCases(stored[THREAT_RADAR_CASES_KEY]).sort((left, right) => right.updatedAt.localeCompare(left.updatedAt))
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
  if (!isAlertIndicatorType(record.indicatorType)) throw new BridgeOperationError("INVALID_IOC", "Choose IP, domain, hash, or identity for the alert rule.");
  const indicatorValue = typeof record.indicatorValue === "string" ? normalizeAlertIndicator(record.indicatorValue) : "";
  if (!isValidAlertIndicator(record.indicatorType, indicatorValue)) throw new BridgeOperationError("INVALID_IOC", "Enter a valid IP address, domain, MD5/SHA hash, or account/email.");

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

async function testThreatAlertDelivery(): Promise<unknown> {
  const stored = await chrome.storage.local.get(THREAT_ALERT_CONFIG_KEY);
  const config = readThreatAlertConfig(stored[THREAT_ALERT_CONFIG_KEY]);
  const candidate: ThreatAlertCandidate = {
    fingerprint: `delivery-test|${Date.now()}`,
    title: "Alert delivery test",
    category: "watched_ioc",
    severity: "high",
    indicatorType: "ip",
    indicator: "198.51.100.10",
    sourceIp: "198.51.100.10",
    destinationIp: "10.0.0.10",
    score: 80,
    events: 1,
    reasons: ["Analyst-requested delivery test; this is not a security finding"],
    ruleIds: [],
    ruleNames: []
  };
  return { delivery: await deliverThreatAlert(candidate, config) };
}

function readThreatRadarFeedback(value: unknown): ThreatFeedbackRecord[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item) => {
    const record = asRecord(item);
    if (typeof record.id !== "string" || typeof record.targetFingerprint !== "string") return [];
    if (!isThreatFeedbackTarget(record.targetKind) || !isThreatFeedbackDisposition(record.disposition)) return [];
    const feedback: ThreatFeedbackRecord = {
      id: record.id,
      targetKind: record.targetKind,
      targetFingerprint: record.targetFingerprint,
      disposition: record.disposition,
      createdAt: typeof record.createdAt === "string" ? record.createdAt : new Date().toISOString()
    };
    if (typeof record.reason === "string" && record.reason.trim()) feedback.reason = record.reason.trim().slice(0, 1000);
    if (typeof record.analyst === "string" && record.analyst.trim()) feedback.analyst = record.analyst.trim().slice(0, 120);
    if (typeof record.expiresAt === "string" && record.expiresAt.trim()) feedback.expiresAt = record.expiresAt;
    return [feedback];
  });
}

async function listThreatRadarFeedback(): Promise<unknown> {
  const stored = await chrome.storage.local.get(THREAT_RADAR_FEEDBACK_KEY);
  return { feedback: readThreatRadarFeedback(stored[THREAT_RADAR_FEEDBACK_KEY]).sort((left, right) => right.createdAt.localeCompare(left.createdAt)) };
}

async function saveThreatRadarFeedback(params: unknown): Promise<unknown> {
  const record = asRecord(params);
  if (!isThreatFeedbackTarget(record.targetKind) || !isThreatFeedbackDisposition(record.disposition)) {
    throw new BridgeOperationError("INVALID_REQUEST", "Choose a valid feedback target and disposition.");
  }
  const targetFingerprint = typeof record.targetFingerprint === "string" ? record.targetFingerprint.trim().slice(0, 1000) : "";
  if (!targetFingerprint) throw new BridgeOperationError("INVALID_REQUEST", "A finding or alert fingerprint is required.");
  let expiresAt: string | undefined;
  if (typeof record.expiresAt === "string" && record.expiresAt.trim()) {
    const expiry = Date.parse(record.expiresAt);
    if (!Number.isFinite(expiry) || expiry <= Date.now()) throw new BridgeOperationError("INVALID_REQUEST", "Feedback expiry must be a future timestamp.");
    expiresAt = new Date(expiry).toISOString();
  }

  const stored = await chrome.storage.local.get(THREAT_RADAR_FEEDBACK_KEY);
  const feedback = readThreatRadarFeedback(stored[THREAT_RADAR_FEEDBACK_KEY]);
  const existing = feedback.find((item) => item.targetKind === record.targetKind && item.targetFingerprint === targetFingerprint);
  const next: ThreatFeedbackRecord = {
    id: existing?.id ?? crypto.randomUUID(),
    targetKind: record.targetKind,
    targetFingerprint,
    disposition: record.disposition,
    createdAt: new Date().toISOString()
  };
  if (typeof record.reason === "string" && record.reason.trim()) next.reason = record.reason.trim().slice(0, 1000);
  if (typeof record.analyst === "string" && record.analyst.trim()) next.analyst = record.analyst.trim().slice(0, 120);
  if (expiresAt) next.expiresAt = expiresAt;
  const updated = [next, ...feedback.filter((item) => item.id !== existing?.id)].slice(0, 2000);
  await chrome.storage.local.set({ [THREAT_RADAR_FEEDBACK_KEY]: updated });
  return { feedback: updated };
}

function isThreatFeedbackTarget(value: unknown): value is ThreatFeedbackTarget {
  return value === "alert" || value === "finding" || value === "indicator" || value === "identity";
}

function isThreatFeedbackDisposition(value: unknown): value is ThreatFeedbackDisposition {
  return value === "confirmed_malicious" || value === "benign" || value === "expected_scanner" || value === "expected_service" || value === "needs_review";
}

function readThreatCases(value: unknown): ThreatCaseRecord[] {
  return Array.isArray(value) ? value.flatMap((item) => {
    const parsed = normalizeCaseRecord(item);
    return parsed ? [parsed] : [];
  }) : [];
}

async function listThreatCases(): Promise<unknown> {
  const stored = await chrome.storage.local.get(THREAT_RADAR_CASES_KEY);
  return { cases: readThreatCases(stored[THREAT_RADAR_CASES_KEY]).sort((left, right) => right.updatedAt.localeCompare(left.updatedAt)) };
}

async function createThreatCase(params: unknown): Promise<unknown> {
  const record = asRecord(params);
  const title = typeof record.title === "string" ? record.title.trim().slice(0, 200) : "";
  if (!title) throw new BridgeOperationError("INVALID_REQUEST", "A case title is required.");
  const alertId = typeof record.alertId === "string" ? record.alertId : "";
  const fingerprint = typeof record.fingerprint === "string" ? record.fingerprint : "";
  const stored = await chrome.storage.local.get(THREAT_RADAR_CASES_KEY);
  const cases = readThreatCases(stored[THREAT_RADAR_CASES_KEY]);
  const existing = fingerprint
    ? cases.find((item) => item.fingerprints.includes(fingerprint) && item.status !== "resolved" && item.status !== "closed")
    : undefined;
  const now = new Date().toISOString();
  if (existing) {
    const updated: ThreatCaseRecord = {
      ...existing,
      updatedAt: now,
      alertIds: [...new Set([...existing.alertIds, ...(alertId ? [alertId] : [])])],
      evidence: mergeCaseEvidence(existing.evidence, readCaseEvidence(record.evidence))
    };
    const next = cases.map((item) => item.id === existing.id ? updated : item);
    await chrome.storage.local.set({ [THREAT_RADAR_CASES_KEY]: next });
    return { case: updated, cases: next };
  }

  const created: ThreatCaseRecord = {
    id: crypto.randomUUID(),
    title,
    status: "open",
    severity: normalizeThreatCaseSeverity(record.severity),
    createdAt: now,
    updatedAt: now,
    summary: typeof record.summary === "string" ? record.summary.slice(0, 4000) : "",
    alertIds: alertId ? [alertId] : [],
    fingerprints: fingerprint ? [fingerprint] : [],
    tags: readStringList(record.tags, 50),
    evidence: readCaseEvidence(record.evidence),
    notes: []
  };
  if (typeof record.assignee === "string" && record.assignee.trim()) created.assignee = record.assignee.trim().slice(0, 120);
  const next = [created, ...cases].slice(0, 1000);
  await chrome.storage.local.set({ [THREAT_RADAR_CASES_KEY]: next });
  return { case: created, cases: next };
}

async function updateThreatCase(params: unknown): Promise<unknown> {
  const record = asRecord(params);
  const id = typeof record.id === "string" ? record.id : "";
  if (!id) throw new BridgeOperationError("INVALID_REQUEST", "A case id is required.");
  const stored = await chrome.storage.local.get(THREAT_RADAR_CASES_KEY);
  const cases = readThreatCases(stored[THREAT_RADAR_CASES_KEY]);
  const existing = cases.find((item) => item.id === id);
  if (!existing) throw new BridgeOperationError("INVALID_REQUEST", "The requested case was not found.");
  const updated: ThreatCaseRecord = {
    ...existing,
    updatedAt: new Date().toISOString(),
    ...(isThreatCaseStatus(record.status) ? { status: record.status } : {}),
    ...(isThreatCaseSeverity(record.severity) ? { severity: record.severity } : {}),
    ...(typeof record.title === "string" && record.title.trim() ? { title: record.title.trim().slice(0, 200) } : {}),
    ...(typeof record.summary === "string" ? { summary: record.summary.slice(0, 4000) } : {}),
    ...(Array.isArray(record.tags) ? { tags: readStringList(record.tags, 50) } : {}),
  };
  if (typeof record.assignee === "string") {
    const assignee = record.assignee.trim().slice(0, 120);
    if (assignee) updated.assignee = assignee;
    else delete updated.assignee;
  }
  if (typeof record.resolution === "string") {
    const resolution = record.resolution.trim().slice(0, 4000);
    if (resolution) updated.resolution = resolution;
    else delete updated.resolution;
  }
  const next = cases.map((item) => item.id === id ? updated : item);
  await chrome.storage.local.set({ [THREAT_RADAR_CASES_KEY]: next });
  return { case: updated, cases: next };
}

async function addThreatCaseNote(params: unknown): Promise<unknown> {
  const record = asRecord(params);
  const id = typeof record.id === "string" ? record.id : "";
  const body = typeof record.body === "string" ? record.body.trim().slice(0, 4000) : "";
  if (!id || !body) throw new BridgeOperationError("INVALID_REQUEST", "A case id and note are required.");
  const stored = await chrome.storage.local.get(THREAT_RADAR_CASES_KEY);
  const cases = readThreatCases(stored[THREAT_RADAR_CASES_KEY]);
  const existing = cases.find((item) => item.id === id);
  if (!existing) throw new BridgeOperationError("INVALID_REQUEST", "The requested case was not found.");
  const now = new Date().toISOString();
  const note = {
    id: crypto.randomUUID(),
    body,
    ...(typeof record.author === "string" && record.author.trim() ? { author: record.author.trim().slice(0, 120) } : {}),
    createdAt: now
  };
  const updated: ThreatCaseRecord = { ...existing, updatedAt: now, notes: [note, ...existing.notes].slice(0, 200) };
  const next = cases.map((item) => item.id === id ? updated : item);
  await chrome.storage.local.set({ [THREAT_RADAR_CASES_KEY]: next });
  return { case: updated, cases: next };
}

function readCaseEvidence(value: unknown): Array<{ label: string; value: string }> {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item) => {
    const record = asRecord(item);
    return typeof record.label === "string" && typeof record.value === "string"
      ? [{ label: record.label.slice(0, 120), value: record.value.slice(0, 2000) }]
      : [];
  }).slice(0, 100);
}

function mergeCaseEvidence(current: Array<{ label: string; value: string }>, incoming: Array<{ label: string; value: string }>): Array<{ label: string; value: string }> {
  return [...new Map([...current, ...incoming].map((item) => [`${item.label}|${item.value}`, item])).values()].slice(0, 100);
}

function readStringList(value: unknown, max: number): string[] {
  return Array.isArray(value)
    ? [...new Set(value.filter((item): item is string => typeof item === "string" && Boolean(item.trim())).map((item) => item.trim().slice(0, 512)))].slice(0, max)
    : [];
}

function normalizeThreatCaseSeverity(value: unknown): ThreatCaseSeverity {
  return isThreatCaseSeverity(value) ? value : "medium";
}

function isThreatCaseSeverity(value: unknown): value is ThreatCaseSeverity {
  return value === "critical" || value === "high" || value === "medium" || value === "low";
}

function isThreatCaseStatus(value: unknown): value is ThreatCaseStatus {
  return value === "open" || value === "acknowledged" || value === "in_progress" || value === "resolved" || value === "closed";
}

async function processThreatRadarAlerts(report: ThreatRadarAgentReport): Promise<{ candidates: number; alertsCreated: number; notificationsSent: number; notificationsFailed: number; suppressed: number }> {
  const stored = await chrome.storage.local.get([THREAT_ALERT_CONFIG_KEY, THREAT_ALERT_RULES_KEY, THREAT_ALERT_HISTORY_KEY, THREAT_RADAR_AGENT_ALERTS_KEY, THREAT_RADAR_FEEDBACK_KEY]);
  const config = readThreatAlertConfig(stored[THREAT_ALERT_CONFIG_KEY]);
  const rules = readThreatAlertRules(stored[THREAT_ALERT_RULES_KEY]);
  const history = readThreatAlertHistory(stored[THREAT_ALERT_HISTORY_KEY]);
  const cooldowns = asRecord(stored[THREAT_RADAR_AGENT_ALERTS_KEY]);
  const rawCandidates = buildThreatAlertCandidates(report, rules);
  const feedback = readThreatRadarFeedback(stored[THREAT_RADAR_FEEDBACK_KEY]);
  const candidates = rawCandidates.filter((candidate) => !feedback.some((item) => item.targetFingerprint === candidate.fingerprint && suppressesAutomaticAlert(item)));
  const now = Date.now();
  const nowIso = new Date(now).toISOString();
  let alertsCreated = 0;
  let notificationsSent = 0;
  let notificationsFailed = 0;

  for (const candidate of candidates) {
    const existingIndex = history.findIndex((item) => item.fingerprint === candidate.fingerprint);
    const existing = existingIndex >= 0 ? history[existingIndex] : undefined;
    if (!existing) alertsCreated += 1;
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
      if (hasSuccessfulDelivery(delivery)) {
        notificationsSent += 1;
        item.lastNotifiedAt = nowIso;
        cooldowns[candidate.fingerprint] = now;
      } else if (existing?.lastNotifiedAt) {
        item.lastNotifiedAt = existing.lastNotifiedAt;
      }
      if (delivery.errors.length > 0) notificationsFailed += 1;
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
  return {
    candidates: candidates.length,
    alertsCreated,
    notificationsSent,
    notificationsFailed,
    suppressed: rawCandidates.length - candidates.length
  };
}

async function deliverThreatAlert(candidate: ThreatAlertCandidate, config: ThreatAlertConfig): Promise<ThreatAlertDelivery> {
  const delivery = disabledDelivery();
  const message = formatThreatAlertMessage(candidate);
  if (config.browserNotifications) {
    const attemptedAt = new Date().toISOString();
    let permission: BrowserNotificationPermission = "unavailable";
    let iconUrl: string | null = null;
    delivery.browserAttemptedAt = attemptedAt;
    try {
      if (!isBrowserNotificationApiAvailable()) {
        throw new Error("Chrome notifications API is unavailable. Reload the extension and verify the notifications permission.");
      }
      permission = await getChromeNotificationPermission();
      delivery.browserPermission = permission;
      if (permission !== "granted") {
        throw new Error("Chrome notification permission is denied. Enable notifications for Chrome in browser and Windows settings.");
      }
      iconUrl = getPackagedNotificationIconUrl();
      const notificationId = await createChromeNotification(`soc-watch-alert-${Date.now()}-${crypto.randomUUID()}`, {
        type: "basic",
        iconUrl,
        title: `SOC Watch: ${candidate.title}`.slice(0, 120),
        message: message.slice(0, 900)
      });
      delivery.browser = "sent";
      delivery.browserNotificationId = notificationId;
      const diagnosticsError = await recordBrowserNotificationAttempt({
        status: "sent",
        permission,
        attemptedAt,
        iconUrl,
        notificationId
      });
      if (diagnosticsError) delivery.errors.push(`Browser diagnostics: ${diagnosticsError}`);
    } catch (error) {
      delivery.browser = "failed";
      delivery.browserPermission = permission;
      const errorMessage = error instanceof Error ? error.message : "notification failed";
      delivery.errors.push(`Browser: ${errorMessage}`);
      const diagnosticsError = await recordBrowserNotificationAttempt({
        status: "failed",
        permission,
        attemptedAt,
        iconUrl,
        error: errorMessage
      });
      if (diagnosticsError) delivery.errors.push(`Browser diagnostics: ${diagnosticsError}`);
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

function hasSuccessfulDelivery(delivery: ThreatAlertDelivery): boolean {
  return delivery.browser === "sent" || delivery.discord === "sent" || delivery.telegram === "sent";
}

function isBrowserNotificationApiAvailable(): boolean {
  return typeof chrome.notifications?.create === "function" && typeof chrome.notifications.getPermissionLevel === "function";
}

function getPackagedNotificationIconUrl(): string {
  const iconPath = chrome.runtime.getManifest().icons?.["128"];
  if (iconPath !== THREAT_ALERT_NOTIFICATION_ICON) {
    throw new Error(`Packaged notification icon ${THREAT_ALERT_NOTIFICATION_ICON} is missing from the extension manifest.`);
  }
  return chrome.runtime.getURL(iconPath);
}

function getChromeNotificationPermission(): Promise<BrowserNotificationPermission> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      reject(new Error("Chrome notification permission check timed out."));
    }, CHROME_NOTIFICATION_API_TIMEOUT_MS);

    try {
      chrome.notifications.getPermissionLevel((level) => {
        const runtimeError = chrome.runtime.lastError?.message;
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (runtimeError) {
          reject(new Error(runtimeError));
          return;
        }
        if (level !== "granted" && level !== "denied") {
          reject(new Error(`Chrome returned an unknown notification permission level: ${String(level)}.`));
          return;
        }
        resolve(level);
      });
    } catch (error) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(error instanceof Error ? error : new Error(String(error)));
    }
  });
}

function createChromeNotification(
  notificationId: string,
  options: chrome.notifications.NotificationOptions<true>
): Promise<string> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      reject(new Error("Chrome did not acknowledge the notification request within 5 seconds."));
    }, CHROME_NOTIFICATION_API_TIMEOUT_MS);

    try {
      chrome.notifications.create(notificationId, options, (createdId) => {
        const runtimeError = chrome.runtime.lastError?.message;
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (runtimeError) {
          reject(new Error(runtimeError));
          return;
        }
        if (!createdId) {
          reject(new Error("Chrome returned no notification ID."));
          return;
        }
        resolve(createdId);
      });
    } catch (error) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(error instanceof Error ? error : new Error(String(error)));
    }
  });
}

async function getBrowserNotificationDiagnostics(
  enabled: boolean,
  storedValue: unknown
): Promise<BrowserNotificationDiagnostics> {
  const previous = readBrowserNotificationDiagnostics(storedValue);
  const checkedAt = new Date().toISOString();
  const apiAvailable = isBrowserNotificationApiAvailable();
  let iconUrl: string | null = null;
  let iconError: string | null = null;
  try {
    iconUrl = getPackagedNotificationIconUrl();
  } catch (error) {
    iconError = error instanceof Error ? error.message : String(error);
  }

  if (!enabled) {
    return { ...previous, enabled, apiAvailable, status: "disabled", checkedAt, iconUrl, lastError: iconError };
  }
  if (!apiAvailable) {
    return {
      ...previous,
      enabled,
      apiAvailable,
      permission: "unavailable",
      status: "failed",
      checkedAt,
      iconUrl,
      lastError: "Chrome notifications API is unavailable."
    };
  }

  try {
    const permission = await getChromeNotificationPermission();
    if (permission === "denied") {
      return {
        ...previous,
        enabled,
        apiAvailable,
        permission,
        status: "blocked",
        checkedAt,
        iconUrl,
        lastError: "Chrome notification permission is denied."
      };
    }
    if (iconError) {
      return { ...previous, enabled, apiAvailable, permission, status: "failed", checkedAt, iconUrl, lastError: iconError };
    }
    return {
      ...previous,
      enabled,
      apiAvailable,
      permission,
      status: previous.status === "sent" ? "sent" : "ready",
      checkedAt,
      iconUrl,
      lastError: null
    };
  } catch (error) {
    return {
      ...previous,
      enabled,
      apiAvailable,
      permission: "unavailable",
      status: "failed",
      checkedAt,
      iconUrl,
      lastError: error instanceof Error ? error.message : String(error)
    };
  }
}

function readBrowserNotificationDiagnostics(value: unknown): BrowserNotificationDiagnostics {
  const record = asRecord(value);
  const permission = record.permission === "granted" || record.permission === "denied" ? record.permission : "unavailable";
  const validStatuses = new Set<BrowserNotificationDiagnostics["status"]>(["ready", "disabled", "blocked", "sent", "failed"]);
  return {
    enabled: record.enabled === true,
    apiAvailable: record.apiAvailable === true,
    permission,
    status: validStatuses.has(record.status as BrowserNotificationDiagnostics["status"])
      ? record.status as BrowserNotificationDiagnostics["status"]
      : "disabled",
    checkedAt: typeof record.checkedAt === "string" ? record.checkedAt : new Date(0).toISOString(),
    iconUrl: typeof record.iconUrl === "string" ? record.iconUrl : null,
    lastAttemptAt: typeof record.lastAttemptAt === "string" ? record.lastAttemptAt : null,
    lastSuccessAt: typeof record.lastSuccessAt === "string" ? record.lastSuccessAt : null,
    lastNotificationId: typeof record.lastNotificationId === "string" ? record.lastNotificationId : null,
    lastError: typeof record.lastError === "string" ? record.lastError : null
  };
}

async function recordBrowserNotificationAttempt(attempt: {
  status: "sent" | "failed";
  permission: BrowserNotificationPermission;
  attemptedAt: string;
  iconUrl: string | null;
  notificationId?: string;
  error?: string;
}): Promise<string | null> {
  try {
    const stored = await chrome.storage.local.get(THREAT_ALERT_BROWSER_DIAGNOSTICS_KEY);
    const previous = readBrowserNotificationDiagnostics(stored[THREAT_ALERT_BROWSER_DIAGNOSTICS_KEY]);
    const diagnostics: BrowserNotificationDiagnostics = {
      enabled: true,
      apiAvailable: isBrowserNotificationApiAvailable(),
      permission: attempt.permission,
      status: attempt.status,
      checkedAt: attempt.attemptedAt,
      iconUrl: attempt.iconUrl,
      lastAttemptAt: attempt.attemptedAt,
      lastSuccessAt: attempt.status === "sent" ? attempt.attemptedAt : previous.lastSuccessAt,
      lastNotificationId: attempt.notificationId ?? previous.lastNotificationId,
      lastError: attempt.error ?? null
    };
    await chrome.storage.local.set({ [THREAT_ALERT_BROWSER_DIAGNOSTICS_KEY]: diagnostics });
    return null;
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
}

function formatThreatAlertMessage(candidate: ThreatAlertCandidate): string {
  const route = candidate.sourceIp || candidate.destinationIp
    ? `${candidate.sourceIp ?? "--"} -> ${candidate.destinationIp ?? "--"}`
    : candidate.indicator;
  const rule = candidate.ruleNames.length ? ` Rule: ${candidate.ruleNames.join(", ")}.` : "";
  return `${route}. Score ${candidate.score}; ${candidate.events.toLocaleString()} events. ${candidate.reasons.slice(0, 3).join("; ")}.${rule}`;
}

function isAlertIndicatorType(value: unknown): value is AlertIndicatorType {
  return value === "ip" || value === "domain" || value === "hash" || value === "identity";
}

function isValidAlertIndicator(type: AlertIndicatorType, value: string): boolean {
  if (type === "ip") return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value) || /^[0-9a-f:]{2,}$/i.test(value);
  if (type === "domain") return /^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$/i.test(value);
  if (type === "identity") return Boolean(classifyIdentityValue(value, true));
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
  }, agentConfig.candidateExclusions, agentConfig.candidateExceptions));
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

async function setConnectionIcon(state: ConnectionState): Promise<void> {
  if (state === "connected") {
    await setConnectedIcon();
    return;
  }
  if (state === "degraded") {
    await setDegradedIcon();
    return;
  }
  await setDisconnectedIcon();
}

async function setConnectedIcon(): Promise<void> {
  await chrome.action.setBadgeText({ text: "" });
  await chrome.action.setTitle({ title: "SOC Watch Bridge: Kibana connected" });
  await setGeneratedIcon("#22c55e", "#0f172a");
}

async function setDegradedIcon(): Promise<void> {
  await chrome.action.setBadgeBackgroundColor({ color: "#f59e0b" });
  await chrome.action.setBadgeText({ text: "!" });
  await chrome.action.setTitle({ title: "SOC Watch Bridge: Kibana connection degraded" });
  await setGeneratedIcon("#f59e0b", "#1f2937");
}

async function setDisconnectedIcon(): Promise<void> {
  await chrome.action.setBadgeBackgroundColor({ color: "#ef4444" });
  await chrome.action.setBadgeText({ text: "!" });
  await chrome.action.setTitle({ title: "SOC Watch Bridge: Kibana disconnected" });
  await setGeneratedIcon("#ef4444", "#1f2937");
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
  const blocks: Array<[number, number, number, number]> = [
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
