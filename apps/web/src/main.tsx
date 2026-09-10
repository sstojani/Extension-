import React, { useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  AlertTriangle,
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  Bell,
  ChevronLeft,
  ChevronRight,
  ExternalLink,
  Database,
  FileSearch,
  Gauge,
  ListChecks,
  MonitorCog,
  Play,
  Plus,
  Radar,
  RefreshCw,
  Search,
  Server,
  Settings,
  ShieldCheck,
  Trash2,
  X
} from "lucide-react";
import type { FleetSummary, KibanaStatus } from "@soc-watch/protocol";
import type { DataViewSummary, SanitizedFleetAgent } from "@soc-watch/protocol";
import type { ClassifiedIOC } from "@soc-watch/ioc";
import { connectBridgeStream, getExtensionId, saveExtensionId, sendBridgeMessage, type BridgeStream } from "./bridge";
import "./styles.css";

type Panel = "Dashboard" | "Infrastructure" | "Agents" | "IOC Search" | "IOC Hunt" | "Threat Radar" | "Logs" | "Watchlist" | "Alerts" | "Settings" | "Diagnostics";
type HuntStatus = "idle" | "running" | "complete";
type HuntTimeRange = "today" | "last7d" | "last30d";
type HuntFilter = "all" | "ip" | "domain" | "url" | "hash";
type RadarTimeRange = "last15m" | "last1h" | "today";
type RadarViewMode = "automatic" | "manual";
type RadarSortDirection = "asc" | "desc";
type RadarSortField = "sourceIp" | "destinationIp" | "score" | "gti" | "events" | "denied" | "outbound" | "infrastructure" | "ports" | "reasons" | "history";
type RadarSort = { field: RadarSortField; direction: RadarSortDirection };
type GtiLookupStatus = "scored" | "not_configured" | "pending" | "not_found" | "rate_limited" | "unauthorized" | "unavailable";
type RadarCardId = "sources" | "destinations" | "outbound" | "denied" | "ports" | "indicators" | "review";
type SettingsView = "agent" | "allowlist" | "integrations" | "dataViews" | "connection";
type AllowlistScope = "ip" | "domain" | "hash" | "keyword";
type RadarLayoutItem = { id: RadarCardId; width?: number; height?: number; x?: number; y?: number };
type SearchHitSummary = {
  index: string;
  timestamp: string | undefined;
  host: string | undefined;
  eventAction?: string;
  destinationPort?: number;
  sourceIp?: string;
  destinationIp?: string;
  message: string | undefined;
};
type HuntedIOC = ClassifiedIOC & {
  sources?: string[];
  sourceCount?: number;
  malware?: string;
  threatType?: string;
  confidence?: number;
  firstSeen?: string;
};
type HuntResult = {
  ioc: HuntedIOC;
  total: number;
  hits: SearchHitSummary[];
  error?: string;
};
type ProviderStatus = {
  name: string;
  status: "healthy" | "skipped" | "error";
  collected: number;
  checked?: number;
  matched?: number;
  byType?: Record<string, number>;
  checkedByType?: Record<string, number>;
  matchedByType?: Record<string, number>;
  message?: string;
};
type DailyHuntResponse = {
  providers: ProviderStatus[];
  collected: number;
  hunted: number;
  matched: number;
  siemEvents: number;
  results: HuntResult[];
  batchNumber: number;
  batchOffset: number;
  batchSize: number;
  totalAvailable: number;
  nextBatchOffset: number;
  hasMore: boolean;
};
type ThreatRadarSuspect = {
  ip: string;
  sourceIp: string;
  destinationIp: string;
  gtiIp: string;
  role: "source" | "destination";
  direction: "inbound" | "outbound" | "internal" | "external" | "unknown";
  score: number;
  severity: "critical" | "high" | "medium" | "low";
  events: number;
  relatedHosts: number;
  infrastructureCount: number;
  destinationPorts: number;
  dangerousPorts: number[];
  topPorts: number[];
  actions: Array<{ key: string; count: number }>;
  datasets: Array<{ key: string; count: number }>;
  deniedEvents: number;
  successfulEvents: number;
  outboundEvents: number;
  suspiciousKeywordHits: number;
  matchedKeywords: string[];
  signalCounts?: Record<string, number>;
  latest?: {
    timestamp?: string;
    sourceIp?: string;
    destinationIp?: string;
    destinationPort?: number;
    action?: string;
    host?: string;
    message?: string;
  };
  reasons: string[];
  firstSeen?: string;
  lastSeen?: string;
  observations?: number;
  previousEvents?: number;
  eventDelta?: number;
  active?: boolean;
  gtiStatus?: GtiLookupStatus;
  gtiMessage?: string;
  gtiCached?: boolean;
  gti?: {
    verdict?: string;
    severity?: string;
    threatScore: number;
    malicious: number;
    suspicious: number;
    harmless?: number;
    undetected?: number;
    totalEngines?: number;
    reputation: number;
    country?: string;
    asn: number;
    asOwner?: string;
  };
};
type ThreatRadarIndicator = {
  value: string;
  type: "domain" | "hash";
  score: number;
  severity: "critical" | "high" | "medium" | "low";
  events: number;
  infrastructureCount: number;
  deniedEvents: number;
  suspiciousKeywordHits: number;
  matchedKeywords: string[];
  signalCounts?: Record<string, number>;
  actions: Array<{ key: string; count: number }>;
  datasets: Array<{ key: string; count: number }>;
  latest?: ThreatRadarSuspect["latest"];
  reasons: string[];
  gtiStatus?: GtiLookupStatus;
  gtiMessage?: string;
  gtiCached?: boolean;
  gti?: ThreatRadarSuspect["gti"];
};
type ThreatRadarResponse = {
  from: string;
  to: string;
  analyzedAt: string;
  eventsAnalyzed: number;
  suspects: ThreatRadarSuspect[];
  externalSources: ThreatRadarSuspect[];
  suspiciousDestinations: ThreatRadarSuspect[];
  suspiciousOutbound: ThreatRadarSuspect[];
  deniedActivity: ThreatRadarSuspect[];
  reviewCandidates?: ThreatRadarSuspect[];
  suspiciousIndicators: ThreatRadarIndicator[];
  signals: Array<{ key: string; label: string; count: number }>;
  gtiEnabled: boolean;
  analysis?: {
    strategy: "single" | "staged";
    partial: boolean;
    completedStages: string[];
    skippedStages: string[];
    candidatesEvaluated?: number;
    candidatesForReview?: number;
    candidateMethods?: string[];
    reputation?: {
      status: "healthy" | "partial" | "unavailable" | "not_configured";
      requested: number;
      scored: number;
      cached: number;
      pending: number;
      rateLimited: number;
      failed: number;
    };
  };
  summary: {
    suspects: number;
    critical: number;
    high: number;
    medium: number;
  };
};
type PinnedThreatRadarAnalysis = {
  range: RadarTimeRange;
  report: ThreatRadarResponse;
};
type ThreatRadarAgentConfig = {
  enabled: boolean;
  intervalMinutes: number;
  indexPattern: string;
  timestampField: string;
  candidateExclusions: string[];
};
type ThreatRadarAgentState = {
  status?: "healthy" | "error" | "running" | "disabled";
  startedAt?: string;
  completedAt?: string;
  candidates?: number;
  alertsCreated?: number;
  lastError?: string;
  report?: ThreatRadarResponse;
};
type BridgeConfigResponse = {
  extensionVersion?: string;
  threatFoxAuthKeySaved?: boolean;
  malwareBazaarAuthKeySaved?: boolean;
  googleThreatIntelApiKeySaved?: boolean;
  threatRadarAgent?: ThreatRadarAgentConfig;
  threatRadarAgentState?: ThreatRadarAgentState;
};
type AlertRule = {
  id: string;
  name: string;
  indicatorType: "ip" | "domain" | "hash";
  indicatorValue: string;
  minScore: number;
  enabled: boolean;
  createdAt: string;
};
type AlertDelivery = {
  browser: "sent" | "disabled" | "failed";
  discord: "sent" | "disabled" | "failed";
  telegram: "sent" | "disabled" | "failed";
  errors: string[];
};
type AlertHistoryItem = {
  id: string;
  title: string;
  category: string;
  severity: "critical" | "high";
  indicatorType: "ip" | "domain" | "hash";
  indicator: string;
  sourceIp?: string;
  destinationIp?: string;
  score: number;
  events: number;
  reasons: string[];
  ruleNames: string[];
  createdAt: string;
  lastSeenAt: string;
  lastNotifiedAt?: string;
  occurrences: number;
  delivery: AlertDelivery;
};
type AlertDashboardResponse = {
  config: {
    browserNotifications: boolean;
    discordConfigured: boolean;
    telegramConfigured: boolean;
    cooldownMinutes: number;
  };
  rules: AlertRule[];
  history: AlertHistoryItem[];
};

const DAILY_HUNT_BATCH_SIZE = 500;
const SOC_WATCH_WEB_VERSION = "0.8.1";
const THREAT_RADAR_LAYOUT_KEY = "socWatchThreatRadarLayout";
const THREAT_RADAR_PINNED_ANALYSIS_KEY = "socWatchThreatRadarPinnedAnalysis";
const IOC_HUNT_CURSOR_KEY = "socWatchIocHuntCursors";

const nav: Array<{ label: Panel; icon: React.ComponentType<{ size?: number }> }> = [
  { label: "Dashboard", icon: Gauge },
  { label: "Infrastructure", icon: Server },
  { label: "Agents", icon: MonitorCog },
  { label: "IOC Search", icon: Search },
  { label: "IOC Hunt", icon: Radar },
  { label: "Threat Radar", icon: Activity },
  { label: "Logs", icon: FileSearch },
  { label: "Watchlist", icon: ListChecks },
  { label: "Alerts", icon: Bell },
  { label: "Settings", icon: Settings },
  { label: "Diagnostics", icon: Activity }
];

function App() {
  const [active, setActive] = useState<Panel>("Dashboard");
  const [loading, setLoading] = useState(false);
  const [bridgeState, setBridgeState] = useState("Not checked");
  const [extensionVersion, setExtensionVersion] = useState<string | null>(null);
  const [streamState, setStreamState] = useState("Disconnected");
  const [kibana, setKibana] = useState<KibanaStatus | null>(null);
  const [fleet, setFleet] = useState<FleetSummary | null>(null);
  const [agents, setAgents] = useState<SanitizedFleetAgent[]>([]);
  const [dataViews, setDataViews] = useState<DataViewSummary[]>([]);
  const [iocValue, setIocValue] = useState("62[.]238[.]44[.]99");
  const [huntTimeRange, setHuntTimeRange] = useState<HuntTimeRange>("today");
  const [huntFilter, setHuntFilter] = useState<HuntFilter>("all");
  const [huntStatus, setHuntStatus] = useState<HuntStatus>("idle");
  const [huntProgress, setHuntProgress] = useState({ processed: 0, total: 0 });
  const [huntBatchOffset, setHuntBatchOffset] = useState(() => loadIocHuntOffset("today"));
  const [huntBatchInfo, setHuntBatchInfo] = useState<Pick<DailyHuntResponse, "batchNumber" | "batchOffset" | "batchSize" | "totalAvailable" | "nextBatchOffset" | "hasMore"> | null>(null);
  const [huntProviders, setHuntProviders] = useState<ProviderStatus[]>([]);
  const [huntResults, setHuntResults] = useState<HuntResult[]>([]);
  const [pinnedRadarAnalysis, setPinnedRadarAnalysis] = useState<PinnedThreatRadarAnalysis | null>(() => loadPinnedThreatRadarAnalysis());
  const [radarTimeRange, setRadarTimeRange] = useState<RadarTimeRange>(() => pinnedRadarAnalysis?.range ?? "last15m");
  const [radarLoading, setRadarLoading] = useState(false);
  const [radarViewMode, setRadarViewMode] = useState<RadarViewMode>(() => pinnedRadarAnalysis ? "manual" : "automatic");
  const [indexPattern, setIndexPattern] = useState("logs-*");
  const [iocResult, setIocResult] = useState<unknown>(null);
  const [lastError, setLastError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);
  const [extensionId, setExtensionId] = useState(getExtensionId() ?? "");
  const [threatFoxAuthKey, setThreatFoxAuthKey] = useState("");
  const [threatFoxAuthKeySaved, setThreatFoxAuthKeySaved] = useState(false);
  const [malwareBazaarAuthKey, setMalwareBazaarAuthKey] = useState("");
  const [malwareBazaarAuthKeySaved, setMalwareBazaarAuthKeySaved] = useState(false);
  const [googleThreatIntelApiKey, setGoogleThreatIntelApiKey] = useState("");
  const [googleThreatIntelApiKeySaved, setGoogleThreatIntelApiKeySaved] = useState(false);
  const [threatRadarAgent, setThreatRadarAgent] = useState<ThreatRadarAgentConfig>({ enabled: true, intervalMinutes: 15, indexPattern: "logs-*", timestampField: "@timestamp", candidateExclusions: [] });
  const [threatRadarAgentState, setThreatRadarAgentState] = useState<ThreatRadarAgentState>({});
  const [savingThreatRadarAgent, setSavingThreatRadarAgent] = useState(false);
  const streamRef = useRef<BridgeStream | null>(null);
  const retryTimerRef = useRef<number | undefined>(undefined);
  const retryAttemptRef = useRef(0);
  const connectionGenerationRef = useRef(0);

  const fleetTotal = useMemo(() => (fleet ? fleet.online + fleet.offline + fleet.error + fleet.inactive : 0), [fleet]);
  const iocHuntReadyScreen = active === "IOC Hunt" && huntStatus === "idle" && huntResults.length === 0;
  const hideIocHuntChrome = active === "IOC Hunt" && huntStatus !== "complete";
  const isThreatRadarView = active === "Threat Radar";

  useEffect(() => {
    startLiveBridge();
    void loadBridgeConfig(false);
    return () => {
      if (retryTimerRef.current !== undefined) window.clearTimeout(retryTimerRef.current);
      streamRef.current?.disconnect();
    };
  }, []);

  useEffect(() => {
    if (active !== "Threat Radar") return;
    void loadBridgeConfig(true);
    const refresh = window.setInterval(() => void loadBridgeConfig(true), 15000);
    return () => window.clearInterval(refresh);
  }, [active]);

  function startLiveBridge(options: { automatic?: boolean } = {}) {
    if (!options.automatic) retryAttemptRef.current = 0;
    if (retryTimerRef.current !== undefined) {
      window.clearTimeout(retryTimerRef.current);
      retryTimerRef.current = undefined;
    }
    const generation = connectionGenerationRef.current + 1;
    connectionGenerationRef.current = generation;
    streamRef.current?.disconnect();
    streamRef.current = connectBridgeStream({
      onStatus(status, message) {
        if (generation !== connectionGenerationRef.current) return;
        setStreamState(status);
        if (status === "connected") {
          retryAttemptRef.current = 0;
          setBridgeState("Bridge connected");
          setLastError(null);
          return;
        }
        if (status === "disconnected" || status === "unavailable") {
          scheduleBridgeRetry(message ?? "SOC Watch Bridge disconnected.");
          return;
        }
        if (message) setLastError(message);
      },
      onSnapshot(snapshot) {
        if (generation !== connectionGenerationRef.current) return;
        applySnapshot(snapshot);
      }
    });
    if (!streamRef.current) {
      scheduleBridgeRetry("SOC Watch Bridge is unavailable.");
    }
  }

  function scheduleBridgeRetry(reason: string) {
    if (retryTimerRef.current !== undefined) return;
    if (retryAttemptRef.current >= 5) {
      setLastError(`${reason} Auto reconnect stopped after 5 attempts. Reload the extension once, then leave this tab open.`);
      return;
    }

    const attempt = retryAttemptRef.current + 1;
    retryAttemptRef.current = attempt;
    const delay = Math.min(1000 + attempt * 1000, 6000);
    setLastError(`${reason} Auto reconnect attempt ${attempt}/5 in ${Math.round(delay / 1000)} seconds.`);
    retryTimerRef.current = window.setTimeout(() => {
      retryTimerRef.current = undefined;
      startLiveBridge({ automatic: true });
    }, delay);
  }

  function applySnapshot(snapshot: unknown) {
    const record = typeof snapshot === "object" && snapshot !== null ? (snapshot as Record<string, unknown>) : {};
    setLastUpdated(typeof record.updatedAt === "string" ? record.updatedAt : new Date().toISOString());
    if (record.state === "connected") {
      setStreamState("connected");
      setBridgeState("Bridge connected");
      setKibana(record.kibana as KibanaStatus);
      setFleet(record.fleet as FleetSummary);
      if (Array.isArray(record.agents)) {
        setAgents(record.agents as SanitizedFleetAgent[]);
      }
      setLastError(null);
      return;
    }
    const error = typeof record.error === "object" && record.error !== null ? (record.error as { message?: string; code?: string }) : undefined;
    setLastError(error ? `${error.code ?? "ERROR"}: ${error.message ?? "Live bridge update failed."}` : "Live bridge update failed.");
  }

  function saveAndReconnectExtensionId() {
    saveExtensionId(extensionId);
    startLiveBridge();
  }

  async function loadBridgeConfig(includeReport = false) {
    const response = await sendBridgeMessage<{ includeReport: boolean }, BridgeConfigResponse>("config.get", { includeReport });
    if (response.success) {
      setExtensionVersion(response.data.extensionVersion ?? null);
      setThreatFoxAuthKeySaved(Boolean(response.data.threatFoxAuthKeySaved));
      setMalwareBazaarAuthKeySaved(Boolean(response.data.malwareBazaarAuthKeySaved));
      setGoogleThreatIntelApiKeySaved(Boolean(response.data.googleThreatIntelApiKeySaved));
      if (response.data.threatRadarAgent) setThreatRadarAgent(response.data.threatRadarAgent);
      if (response.data.threatRadarAgentState) {
        setThreatRadarAgentState(response.data.threatRadarAgentState);
      }
    }
  }

  async function saveApiKeys() {
    setLoading(true);
    setLastError(null);
    const response = await sendBridgeMessage<unknown, { threatFoxAuthKeySaved?: boolean; malwareBazaarAuthKeySaved?: boolean; googleThreatIntelApiKeySaved?: boolean }>("config.save", {
      threatFoxAuthKey,
      malwareBazaarAuthKey,
      googleThreatIntelApiKey
    });
    if (response.success) {
      setThreatFoxAuthKey("");
      setMalwareBazaarAuthKey("");
      setGoogleThreatIntelApiKey("");
      setThreatFoxAuthKeySaved(Boolean(response.data.threatFoxAuthKeySaved));
      setMalwareBazaarAuthKeySaved(Boolean(response.data.malwareBazaarAuthKeySaved));
      setGoogleThreatIntelApiKeySaved(Boolean(response.data.googleThreatIntelApiKeySaved));
    } else {
      setLastError(response.error.message);
    }
    setLoading(false);
  }

  async function saveThreatRadarAgent(runNow = false, resetVisibleResults = false) {
    setSavingThreatRadarAgent(true);
    setLastError(null);
    const response = await sendBridgeMessage<ThreatRadarAgentConfig, { config: ThreatRadarAgentConfig; state: ThreatRadarAgentState }>("threatRadar.agent.configure", {
      ...threatRadarAgent,
      indexPattern
    });
    if (!response.success) {
      setLastError(response.error.message);
      setSavingThreatRadarAgent(false);
      return;
    }
    setThreatRadarAgent(response.data.config);
    setThreatRadarAgentState(response.data.state);
    if (resetVisibleResults) {
      setPinnedRadarAnalysis(null);
      clearPinnedThreatRadarAnalysis();
      setRadarViewMode("automatic");
      setHuntResults([]);
      setHuntProviders([]);
      setHuntBatchInfo(null);
      setHuntStatus("idle");
    }
    if (runNow && response.data.config.enabled) {
      const run = await sendBridgeMessage<unknown, { config: ThreatRadarAgentConfig; state: ThreatRadarAgentState }>("threatRadar.agent.run", {});
      if (run.success) {
        setThreatRadarAgentState(run.data.state);
      }
      else setLastError(run.error.message);
    }
    setSavingThreatRadarAgent(false);
  }

  async function runProofCheck() {
    setLoading(true);
    setLastError(null);
    const ping = await sendBridgeMessage("bridge.ping", {});
    if (!ping.success) {
      setBridgeState("Bridge unavailable");
      setLastError(ping.error.message);
      setLoading(false);
      return;
    }
    setBridgeState("Bridge connected");

    const status = await sendBridgeMessage<unknown, KibanaStatus>("kibana.status", {});
    if (status.success) setKibana(status.data);
    else setLastError(status.error.message);

    const summary = await sendBridgeMessage<unknown, FleetSummary>("fleet.summary", {});
    if (summary.success) setFleet(summary.data);
    else setLastError(summary.error.message);
    setLoading(false);
  }

  async function loadAgents() {
    setLoading(true);
    setLastError(null);
    const response = await sendBridgeMessage<unknown, { items: SanitizedFleetAgent[] }>("fleet.list", {
      page: 1,
      perPage: 100,
      showInactive: true,
      withMetrics: true,
      getStatusSummary: false
    });
    if (response.success) setAgents(response.data.items);
    else setLastError(response.error.message);
    setLoading(false);
  }

  async function loadDataViews() {
    setLoading(true);
    setLastError(null);
    const response = await sendBridgeMessage<unknown, DataViewSummary[]>("dataViews.list", {});
    if (response.success) {
      setDataViews(response.data);
      if (response.data[0]?.title) setIndexPattern(response.data[0].title);
    } else {
      setLastError(response.error.message);
    }
    setLoading(false);
  }

  async function runIocSearch() {
    setLoading(true);
    setLastError(null);
    setIocResult(null);
    const response = await sendBridgeMessage("ioc.search", {
      value: iocValue,
      indexPattern,
      timestampField: "@timestamp",
      from: "now-24h",
      to: "now",
      size: 25
    });
    if (response.success) setIocResult(response.data);
    else setLastError(response.error.message);
    setLoading(false);
  }

  function changeHuntTimeRange(value: HuntTimeRange) {
    setHuntTimeRange(value);
    setHuntBatchOffset(loadIocHuntOffset(value));
    setHuntBatchInfo(null);
    setHuntStatus("idle");
    setHuntResults([]);
    setHuntProviders([]);
  }

  async function runIocHunt(fresh = false) {
    const timeRange = huntTimeRangeToParams(huntTimeRange);
    const batchOffset = fresh ? 0 : huntBatchInfo?.hasMore === false ? 0 : huntBatchOffset;
    if (fresh) {
      setHuntBatchOffset(0);
      setHuntBatchInfo(null);
      saveIocHuntOffset(huntTimeRange, 0);
    }
    setHuntStatus("running");
    setHuntProgress({ processed: 0, total: DAILY_HUNT_BATCH_SIZE });
    setHuntProviders([]);
    setHuntResults([]);
    setLastError(null);

    const response = await sendBridgeMessage<unknown, DailyHuntResponse>("threatIntel.dailyHunt", {
      indexPattern,
      timestampField: "@timestamp",
      from: timeRange.from,
      to: "now",
      size: 5,
      maxIocs: DAILY_HUNT_BATCH_SIZE,
      batchOffset
    });

    if (response.success) {
      setHuntProviders(response.data.providers);
      setHuntResults(response.data.results);
      setHuntBatchInfo({
        batchNumber: response.data.batchNumber,
        batchOffset: response.data.batchOffset,
        batchSize: response.data.batchSize,
        totalAvailable: response.data.totalAvailable,
        nextBatchOffset: response.data.nextBatchOffset,
        hasMore: response.data.hasMore
      });
      setHuntBatchOffset(response.data.nextBatchOffset);
      saveIocHuntOffset(huntTimeRange, response.data.nextBatchOffset >= response.data.totalAvailable ? 0 : response.data.nextBatchOffset);
      setHuntProgress({ processed: response.data.hunted, total: response.data.hunted });
    } else {
      setLastError(response.error.message);
      setHuntProgress({ processed: 0, total: 0 });
    }

    setHuntStatus("complete");
  }

  async function runThreatRadar() {
    const timeRange = threatRadarTimeRangeToParams(radarTimeRange);
    setRadarLoading(true);
    setLastError(null);
    const response = await sendBridgeMessage<unknown, ThreatRadarResponse>("threatRadar.analyze", {
      indexPattern,
      timestampField: "@timestamp",
      from: timeRange.from,
      to: "now",
      size: 20
    });
    if (response.success) {
      if (!hasThreatRadarCoreCoverage(response.data)) {
        setLastError("Kibana did not complete either IP activity stage. The previous completed analysis remains pinned; retry Today or use Last 1 hour.");
        setRadarLoading(false);
        return;
      }
      const analysis = { range: radarTimeRange, report: response.data } satisfies PinnedThreatRadarAnalysis;
      setPinnedRadarAnalysis(analysis);
      savePinnedThreatRadarAnalysis(analysis);
      setRadarViewMode("manual");
    } else {
      setLastError(formatThreatRadarError(response.error.message, radarTimeRange));
    }
    setRadarLoading(false);
  }

  function resumeAutomaticThreatRadar() {
    setRadarViewMode("automatic");
    setPinnedRadarAnalysis(null);
    clearPinnedThreatRadarAnalysis();
    void loadBridgeConfig(true);
  }

  const visibleRadarResult = radarViewMode === "manual" && pinnedRadarAnalysis
    ? pinnedRadarAnalysis.report
    : threatRadarAgentState.report ?? null;

  return (
    <main className="shell">
      <aside className="sidebar" aria-label="SOC Watch navigation">
        <div className="brand">
          <ShieldCheck size={24} aria-hidden="true" />
          <div>
            <strong>SOC Watch</strong>
            <span>Bridge Console</span>
            <small>Web v{SOC_WATCH_WEB_VERSION} | Bridge {extensionVersion ? `v${extensionVersion}` : "--"}</small>
          </div>
        </div>
        <nav>
          {nav.map((item) => {
            const Icon = item.icon;
            return (
              <button key={item.label} className={active === item.label ? "active" : ""} onClick={() => setActive(item.label)}>
                <Icon size={17} aria-hidden="true" />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
      </aside>

      <section className="workspace">
        {!iocHuntReadyScreen ? (
          <header className="topbar">
            <div>
              <p className="eyebrow">Internal Elastic Security Operations</p>
              <h1>{active}</h1>
            </div>
            <div className="top-actions">
              <span className={`live-dot ${streamState === "connected" ? "healthy" : "unknown"}`}>
                {streamState === "connected" ? "Live" : streamState}
              </span>
              <button className="primary" onClick={() => startLiveBridge()} disabled={loading}>
                <RefreshCw size={16} aria-hidden="true" className={loading ? "spin" : ""} />
                <span>{loading ? "Checking" : "Reconnect"}</span>
              </button>
            </div>
          </header>
        ) : null}

        {isThreatRadarView ? (
          <section className="status-strip radar-summary-strip" aria-label="Threat Radar finding summary">
            <StatusTile label="Suspects" value={String(visibleRadarResult?.summary.suspects ?? 0)} tone={visibleRadarResult?.summary.suspects ? "critical" : "unknown"} />
            <StatusTile label="Critical" value={String(visibleRadarResult?.summary.critical ?? 0)} tone={visibleRadarResult?.summary.critical ? "critical" : "unknown"} />
            <StatusTile label="High" value={String(visibleRadarResult?.summary.high ?? 0)} tone={visibleRadarResult?.summary.high ? "critical" : "unknown"} />
            <StatusTile label="Medium" value={String(visibleRadarResult?.summary.medium ?? 0)} tone={visibleRadarResult?.summary.medium ? "healthy" : "unknown"} />
          </section>
        ) : !hideIocHuntChrome ? (
          <>
            <section className="status-strip" aria-label="Current SOC Watch status">
              <StatusTile label="Bridge" value={bridgeState} tone={bridgeState.includes("connected") ? "healthy" : "unknown"} />
              <StatusTile label="Kibana" value={kibana?.overall ?? "Unknown"} tone={kibana?.overall === "available" ? "healthy" : "unknown"} />
              <StatusTile label="Fleet Online" value={fleet ? String(fleet.online) : "--"} tone="healthy" />
              <StatusTile label="Fleet Offline" value={fleet ? String(fleet.offline) : "--"} tone={fleet?.offline ? "critical" : "unknown"} />
            </section>
            <section className="live-strip" aria-label="Live bridge connection">
              <span>Fleet status and agent state update automatically every 10 seconds</span>
              <strong>{lastUpdated ? `Last update ${new Date(lastUpdated).toLocaleTimeString()}` : "Waiting for first update"}</strong>
            </section>
          </>
        ) : null}

        {lastError && !hideIocHuntChrome && !isThreatRadarView ? (
          <section className="notice" role="status">
            <AlertTriangle size={18} aria-hidden="true" />
            <div>
              <strong>Kibana authentication required or bridge unavailable</strong>
              <span>{lastError}</span>
            </div>
            <a href="https://10.10.254.202:8888" target="_blank" rel="noreferrer">Open Kibana</a>
          </section>
        ) : null}

        {active === "Dashboard" ? <Dashboard kibana={kibana} fleet={fleet} fleetTotal={fleetTotal} agents={agents} /> : null}
        {active === "Agents" ? <Agents agents={agents} onRefresh={loadAgents} /> : null}
        {active === "Settings" ? (
          <SettingsPanel
            dataViews={dataViews}
            indexPattern={indexPattern}
            extensionId={extensionId}
            threatFoxAuthKey={threatFoxAuthKey}
            threatFoxAuthKeySaved={threatFoxAuthKeySaved}
            malwareBazaarAuthKey={malwareBazaarAuthKey}
            malwareBazaarAuthKeySaved={malwareBazaarAuthKeySaved}
            googleThreatIntelApiKey={googleThreatIntelApiKey}
            googleThreatIntelApiKeySaved={googleThreatIntelApiKeySaved}
            onIndexPatternChange={setIndexPattern}
            onExtensionIdChange={setExtensionId}
            onThreatFoxAuthKeyChange={setThreatFoxAuthKey}
            onMalwareBazaarAuthKeyChange={setMalwareBazaarAuthKey}
            onGoogleThreatIntelApiKeyChange={setGoogleThreatIntelApiKey}
            onSaveExtensionId={saveAndReconnectExtensionId}
            onSaveApiKeys={saveApiKeys}
            onLoadDataViews={loadDataViews}
            threatRadarAgent={threatRadarAgent}
            threatRadarAgentState={threatRadarAgentState}
            savingThreatRadarAgent={savingThreatRadarAgent}
            onThreatRadarAgentChange={setThreatRadarAgent}
            onSaveThreatRadarAgent={() => void saveThreatRadarAgent(false)}
            onSaveAllowlist={() => void saveThreatRadarAgent(false, true)}
            onRunThreatRadarAgent={() => void saveThreatRadarAgent(true)}
          />
        ) : null}
        {active === "IOC Search" ? (
          <IOCSearch
            value={iocValue}
            indexPattern={indexPattern}
            result={iocResult}
            onValueChange={setIocValue}
            onIndexPatternChange={setIndexPattern}
            onSearch={runIocSearch}
          />
        ) : null}
        {active === "Infrastructure" ? <Infrastructure agents={agents} /> : null}
        {active === "IOC Hunt" ? (
          <IOCHunt
            timeRange={huntTimeRange}
            filter={huntFilter}
            status={huntStatus}
            progress={huntProgress}
            batchInfo={huntBatchInfo}
            providers={huntProviders}
            results={huntResults}
            onTimeRangeChange={changeHuntTimeRange}
            onFilterChange={setHuntFilter}
            onHunt={() => void runIocHunt(false)}
            onFreshHunt={() => void runIocHunt(true)}
          />
        ) : null}
        {active === "Threat Radar" ? (
          <ThreatRadar
            timeRange={radarTimeRange}
            loading={radarLoading}
            result={visibleRadarResult}
            agentConfig={threatRadarAgent}
            agentState={threatRadarAgentState}
            viewMode={radarViewMode}
            pinnedRange={pinnedRadarAnalysis?.range ?? radarTimeRange}
            error={lastError}
            onTimeRangeChange={setRadarTimeRange}
            onAnalyze={runThreatRadar}
            onResumeAutomatic={resumeAutomaticThreatRadar}
          />
        ) : null}
        {active === "Alerts" ? <AlertsPanel /> : null}
        {!["Dashboard", "Agents", "Settings", "IOC Search", "Infrastructure", "IOC Hunt", "Threat Radar", "Alerts"].includes(active) ? <Placeholder panel={active} /> : null}
      </section>
    </main>
  );
}

function Dashboard({
  kibana,
  fleet,
  fleetTotal,
  agents
}: {
  kibana: KibanaStatus | null;
  fleet: FleetSummary | null;
  fleetTotal: number;
  agents: SanitizedFleetAgent[];
}) {
  const problemAgents = agents.filter((agent) => agent.status === "offline" || agent.status === "error");
  return (
    <section className="grid">
      {problemAgents.length > 0 ? (
        <div className="panel wide critical-panel">
          <div className="panel-title">
            <AlertTriangle size={18} aria-hidden="true" />
            <h2>Fleet Attention Required</h2>
          </div>
          <div className="problem-grid">
            {problemAgents.map((agent) => (
              <div className="problem-agent" key={agent.id}>
                <Badge value={agent.status} />
                <strong>{agent.hostname ?? agent.id}</strong>
                <span>{agent.hostIps?.join(", ") ?? "No IP reported"}</span>
                <span>{agent.lastCheckin ?? "No check-in timestamp"}</span>
              </div>
            ))}
          </div>
        </div>
      ) : null}

      <div className="panel wide">
        <div className="panel-title">
          <Database size={18} aria-hidden="true" />
          <h2>Bridge Proof Path</h2>
        </div>
        <div className="flow" aria-label="SOC Watch bridge proof flow">
          {["SOC Watch Web", "Bridge Extension", "Kibana Session", "Fleet API", "Sanitized Counters"].map((step) => (
            <div className="flow-step" key={step}>{step}</div>
          ))}
        </div>
      </div>

      <div className="panel">
        <h2>Kibana</h2>
        <dl className="facts">
          <dt>Base URL</dt>
          <dd>10.10.254.202:8888</dd>
          <dt>Version</dt>
          <dd>{kibana?.version ?? "Not checked"}</dd>
          <dt>Elasticsearch</dt>
          <dd>{kibana?.elasticsearch ?? "Unknown"}</dd>
          <dt>Saved Objects</dt>
          <dd>{kibana?.savedObjects ?? "Unknown"}</dd>
        </dl>
      </div>

      <div className="panel">
        <h2>Fleet Summary</h2>
        <dl className="facts">
          <dt>Active</dt>
          <dd>{fleet?.active ?? "--"}</dd>
          <dt>Total Visible</dt>
          <dd>{fleetTotal || "--"}</dd>
          <dt>Error</dt>
          <dd>{fleet?.error ?? "--"}</dd>
          <dt>Inactive</dt>
          <dd>{fleet?.inactive ?? "--"}</dd>
        </dl>
      </div>
    </section>
  );
}

function Agents({ agents, onRefresh }: { agents: SanitizedFleetAgent[]; onRefresh: () => void }) {
  return (
    <section className="panel wide">
      <div className="panel-actions">
        <h2>Fleet Agents</h2>
        <button className="secondary" onClick={onRefresh}>
          <RefreshCw size={16} aria-hidden="true" />
          <span>Refresh Agents</span>
        </button>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Status</th>
              <th>Hostname</th>
              <th>Version</th>
              <th>Last Check-in</th>
            </tr>
          </thead>
          <tbody>
            {agents.length === 0 ? (
              <tr>
                <td colSpan={4}>No agents loaded yet.</td>
              </tr>
            ) : (
              agents.map((agent) => (
                <tr key={agent.id}>
                  <td><Badge value={agent.status} /></td>
                  <td>{agent.hostname ?? agent.id}</td>
                  <td>{agent.agentVersion ?? "--"}</td>
                  <td>{agent.lastCheckin ?? "--"}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function Infrastructure({ agents }: { agents: SanitizedFleetAgent[] }) {
  const rows = buildInfrastructureRows(agents);
  const critical = rows.filter((row) => row.health === "critical").length;
  const healthy = rows.filter((row) => row.health === "healthy").length;

  return (
    <section className="grid">
      <div className="panel">
        <h2>Infrastructure Health</h2>
        <dl className="facts">
          <dt>Healthy</dt>
          <dd>{healthy}</dd>
          <dt>Critical</dt>
          <dd>{critical}</dd>
          <dt>Total</dt>
          <dd>{rows.length}</dd>
        </dl>
      </div>
      <div className="panel">
        <h2>Monitoring Basis</h2>
        <p className="muted">This view derives infrastructure from live Fleet agents. Expected log-source health is the next layer on top of this live agent inventory.</p>
      </div>
      <div className="panel wide">
        <div className="panel-title">
          <Server size={18} aria-hidden="true" />
          <h2>Infrastructure</h2>
        </div>
        <div className="table-wrap">
          <table className="compact-table">
            <thead>
              <tr>
                <th>Health</th>
                <th>Infrastructure</th>
                <th>Agent Status</th>
                <th>Version</th>
                <th>Last Check-in</th>
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 ? (
                <tr>
                  <td colSpan={5}>Waiting for live Fleet agent data.</td>
                </tr>
              ) : (
                rows.map((row) => (
                  <tr key={row.id}>
                    <td><Badge value={row.health} /></td>
                    <td>{row.name}</td>
                    <td><Badge value={row.agentStatus} /></td>
                    <td>{row.version ?? "--"}</td>
                    <td>{row.lastSeen ?? "--"}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}

function SettingsPanel({
  dataViews,
  indexPattern,
  extensionId,
  threatFoxAuthKey,
  threatFoxAuthKeySaved,
  malwareBazaarAuthKey,
  malwareBazaarAuthKeySaved,
  googleThreatIntelApiKey,
  googleThreatIntelApiKeySaved,
  onIndexPatternChange,
  onExtensionIdChange,
  onThreatFoxAuthKeyChange,
  onMalwareBazaarAuthKeyChange,
  onGoogleThreatIntelApiKeyChange,
  onSaveExtensionId,
  onSaveApiKeys,
  onLoadDataViews,
  threatRadarAgent,
  threatRadarAgentState,
  savingThreatRadarAgent,
  onThreatRadarAgentChange,
  onSaveThreatRadarAgent,
  onSaveAllowlist,
  onRunThreatRadarAgent
}: {
  dataViews: DataViewSummary[];
  indexPattern: string;
  extensionId: string;
  threatFoxAuthKey: string;
  threatFoxAuthKeySaved: boolean;
  malwareBazaarAuthKey: string;
  malwareBazaarAuthKeySaved: boolean;
  googleThreatIntelApiKey: string;
  googleThreatIntelApiKeySaved: boolean;
  onIndexPatternChange: (value: string) => void;
  onExtensionIdChange: (value: string) => void;
  onThreatFoxAuthKeyChange: (value: string) => void;
  onMalwareBazaarAuthKeyChange: (value: string) => void;
  onGoogleThreatIntelApiKeyChange: (value: string) => void;
  onSaveExtensionId: () => void;
  onSaveApiKeys: () => void;
  onLoadDataViews: () => void;
  threatRadarAgent: ThreatRadarAgentConfig;
  threatRadarAgentState: ThreatRadarAgentState;
  savingThreatRadarAgent: boolean;
  onThreatRadarAgentChange: (value: ThreatRadarAgentConfig) => void;
  onSaveThreatRadarAgent: () => void;
  onSaveAllowlist: () => void;
  onRunThreatRadarAgent: () => void;
}) {
  const [settingsView, setSettingsView] = useState<SettingsView>("agent");
  const [allowlistScope, setAllowlistScope] = useState<AllowlistScope>("ip");
  const [allowlistValue, setAllowlistValue] = useState("");
  const [allowlistError, setAllowlistError] = useState<string | null>(null);

  function addAllowlistEntry(event: React.FormEvent) {
    event.preventDefault();
    const values = allowlistValue.split(/[\n,]+/).map((value) => value.trim()).filter(Boolean);
    const entries = values.map((value) => normalizeAllowlistEntry(allowlistScope, value));
    const invalidIndex = entries.findIndex((entry) => entry === null);
    if (values.length === 0 || invalidIndex >= 0) {
      setAllowlistError(values.length === 0 ? "Enter at least one value." : `Invalid ${allowlistScope}: ${values[invalidIndex]}`);
      return;
    }
    onThreatRadarAgentChange({
      ...threatRadarAgent,
      candidateExclusions: [...new Set([...threatRadarAgent.candidateExclusions, ...(entries as string[])])]
    });
    setAllowlistValue("");
    setAllowlistError(null);
  }

  function removeAllowlistEntry(entry: string) {
    onThreatRadarAgentChange({
      ...threatRadarAgent,
      candidateExclusions: threatRadarAgent.candidateExclusions.filter((candidate) => candidate !== entry)
    });
  }

  return (
    <section className="grid">
      <div className="panel wide">
        <div className="settings-tabs" role="tablist" aria-label="Settings sections">
          {([
            ["agent", "Threat Radar Agent"],
            ["allowlist", "Allowlist"],
            ["integrations", "Integrations"],
            ["dataViews", "Data Views"],
            ["connection", "Bridge Connection"]
          ] as Array<[SettingsView, string]>).map(([id, label]) => (
            <button key={id} role="tab" aria-selected={settingsView === id} className={settingsView === id ? "active" : ""} onClick={() => setSettingsView(id)}>{label}</button>
          ))}
        </div>
        {settingsView === "integrations" ? <>
        <h2>Integrations</h2>
        <div className="form-grid api-key-grid">
          <label className="field">
            <span>ThreatFox Auth-Key</span>
            <input
              type="password"
              value={threatFoxAuthKey}
              placeholder={threatFoxAuthKeySaved ? "Saved" : "Paste Auth-Key"}
              onChange={(event) => onThreatFoxAuthKeyChange(event.target.value)}
            />
          </label>
          <label className="field">
            <span>MalwareBazaar Auth-Key</span>
            <input
              type="password"
              value={malwareBazaarAuthKey}
              placeholder={malwareBazaarAuthKeySaved ? "Saved" : "Paste Auth-Key"}
              onChange={(event) => onMalwareBazaarAuthKeyChange(event.target.value)}
            />
          </label>
          <label className="field">
            <span>Google Threat Intelligence / VirusTotal API Key</span>
            <input
              type="password"
              value={googleThreatIntelApiKey}
              placeholder={googleThreatIntelApiKeySaved ? "Saved" : "Paste GTI API key"}
              onChange={(event) => onGoogleThreatIntelApiKeyChange(event.target.value)}
            />
          </label>
        </div>
        <div className="settings-action-row">
          <span className="muted">
            ThreatFox {threatFoxAuthKeySaved ? "key saved" : "key missing"} | MalwareBazaar {malwareBazaarAuthKeySaved ? "key saved" : "key optional/missing"} | GTI {googleThreatIntelApiKeySaved ? "key saved" : "key missing"}
          </span>
          <button className="secondary align-end" onClick={onSaveApiKeys} disabled={!threatFoxAuthKey.trim() && !malwareBazaarAuthKey.trim() && !googleThreatIntelApiKey.trim()}>
            <ShieldCheck size={16} aria-hidden="true" />
            <span>Save API Keys</span>
          </button>
        </div>
        </> : null}
        {settingsView === "agent" ? <>
        <section className="agent-settings" aria-labelledby="threat-radar-agent-title">
          <div className="panel-actions">
            <div>
              <h2 id="threat-radar-agent-title">Threat Radar Agent</h2>
              <p className="muted">Read-only recurring scans. Alerts require a risky authentication service, repeated failures, a later successful authentication signal, and adverse GTI/VT reputation.</p>
            </div>
            <label className="agent-toggle">
              <input
                type="checkbox"
                checked={threatRadarAgent.enabled}
                onChange={(event) => onThreatRadarAgentChange({ ...threatRadarAgent, enabled: event.target.checked })}
              />
              <span>{threatRadarAgent.enabled ? "Enabled" : "Paused"}</span>
            </label>
          </div>
          <div className="form-grid compact agent-config-grid">
            <label className="field">
              <span>Scan interval</span>
              <select value={threatRadarAgent.intervalMinutes} onChange={(event) => onThreatRadarAgentChange({ ...threatRadarAgent, intervalMinutes: Number(event.target.value) })}>
                <option value={5}>Every 5 minutes</option>
                <option value={15}>Every 15 minutes</option>
                <option value={30}>Every 30 minutes</option>
                <option value={60}>Every hour</option>
              </select>
            </label>
            <div className="agent-status" role="status">
              <strong>{threatRadarAgentState.status === "healthy" ? "Monitoring healthy" : threatRadarAgentState.status === "error" ? "Last scan failed" : threatRadarAgent.enabled ? "Ready to monitor" : "Monitoring paused"}</strong>
              <span>{formatThreatRadarAgentState(threatRadarAgentState)}</span>
            </div>
            <button className="secondary align-end" onClick={onSaveThreatRadarAgent} disabled={savingThreatRadarAgent}>
              <Settings size={16} aria-hidden="true" />
              <span>{savingThreatRadarAgent ? "Saving" : "Save Agent"}</span>
            </button>
            <button className="secondary align-end" onClick={onRunThreatRadarAgent} disabled={savingThreatRadarAgent || !threatRadarAgent.enabled}>
              <Radar size={16} aria-hidden="true" />
              <span>Run Scan Now</span>
            </button>
          </div>
        </section>
        </> : null}
        {settingsView === "allowlist" ? <section className="allowlist-settings" aria-labelledby="allowlist-title">
          <div className="panel-actions">
            <div>
              <h2 id="allowlist-title">Detection Allowlist</h2>
              <p className="muted">Trusted values are excluded from Threat Radar findings, investigation candidates, IOC Hunt matches, and automatic alerts.</p>
            </div>
            <Badge value={`${threatRadarAgent.candidateExclusions.length} entries`} />
          </div>
          <form className="allowlist-editor" onSubmit={addAllowlistEntry}>
            <label className="field">
              <span>Type</span>
              <select value={allowlistScope} onChange={(event) => setAllowlistScope(event.target.value as AllowlistScope)}>
                <option value="ip">IP or IPv4 CIDR</option>
                <option value="domain">Domain</option>
                <option value="hash">File hash</option>
                <option value="keyword">Activity keyword</option>
              </select>
            </label>
            <label className="field allowlist-value-field">
              <span>Trusted value</span>
              <input
                value={allowlistValue}
                onChange={(event) => setAllowlistValue(event.target.value)}
                placeholder={allowlistPlaceholder(allowlistScope)}
                autoComplete="off"
              />
            </label>
            <button className="secondary align-end" type="submit">
              <Plus size={16} aria-hidden="true" />
              <span>Add</span>
            </button>
          </form>
          {allowlistError ? <div className="field-error" role="alert">{allowlistError}</div> : null}
          {threatRadarAgent.candidateExclusions.length > 0 ? (
            <div className="table-wrap allowlist-table-wrap">
              <table className="allowlist-table">
                <thead><tr><th>Type</th><th>Value</th><th>Coverage</th><th>Remove</th></tr></thead>
                <tbody>{threatRadarAgent.candidateExclusions.map((entry) => {
                  const parsed = parseAllowlistEntry(entry);
                  return <tr key={entry}>
                    <td><Badge value={parsed.scope.toUpperCase()} /></td>
                    <td className="mono-cell">{parsed.value}</td>
                    <td>Threat Radar and IOC Hunt</td>
                    <td><button className="icon-button danger-button" type="button" aria-label={`Remove ${parsed.value} from allowlist`} onClick={() => removeAllowlistEntry(entry)}><Trash2 size={16} aria-hidden="true" /></button></td>
                  </tr>;
                })}</tbody>
              </table>
            </div>
          ) : <div className="empty-card"><strong>No trusted values configured.</strong><span>All candidates are currently evaluated.</span></div>}
          <div className="settings-action-row allowlist-save-row">
            <span className="muted">Saved entries take effect immediately; explicit IOC Search remains available for analyst investigation.</span>
            <button className="primary" type="button" onClick={onSaveAllowlist} disabled={savingThreatRadarAgent}>
              <ShieldCheck size={16} aria-hidden="true" />
              <span>{savingThreatRadarAgent ? "Saving" : "Save Allowlist"}</span>
            </button>
          </div>
        </section> : null}
        {settingsView === "dataViews" ? <>
        <div className="panel-actions">
          <h2>Data Views</h2>
          <button className="secondary" onClick={onLoadDataViews}>
            <RefreshCw size={16} aria-hidden="true" />
            <span>Load Data Views</span>
          </button>
        </div>
        <label className="field">
          <span>Selected index pattern</span>
          <input value={indexPattern} onChange={(event) => onIndexPatternChange(event.target.value)} />
        </label>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Title</th>
                <th>Time Field</th>
                <th>Select</th>
              </tr>
            </thead>
            <tbody>
              {dataViews.length === 0 ? (
                <tr><td colSpan={4}>No data views loaded yet.</td></tr>
              ) : (
                dataViews.map((view) => (
                  <tr key={view.id}>
                    <td>{view.name ?? view.id}</td>
                    <td>{view.title}</td>
                    <td>{view.timeFieldName ?? "--"}</td>
                    <td>
                      <button className="icon-button" aria-label={`Use ${view.title}`} onClick={() => onIndexPatternChange(view.title)}>
                        <ShieldCheck size={16} aria-hidden="true" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
        </> : null}
        {settingsView === "connection" ? <>
        <div className="form-grid compact">
          <label className="field">
            <span>Extension ID</span>
            <input value={extensionId} onChange={(event) => onExtensionIdChange(event.target.value)} />
          </label>
          <button className="secondary align-end" onClick={onSaveExtensionId}>
            <RefreshCw size={16} aria-hidden="true" />
            <span>Save and Reconnect</span>
          </button>
        </div>
        </> : null}
      </div>
    </section>
  );
}

function formatThreatRadarAgentState(state: ThreatRadarAgentState): string {
  if (state.lastError) return state.lastError;
  if (state.status === "running") return "Scan in progress. The agent is querying the configured SIEM index now.";
  if (state.completedAt) {
    const scoredFlows = state.report?.summary.suspects ?? 0;
    const analyzedEvents = state.report?.eventsAnalyzed ?? 0;
    return `Last scan completed ${new Date(state.completedAt).toLocaleString()}; ${analyzedEvents.toLocaleString()} events were analyzed, ${scoredFlows} findings were promoted, and ${state.candidates ?? 0} met the automatic alert criteria.`;
  }
  return "No scheduled scan has completed yet.";
}

function normalizeAllowlistEntry(scope: AllowlistScope, rawValue: string): string | null {
  const value = rawValue.trim().toLowerCase();
  if (!value || value.length > 240) return null;
  if (scope === "ip") {
    const [address, prefix] = value.split("/");
    const ipv4Parts = address?.split(".").map(Number) ?? [];
    const validIpv4 = ipv4Parts.length === 4 && ipv4Parts.every((part) => Number.isInteger(part) && part >= 0 && part <= 255);
    const validIpv4Prefix = prefix === undefined || (/^\d{1,2}$/.test(prefix) && Number(prefix) >= 0 && Number(prefix) <= 32);
    const validIpv6 = prefix === undefined && /^[0-9a-f:]+$/.test(address ?? "") && (address?.includes(":") ?? false);
    if (!(validIpv4 && validIpv4Prefix) && !validIpv6) return null;
  }
  if (scope === "domain" && !/^(?=.{1,253}$)(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$/.test(value)) return null;
  if (scope === "hash" && !/^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/.test(value)) return null;
  if (scope === "keyword" && value.length < 3) return null;
  return `${scope}:${value}`;
}

function parseAllowlistEntry(entry: string): { scope: AllowlistScope | "value"; value: string } {
  const separator = entry.indexOf(":");
  const scope = entry.slice(0, separator) as AllowlistScope;
  if (separator > 0 && ["ip", "domain", "hash", "keyword"].includes(scope)) {
    return { scope, value: entry.slice(separator + 1) };
  }
  return { scope: "value", value: entry };
}

function allowlistPlaceholder(scope: AllowlistScope): string {
  if (scope === "ip") return "198.51.100.25 or 198.51.100.0/24";
  if (scope === "domain") return "trusted.example";
  if (scope === "hash") return "MD5, SHA-1, or SHA-256";
  return "approved scanner name";
}

function IOCSearch({
  value,
  indexPattern,
  result,
  onValueChange,
  onIndexPatternChange,
  onSearch
}: {
  value: string;
  indexPattern: string;
  result: unknown;
  onValueChange: (value: string) => void;
  onIndexPatternChange: (value: string) => void;
  onSearch: () => void;
}) {
  const summary = summarizeIocResult(result);
  return (
    <section className="grid">
      <div className="panel wide">
        <div className="panel-actions">
          <h2>IOC Search</h2>
          <button className="secondary" onClick={onSearch}>
            <Search size={16} aria-hidden="true" />
            <span>Search</span>
          </button>
        </div>
        <div className="form-grid">
          <label className="field">
            <span>Indicator</span>
            <input value={value} onChange={(event) => onValueChange(event.target.value)} />
          </label>
          <label className="field">
            <span>Index pattern</span>
            <input value={indexPattern} onChange={(event) => onIndexPatternChange(event.target.value)} />
          </label>
        </div>
        {summary ? (
          <div className="ioc-results">
            <div className="result-metrics">
              <StatusTile label="Type" value={summary.type} tone="unknown" />
              <StatusTile label="Normalized" value={summary.normalized} tone="unknown" />
              <StatusTile label="Total Hits" value={String(summary.total)} tone={summary.total > 0 ? "healthy" : "unknown"} />
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Index</th>
                    <th>Host</th>
                    <th>Message</th>
                  </tr>
                </thead>
                <tbody>
                  {summary.hits.length === 0 ? (
                    <tr><td colSpan={4}>No matching events found for this time range.</td></tr>
                  ) : (
                    summary.hits.map((hit, index) => (
                      <tr key={`${hit.index}-${index}`}>
                        <td>{hit.timestamp ?? "--"}</td>
                        <td>{hit.index}</td>
                        <td>{hit.host ?? "--"}</td>
                        <td>{hit.message ?? "--"}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        ) : (
          <pre className="result">No search has run yet.</pre>
        )}
      </div>
    </section>
  );
}

function IOCHunt({
  timeRange,
  filter,
  status,
  progress,
  batchInfo,
  providers,
  results,
  onTimeRangeChange,
  onFilterChange,
  onHunt,
  onFreshHunt
}: {
  timeRange: HuntTimeRange;
  filter: HuntFilter;
  status: HuntStatus;
  progress: { processed: number; total: number };
  batchInfo: Pick<DailyHuntResponse, "batchNumber" | "batchOffset" | "batchSize" | "totalAvailable" | "nextBatchOffset" | "hasMore"> | null;
  providers: ProviderStatus[];
  results: HuntResult[];
  onTimeRangeChange: (value: HuntTimeRange) => void;
  onFilterChange: (value: HuntFilter) => void;
  onHunt: () => void;
  onFreshHunt: () => void;
}) {
  const stagedProgress = useAnimatedHuntStages(status, progress.total || DAILY_HUNT_BATCH_SIZE);
  const matched = results.filter((result) => result.total > 0);
  const filteredMatches = matched.filter((result) => matchesHuntFilter(result.ioc.type, filter));
  const first = matched[0]?.ioc ?? results[0]?.ioc;
  const collected = batchInfo?.totalAvailable ?? providers.reduce((sum, provider) => sum + provider.collected, 0);
  const checked = providers.reduce((sum, provider) => sum + (provider.checked ?? 0), 0);
  const healthySources = providers.filter((provider) => provider.status === "healthy").length;
  const typeStats = buildHuntTypeStats(results);

  if (status !== "running" && results.length === 0) {
    return (
      <section className="hunt-start-screen" aria-label="Start IOC Hunt">
        <TimeRangePicker value={timeRange} onChange={onTimeRangeChange} />
        <button className="primary mega-hunt-button" onClick={onHunt}>
          <Radar size={42} aria-hidden="true" />
          <span>IOC Hunt</span>
        </button>
      </section>
    );
  }

  if (status === "running") {
    return (
      <section className="panel wide hunt-scope-panel" role="status" aria-label="IOC Hunt running">
        <div className="scope-scene" aria-hidden="true">
          <div className="scope-ring outer" />
          <div className="scope-ring middle" />
          <div className="scope-ring inner" />
          <div className="scope-line vertical" />
          <div className="scope-line horizontal" />
          <div className="scope-sweep" />
          <span className="scope-blip one" />
          <span className="scope-blip two" />
          <span className="scope-blip three" />
          <span className="scope-blip four" />
        </div>
        <div className="scope-copy">
          <h2>IOC Hunt in progress</h2>
          <p>Scanning threat-intel feeds, normalizing indicators, and checking Elastic for internal matches.</p>
          <div className="hunt-stage-grid">
            <StageCard label="Vendor feeds" current={stagedProgress.vendors} total={progress.total || DAILY_HUNT_BATCH_SIZE} />
            <StageCard label="Normalization" current={stagedProgress.normalized} total={progress.total || DAILY_HUNT_BATCH_SIZE} />
            <StageCard label="SIEM checks" current={stagedProgress.checked} total={progress.total || DAILY_HUNT_BATCH_SIZE} />
          </div>
          <p className="scope-finalizing">Checking this {progress.total || DAILY_HUNT_BATCH_SIZE}-indicator batch in Elastic...</p>
        </div>
      </section>
    );
  }

  return (
    <section className="grid">
      <div className="panel wide">
        <div className="hunt-dashboard-head">
          <div>
            <h2>IOC Hunt</h2>
            <p className="muted compact-copy">Showing SIEM matches only. Feed collection and checked coverage are below.</p>
            {batchInfo ? (
              <p className="hunt-batch-summary">
                Batch {batchInfo.batchNumber}: indicators {batchInfo.batchOffset + 1}-{batchInfo.batchOffset + batchInfo.batchSize} of {batchInfo.totalAvailable} checked
                {batchInfo.hasMore ? " | Run Again checks the next batch" : " | All collected batches checked"}
              </p>
            ) : null}
          </div>
          <div className="top-actions">
            <TimeRangePicker value={timeRange} onChange={onTimeRangeChange} />
            <button className="secondary large-action" onClick={onFreshHunt}>
              <RefreshCw size={18} aria-hidden="true" />
              <span>Fresh Scan</span>
            </button>
            <button className="primary large-action" onClick={onHunt}>
              <Play size={18} aria-hidden="true" />
              <span>{batchInfo?.hasMore === false ? "Restart Batches" : "Run Again"}</span>
            </button>
          </div>
        </div>

        <div className="hunt-complete-grid">
          <div className="hunt-controls panel-surface">
            <div className="result-metrics compact-metrics">
              <StatusTile label="Feeds Healthy" value={String(healthySources)} tone={healthySources ? "healthy" : "unknown"} />
              <StatusTile label="IOCs Collected" value={String(collected)} tone={collected ? "healthy" : "unknown"} />
              <StatusTile label="IOCs Checked" value={String(checked)} tone={checked ? "healthy" : "unknown"} />
              <StatusTile label="SIEM Matches" value={String(matched.length)} tone={matched.length ? "critical" : "unknown"} />
            </div>
            <HuntFilterCards stats={typeStats} active={filter} onChange={onFilterChange} />
            <IntelPivots ioc={first} />
          </div>
          <div className="panel-surface">
            <h3>Threat Feed Coverage</h3>
            <ProviderStatusGrid providers={providers} />
          </div>
        </div>

      </div>

      <div className="panel wide">
        <div className="panel-title">
          <Radar size={18} aria-hidden="true" />
          <h2>Hunt Results</h2>
        </div>
        <HuntResultCards results={filteredMatches} hasRun={results.length > 0} />
      </div>
    </section>
  );
}

function ThreatRadar({
  timeRange,
  loading,
  result,
  agentConfig,
  agentState,
  viewMode,
  pinnedRange,
  error,
  onTimeRangeChange,
  onAnalyze,
  onResumeAutomatic
}: {
  timeRange: RadarTimeRange;
  loading: boolean;
  result: ThreatRadarResponse | null;
  agentConfig: ThreatRadarAgentConfig;
  agentState: ThreatRadarAgentState;
  viewMode: RadarViewMode;
  pinnedRange: RadarTimeRange;
  error: string | null;
  onTimeRangeChange: (value: RadarTimeRange) => void;
  onAnalyze: () => void;
  onResumeAutomatic: () => void;
}) {
  const [editingLayout, setEditingLayout] = useState(false);
  const [layout, setLayout] = useState<RadarLayoutItem[]>(() => resolveRadarCollisions(loadThreatRadarLayout()));
  const [draggingCard, setDraggingCard] = useState<RadarCardId | null>(null);
  const [activeCardDrag, setActiveCardDrag] = useState<{
    id: RadarCardId;
    clientX: number;
    clientY: number;
    grabX: number;
    grabY: number;
    width: number;
    height: number;
    x: number;
    y: number;
  } | null>(null);
  const [sourceSort, setSourceSort] = useState<RadarSort>({ field: "gti", direction: "desc" });
  const [destinationSort, setDestinationSort] = useState<RadarSort>({ field: "gti", direction: "desc" });
  const [outboundSort, setOutboundSort] = useState<RadarSort>({ field: "gti", direction: "desc" });
  const [deniedSort, setDeniedSort] = useState<RadarSort>({ field: "denied", direction: "desc" });
  const [portSort, setPortSort] = useState<RadarSort>({ field: "gti", direction: "desc" });
  const [reviewSort, setReviewSort] = useState<RadarSort>({ field: "score", direction: "desc" });
  const layoutCanvasRef = useRef<HTMLDivElement | null>(null);
  const cardDragRef = useRef<{
    id: RadarCardId;
    startX: number;
    startY: number;
    grabX: number;
    grabY: number;
    width: number;
    height: number;
    active: boolean;
  } | null>(null);
  const activeCardDragRef = useRef<typeof activeCardDrag>(null);
  const sourceSuspects = sortRadarSuspects(result?.externalSources ?? [], sourceSort);
  const destinationSuspects = sortRadarSuspects(result?.suspiciousDestinations ?? [], destinationSort);
  const outboundSuspects = sortRadarSuspects(result?.suspiciousOutbound ?? [], outboundSort);
  const deniedSuspects = sortRadarSuspects(result?.deniedActivity ?? [], deniedSort);
  const reviewCandidates = sortRadarSuspects(result?.reviewCandidates ?? [], reviewSort);
  const portSuspects = sortRadarSuspects(
    (result?.externalSources ?? []).filter((suspect) => suspect.dangerousPorts.length > 0),
    portSort
  );
  const suspiciousIndicators = result?.suspiciousIndicators ?? [];
  const usesSavedCanvas = layout.every((item) => typeof item.x === "number" && typeof item.y === "number");
  const canvasPositioning = editingLayout || usesSavedCanvas;
  const agentIsScanning = agentState.status === "running";
  const showingManualAnalysis = viewMode === "manual";

  function beginLayoutEdit() {
    const canvas = layoutCanvasRef.current?.getBoundingClientRect();
    const next = layout.map((item) => {
      const defaults = defaultRadarCardSize(item.id);
      const element = document.querySelector<HTMLElement>(`[data-radar-card="${item.id}"]`);
      const rect = element?.getBoundingClientRect();
      return {
        ...item,
        width: item.width ?? (rect ? Math.round(rect.width) : defaults.width),
        height: item.height ?? (rect ? Math.round(rect.height) : defaults.height),
        x: rect && canvas ? Math.max(0, Math.round(rect.left - canvas.left)) : item.x ?? 0,
        y: rect && canvas ? Math.max(0, Math.round(rect.top - canvas.top)) : item.y ?? 0
      };
    });
    setLayout(resolveRadarCollisions(next));
    setEditingLayout(true);
  }

  function saveLayout() {
    const next = layout.map((item) => ({
      id: item.id,
      width: Math.round(item.width ?? defaultRadarCardSize(item.id).width),
      height: Math.round(item.height ?? defaultRadarCardSize(item.id).height),
      x: Math.round(item.x ?? 0),
      y: Math.round(item.y ?? 0)
    }));
    localStorage.setItem(THREAT_RADAR_LAYOUT_KEY, JSON.stringify(next));
    setLayout(next);
    setEditingLayout(false);
    setDraggingCard(null);
    setActiveCardDrag(null);
    activeCardDragRef.current = null;
  }

  function updateCardLayout(id: RadarCardId, changes: Partial<RadarLayoutItem>) {
    setLayout((items) => items.map((item) => item.id === id ? { ...item, ...changes } : item));
  }

  function placeCard(id: RadarCardId, x: number, y: number) {
    setLayout((items) => resolveRadarCollisions(
      items.map((item) => item.id === id ? { ...item, x, y } : item),
      id
    ));
  }

  function startCardPointerDrag(event: React.PointerEvent<HTMLDivElement>, id: RadarCardId) {
    if (!editingLayout) return;
    if (isLayoutControlTarget(event.target)) return;
    if (event.button !== 0) return;
    event.preventDefault();
    const rect = event.currentTarget.getBoundingClientRect();
    cardDragRef.current = {
      id,
      startX: event.clientX,
      startY: event.clientY,
      grabX: event.clientX - rect.left,
      grabY: event.clientY - rect.top,
      width: Math.round(rect.width),
      height: Math.round(rect.height),
      active: false
    };

    const onMove = (moveEvent: PointerEvent) => {
      const current = cardDragRef.current;
      if (!current) return;
      const distance = Math.hypot(moveEvent.clientX - current.startX, moveEvent.clientY - current.startY);
      if (!current.active && distance < 5) return;
      if (!current.active) {
        current.active = true;
        setDraggingCard(current.id);
      }
      moveEvent.preventDefault();
      const canvas = layoutCanvasRef.current?.getBoundingClientRect();
      if (!canvas) return;
      const next = {
        id: current.id,
        clientX: moveEvent.clientX,
        clientY: moveEvent.clientY,
        grabX: current.grabX,
        grabY: current.grabY,
        width: current.width,
        height: current.height,
        x: clamp(Math.round(moveEvent.clientX - canvas.left - current.grabX), 0, Math.max(0, Math.round(canvas.width - current.width))),
        y: Math.max(0, Math.round(moveEvent.clientY - canvas.top - current.grabY))
      };
      activeCardDragRef.current = next;
      setActiveCardDrag(next);
    };

    const onUp = () => {
      const activeDrag = activeCardDragRef.current;
      if (activeDrag) placeCard(activeDrag.id, activeDrag.x, activeDrag.y);
      cardDragRef.current = null;
      activeCardDragRef.current = null;
      setDraggingCard(null);
      setActiveCardDrag(null);
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
      window.removeEventListener("pointercancel", onUp);
    };

    window.addEventListener("pointermove", onMove, { passive: false });
    window.addEventListener("pointerup", onUp);
    window.addEventListener("pointercancel", onUp);
  }

  function startCardDrag(event: React.DragEvent) {
    event.preventDefault();
  }

  function startCardResize(event: React.PointerEvent, id: RadarCardId, edge: string) {
    if (!editingLayout) return;
    event.preventDefault();
    event.stopPropagation();
    const item = layout.find((entry) => entry.id === id);
    if (!item) return;
    const startX = event.clientX;
    const startY = event.clientY;
    const originWidth = item.width ?? defaultRadarCardSize(id).width;
    const originHeight = item.height ?? defaultRadarCardSize(id).height;

    const onMove = (moveEvent: PointerEvent) => {
      const deltaX = moveEvent.clientX - startX;
      const deltaY = moveEvent.clientY - startY;
      const next: Partial<RadarLayoutItem> = {};

      if (edge.includes("e")) {
        next.width = clamp(originWidth + deltaX, 360, 1400);
      }
      if (edge.includes("s")) {
        next.height = clamp(originHeight + deltaY, 260, 1000);
      }
      if (edge.includes("w")) {
        next.width = clamp(originWidth - deltaX, 360, 1400);
      }
      if (edge.includes("n")) {
        next.height = clamp(originHeight - deltaY, 260, 1000);
      }

      updateCardLayout(id, next);
    };
    const onUp = () => {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
      window.removeEventListener("pointercancel", onUp);
    };
    window.addEventListener("pointermove", onMove, { passive: false });
    window.addEventListener("pointerup", onUp);
    window.addEventListener("pointercancel", onUp);
  }

  function handleCardLayoutKey(event: React.KeyboardEvent<HTMLDivElement>, item: RadarLayoutItem) {
    if (!editingLayout || !["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown"].includes(event.key)) return;
    event.preventDefault();
    const amount = event.altKey ? 1 : 16;
    const defaults = defaultRadarCardSize(item.id);
    if (event.shiftKey) {
      const widthDelta = event.key === "ArrowRight" ? amount : event.key === "ArrowLeft" ? -amount : 0;
      const heightDelta = event.key === "ArrowDown" ? amount : event.key === "ArrowUp" ? -amount : 0;
      updateCardLayout(item.id, {
        width: clamp((item.width ?? defaults.width) + widthDelta, 360, 1400),
        height: clamp((item.height ?? defaults.height) + heightDelta, 260, 1000)
      });
      return;
    }
    const nextX = Math.max(0, (item.x ?? 0) + (event.key === "ArrowRight" ? amount : event.key === "ArrowLeft" ? -amount : 0));
    const nextY = Math.max(0, (item.y ?? 0) + (event.key === "ArrowDown" ? amount : event.key === "ArrowUp" ? -amount : 0));
    placeCard(item.id, nextX, nextY);
  }

  function renderCard(item: RadarLayoutItem, floating = false) {
    const defaults = defaultRadarCardSize(item.id);
    const width = item.width ?? defaults.width;
    const height = item.height ?? defaults.height;
    const style = floating && activeCardDrag
      ? {
        position: "fixed" as const,
        left: `${Math.round(activeCardDrag.clientX - activeCardDrag.grabX)}px`,
        top: `${Math.round(activeCardDrag.clientY - activeCardDrag.grabY)}px`,
        width: `${activeCardDrag.width}px`,
        height: `${activeCardDrag.height}px`,
        zIndex: 30,
        pointerEvents: "none" as const
      }
      : canvasPositioning
      ? {
        position: "absolute" as const,
        left: `${item.x ?? 0}px`,
        top: `${item.y ?? 0}px`,
        width: `${width}px`,
        height: `${height}px`
      }
      : item.width || item.height ? {
        width: item.width ? `${item.width}px` : undefined,
        minHeight: item.height ? `${item.height}px` : undefined
      } : undefined;
    const editHandles = editingLayout ? <RadarResizeHandles onResize={(event, edge) => startCardResize(event, item.id, edge)} /> : null;
    const cardProps: React.HTMLAttributes<HTMLDivElement> = {
      draggable: false,
      onDragStart: startCardDrag,
      onPointerDown: floating ? undefined : (event) => startCardPointerDrag(event, item.id),
      onKeyDown: floating ? undefined : (event) => handleCardLayoutKey(event, item),
      tabIndex: editingLayout && !floating ? 0 : undefined,
      "aria-label": editingLayout ? `${item.id} card. Use arrow keys to move; Shift and arrow keys to resize.` : undefined,
      className: `panel radar-widget ${floating ? "dragging floating" : ""}`
    };

    if (item.id === "sources") {
      return (
        <div key={item.id} data-radar-card={item.id} style={style} {...cardProps}>
          {editHandles}
          <div className="ranked-card-head">
            <div>
              <h3>Suspicious Source Flows</h3>
              <span>Public sources with corroborated hostile behavior</span>
            </div>
          </div>
          <ThreatRadarList suspects={sourceSuspects} mode="source" sort={sourceSort} onSort={setSourceSort} />
        </div>
      );
    }

    if (item.id === "destinations") {
      return (
        <div key={item.id} data-radar-card={item.id} style={style} {...cardProps}>
          {editHandles}
          <div className="ranked-card-head">
            <div>
              <h3>Suspicious Destination Flows</h3>
              <span>Public destinations with corroborated reputation or behavior risk</span>
            </div>
          </div>
          <ThreatRadarList suspects={destinationSuspects} mode="destination" sort={destinationSort} onSort={setDestinationSort} />
        </div>
      );
    }

    if (item.id === "outbound") {
      return (
        <div key={item.id} data-radar-card={item.id} style={style} {...cardProps}>
          {editHandles}
          <div className="ranked-card-head">
            <div>
              <h3>Suspicious Outbound Activity</h3>
              <span>Internal sources communicating with public destinations</span>
            </div>
          </div>
          <ThreatRadarList suspects={outboundSuspects} mode="outbound" sort={outboundSort} onSort={setOutboundSort} />
        </div>
      );
    }

    if (item.id === "denied") {
      return (
        <div key={item.id} data-radar-card={item.id} style={style} {...cardProps}>
          {editHandles}
          <div className="ranked-card-head">
            <div>
              <h3>Denied and Failed Activity</h3>
              <span>Public inbound sources ranked by rejected attack volume</span>
            </div>
          </div>
          <ThreatRadarList suspects={deniedSuspects} mode="denied" sort={deniedSort} onSort={setDeniedSort} />
        </div>
      );
    }

    if (item.id === "indicators") {
      return (
        <div key={item.id} data-radar-card={item.id} style={style} {...cardProps}>
          {editHandles}
          <div className="ranked-card-head">
            <div>
              <h3>Suspicious Domains and Hashes</h3>
              <span>Reputation-prioritized indicators with behavioral evidence</span>
            </div>
          </div>
          <ThreatIndicatorList indicators={suspiciousIndicators} />
        </div>
      );
    }

    if (item.id === "review") {
      return (
        <div key={item.id} data-radar-card={item.id} style={style} {...cardProps}>
          {editHandles}
          <div className="ranked-card-head">
            <div>
              <h3>Investigation Queue</h3>
              <span>Corroborated anomalies below the automatic-alert threshold</span>
            </div>
          </div>
          <ThreatRadarList suspects={reviewCandidates} mode="review" sort={reviewSort} onSort={setReviewSort} />
        </div>
      );
    }

    return (
      <div key={item.id} data-radar-card={item.id} style={style} {...cardProps}>
        {editHandles}
        <div className="ranked-card-head">
          <div>
            <h3>Suspicious Port Activity</h3>
            <span>Public sources targeting risky services across infrastructure</span>
          </div>
        </div>
        <ThreatRadarList suspects={portSuspects} mode="ports" sort={portSort} onSort={setPortSort} />
      </div>
    );
  }

  return (
    <section className="grid">
      <div className="panel wide radar-agent-status" role="status">
        <div>
          <div className="panel-title">
            <Activity size={18} aria-hidden="true" className={agentConfig.enabled ? "agent-heartbeat" : ""} />
            <h2>{showingManualAnalysis
              ? `${formatRadarRangeLabel(pinnedRange ?? timeRange)} analysis pinned`
              : agentConfig.enabled
                ? agentIsScanning ? "Agent scan in progress" : "Agent monitoring active"
                : "Agent monitoring paused"}</h2>
          </div>
          <p className="muted">{showingManualAnalysis
            ? agentConfig.enabled
              ? `Showing the completed ${formatRadarRangeLabel(pinnedRange ?? timeRange).toLowerCase()} analysis. Automatic monitoring continues every ${agentConfig.intervalMinutes} minutes in the background and will not replace these findings.`
              : `Showing the completed ${formatRadarRangeLabel(pinnedRange ?? timeRange).toLowerCase()} analysis. Automatic monitoring is currently paused in Settings.`
            : <>Scanning <strong>{agentConfig.indexPattern}</strong> every {agentConfig.intervalMinutes} minutes across threat signals, denied activity, risky authentication, exposed services, and traffic behavior. Public inbound threats require corroborated evidence; private hosts are evaluated only for suspicious outbound communication. Findings remain visible in a rolling 24-hour history.</>}</p>
          <p className="radar-run-summary">
            {result
              ? `${result.eventsAnalyzed.toLocaleString()} events analyzed | ${(result.analysis?.candidatesEvaluated ?? result.summary.suspects).toLocaleString()} evidence candidates evaluated | ${result.summary.suspects.toLocaleString()} promoted findings | ${(result.analysis?.candidatesForReview ?? result.reviewCandidates?.length ?? 0).toLocaleString()} queued for review | ${result.signals.length.toLocaleString()} active signal families`
              : "No completed analysis is available yet."}
          </p>
        </div>
        <div className="top-actions">
          <ThreatRadarRangePicker value={timeRange} onChange={onTimeRangeChange} />
          {showingManualAnalysis ? (
            <button className="secondary" onClick={onResumeAutomatic} disabled={loading} title="Return to findings from the scheduled monitoring agent">
              <Activity size={16} aria-hidden="true" />
              <span>Run Automatically</span>
            </button>
          ) : null}
          <button className="secondary" onClick={editingLayout ? saveLayout : beginLayoutEdit}>
            <Settings size={16} aria-hidden="true" />
            <span>{editingLayout ? "Save Layout" : "Edit Layout"}</span>
          </button>
          <button className="primary large-action" onClick={onAnalyze} disabled={loading}>
            <Radar size={18} aria-hidden="true" className={loading ? "spin" : ""} />
            <span>{loading ? "Analyzing" : "Analyze Logs"}</span>
          </button>
        </div>
      </div>

      {error ? (
        <div className="notice wide radar-error" role="alert">
          <AlertTriangle size={18} aria-hidden="true" />
          <div>
            <strong>Threat Radar scan did not complete</strong>
            <span>{error}</span>
          </div>
        </div>
      ) : null}

      {result?.analysis?.partial ? (
        <div className="notice wide radar-coverage-warning" role="status">
          <AlertTriangle size={18} aria-hidden="true" />
          <div>
            <strong>Analysis completed with reduced coverage</strong>
            <span>Unavailable stages: {result.analysis.skippedStages.join(", ")}. The findings shown are valid, but some activity categories may be missing.</span>
          </div>
        </div>
      ) : null}

      {result?.analysis?.reputation && result.analysis.reputation.requested > 0 && result.analysis.reputation.status !== "healthy" ? (
        <div className="notice wide radar-coverage-warning" role="status">
          <AlertTriangle size={18} aria-hidden="true" />
          <div>
            <strong>Reputation coverage is {result.analysis.reputation.status === "not_configured" ? "not configured" : "still in progress"}</strong>
            <span>{formatReputationCoverage(result.analysis.reputation)}</span>
          </div>
        </div>
      ) : null}

      <DetectionSignalDashboard result={result} />

      <div
        ref={layoutCanvasRef}
        className={`radar-widget-grid ${editingLayout ? "layout-editing" : ""} ${canvasPositioning ? "layout-positioned" : ""}`}
        style={canvasPositioning ? { minHeight: `${Math.max(760, ...layout.map((item) => (item.y ?? 0) + (item.height ?? defaultRadarCardSize(item.id).height) + 24))}px` } : undefined}
      >
        {layout.filter((item) => item.id !== activeCardDrag?.id).map((item) => renderCard(item))}
        {activeCardDrag ? (
          <div
            className="radar-drop-placeholder"
            style={{ position: "absolute", left: `${activeCardDrag.x}px`, top: `${activeCardDrag.y}px`, width: `${activeCardDrag.width}px`, height: `${activeCardDrag.height}px` }}
            aria-hidden="true"
          />
        ) : null}
        {activeCardDrag ? renderCard(layout.find((item) => item.id === activeCardDrag.id)!, true) : null}
      </div>
    </section>
  );
}

function ThreatRadarRangePicker({ value, onChange }: { value: RadarTimeRange; onChange: (value: RadarTimeRange) => void }) {
  const ranges: Array<{ value: RadarTimeRange; label: string }> = [
    { value: "last15m", label: "Last 15 min" },
    { value: "last1h", label: "Last 1 hour" },
    { value: "today", label: "Today" }
  ];
  return (
    <div className="segmented-control radar-range" aria-label="Threat Radar time range">
      {ranges.map((range) => (
        <button key={range.value} className={value === range.value ? "selected" : ""} onClick={() => onChange(range.value)}>
          {range.label}
        </button>
      ))}
    </div>
  );
}

function RadarResizeHandles({ onResize }: { onResize: (event: React.PointerEvent, edge: string) => void }) {
  const handles = ["n", "e", "s", "w", "ne", "se", "sw", "nw"];
  return (
    <>
      {handles.map((edge) => (
        <span
          key={edge}
          className={`resize-handle resize-${edge}`}
          onPointerDown={(event) => onResize(event, edge)}
          aria-hidden="true"
        />
      ))}
    </>
  );
}

function ThreatRadarList({
  suspects,
  mode,
  sort,
  onSort
}: {
  suspects: ThreatRadarSuspect[];
  mode: "source" | "destination" | "outbound" | "denied" | "ports" | "review";
  sort: RadarSort;
  onSort: (sort: RadarSort) => void;
}) {
  const pageSize = 10;
  const [page, setPage] = useState(1);
  const pageCount = Math.max(1, Math.ceil(suspects.length / pageSize));
  const currentPage = Math.min(page, pageCount);
  const pageStart = (currentPage - 1) * pageSize;
  const visibleSuspects = suspects.slice(pageStart, pageStart + pageSize);

  useEffect(() => {
    setPage((current) => Math.min(current, pageCount));
  }, [pageCount]);

  if (suspects.length === 0) {
    const emptyTitles: Record<typeof mode, string> = {
      source: "No source IP met the malicious-intent evidence threshold.",
      destination: "No suspicious destination IP met the evidence threshold.",
      outbound: "No private host communicating with a risky public destination was detected.",
      denied: "No denied or failed activity met the attack threshold.",
      ports: "No risky-port activity met the evidence threshold.",
      review: "No additional IP has enough independent evidence for analyst review."
    };
    return <EmptyRadarState title={emptyTitles[mode]} />;
  }
  return (
    <div className="radar-list">
      <div className="mini-table-wrap radar-table-wrap">
        <table className="mini-ioc-table radar-table">
          <thead>
            <tr>
              <SortableRadarHeader label="Source IP" field="sourceIp" sort={sort} onSort={onSort} />
              <SortableRadarHeader label="Destination IP" field="destinationIp" sort={sort} onSort={onSort} />
              <SortableRadarHeader label="Score" field="score" sort={sort} onSort={onSort} />
              <SortableRadarHeader label="Reputation" field="gti" sort={sort} onSort={onSort} />
              <SortableRadarHeader label="Events" field="events" sort={sort} onSort={onSort} />
              <SortableRadarHeader label="Denied" field="denied" sort={sort} onSort={onSort} />
              <SortableRadarHeader label="Outbound" field="outbound" sort={sort} onSort={onSort} />
              <SortableRadarHeader label="Infrastructure" field="infrastructure" sort={sort} onSort={onSort} />
              <SortableRadarHeader label="Ports" field="ports" sort={sort} onSort={onSort} />
              <SortableRadarHeader label="History" field="history" sort={sort} onSort={onSort} />
              <SortableRadarHeader label="Reasons" field="reasons" sort={sort} onSort={onSort} />
            </tr>
          </thead>
          <tbody>
            {visibleSuspects.map((suspect) => (
              <tr key={`${mode}:${suspect.role}:${suspect.sourceIp}:${suspect.destinationIp}`}>
                <td className="mono-cell">{suspect.sourceIp}</td>
                <td className="mono-cell">{suspect.destinationIp}</td>
                <td><Badge value={`${suspect.score}`} /></td>
                <td><ReputationCell gti={suspect.gti} target={suspect.gtiIp} status={suspect.gtiStatus} message={suspect.gtiMessage} cached={suspect.gtiCached} /></td>
                <td>{suspect.events}</td>
                <td>{suspect.deniedEvents ?? 0}</td>
                <td>{suspect.outboundEvents ?? 0}</td>
                <td>{suspect.infrastructureCount}</td>
                <td>{suspect.topPorts.length ? suspect.topPorts.join(", ") : "--"}</td>
                <td><FindingHistoryCell suspect={suspect} /></td>
                <td>{suspect.reasons.slice(0, 3).join(" | ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <RadarPagination page={currentPage} pageCount={pageCount} total={suspects.length} pageSize={pageSize} onChange={setPage} />
    </div>
  );
}

function SortableRadarHeader({
  label,
  field,
  sort,
  onSort
}: {
  label: string;
  field: RadarSortField;
  sort: RadarSort;
  onSort: (sort: RadarSort) => void;
}) {
  const active = sort.field === field;
  const Icon = active ? sort.direction === "asc" ? ArrowUp : ArrowDown : ArrowUpDown;
  return (
    <th aria-sort={active ? sort.direction === "asc" ? "ascending" : "descending" : "none"}>
      <button
        className={`sortable-table-head ${active ? "active" : ""}`}
        onClick={() => onSort({ field, direction: active && sort.direction === "asc" ? "desc" : "asc" })}
        aria-label={`Sort by ${label} ${active && sort.direction === "asc" ? "descending" : "ascending"}`}
      >
        <span>{label}</span>
        <Icon size={13} aria-hidden="true" />
      </button>
    </th>
  );
}

function FindingHistoryCell({ suspect }: { suspect: ThreatRadarSuspect }) {
  const observations = suspect.observations ?? 1;
  const delta = suspect.eventDelta;
  const trend = delta === undefined ? suspect.active === false ? "Quiet" : "New" : delta > 0 ? `+${delta}` : String(delta);
  const trendClass = delta === undefined ? "neutral" : delta > 0 ? "up" : delta < 0 ? "down" : "neutral";
  return (
    <div className="finding-history">
      <strong className={trendClass}>{trend}</strong>
      <span>{observations} scan{observations === 1 ? "" : "s"}</span>
      <span>{suspect.lastSeen ? formatRelativeTime(suspect.lastSeen) : "Current scan"}</span>
    </div>
  );
}

function ThreatIndicatorList({ indicators }: { indicators: ThreatRadarIndicator[] }) {
  const pageSize = 10;
  const [page, setPage] = useState(1);
  const pageCount = Math.max(1, Math.ceil(indicators.length / pageSize));
  const currentPage = Math.min(page, pageCount);
  const pageStart = (currentPage - 1) * pageSize;
  const visibleIndicators = indicators.slice(pageStart, pageStart + pageSize);

  useEffect(() => {
    setPage((current) => Math.min(current, pageCount));
  }, [pageCount]);

  if (indicators.length === 0) return <EmptyRadarState title="No suspicious domains or hashes scored yet." />;
  return (
    <div className="radar-list">
      <div className="mini-table-wrap radar-table-wrap">
        <table className="mini-ioc-table radar-table indicator-table">
          <thead>
            <tr>
              <th>Type</th>
              <th>Indicator</th>
              <th>Score</th>
              <th>Reputation</th>
              <th>Events</th>
              <th>Denied</th>
              <th>Infrastructure</th>
              <th>Signals</th>
              <th>Reasons</th>
            </tr>
          </thead>
          <tbody>
            {visibleIndicators.map((indicator) => (
              <tr key={`${indicator.type}:${indicator.value}`}>
                <td><Badge value={indicator.type.toUpperCase()} /></td>
                <td className="mono-cell indicator-value">{indicator.value}</td>
                <td><Badge value={`${indicator.score}`} /></td>
                <td><ReputationCell gti={indicator.gti} target={indicator.value} status={indicator.gtiStatus} message={indicator.gtiMessage} cached={indicator.gtiCached} /></td>
                <td>{indicator.events}</td>
                <td>{indicator.deniedEvents}</td>
                <td>{indicator.infrastructureCount}</td>
                <td>{indicator.matchedKeywords.length ? indicator.matchedKeywords.map(formatRadarSignal).join(", ") : "--"}</td>
                <td>{indicator.reasons.slice(0, 3).join(" | ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <RadarPagination page={currentPage} pageCount={pageCount} total={indicators.length} pageSize={pageSize} onChange={setPage} />
    </div>
  );
}

type ThreatSignalDetail = {
  id: string;
  entity: string;
  sourceIp: string;
  destinationIp: string;
  events: number;
  actions: Array<{ key: string; count: number }>;
  infrastructureCount: number;
  ports: number[];
  score: number;
  gti: ThreatRadarSuspect["gti"] | undefined;
  gtiTarget: string;
  evidence: string[];
};

function DetectionSignalDashboard({ result }: { result: ThreatRadarResponse | null }) {
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const dialogRef = useRef<HTMLDivElement | null>(null);
  const triggerRef = useRef<HTMLButtonElement | null>(null);
  const signals = useMemo(() => buildDetectionSignalSummaries(result), [result]);
  const selectedSignal = signals.find((signal) => signal.key === selectedKey);
  const details = useMemo(
    () => selectedKey && result ? getThreatSignalDetails(result, selectedKey) : [],
    [result, selectedKey]
  );
  const pageSize = 10;
  const pageCount = Math.max(1, Math.ceil(details.length / pageSize));
  const currentPage = Math.min(page, pageCount);
  const visibleDetails = details.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  useEffect(() => {
    setPage(1);
  }, [selectedKey]);

  useEffect(() => {
    if (selectedKey && !selectedSignal) setSelectedKey(null);
  }, [selectedKey, selectedSignal]);

  useEffect(() => {
    if (!selectedKey) return;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = previousOverflow;
    };
  }, [selectedKey]);

  function closeDialog() {
    setSelectedKey(null);
    window.requestAnimationFrame(() => triggerRef.current?.focus());
  }

  function handleDialogKeyDown(event: React.KeyboardEvent<HTMLDivElement>) {
    if (event.key === "Escape") {
      event.preventDefault();
      closeDialog();
      return;
    }
    if (event.key !== "Tab") return;
    const focusable = Array.from(dialogRef.current?.querySelectorAll<HTMLElement>(
      "button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex='-1'])"
    ) ?? []);
    if (focusable.length === 0) return;
    const first = focusable[0]!;
    const last = focusable[focusable.length - 1]!;
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  return (
    <>
      <section className="panel wide signal-dashboard" aria-labelledby="detection-signals-title">
        <div className="signal-dashboard-head">
          <div>
            <h2 id="detection-signals-title">Detection Signals</h2>
            <span>Evidence-backed activity families. Open a signal to inspect every associated finding.</span>
          </div>
          <strong>{signals.length} active</strong>
        </div>
        {signals.length === 0 ? (
          <div className="signal-dashboard-empty">No corroborated detection signals in the current result.</div>
        ) : (
          <div className="signal-dashboard-grid">
            {signals.map((signal) => (
              <button
                key={signal.key}
                type="button"
                className="signal-summary-button"
                aria-haspopup="dialog"
                onClick={(event) => {
                  triggerRef.current = event.currentTarget;
                  setSelectedKey(signal.key);
                }}
              >
                <span>{signal.label}</span>
                <span className="signal-summary-count">{signal.count}</span>
                <ChevronRight size={18} aria-hidden="true" />
              </button>
            ))}
          </div>
        )}
      </section>

      {selectedSignal ? (
        <div className="signal-modal-backdrop" onMouseDown={closeDialog}>
          <div
            ref={dialogRef}
            className="signal-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="signal-modal-title"
            aria-describedby="signal-modal-description"
            onMouseDown={(event) => event.stopPropagation()}
            onKeyDown={handleDialogKeyDown}
          >
            <div className="signal-modal-head">
              <div>
                <span className="eyebrow">Detection Signal</span>
                <h2 id="signal-modal-title">{selectedSignal.label}</h2>
                <p id="signal-modal-description">{details.length} associated {details.length === 1 ? "finding" : "findings"} with the evidence used by Threat Radar.</p>
              </div>
              <button type="button" className="icon-button signal-modal-close" aria-label="Close signal details" onClick={closeDialog} autoFocus>
                <X size={20} aria-hidden="true" />
              </button>
            </div>
            <div className="signal-modal-body">
              {details.length === 0 ? <EmptyRadarState title="No retained entities are available for this signal." /> : (
                <div className="mini-table-wrap signal-detail-table-wrap">
                  <table className="mini-ioc-table signal-detail-table">
                    <thead>
                      <tr>
                        <th>Source IP</th>
                        <th>Destination IP</th>
                        <th>Logs</th>
                        <th>Event actions</th>
                        <th>Infrastructure</th>
                        <th>Destination ports</th>
                        <th>Score</th>
                        <th>GTI / VT</th>
                        <th>Evidence</th>
                      </tr>
                    </thead>
                    <tbody>
                      {visibleDetails.map((detail) => (
                        <tr key={detail.id}>
                          <td className="mono-cell">{detail.sourceIp}</td>
                          <td className="mono-cell">{detail.destinationIp}</td>
                          <td>{detail.events.toLocaleString()}</td>
                          <td>{formatSignalActions(detail.actions)}</td>
                          <td>{detail.infrastructureCount.toLocaleString()}</td>
                          <td>{detail.ports.length ? detail.ports.join(", ") : "--"}</td>
                          <td><Badge value={String(detail.score)} /></td>
                          <td>{formatGti(detail.gti, detail.gtiTarget)}</td>
                          <td>{detail.evidence.slice(0, 3).join(" | ") || "--"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
            {details.length > 0 ? (
              <RadarPagination
                page={currentPage}
                pageCount={pageCount}
                total={details.length}
                pageSize={pageSize}
                onChange={setPage}
                ariaLabel={`${selectedSignal.label} finding pages`}
              />
            ) : null}
          </div>
        </div>
      ) : null}
    </>
  );
}

function buildDetectionSignalSummaries(result: ThreatRadarResponse | null): Array<{ key: string; label: string; count: number }> {
  if (!result) return [];
  const labels = new Map(result.signals.map((signal) => [signal.key, signal.label]));
  if (result.suspects.some((finding) => isPublicInboundSource(finding) && finding.deniedEvents > 0)) labels.set("denied", labels.get("denied") ?? "Denied activity");
  if (result.suspects.some((finding) => finding.direction === "outbound")) labels.set("outbound", labels.get("outbound") ?? "Suspicious outbound");
  if (result.suspects.some((finding) => isPublicInboundSource(finding) && finding.dangerousPorts.length > 0)) labels.set("dangerous_ports", labels.get("dangerous_ports") ?? "Risky ports");
  if (result.suspiciousIndicators.length > 0) labels.set("indicators", labels.get("indicators") ?? "Domain and hash indicators");
  for (const key of [...result.suspects.flatMap((finding) => finding.matchedKeywords), ...result.suspiciousIndicators.flatMap((indicator) => indicator.matchedKeywords)]) {
    labels.set(key, labels.get(key) ?? formatRadarSignal(key));
  }
  return [...labels.entries()]
    .map(([key, label]) => ({ key, label, count: getThreatSignalDetails(result, key).length }))
    .filter((signal) => signal.count > 0)
    .sort((left, right) => right.count - left.count || left.label.localeCompare(right.label));
}

function getThreatSignalDetails(result: ThreatRadarResponse, signalKey: string): ThreatSignalDetail[] {
  const details: ThreatSignalDetail[] = [];
  if (signalKey !== "indicators") {
    for (const finding of result.suspects.filter((item) => findingMatchesSignal(item, signalKey))) {
      details.push({
        id: `ip:${finding.role}:${finding.direction}:${finding.ip}`,
        entity: finding.ip,
        sourceIp: finding.sourceIp,
        destinationIp: finding.destinationIp,
        events: finding.events,
        actions: finding.actions,
        infrastructureCount: finding.infrastructureCount,
        ports: finding.topPorts,
        score: finding.score,
        gti: finding.gti,
        gtiTarget: finding.gtiIp,
        evidence: finding.active === false ? ["Retained from history", ...finding.reasons] : finding.reasons
      });
    }
  }
  if (signalKey === "indicators" || !["denied", "outbound", "dangerous_ports"].includes(signalKey)) {
    for (const indicator of result.suspiciousIndicators.filter((item) => signalKey === "indicators" || item.matchedKeywords.includes(signalKey))) {
      details.push({
        id: `${indicator.type}:${indicator.value}`,
        entity: indicator.value,
        sourceIp: indicator.latest?.sourceIp ?? "--",
        destinationIp: indicator.latest?.destinationIp ?? "--",
        events: indicator.events,
        actions: indicator.actions,
        infrastructureCount: indicator.infrastructureCount,
        ports: indicator.latest?.destinationPort ? [indicator.latest.destinationPort] : [],
        score: indicator.score,
        gti: indicator.gti,
        gtiTarget: indicator.value,
        evidence: indicator.reasons
      });
    }
  }
  return details.sort((left, right) => right.score - left.score || right.events - left.events || left.entity.localeCompare(right.entity));
}

function findingMatchesSignal(finding: ThreatRadarSuspect, signalKey: string): boolean {
  if (signalKey === "denied") return isPublicInboundSource(finding) && finding.deniedEvents > 0;
  if (signalKey === "outbound") return finding.direction === "outbound";
  if (signalKey === "dangerous_ports") return isPublicInboundSource(finding) && finding.dangerousPorts.length > 0;
  return finding.matchedKeywords.includes(signalKey);
}

function isPublicInboundSource(finding: ThreatRadarSuspect): boolean {
  return finding.role === "source" && finding.direction === "inbound" && !isPrivateAddress(finding.ip);
}

function isPrivateAddress(value: string): boolean {
  if (value.includes(":")) {
    const normalized = value.toLowerCase();
    return normalized.startsWith("fc") || normalized.startsWith("fd") || normalized.startsWith("fe8") || normalized.startsWith("fe9") || normalized.startsWith("fea") || normalized.startsWith("feb");
  }
  const parts = value.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return true;
  const first = parts[0] ?? -1;
  const second = parts[1] ?? -1;
  return first === 10
    || (first === 172 && second >= 16 && second <= 31)
    || (first === 192 && second === 168)
    || first === 127
    || first === 0
    || (first === 169 && second === 254)
    || (first === 100 && second >= 64 && second <= 127)
    || first >= 224;
}

function formatSignalActions(actions: Array<{ key: string; count: number }>): string {
  return actions.length ? actions.slice(0, 4).map((action) => `${action.key} (${action.count.toLocaleString()})`).join(", ") : "--";
}

function RadarPagination({ page, pageCount, total, pageSize, onChange, ariaLabel = "Radar card pages" }: { page: number; pageCount: number; total: number; pageSize: number; onChange: (page: number) => void; ariaLabel?: string }) {
  if (pageCount <= 1) return <span className="radar-result-count">{total} result{total === 1 ? "" : "s"}</span>;
  const pages = compactPageNumbers(page, pageCount);
  const from = (page - 1) * pageSize + 1;
  const to = Math.min(total, page * pageSize);
  return (
    <nav className="radar-pagination" aria-label={ariaLabel}>
      <span>{from}-{to} of {total}</span>
      <div>
        <button className="icon-button" aria-label="Previous page" onClick={() => onChange(page - 1)} disabled={page === 1}><ChevronLeft size={16} aria-hidden="true" /></button>
        {pages.map((item, index) => item === "ellipsis" ? <span className="pagination-ellipsis" key={`ellipsis-${index}`}>...</span> : (
          <button key={item} className={item === page ? "selected" : ""} aria-label={`Page ${item}`} aria-current={item === page ? "page" : undefined} onClick={() => onChange(item)}>{item}</button>
        ))}
        <button className="icon-button" aria-label="Next page" onClick={() => onChange(page + 1)} disabled={page === pageCount}><ChevronRight size={16} aria-hidden="true" /></button>
      </div>
    </nav>
  );
}

function ThreatRadarLead({ suspect }: { suspect: ThreatRadarSuspect }) {
  return (
    <div className="radar-lead">
      <strong className="ioc-value">{`${suspect.sourceIp} -> ${suspect.destinationIp}`}</strong>
      <div className="radar-score">
        <span>Risk score</span>
        <strong>{suspect.score}</strong>
      </div>
      <div className="ioc-card-stats">
        <div>
          <span>Events</span>
          <strong>{suspect.events}</strong>
        </div>
        <div>
          <span>Infrastructure</span>
          <strong>{suspect.infrastructureCount}</strong>
        </div>
        <div>
          <span>Ports</span>
          <strong>{suspect.destinationPorts}</strong>
        </div>
      </div>
      <div className="radar-chip-row">
        {suspect.reasons.map((reason) => <span key={reason}>{reason}</span>)}
      </div>
      <dl className="ioc-card-facts">
        <dt>Latest event</dt>
        <dd>{suspect.latest?.timestamp ?? "--"}</dd>
        <dt>Source</dt>
        <dd>{suspect.latest?.sourceIp ?? suspect.sourceIp}</dd>
        <dt>Action</dt>
        <dd>{suspect.latest?.action ?? "--"}</dd>
        <dt>Destination</dt>
        <dd>{formatDestination(suspect)}</dd>
        <dt>GTI / VT</dt>
        <dd>{formatGti(suspect.gti)}</dd>
        <dt>Datasets</dt>
        <dd>{suspect.datasets.map((item) => `${item.key} ${item.count}`).join(", ") || "--"}</dd>
      </dl>
    </div>
  );
}

function EmptyRadarState({ title = "No suspicious flows scored yet." }: { title?: string } = {}) {
  return (
    <div className="empty-card">
      <strong>{title}</strong>
      <span>Run an analysis now or wait for the next scheduled agent scan.</span>
    </div>
  );
}

function ProviderStatusGrid({ providers }: { providers: ProviderStatus[] }) {
  return (
    <div className="provider-grid">
      {providers.length === 0 ? (
        <div className="provider-card">
          <strong>Threat feeds</strong>
          <span>Press IOC Hunt to collect today&apos;s IOCs.</span>
        </div>
      ) : (
        providers.map((provider) => (
          <div className="provider-card" key={provider.name}>
            <div>
              <strong>{provider.name}</strong>
              <Badge value={provider.status} />
            </div>
            <span>{provider.collected} fetched | {provider.checked ?? 0} checked | {provider.matched ?? 0} matched</span>
            <TypeBreakdown counts={provider.byType} />
            {provider.message ? <small>{provider.message}</small> : null}
          </div>
        ))
      )}
    </div>
  );
}

function TimeRangePicker({ value, onChange }: { value: HuntTimeRange; onChange: (value: HuntTimeRange) => void }) {
  const ranges: Array<{ value: HuntTimeRange; label: string }> = [
    { value: "today", label: "Today" },
    { value: "last7d", label: "Last 7 days" },
    { value: "last30d", label: "Last 30 days" }
  ];
  return (
    <div className="segmented-control" aria-label="IOC hunt time range">
      {ranges.map((range) => (
        <button key={range.value} className={value === range.value ? "selected" : ""} onClick={() => onChange(range.value)}>
          {range.label}
        </button>
      ))}
    </div>
  );
}

function StageCard({ label, current, total }: { label: string; current: number; total: number }) {
  const state = current >= total ? "done" : current > 0 ? "working" : "queued";
  const percent = total > 0 ? Math.min(100, Math.round((current / total) * 100)) : 0;
  return (
    <div className={`stage-card ${state}`} style={{ "--progress": `${percent}%` } as React.CSSProperties}>
      <strong>{label}</strong>
      <span>{current} / {total}</span>
      <div className="stage-progress" aria-hidden="true">
        <i />
      </div>
    </div>
  );
}

function HuntResultCards({ results, hasRun }: { results: HuntResult[]; hasRun: boolean }) {
  if (results.length === 0) {
    return (
      <div className="empty-card">
        <strong>{hasRun ? "No SIEM matches for this filter." : "No IOC hunt has run yet."}</strong>
        <span>{hasRun ? "Change the filter above or run another hunt window." : "Press IOC Hunt to collect public threat intel and check Elastic."}</span>
      </div>
    );
  }

  const ranked = [...results].sort((left, right) => right.total - left.total);
  const hottest = ranked[0] as HuntResult;

  return (
    <article className="ranked-ioc-card">
      <div className="ranked-card-head">
        <div>
          <h3>Top SIEM IOC Matches</h3>
          <span>Highest match count first</span>
        </div>
        <Badge value={`${ranked.length} matches`} />
      </div>
      <div className="ranked-card-leader">
        <div>
          <span>Top IOC</span>
          <strong>{hottest.ioc.normalized}</strong>
        </div>
        <div>
          <span>Logs</span>
          <strong>{hottest.total}</strong>
        </div>
        <div>
          <span>Action / port</span>
          <strong>{formatActionPort(hottest.hits[0])}</strong>
        </div>
      </div>
      <div className="mini-table-wrap">
        <table className="mini-ioc-table">
          <thead>
            <tr>
              <th>IOC</th>
              <th>Type</th>
              <th>Logs</th>
              <th>Action / Port</th>
              <th>Latest Event</th>
              <th>Sources</th>
            </tr>
          </thead>
          <tbody>
            {ranked.map((result) => (
              <tr key={`${result.ioc.type}:${result.ioc.normalized}`}>
                <td className="mono-cell">{result.ioc.normalized}</td>
                <td>{result.ioc.type}</td>
                <td>{result.total}</td>
                <td>{formatActionPort(result.hits[0])}</td>
                <td>{result.hits[0]?.timestamp ?? "--"}</td>
                <td>{result.ioc.sources?.join(", ") ?? String(result.ioc.sourceCount ?? 1)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </article>
  );
}

function HuntFilterCards({
  stats,
  active,
  onChange
}: {
  stats: Array<{ filter: HuntFilter; label: string; count: number; logs: number; ports: string }>;
  active: HuntFilter;
  onChange: (value: HuntFilter) => void;
}) {
  return (
    <div className="hunt-filter-grid">
      {stats.map((stat) => (
        <button key={stat.filter} className={active === stat.filter ? "selected" : ""} onClick={() => onChange(stat.filter)}>
          <span>{stat.label}</span>
          <strong>{stat.count}</strong>
          <small>{stat.logs} logs | ports {stat.ports}</small>
        </button>
      ))}
    </div>
  );
}

function TypeBreakdown({ counts }: { counts: Record<string, number> | undefined }) {
  const parts = [
    ["IP", counts?.ip],
    ["Domain", counts?.domain],
    ["URL", counts?.url],
    ["Hash", (counts?.md5 ?? 0) + (counts?.sha1 ?? 0) + (counts?.sha256 ?? 0)]
  ].filter((entry): entry is [string, number] => typeof entry[1] === "number" && entry[1] > 0);

  if (parts.length === 0) return <small>No valid IOC types reported.</small>;
  return (
    <div className="type-breakdown">
      {parts.map(([label, count]) => (
        <span key={label}>{label}: {count}</span>
      ))}
    </div>
  );
}

function IntelPivots({ ioc }: { ioc: HuntedIOC | undefined }) {
  const pivots = useMemo(() => (ioc ? buildIntelPivots(ioc.normalized, ioc.type) : []), [ioc]);
  return (
    <div className="intel-pivots">
      <div className="panel-actions tight">
        <h2>Intel Pivots</h2>
        <button className="secondary" onClick={() => openIntelPivots(pivots)} disabled={pivots.length === 0}>
          <ExternalLink size={16} aria-hidden="true" />
          <span>Open All</span>
        </button>
      </div>
      <div className="pivot-grid">
        {pivots.length === 0 ? (
          <span className="muted">Enter a valid IOC to enable pivots.</span>
        ) : (
          pivots.map((pivot) => (
            <a key={pivot.name} className="pivot-link" href={pivot.url} target="_blank" rel="noreferrer">
              <ExternalLink size={15} aria-hidden="true" />
              <span>{pivot.name}</span>
            </a>
          ))
        )}
      </div>
    </div>
  );
}

function AlertsPanel() {
  const [dashboard, setDashboard] = useState<AlertDashboardResponse | null>(null);
  const [loadingAlerts, setLoadingAlerts] = useState(true);
  const [alertError, setAlertError] = useState<string | null>(null);
  const [savedMessage, setSavedMessage] = useState<string | null>(null);
  const [ruleName, setRuleName] = useState("");
  const [indicatorType, setIndicatorType] = useState<AlertRule["indicatorType"]>("ip");
  const [indicatorValue, setIndicatorValue] = useState("");
  const [minScore, setMinScore] = useState(55);
  const [browserNotifications, setBrowserNotifications] = useState(true);
  const [cooldownMinutes, setCooldownMinutes] = useState(60);
  const [discordWebhookUrl, setDiscordWebhookUrl] = useState("");
  const [telegramBotToken, setTelegramBotToken] = useState("");
  const [telegramChatId, setTelegramChatId] = useState("");
  const [historyPage, setHistoryPage] = useState(1);

  const historyPageSize = 10;
  const historyPageCount = Math.max(1, Math.ceil((dashboard?.history.length ?? 0) / historyPageSize));
  const currentHistoryPage = Math.min(historyPage, historyPageCount);
  const visibleHistory = dashboard?.history.slice((currentHistoryPage - 1) * historyPageSize, currentHistoryPage * historyPageSize) ?? [];

  useEffect(() => {
    void loadAlerts(true);
    const interval = window.setInterval(() => void loadAlerts(false), 15000);
    return () => window.clearInterval(interval);
  }, []);

  useEffect(() => {
    setHistoryPage((page) => Math.min(page, historyPageCount));
  }, [historyPageCount]);

  async function loadAlerts(showLoading: boolean) {
    if (showLoading) setLoadingAlerts(true);
    const response = await sendBridgeMessage<unknown, AlertDashboardResponse>("alerts.get", {});
    if (response.success) {
      setDashboard(response.data);
      setBrowserNotifications(response.data.config.browserNotifications);
      setCooldownMinutes(response.data.config.cooldownMinutes);
      setAlertError(null);
    } else {
      setAlertError(response.error.message);
    }
    if (showLoading) setLoadingAlerts(false);
  }

  async function addRule(event: React.FormEvent) {
    event.preventDefault();
    setLoadingAlerts(true);
    setAlertError(null);
    setSavedMessage(null);
    const response = await sendBridgeMessage<unknown, AlertDashboardResponse>("alerts.rule.add", {
      name: ruleName,
      indicatorType,
      indicatorValue,
      minScore
    });
    if (response.success) {
      setDashboard(response.data);
      setRuleName("");
      setIndicatorValue("");
      setSavedMessage("Alert rule saved. Threat Radar will evaluate it on every scan.");
    } else {
      setAlertError(response.error.message);
    }
    setLoadingAlerts(false);
  }

  async function removeRule(id: string) {
    setLoadingAlerts(true);
    setAlertError(null);
    const response = await sendBridgeMessage<unknown, AlertDashboardResponse>("alerts.rule.remove", { id });
    if (response.success) setDashboard(response.data);
    else setAlertError(response.error.message);
    setLoadingAlerts(false);
  }

  async function saveDelivery(options: { clearDiscord?: boolean; clearTelegram?: boolean } = {}) {
    setLoadingAlerts(true);
    setAlertError(null);
    setSavedMessage(null);
    const response = await sendBridgeMessage<unknown, AlertDashboardResponse>("alerts.configure", {
      browserNotifications,
      cooldownMinutes,
      discordWebhookUrl,
      telegramBotToken,
      telegramChatId,
      ...options
    });
    if (response.success) {
      setDashboard(response.data);
      setDiscordWebhookUrl("");
      setTelegramBotToken("");
      setTelegramChatId("");
      setSavedMessage("Alert delivery settings saved.");
    } else {
      setAlertError(response.error.message);
    }
    setLoadingAlerts(false);
  }

  async function clearHistory() {
    setLoadingAlerts(true);
    setAlertError(null);
    const response = await sendBridgeMessage<unknown, AlertDashboardResponse>("alerts.history.clear", {});
    if (response.success) {
      setDashboard(response.data);
      setHistoryPage(1);
      setSavedMessage("Alert history cleared. Saved rules are still active.");
    } else {
      setAlertError(response.error.message);
    }
    setLoadingAlerts(false);
  }

  const channelCount = dashboard
    ? Number(dashboard.config.browserNotifications) + Number(dashboard.config.discordConfigured) + Number(dashboard.config.telegramConfigured)
    : 0;
  const criticalCount = dashboard?.history.filter((item) => item.severity === "critical").length ?? 0;

  return (
    <section className="grid alerts-view">
      <div className="status-strip wide" aria-label="Alert system summary">
        <StatusTile label="Active Rules" value={String(dashboard?.rules.filter((rule) => rule.enabled).length ?? 0)} tone={dashboard?.rules.length ? "healthy" : "unknown"} />
        <StatusTile label="Alert Events" value={String(dashboard?.history.length ?? 0)} tone={dashboard?.history.length ? "critical" : "unknown"} />
        <StatusTile label="Critical" value={String(criticalCount)} tone={criticalCount ? "critical" : "unknown"} />
        <StatusTile label="Delivery Channels" value={String(channelCount)} tone={channelCount ? "healthy" : "unknown"} />
      </div>

      {alertError ? <div className="notice wide" role="alert"><AlertTriangle size={18} aria-hidden="true" /><div><strong>Alert operation failed</strong><span>{alertError}</span></div></div> : null}
      {savedMessage ? <div className="alert-success wide" role="status">{savedMessage}</div> : null}

      <div className="panel alert-rules-panel">
        <div className="panel-title-row">
          <div>
            <h2>IOC Alert Rules</h2>
            <p className="muted">Notify when a promoted Threat Radar finding contains this exact IP, domain, or hash.</p>
          </div>
          <button className="icon-button" type="button" aria-label="Refresh alert rules" onClick={() => void loadAlerts(true)} disabled={loadingAlerts}>
            <RefreshCw size={18} aria-hidden="true" className={loadingAlerts ? "spin" : ""} />
          </button>
        </div>
        <form className="alert-rule-form" onSubmit={addRule}>
          <label className="field">
            <span>Rule name</span>
            <input value={ruleName} onChange={(event) => setRuleName(event.target.value)} placeholder="SSH scanner watch" maxLength={120} />
          </label>
          <label className="field">
            <span>Indicator type</span>
            <select value={indicatorType} onChange={(event) => setIndicatorType(event.target.value as AlertRule["indicatorType"])}>
              <option value="ip">IP address</option>
              <option value="domain">Domain</option>
              <option value="hash">File hash</option>
            </select>
          </label>
          <label className="field alert-indicator-field">
            <span>Indicator</span>
            <input value={indicatorValue} onChange={(event) => setIndicatorValue(event.target.value)} placeholder={indicatorType === "ip" ? "203.0.113.10" : indicatorType === "domain" ? "example.com" : "MD5, SHA-1, or SHA-256"} required />
          </label>
          <label className="field">
            <span>Minimum score</span>
            <input type="number" min="0" max="200" value={minScore} onChange={(event) => setMinScore(Number(event.target.value))} />
          </label>
          <button className="primary alert-add-rule" type="submit" disabled={loadingAlerts || !indicatorValue.trim()}>
            <Bell size={17} aria-hidden="true" />
            <span>Add Alert Rule</span>
          </button>
        </form>

        {dashboard?.rules.length ? (
          <div className="mini-table-wrap alert-table-wrap">
            <table className="mini-ioc-table alert-rules-table">
              <thead><tr><th>Rule</th><th>Indicator</th><th>Minimum score</th><th>Created</th><th>Action</th></tr></thead>
              <tbody>{dashboard.rules.map((rule) => (
                <tr key={rule.id}>
                  <td><strong>{rule.name}</strong></td>
                  <td><Badge value={rule.indicatorType.toUpperCase()} /> <span className="mono-cell">{rule.indicatorValue}</span></td>
                  <td>{rule.minScore}</td>
                  <td>{new Date(rule.createdAt).toLocaleString()}</td>
                  <td><button className="icon-button danger-button" type="button" aria-label={`Remove alert rule ${rule.name}`} onClick={() => void removeRule(rule.id)} disabled={loadingAlerts}><Trash2 size={17} aria-hidden="true" /></button></td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        ) : <div className="empty-card"><strong>No IOC alert rules yet.</strong><span>Automatic high-confidence detections still create alert events.</span></div>}
      </div>

      <div className="panel alert-delivery-panel">
        <div>
          <h2>Delivery</h2>
          <p className="muted">Secrets stay in extension-local storage and are never returned to the webpage.</p>
        </div>
        <label className="agent-toggle">
          <input type="checkbox" checked={browserNotifications} onChange={(event) => setBrowserNotifications(event.target.checked)} />
          <span>Chrome desktop notifications</span>
        </label>
        <label className="field">
          <span>Alert cooldown</span>
          <select value={cooldownMinutes} onChange={(event) => setCooldownMinutes(Number(event.target.value))}>
            <option value="5">5 minutes</option>
            <option value="15">15 minutes</option>
            <option value="60">1 hour</option>
            <option value="360">6 hours</option>
            <option value="1440">24 hours</option>
          </select>
        </label>
        <label className="field">
          <span>Discord webhook</span>
          <input type="password" autoComplete="off" value={discordWebhookUrl} onChange={(event) => setDiscordWebhookUrl(event.target.value)} placeholder={dashboard?.config.discordConfigured ? "Configured; leave blank to keep" : "https://discord.com/api/webhooks/..."} />
        </label>
        <label className="field">
          <span>Telegram bot token</span>
          <input type="password" autoComplete="off" value={telegramBotToken} onChange={(event) => setTelegramBotToken(event.target.value)} placeholder={dashboard?.config.telegramConfigured ? "Configured; leave blank to keep" : "Bot token"} />
        </label>
        <label className="field">
          <span>Telegram chat ID</span>
          <input value={telegramChatId} onChange={(event) => setTelegramChatId(event.target.value)} placeholder={dashboard?.config.telegramConfigured ? "Configured; leave blank to keep" : "Chat or channel ID"} />
        </label>
        <div className="alert-channel-status" aria-label="Configured alert channels">
          <Badge value={dashboard?.config.discordConfigured ? "Discord ready" : "Discord off"} />
          <Badge value={dashboard?.config.telegramConfigured ? "Telegram ready" : "Telegram off"} />
        </div>
        <div className="alert-delivery-actions">
          <button className="primary" type="button" onClick={() => void saveDelivery()} disabled={loadingAlerts}><ShieldCheck size={17} aria-hidden="true" /><span>Save Delivery</span></button>
          {dashboard?.config.discordConfigured ? <button className="secondary" type="button" onClick={() => void saveDelivery({ clearDiscord: true })} disabled={loadingAlerts}>Remove Discord</button> : null}
          {dashboard?.config.telegramConfigured ? <button className="secondary" type="button" onClick={() => void saveDelivery({ clearTelegram: true })} disabled={loadingAlerts}>Remove Telegram</button> : null}
        </div>
      </div>

      <div className="panel wide alert-history-panel">
        <div className="panel-title-row">
          <div><h2>Alert History</h2><p className="muted">Corroborated detections and watched IOC matches retained by the extension.</p></div>
          <button className="secondary danger-action" type="button" onClick={() => void clearHistory()} disabled={loadingAlerts || !dashboard?.history.length}><Trash2 size={17} aria-hidden="true" /><span>Clear History</span></button>
        </div>
        {visibleHistory.length ? (
          <>
            <div className="mini-table-wrap alert-table-wrap">
              <table className="mini-ioc-table alert-history-table">
                <thead><tr><th>Severity</th><th>Alert</th><th>Indicator / route</th><th>Score</th><th>Events</th><th>Evidence</th><th>Occurrences</th><th>Last seen</th><th>Delivery</th></tr></thead>
                <tbody>{visibleHistory.map((item) => (
                  <tr key={item.id}>
                    <td><Badge value={item.severity} /></td>
                    <td><strong>{item.title}</strong>{item.ruleNames.length ? <small>{item.ruleNames.join(", ")}</small> : null}</td>
                    <td className="mono-cell"><strong>{item.indicator}</strong><small>{item.sourceIp || item.destinationIp ? `${item.sourceIp ?? "--"} -> ${item.destinationIp ?? "--"}` : item.indicatorType}</small></td>
                    <td><Badge value={String(item.score)} /></td>
                    <td>{item.events.toLocaleString()}</td>
                    <td>{item.reasons.slice(0, 3).join(" | ") || "--"}</td>
                    <td>{item.occurrences}</td>
                    <td>{new Date(item.lastSeenAt).toLocaleString()}</td>
                    <td><AlertDeliveryCell delivery={item.delivery} /></td>
                  </tr>
                ))}</tbody>
              </table>
            </div>
            <RadarPagination page={currentHistoryPage} pageCount={historyPageCount} total={dashboard?.history.length ?? 0} pageSize={historyPageSize} onChange={setHistoryPage} ariaLabel="Alert history pages" />
          </>
        ) : <div className="empty-card"><strong>No alert events yet.</strong><span>Scheduled and manual Threat Radar scans will populate this history when evidence or an IOC rule matches.</span></div>}
      </div>
    </section>
  );
}

function AlertDeliveryCell({ delivery }: { delivery: AlertDelivery }) {
  const sent = (["browser", "discord", "telegram"] as const).filter((channel) => delivery[channel] === "sent");
  const failed = (["browser", "discord", "telegram"] as const).filter((channel) => delivery[channel] === "failed");
  return (
    <div className="alert-delivery-cell">
      <span>{sent.length ? `Sent: ${sent.join(", ")}` : "In-app only"}</span>
      {failed.length ? <small title={delivery.errors.join(" | ")}>Failed: {failed.join(", ")}</small> : null}
    </div>
  );
}

function Placeholder({ panel }: { panel: Panel }) {
  return (
    <section className="panel wide">
      <h2>{panel}</h2>
      <p className="muted">This area is reserved for the next SOC Watch phase. The bridge protocol already keeps unsupported actions closed.</p>
    </section>
  );
}

function Badge({ value }: { value: string }) {
  const normalized = value.toLowerCase();
  const tone = ["online", "clear", "match", "clean"].includes(normalized)
    ? "healthy"
    : ["offline", "error", "critical", "high", "malicious", "key rejected", "unavailable"].includes(normalized)
      ? "critical"
      : ["suspicious", "pending", "quota reached"].includes(normalized) ? "warning" : "unknown";
  return <span className={`badge ${tone}`}>{value}</span>;
}

function ReputationCell({
  gti,
  target,
  status,
  message,
  cached
}: {
  gti: ThreatRadarSuspect["gti"];
  target: string;
  status: GtiLookupStatus | undefined;
  message: string | undefined;
  cached: boolean | undefined;
}) {
  const category = getGtiDisplayCategory(gti, status);
  const engineRatio = gti?.totalEngines ? ` | VT ${gti.malicious}/${gti.totalEngines}` : "";
  return (
    <div className="reputation-cell" title={message}>
      <Badge value={category} />
      <span className="reputation-score">{gti
        ? `GTI ${gti.threatScore}${engineRatio}${cached ? " | cached" : ""}`
        : getGtiStatusText(status)}</span>
      <span className="reputation-target" title={target}>{target !== "--" ? target : "No public IOC"}</span>
    </div>
  );
}

function getGtiDisplayCategory(gti: ThreatRadarSuspect["gti"], status?: GtiLookupStatus): string {
  if (gti) return getGtiCategory(gti);
  if (status === "pending") return "Pending";
  if (status === "rate_limited") return "Quota reached";
  if (status === "unauthorized") return "Key rejected";
  if (status === "unavailable") return "Unavailable";
  if (status === "not_found") return "Not found";
  if (status === "not_configured") return "No key";
  return "Unknown";
}

function getGtiStatusText(status?: GtiLookupStatus): string {
  if (status === "pending") return "Waiting for automatic lookup";
  if (status === "rate_limited") return "GTI quota reached; retry scheduled";
  if (status === "unauthorized") return "Configured API key was rejected";
  if (status === "unavailable") return "GTI/VT service could not be reached";
  if (status === "not_found") return "No GTI/VT report exists";
  if (status === "not_configured") return "Configure a GTI/VT API key";
  return "Not scored";
}

function formatReputationCoverage(coverage: NonNullable<NonNullable<ThreatRadarResponse["analysis"]>["reputation"]>): string {
  const details = [`${coverage.scored.toLocaleString()} of ${coverage.requested.toLocaleString()} candidates scored`];
  if (coverage.cached > 0) details.push(`${coverage.cached.toLocaleString()} served from cache`);
  if (coverage.pending > 0) details.push(`${coverage.pending.toLocaleString()} queued`);
  if (coverage.rateLimited > 0) details.push(`${coverage.rateLimited.toLocaleString()} rate limited`);
  if (coverage.failed > 0) details.push(`${coverage.failed.toLocaleString()} unavailable`);
  return `${details.join(" | ")}. Pending reputation checks retry automatically on later agent scans.`;
}

function buildIntelPivots(value: string, type: string) {
  const encoded = encodeURIComponent(value);
  const pivots = [
    { name: "VirusTotal", url: `https://www.virustotal.com/gui/search/${encoded}` },
    { name: "AlienVault OTX", url: `https://otx.alienvault.com/browse/global/pulses?q=${encoded}` },
    { name: "ThreatFox", url: `https://threatfox.abuse.ch/browse.php?search=ioc%3A${encoded}` },
    { name: "Hunt.io", url: `https://hunt.io/search?query=${encoded}` },
    { name: "Censys", url: `https://search.censys.io/search?resource=hosts&q=${encoded}` },
    { name: "Shodan", url: `https://www.shodan.io/search?query=${encoded}` }
  ];
  if (type === "ip") {
    pivots.push(
      { name: "AbuseIPDB", url: `https://www.abuseipdb.com/check/${encoded}` },
      { name: "GreyNoise", url: `https://viz.greynoise.io/ip/${encoded}` }
    );
  }
  if (type === "url" || type === "domain") {
    pivots.push({ name: "URLhaus", url: `https://urlhaus.abuse.ch/browse.php?search=${encoded}` });
  }
  if (type === "md5" || type === "sha1" || type === "sha256") {
    pivots.push({ name: "MalwareBazaar", url: `https://bazaar.abuse.ch/browse.php?search=${encoded}` });
  }
  return pivots;
}

function formatActionPort(hit: SearchHitSummary | undefined): string {
  if (!hit) return "--";
  const parts = [hit.eventAction, hit.destinationPort ? `:${hit.destinationPort}` : undefined].filter(Boolean);
  return parts.length ? parts.join(" ") : hit.host ?? "--";
}

function openIntelPivots(pivots: Array<{ name: string; url: string }>): void {
  for (const pivot of pivots.slice(0, 10)) {
    window.open(pivot.url, "_blank", "noopener,noreferrer");
  }
}

function huntTimeRangeToParams(range: HuntTimeRange): { from: string } {
  if (range === "today") return { from: "now/d" };
  if (range === "last7d") return { from: "now-7d" };
  return { from: "now-30d" };
}

function loadIocHuntOffset(range: HuntTimeRange): number {
  try {
    const stored = JSON.parse(localStorage.getItem(IOC_HUNT_CURSOR_KEY) ?? "{}") as Record<string, unknown>;
    return typeof stored[range] === "number" && Number.isInteger(stored[range]) && stored[range] >= 0 ? stored[range] : 0;
  } catch {
    return 0;
  }
}

function saveIocHuntOffset(range: HuntTimeRange, offset: number): void {
  try {
    const stored = JSON.parse(localStorage.getItem(IOC_HUNT_CURSOR_KEY) ?? "{}") as Record<string, unknown>;
    localStorage.setItem(IOC_HUNT_CURSOR_KEY, JSON.stringify({ ...stored, [range]: Math.max(0, Math.floor(offset)) }));
  } catch {
    // A missing cursor only causes the next hunt to start from batch one.
  }
}

function threatRadarTimeRangeToParams(range: RadarTimeRange): { from: string } {
  if (range === "last15m") return { from: "now-15m" };
  if (range === "last1h") return { from: "now-1h" };
  return { from: "now/d" };
}

function formatRadarRangeLabel(range: RadarTimeRange): string {
  if (range === "last15m") return "Last 15 minutes";
  if (range === "last1h") return "Last 1 hour";
  return "Today";
}

function loadPinnedThreatRadarAnalysis(): PinnedThreatRadarAnalysis | null {
  try {
    const parsed = JSON.parse(localStorage.getItem(THREAT_RADAR_PINNED_ANALYSIS_KEY) ?? "null") as Partial<PinnedThreatRadarAnalysis> | null;
    if (!parsed || !["last15m", "last1h", "today"].includes(parsed.range ?? "")) return null;
    if (!parsed.report || typeof parsed.report.analyzedAt !== "string" || !Array.isArray(parsed.report.suspects)) return null;
    if (!hasThreatRadarCoreCoverage(parsed.report as ThreatRadarResponse)) {
      localStorage.removeItem(THREAT_RADAR_PINNED_ANALYSIS_KEY);
      return null;
    }
    return parsed as PinnedThreatRadarAnalysis;
  } catch {
    return null;
  }
}

function hasThreatRadarCoreCoverage(report: ThreatRadarResponse): boolean {
  if (report.analysis?.strategy !== "staged") return true;
  return report.analysis.completedStages.some((stage) => stage === "source IP activity" || stage === "destination IP activity");
}

function savePinnedThreatRadarAnalysis(analysis: PinnedThreatRadarAnalysis): void {
  try {
    localStorage.setItem(THREAT_RADAR_PINNED_ANALYSIS_KEY, JSON.stringify(analysis));
  } catch {
    // The in-memory snapshot remains pinned when browser storage is unavailable.
  }
}

function clearPinnedThreatRadarAnalysis(): void {
  try {
    localStorage.removeItem(THREAT_RADAR_PINNED_ANALYSIS_KEY);
  } catch {
    // The current session still switches back to automatic results.
  }
}

function formatThreatRadarError(message: string, range: RadarTimeRange): string {
  if (/HTTP 502|Bad Gateway/i.test(message)) {
    return range === "today"
      ? "Kibana could not complete any stage of the Today analysis. Your previous pinned findings remain visible; try Last 1 hour while Kibana recovers."
      : "Kibana returned HTTP 502 while analyzing this window. Try Analyze Logs again after the Kibana session responds.";
  }
  return message;
}

function loadThreatRadarLayout(): RadarLayoutItem[] {
  const fallback: RadarLayoutItem[] = [
    { id: "sources" },
    { id: "destinations" },
    { id: "outbound" },
    { id: "denied" },
    { id: "ports" },
    { id: "indicators" },
    { id: "review" }
  ];
  try {
    const value = localStorage.getItem(THREAT_RADAR_LAYOUT_KEY);
    if (!value) return fallback;
    const parsed = JSON.parse(value);
    if (!Array.isArray(parsed)) return fallback;
    const ids = new Set<RadarCardId>();
    const items = parsed
      .map((item) => {
        const record = typeof item === "object" && item !== null ? (item as Partial<RadarLayoutItem>) : {};
        const legacyId = (record as { id?: string }).id;
        const id = legacyId === "lead" ? "ports" : legacyId;
        if (id !== "sources" && id !== "destinations" && id !== "outbound" && id !== "denied" && id !== "ports" && id !== "indicators" && id !== "review") return null;
        ids.add(id);
        return {
          id,
          width: typeof record.width === "number" ? record.width : undefined,
          height: typeof record.height === "number" ? record.height : undefined,
          x: typeof record.x === "number" ? record.x : undefined,
          y: typeof record.y === "number" ? record.y : undefined
        };
      })
      .filter(Boolean) as RadarLayoutItem[];
    for (const item of fallback) {
      if (ids.has(item.id)) continue;
      const usesCanvas = items.length > 0 && items.every((entry) => typeof entry.x === "number" && typeof entry.y === "number");
      if (!usesCanvas) {
        items.push(item);
        continue;
      }
      const nextY = Math.max(...items.map((entry) => (
        (entry.y ?? 0) + (entry.height ?? defaultRadarCardSize(entry.id).height) + 18
      )));
      items.push({ ...item, x: 0, y: nextY });
    }
    return items;
  } catch {
    return fallback;
  }
}

function defaultRadarCardSize(id: RadarCardId): { width: number; height: number } {
  if (id === "ports" || id === "indicators" || id === "review") return { width: 760, height: 440 };
  return { width: 820, height: 420 };
}

function resolveRadarCollisions(items: RadarLayoutItem[], preferredId?: RadarCardId): RadarLayoutItem[] {
  const gap = 18;
  const next = items.map((item) => ({
    ...item,
    x: Math.max(0, Math.round(item.x ?? 0)),
    y: Math.max(0, Math.round(item.y ?? 0))
  }));
  const queue = preferredId ? [preferredId] : next.map((item) => item.id);
  let safety = 0;

  while (queue.length && safety < 30) {
    const currentId = queue.shift();
    const current = next.find((item) => item.id === currentId);
    if (!current) continue;
    const currentWidth = current.width ?? defaultRadarCardSize(current.id).width;
    const currentHeight = current.height ?? defaultRadarCardSize(current.id).height;
    for (const other of next) {
      if (other.id === current.id) continue;
      const otherWidth = other.width ?? defaultRadarCardSize(other.id).width;
      const otherHeight = other.height ?? defaultRadarCardSize(other.id).height;
      const overlaps = current.x! < other.x! + otherWidth && current.x! + currentWidth > other.x! && current.y! < other.y! + otherHeight && current.y! + currentHeight > other.y!;
      if (!overlaps) continue;
      other.y = current.y! + currentHeight + gap;
      queue.push(other.id);
    }
    safety += 1;
  }

  return next;
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

function compactPageNumbers(current: number, total: number): Array<number | "ellipsis"> {
  if (total <= 7) return Array.from({ length: total }, (_, index) => index + 1);
  const pages: Array<number | "ellipsis"> = [1];
  if (current > 4) pages.push("ellipsis");
  for (let page = Math.max(2, current - 1); page <= Math.min(total - 1, current + 1); page += 1) pages.push(page);
  if (current < total - 3) pages.push("ellipsis");
  pages.push(total);
  return pages;
}

function isLayoutControlTarget(target: EventTarget | null): boolean {
  if (!(target instanceof Element)) return false;
  return Boolean(target.closest("button, select, input, textarea, a, .resize-handle"));
}

function sortRadarSuspects(suspects: ThreatRadarSuspect[], sort: RadarSort): ThreatRadarSuspect[] {
  const sorted = [...suspects];
  sorted.sort((left, right) => {
    let comparison = 0;
    if (sort.field === "sourceIp") comparison = left.sourceIp.localeCompare(right.sourceIp, undefined, { numeric: true });
    if (sort.field === "destinationIp") comparison = left.destinationIp.localeCompare(right.destinationIp, undefined, { numeric: true });
    if (sort.field === "score") comparison = left.score - right.score;
    if (sort.field === "gti") {
      comparison = getGtiCategoryWeight(left.gti) - getGtiCategoryWeight(right.gti)
        || (left.gti?.threatScore ?? -1) - (right.gti?.threatScore ?? -1)
        || left.score - right.score;
    }
    if (sort.field === "events") comparison = left.events - right.events;
    if (sort.field === "denied") comparison = (left.deniedEvents ?? 0) - (right.deniedEvents ?? 0);
    if (sort.field === "outbound") comparison = (left.outboundEvents ?? 0) - (right.outboundEvents ?? 0);
    if (sort.field === "infrastructure") comparison = left.infrastructureCount - right.infrastructureCount;
    if (sort.field === "ports") comparison = left.destinationPorts - right.destinationPorts;
    if (sort.field === "history") comparison = (left.eventDelta ?? 0) - (right.eventDelta ?? 0) || (left.observations ?? 1) - (right.observations ?? 1);
    if (sort.field === "reasons") comparison = left.reasons.join(" ").localeCompare(right.reasons.join(" "));
    if (comparison === 0) comparison = left.sourceIp.localeCompare(right.sourceIp, undefined, { numeric: true });
    return sort.direction === "asc" ? comparison : -comparison;
  });
  return sorted;
}

function formatRadarSignal(value: string): string {
  return value.split("_").map((part) => part ? `${part.charAt(0).toUpperCase()}${part.slice(1)}` : part).join(" ");
}

function formatRelativeTime(value: string): string {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) return "Previously seen";
  const elapsedMinutes = Math.max(0, Math.round((Date.now() - timestamp) / 60000));
  if (elapsedMinutes < 1) return "Seen now";
  if (elapsedMinutes < 60) return `${elapsedMinutes}m ago`;
  const elapsedHours = Math.round(elapsedMinutes / 60);
  return elapsedHours < 24 ? `${elapsedHours}h ago` : `${Math.round(elapsedHours / 24)}d ago`;
}

function formatDestination(suspect: ThreatRadarSuspect): string {
  const destinationIp = suspect.latest?.destinationIp ?? suspect.destinationIp;
  const port = suspect.latest?.destinationPort;
  return `${destinationIp}${port ? `:${port}` : ""}`;
}

function formatGti(gti: ThreatRadarSuspect["gti"], target = ""): string {
  if (!gti) return `Unknown | not scored${target && target !== "--" ? ` | ${target}` : ""}`;
  const verdict = gti.verdict?.replace("VERDICT_", "").toLowerCase() ?? "unknown";
  const vendorTotal = gti.totalEngines ?? gti.malicious + gti.suspicious;
  return `${getGtiCategory(gti)} | GTI ${gti.threatScore} | ${verdict} | VT ${gti.malicious}/${vendorTotal}${target && target !== "--" ? ` | ${target}` : ""}`;
}

function getGtiCategory(gti: ThreatRadarSuspect["gti"]): "Malicious" | "Suspicious" | "Clean" | "Unknown" {
  if (!gti) return "Unknown";
  if (/malicious/i.test(gti.verdict ?? "") || gti.malicious >= 3 || /critical|high/i.test(gti.severity ?? "") || gti.threatScore >= 70) return "Malicious";
  if (/suspicious/i.test(gti.verdict ?? "")
    || gti.malicious > 0
    || gti.suspicious > 0
    || /medium/i.test(gti.severity ?? "")
    || gti.threatScore >= 20
    || gti.reputation < 0) return "Suspicious";
  return "Clean";
}

function getGtiCategoryWeight(gti: ThreatRadarSuspect["gti"]): number {
  const category = getGtiCategory(gti);
  if (category === "Malicious") return 3;
  if (category === "Suspicious") return 2;
  if (category === "Unknown") return 1;
  return 0;
}

function useAnimatedHuntStages(status: HuntStatus, total: number): { vendors: number; normalized: number; checked: number } {
  const [tick, setTick] = useState(0);

  useEffect(() => {
    if (status !== "running") {
      setTick(0);
      return;
    }

    const id = window.setInterval(() => {
      setTick((value) => value + 1);
    }, 360);

    return () => window.clearInterval(id);
  }, [status]);

  const ceiling = Math.max(0, total);
  const pendingCeiling = ceiling > 1 ? ceiling - 1 : ceiling;
  return {
    vendors: Math.min(ceiling, tick * 10),
    normalized: Math.min(ceiling, Math.max(0, tick - 5) * 9),
    checked: Math.min(pendingCeiling, Math.max(0, tick - 11) * 7)
  };
}

function matchesHuntFilter(type: string, filter: HuntFilter): boolean {
  if (filter === "all") return true;
  if (filter === "hash") return type === "md5" || type === "sha1" || type === "sha256";
  return type === filter;
}

function buildHuntTypeStats(results: HuntResult[]): Array<{ filter: HuntFilter; label: string; count: number; logs: number; ports: string }> {
  const matched = results.filter((result) => result.total > 0);
  const stats: Array<{ filter: HuntFilter; label: string; count: number; logs: number; ports: string }> = [
    { filter: "all", label: "All Matches", count: matched.length, logs: sumLogs(matched), ports: summarizePorts(matched) },
    { filter: "ip", label: "IPs", count: countMatches(matched, "ip"), logs: sumLogs(matched.filter((result) => result.ioc.type === "ip")), ports: summarizePorts(matched.filter((result) => result.ioc.type === "ip")) },
    { filter: "domain", label: "Domains", count: countMatches(matched, "domain"), logs: sumLogs(matched.filter((result) => result.ioc.type === "domain")), ports: summarizePorts(matched.filter((result) => result.ioc.type === "domain")) },
    { filter: "url", label: "URLs", count: countMatches(matched, "url"), logs: sumLogs(matched.filter((result) => result.ioc.type === "url")), ports: summarizePorts(matched.filter((result) => result.ioc.type === "url")) },
    { filter: "hash", label: "Hashes", count: matched.filter((result) => matchesHuntFilter(result.ioc.type, "hash")).length, logs: sumLogs(matched.filter((result) => matchesHuntFilter(result.ioc.type, "hash"))), ports: summarizePorts(matched.filter((result) => matchesHuntFilter(result.ioc.type, "hash"))) }
  ];
  return stats;
}

function countMatches(results: HuntResult[], type: string): number {
  return results.filter((result) => result.ioc.type === type).length;
}

function sumLogs(results: HuntResult[]): number {
  return results.reduce((sum, result) => sum + result.total, 0);
}

function summarizePorts(results: HuntResult[]): string {
  const ports = new Set<number>();
  for (const result of results) {
    for (const hit of result.hits) {
      if (hit.destinationPort) ports.add(hit.destinationPort);
    }
  }
  const values = [...ports].sort((left, right) => left - right).slice(0, 4);
  return values.length ? values.join(", ") : "--";
}

function buildInfrastructureRows(agents: SanitizedFleetAgent[]) {
  return agents
    .map((agent) => ({
      id: agent.id,
      name: agent.hostname ?? agent.id,
      health: agent.status === "online" ? "healthy" : agent.status === "offline" || agent.status === "error" ? "critical" : "unknown",
      agentStatus: agent.status,
      version: agent.agentVersion,
      lastSeen: agent.lastCheckin
    }))
    .sort((left, right) => {
      const severity = { critical: 0, unknown: 1, healthy: 2 };
      return severity[left.health as keyof typeof severity] - severity[right.health as keyof typeof severity] || left.name.localeCompare(right.name);
    });
}

function summarizeIocResult(result: unknown) {
  if (typeof result !== "object" || result === null) return null;
  const record = result as Record<string, unknown>;
  const ioc = typeof record.ioc === "object" && record.ioc !== null ? (record.ioc as Record<string, unknown>) : {};
  const raw = typeof record.raw === "object" && record.raw !== null ? (record.raw as Record<string, unknown>) : {};
  const hitsObject = typeof raw.hits === "object" && raw.hits !== null ? (raw.hits as Record<string, unknown>) : {};
  const totalObject = typeof hitsObject.total === "object" && hitsObject.total !== null ? (hitsObject.total as Record<string, unknown>) : {};
  const rawHits = Array.isArray(hitsObject.hits) ? hitsObject.hits : [];

  return {
    type: typeof ioc.type === "string" ? ioc.type : "unknown",
    normalized: typeof ioc.normalized === "string" ? ioc.normalized : "--",
    total: typeof totalObject.value === "number" ? totalObject.value : typeof hitsObject.total === "number" ? hitsObject.total : rawHits.length,
    hits: rawHits.slice(0, 25).map((hit) => {
      const hitRecord = typeof hit === "object" && hit !== null ? (hit as Record<string, unknown>) : {};
      const source = typeof hitRecord._source === "object" && hitRecord._source !== null ? (hitRecord._source as Record<string, unknown>) : {};
      const host = typeof source.host === "object" && source.host !== null ? (source.host as Record<string, unknown>) : {};
      return {
        index: typeof hitRecord._index === "string" ? hitRecord._index : "--",
        timestamp: typeof source["@timestamp"] === "string" ? source["@timestamp"] : undefined,
        host: typeof host.name === "string" ? host.name : undefined,
        message: typeof source.message === "string" ? source.message.slice(0, 220) : undefined
      };
    })
  };
}

function StatusTile({ label, value, tone }: { label: string; value: string; tone: "healthy" | "critical" | "unknown" }) {
  return (
    <div className={`status ${tone}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
