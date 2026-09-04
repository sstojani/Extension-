import React, { useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  AlertTriangle,
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
  Radar,
  RefreshCw,
  Search,
  Server,
  Settings,
  ShieldCheck
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
type RadarSort = "score-desc" | "score-asc" | "events-desc" | "events-asc" | "ip-asc" | "ip-desc";
type RadarCardId = "sources" | "destinations" | "ports";
type SettingsView = "agent" | "integrations" | "dataViews" | "connection";
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
};
type ThreatRadarSuspect = {
  ip: string;
  sourceIp: string;
  destinationIp: string;
  gtiIp: string;
  role: "source" | "destination";
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
  gti?: {
    verdict?: string;
    severity?: string;
    threatScore: number;
    malicious: number;
    suspicious: number;
    reputation: number;
    country?: string;
    asn: number;
    asOwner?: string;
  };
};
type ThreatRadarResponse = {
  from: string;
  to: string;
  analyzedAt: string;
  suspects: ThreatRadarSuspect[];
  externalSources: ThreatRadarSuspect[];
  suspiciousDestinations: ThreatRadarSuspect[];
  gtiEnabled: boolean;
  summary: {
    suspects: number;
    critical: number;
    high: number;
    medium: number;
  };
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
  threatFoxAuthKeySaved?: boolean;
  malwareBazaarAuthKeySaved?: boolean;
  googleThreatIntelApiKeySaved?: boolean;
  threatRadarAgent?: ThreatRadarAgentConfig;
  threatRadarAgentState?: ThreatRadarAgentState;
};

const DAILY_HUNT_LIMIT = 250;
const THREAT_RADAR_LAYOUT_KEY = "socWatchThreatRadarLayout";

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
  const [huntProviders, setHuntProviders] = useState<ProviderStatus[]>([]);
  const [huntResults, setHuntResults] = useState<HuntResult[]>([]);
  const [radarTimeRange, setRadarTimeRange] = useState<RadarTimeRange>("last15m");
  const [radarLoading, setRadarLoading] = useState(false);
  const [radarResult, setRadarResult] = useState<ThreatRadarResponse | null>(null);
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
    void loadBridgeConfig();
    return () => {
      if (retryTimerRef.current !== undefined) window.clearTimeout(retryTimerRef.current);
      streamRef.current?.disconnect();
    };
  }, []);

  useEffect(() => {
    if (active !== "Threat Radar") return;
    void loadBridgeConfig();
    const refresh = window.setInterval(() => void loadBridgeConfig(), 15000);
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

  async function loadBridgeConfig() {
    const response = await sendBridgeMessage<unknown, BridgeConfigResponse>("config.get", {});
    if (response.success) {
      setThreatFoxAuthKeySaved(Boolean(response.data.threatFoxAuthKeySaved));
      setMalwareBazaarAuthKeySaved(Boolean(response.data.malwareBazaarAuthKeySaved));
      setGoogleThreatIntelApiKeySaved(Boolean(response.data.googleThreatIntelApiKeySaved));
      if (response.data.threatRadarAgent) setThreatRadarAgent(response.data.threatRadarAgent);
      if (response.data.threatRadarAgentState) {
        setThreatRadarAgentState(response.data.threatRadarAgentState);
        if (response.data.threatRadarAgentState.report) setRadarResult(response.data.threatRadarAgentState.report);
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

  async function saveThreatRadarAgent(runNow = false) {
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
    if (runNow && response.data.config.enabled) {
      const run = await sendBridgeMessage<unknown, { config: ThreatRadarAgentConfig; state: ThreatRadarAgentState }>("threatRadar.agent.run", {});
      if (run.success) {
        setThreatRadarAgentState(run.data.state);
        if (run.data.state.report) setRadarResult(run.data.state.report);
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

  async function runIocHunt() {
    const timeRange = huntTimeRangeToParams(huntTimeRange);
    setHuntStatus("running");
    setHuntProgress({ processed: 0, total: DAILY_HUNT_LIMIT });
    setHuntProviders([]);
    setHuntResults([]);
    setLastError(null);

    const response = await sendBridgeMessage<unknown, DailyHuntResponse>("threatIntel.dailyHunt", {
      indexPattern,
      timestampField: "@timestamp",
      from: timeRange.from,
      to: "now",
      size: 5,
      maxIocs: DAILY_HUNT_LIMIT
    });

    if (response.success) {
      setHuntProviders(response.data.providers);
      setHuntResults(response.data.results);
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
      setRadarResult(response.data);
    } else {
      setLastError(response.error.message);
    }
    setRadarLoading(false);
  }

  return (
    <main className="shell">
      <aside className="sidebar" aria-label="SOC Watch navigation">
        <div className="brand">
          <ShieldCheck size={24} aria-hidden="true" />
          <div>
            <strong>SOC Watch</strong>
            <span>Bridge Console</span>
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
            <StatusTile label="Suspects" value={String(radarResult?.summary.suspects ?? 0)} tone={radarResult?.summary.suspects ? "critical" : "unknown"} />
            <StatusTile label="Critical" value={String(radarResult?.summary.critical ?? 0)} tone={radarResult?.summary.critical ? "critical" : "unknown"} />
            <StatusTile label="High" value={String(radarResult?.summary.high ?? 0)} tone={radarResult?.summary.high ? "critical" : "unknown"} />
            <StatusTile label="Medium" value={String(radarResult?.summary.medium ?? 0)} tone={radarResult?.summary.medium ? "healthy" : "unknown"} />
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
            providers={huntProviders}
            results={huntResults}
            onTimeRangeChange={setHuntTimeRange}
            onFilterChange={setHuntFilter}
            onHunt={runIocHunt}
          />
        ) : null}
        {active === "Threat Radar" ? (
          <ThreatRadar
            timeRange={radarTimeRange}
            loading={radarLoading}
            result={radarResult}
            agentConfig={threatRadarAgent}
            agentState={threatRadarAgentState}
            onTimeRangeChange={setRadarTimeRange}
            onAnalyze={runThreatRadar}
          />
        ) : null}
        {!["Dashboard", "Agents", "Settings", "IOC Search", "Infrastructure", "IOC Hunt", "Threat Radar"].includes(active) ? <Placeholder panel={active} /> : null}
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
  onRunThreatRadarAgent: () => void;
}) {
  const [settingsView, setSettingsView] = useState<SettingsView>("agent");
  return (
    <section className="grid">
      <div className="panel wide">
        <div className="settings-tabs" role="tablist" aria-label="Settings sections">
          {([
            ["agent", "Threat Radar Agent"],
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
          <label className="field candidate-exclusions">
            <span>Candidate exclusions</span>
            <textarea
              value={threatRadarAgent.candidateExclusions.join("\n")}
              placeholder={"ip:10.0.0.0/8\nip:192.168.0.0/16\nkeyword:dhcp lease renewal\ndomain:trusted.example\nhash:0123456789abcdef"}
              onChange={(event) => onThreatRadarAgentChange({
                ...threatRadarAgent,
                candidateExclusions: event.target.value.split("\n").map((value) => value.trim()).filter(Boolean)
              })}
            />
          </label>
        </section>
        </> : null}
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
    return `Healthy. Last scan completed ${new Date(state.completedAt).toLocaleString()}; it returned ${scoredFlows} scored public flows, and ${state.candidates ?? 0} met the automatic alert criteria.`;
  }
  return "No scheduled scan has completed yet.";
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
  providers,
  results,
  onTimeRangeChange,
  onFilterChange,
  onHunt
}: {
  timeRange: HuntTimeRange;
  filter: HuntFilter;
  status: HuntStatus;
  progress: { processed: number; total: number };
  providers: ProviderStatus[];
  results: HuntResult[];
  onTimeRangeChange: (value: HuntTimeRange) => void;
  onFilterChange: (value: HuntFilter) => void;
  onHunt: () => void;
}) {
  const stagedProgress = useAnimatedHuntStages(status, progress.total || DAILY_HUNT_LIMIT);
  const matched = results.filter((result) => result.total > 0);
  const filteredMatches = matched.filter((result) => matchesHuntFilter(result.ioc.type, filter));
  const first = matched[0]?.ioc ?? results[0]?.ioc;
  const collected = providers.reduce((sum, provider) => sum + provider.collected, 0);
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
            <StageCard label="Vendor feeds" current={stagedProgress.vendors} total={progress.total || DAILY_HUNT_LIMIT} />
            <StageCard label="Normalization" current={stagedProgress.normalized} total={progress.total || DAILY_HUNT_LIMIT} />
            <StageCard label="SIEM checks" current={stagedProgress.checked} total={progress.total || DAILY_HUNT_LIMIT} />
          </div>
          {stagedProgress.checked >= (progress.total || DAILY_HUNT_LIMIT) ? (
            <p className="scope-finalizing">250 checks reached. Finalizing the Elastic response...</p>
          ) : null}
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
          </div>
          <div className="top-actions">
            <TimeRangePicker value={timeRange} onChange={onTimeRangeChange} />
            <button className="primary large-action" onClick={onHunt}>
              <Play size={18} aria-hidden="true" />
              <span>Run Again</span>
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
  onTimeRangeChange,
  onAnalyze
}: {
  timeRange: RadarTimeRange;
  loading: boolean;
  result: ThreatRadarResponse | null;
  agentConfig: ThreatRadarAgentConfig;
  agentState: ThreatRadarAgentState;
  onTimeRangeChange: (value: RadarTimeRange) => void;
  onAnalyze: () => void;
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
  const [sourceSort, setSourceSort] = useState<RadarSort>("score-desc");
  const [destinationSort, setDestinationSort] = useState<RadarSort>("score-desc");
  const [portSort, setPortSort] = useState<RadarSort>("score-desc");
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
  const suspects = result?.suspects ?? [];
  const portSuspects = sortRadarSuspects(suspects.filter((suspect) => suspect.dangerousPorts.length > 0), portSort);
  const usesSavedCanvas = layout.every((item) => typeof item.x === "number" && typeof item.y === "number");
  const canvasPositioning = editingLayout || usesSavedCanvas;
  const agentIsScanning = loading || agentState.status === "running";

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
      className: `panel radar-widget ${floating ? "dragging floating" : ""}`
    };

    if (item.id === "sources") {
      return (
        <div key={item.id} data-radar-card={item.id} style={style} {...cardProps}>
          {editHandles}
          <div className="ranked-card-head">
            <div>
              <h3>Suspicious Source Flows</h3>
              <span>Ranked by source IP behavior across all monitored events</span>
            </div>
            <RadarSortSelect value={sourceSort} onChange={setSourceSort} />
          </div>
          <ThreatRadarList suspects={sourceSuspects} mode="source" />
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
              <span>Ranked by destination IP behavior across all monitored events</span>
            </div>
            <RadarSortSelect value={destinationSort} onChange={setDestinationSort} />
          </div>
          <ThreatRadarList suspects={destinationSuspects} mode="destination" />
        </div>
      );
    }

    return (
      <div key={item.id} data-radar-card={item.id} style={style} {...cardProps}>
        {editHandles}
        <div className="ranked-card-head">
          <div>
            <h3>Suspicious Port Activity</h3>
            <span>Risky services targeted across your infrastructure</span>
          </div>
          <RadarSortSelect value={portSort} onChange={setPortSort} />
        </div>
        <ThreatRadarList suspects={portSuspects} mode="ports" />
      </div>
    );
  }

  return (
    <section className="grid">
      <div className="panel wide radar-agent-status" role="status">
        <div>
          <div className="panel-title">
            <Activity size={18} aria-hidden="true" className={agentConfig.enabled ? "agent-heartbeat" : ""} />
            <h2>{agentConfig.enabled ? agentIsScanning ? "Agent scan in progress" : "Agent monitoring active" : "Agent monitoring paused"}</h2>
          </div>
          <p className="muted">Scanning <strong>{agentConfig.indexPattern}</strong> every {agentConfig.intervalMinutes} minutes across source, destination, client, and server IP activity for risky ports, failed authentication, high-volume bursts, and scan patterns.</p>
        </div>
        <div className="top-actions">
          <ThreatRadarRangePicker value={timeRange} onChange={onTimeRangeChange} />
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

function RadarSortSelect({ value, onChange }: { value: RadarSort; onChange: (value: RadarSort) => void }) {
  return (
    <select className="sort-select" value={value} onChange={(event) => onChange(event.target.value as RadarSort)} aria-label="Sort radar card">
      <option value="score-desc">Score high-low</option>
      <option value="score-asc">Score low-high</option>
      <option value="events-desc">Events high-low</option>
      <option value="events-asc">Events low-high</option>
      <option value="ip-asc">IP A-Z</option>
      <option value="ip-desc">IP Z-A</option>
    </select>
  );
}

function ThreatRadarList({ suspects, mode }: { suspects: ThreatRadarSuspect[]; mode: "source" | "destination" | "ports" }) {
  const pageSize = 10;
  const [page, setPage] = useState(1);
  const pageCount = Math.max(1, Math.ceil(suspects.length / pageSize));
  const currentPage = Math.min(page, pageCount);
  const pageStart = (currentPage - 1) * pageSize;
  const visibleSuspects = suspects.slice(pageStart, pageStart + pageSize);

  useEffect(() => {
    setPage((current) => Math.min(current, pageCount));
  }, [pageCount]);

  if (suspects.length === 0) return <EmptyRadarState />;
  return (
    <div className="radar-list">
      <div className="mini-table-wrap radar-table-wrap">
        <table className="mini-ioc-table radar-table">
          <thead>
            <tr>
              <th>Source IP</th>
              <th>Destination IP</th>
              <th>Score</th>
              <th>GTI</th>
              <th>Events</th>
              <th>Infrastructure</th>
              <th>Ports</th>
              <th>Reasons</th>
            </tr>
          </thead>
          <tbody>
            {visibleSuspects.map((suspect) => (
              <tr key={`${mode}:${suspect.role}:${suspect.sourceIp}:${suspect.destinationIp}`}>
                <td className="mono-cell">{suspect.sourceIp}</td>
                <td className="mono-cell">{suspect.destinationIp}</td>
                <td><Badge value={`${suspect.score}`} /></td>
                <td>{suspect.gti?.threatScore ?? "--"}</td>
                <td>{suspect.events}</td>
                <td>{suspect.infrastructureCount}</td>
                <td>{suspect.topPorts.length ? suspect.topPorts.join(", ") : "--"}</td>
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

function RadarPagination({ page, pageCount, total, pageSize, onChange }: { page: number; pageCount: number; total: number; pageSize: number; onChange: (page: number) => void }) {
  if (pageCount <= 1) return <span className="radar-result-count">{total} result{total === 1 ? "" : "s"}</span>;
  const pages = compactPageNumbers(page, pageCount);
  const from = (page - 1) * pageSize + 1;
  const to = Math.min(total, page * pageSize);
  return (
    <nav className="radar-pagination" aria-label="Radar card pages">
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

function EmptyRadarState() {
  return (
    <div className="empty-card">
      <strong>No suspicious flows scored yet.</strong>
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

function Placeholder({ panel }: { panel: Panel }) {
  return (
    <section className="panel wide">
      <h2>{panel}</h2>
      <p className="muted">This area is reserved for the next SOC Watch phase. The bridge protocol already keeps unsupported actions closed.</p>
    </section>
  );
}

function Badge({ value }: { value: string }) {
  const tone = value === "online" || value === "clear" || value === "match" ? "healthy" : value === "offline" || value === "error" || value === "critical" || value === "high" ? "critical" : "unknown";
  return <span className={`badge ${tone}`}>{value}</span>;
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

function threatRadarTimeRangeToParams(range: RadarTimeRange): { from: string } {
  if (range === "last15m") return { from: "now-15m" };
  if (range === "last1h") return { from: "now-1h" };
  return { from: "now/d" };
}

function loadThreatRadarLayout(): RadarLayoutItem[] {
  const fallback: RadarLayoutItem[] = [{ id: "sources" }, { id: "destinations" }, { id: "ports" }];
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
        if (id !== "sources" && id !== "destinations" && id !== "ports") return null;
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
      if (!ids.has(item.id)) items.push(item);
    }
    return items;
  } catch {
    return fallback;
  }
}

function defaultRadarCardSize(id: RadarCardId): { width: number; height: number } {
  if (id === "ports") return { width: 720, height: 440 };
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
    if (sort === "score-desc") return right.score - left.score;
    if (sort === "score-asc") return left.score - right.score;
    if (sort === "events-desc") return right.events - left.events;
    if (sort === "events-asc") return left.events - right.events;
    if (sort === "ip-desc") return right.ip.localeCompare(left.ip, undefined, { numeric: true });
    return left.ip.localeCompare(right.ip, undefined, { numeric: true });
  });
  return sorted;
}

function formatDestination(suspect: ThreatRadarSuspect): string {
  const destinationIp = suspect.latest?.destinationIp ?? suspect.destinationIp;
  const port = suspect.latest?.destinationPort;
  return `${destinationIp}${port ? `:${port}` : ""}`;
}

function formatGti(gti: ThreatRadarSuspect["gti"]): string {
  if (!gti) return "Not enriched";
  const verdict = gti.verdict?.replace("VERDICT_", "").toLowerCase() ?? "unknown";
  return `score ${gti.threatScore} | ${verdict} | VT ${gti.malicious}/${gti.suspicious}`;
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
  return {
    vendors: Math.min(ceiling, tick * 10),
    normalized: Math.min(ceiling, Math.max(0, tick - 5) * 9),
    checked: Math.min(ceiling, Math.max(0, tick - 11) * 7)
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
