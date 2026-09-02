import React, { useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  AlertTriangle,
  Bell,
  Database,
  FileSearch,
  Gauge,
  HardDrive,
  ListChecks,
  MonitorCog,
  Radar,
  RefreshCw,
  Search,
  Server,
  Settings,
  ShieldCheck
} from "lucide-react";
import type { FleetSummary, KibanaStatus } from "@soc-watch/protocol";
import type { DataViewSummary, SanitizedFleetAgent } from "@soc-watch/protocol";
import { sendBridgeMessage } from "./bridge";
import "./styles.css";

type Panel = "Dashboard" | "Infrastructure" | "Agents" | "IOC Search" | "Bulk Hunt" | "Logs" | "Watchlist" | "Alerts" | "Settings" | "Diagnostics";

const nav: Array<{ label: Panel; icon: React.ComponentType<{ size?: number }> }> = [
  { label: "Dashboard", icon: Gauge },
  { label: "Infrastructure", icon: Server },
  { label: "Agents", icon: MonitorCog },
  { label: "IOC Search", icon: Search },
  { label: "Bulk Hunt", icon: Radar },
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
  const [kibana, setKibana] = useState<KibanaStatus | null>(null);
  const [fleet, setFleet] = useState<FleetSummary | null>(null);
  const [agents, setAgents] = useState<SanitizedFleetAgent[]>([]);
  const [dataViews, setDataViews] = useState<DataViewSummary[]>([]);
  const [iocValue, setIocValue] = useState("62[.]238[.]44[.]99");
  const [indexPattern, setIndexPattern] = useState("logs-*");
  const [iocResult, setIocResult] = useState<unknown>(null);
  const [lastError, setLastError] = useState<string | null>(null);

  const fleetTotal = useMemo(() => (fleet ? fleet.online + fleet.offline + fleet.error + fleet.inactive : 0), [fleet]);

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
        <header className="topbar">
          <div>
            <p className="eyebrow">Internal Elastic Security Operations</p>
            <h1>{active}</h1>
          </div>
          <button className="primary" onClick={runProofCheck} disabled={loading}>
            <RefreshCw size={16} aria-hidden="true" className={loading ? "spin" : ""} />
            <span>{loading ? "Checking" : "Run Bridge Proof"}</span>
          </button>
        </header>

        <section className="status-strip" aria-label="Current SOC Watch status">
          <StatusTile label="Bridge" value={bridgeState} tone={bridgeState.includes("connected") ? "healthy" : "unknown"} />
          <StatusTile label="Kibana" value={kibana?.overall ?? "Unknown"} tone={kibana?.overall === "available" ? "healthy" : "unknown"} />
          <StatusTile label="Fleet Online" value={fleet ? String(fleet.online) : "--"} tone="healthy" />
          <StatusTile label="Fleet Offline" value={fleet ? String(fleet.offline) : "--"} tone={fleet?.offline ? "critical" : "unknown"} />
        </section>

        {lastError ? (
          <section className="notice" role="status">
            <AlertTriangle size={18} aria-hidden="true" />
            <div>
              <strong>Kibana authentication required or bridge unavailable</strong>
              <span>{lastError}</span>
            </div>
            <a href="https://10.10.254.202:8888" target="_blank" rel="noreferrer">Open Kibana</a>
          </section>
        ) : null}

        {active === "Dashboard" ? <Dashboard kibana={kibana} fleet={fleet} fleetTotal={fleetTotal} /> : null}
        {active === "Agents" ? <Agents agents={agents} onRefresh={loadAgents} /> : null}
        {active === "Settings" ? (
          <SettingsPanel
            dataViews={dataViews}
            indexPattern={indexPattern}
            onIndexPatternChange={setIndexPattern}
            onLoadDataViews={loadDataViews}
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
        {!["Dashboard", "Agents", "Settings", "IOC Search"].includes(active) ? <Placeholder panel={active} /> : null}
      </section>
    </main>
  );
}

function Dashboard({ kibana, fleet, fleetTotal }: { kibana: KibanaStatus | null; fleet: FleetSummary | null; fleetTotal: number }) {
  return (
    <section className="grid">
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
              <th>IP</th>
              <th>Version</th>
              <th>Policy</th>
              <th>Last Check-in</th>
            </tr>
          </thead>
          <tbody>
            {agents.length === 0 ? (
              <tr>
                <td colSpan={6}>No agents loaded yet.</td>
              </tr>
            ) : (
              agents.map((agent) => (
                <tr key={agent.id}>
                  <td><Badge value={agent.status} /></td>
                  <td>{agent.hostname ?? agent.id}</td>
                  <td>{agent.hostIps?.join(", ") ?? "--"}</td>
                  <td>{agent.agentVersion ?? "--"}</td>
                  <td>{agent.policyId ?? "--"}</td>
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

function SettingsPanel({
  dataViews,
  indexPattern,
  onIndexPatternChange,
  onLoadDataViews
}: {
  dataViews: DataViewSummary[];
  indexPattern: string;
  onIndexPatternChange: (value: string) => void;
  onLoadDataViews: () => void;
}) {
  return (
    <section className="grid">
      <div className="panel wide">
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
      </div>
    </section>
  );
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
        <pre className="result">{result ? JSON.stringify(result, null, 2) : "No search has run yet."}</pre>
      </div>
    </section>
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
  const tone = value === "online" ? "healthy" : value === "offline" || value === "error" ? "critical" : "unknown";
  return <span className={`badge ${tone}`}>{value}</span>;
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
