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
      </section>
    </main>
  );
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
