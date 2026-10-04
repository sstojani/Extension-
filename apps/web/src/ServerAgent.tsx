import React, { useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
import {
  Activity, AlertTriangle, ArrowLeft, Bell, CheckCircle2, ChevronLeft, ChevronRight,
  FileSearch, LoaderCircle, LogIn, LogOut, Pencil, Play, Plus, RefreshCw, Save, Search,
  Send, Server, Settings, ShieldCheck, Square, Trash2, X
} from "lucide-react";
import "./server-agent.css";
import { sendBridgeMessage } from "./bridge";
import { runBrowserRelay, type RelayProgress } from "./browser-relay";
import { relayPolicySchema, type DataViewSummary } from "@soc-watch/protocol";

type IndicatorType = "ip" | "domain" | "hash" | "identity";
type FindingStatus = "open" | "acknowledged" | "resolved" | "false_positive";
type ScanMode = "live" | "today" | "baseline";
type Tab = "Findings" | "Watch Rules" | "Agent Settings" | "Integrations" | "Delivery";
type Tone = "good" | "warning" | "error" | "neutral";
type JsonObject = Record<string, unknown>;
export type AgentException = {
  indicatorType: IndicatorType; indicatorValue: string; host?: string; infrastructure?: string;
  reason: string; expiresAt?: string; enabled?: boolean;
};
export type AgentConfig = {
  enabled: boolean; intervalMinutes: number; overlapMinutes: number; maxEventsPerRun: number;
  pageSize: number; timezone: string; baselineDays: number; indexPattern: string;
  timestampField: string; infrastructureField: string; autoAlertMinPriority: number;
  retentionDays: number; query: string; assets: unknown[]; accounts: unknown[];
  exceptions?: AgentException[]; autoInvestigate?: boolean; huntEnabled?: boolean;
  liveIntervalSeconds?: number; liveWindowMinutes?: number;
  scanMinAttempts?: number; scanMinTargets?: number; scanMinPorts?: number; authFailures?: number;
  beaconMinConnections?: number; beaconMaxCv?: number; exfilMinBytes?: number; exfilRatio?: number;
};
export type WatchRule = {
  id: string; name: string; indicatorType: IndicatorType; indicatorValue: string;
  includeSubdomains: boolean; enabled: boolean; minEvents: number; minPriority: number;
  cooldownMinutes: number; channels: string[]; scope: { host?: string; infrastructure?: string };
  requireSuccess: boolean;
};
type Evidence = { eventId: string; index: string; timestamp: string; reason: string };
type ActivityContext = {
  infrastructures: string[]; targets: string[]; ports: number[]; countries: string[];
  from?: string; to?: string; blockedAttemptsLowerBound?: number;
  allowed: { timestamp: string; action: string | null; destinationIp: string | null; port: number | null; infrastructure: string | null }[];
};
export type Finding = {
  id: string; fingerprint: string; title: string; category: string; indicator: string;
  indicatorType: IndicatorType; severity: string; priority: number; behaviorScore: number;
  confidence: number; reputation: {
    verdict: string; score?: number; malicious?: number; suspicious?: number; checkedAt?: string; status?: string;
    source?: string; gtiVerdict?: string | null; assessment?: string;
  } | null; firstSeen: string; lastSeen: string; count: number; evidence: Evidence[];
  reasons: string[]; limitations: string[]; status: FindingStatus; assignedTo?: string; notes?: unknown; activity?: ActivityContext;
};
type Run = {
  id: string; startedAt: string; finishedAt: string | null; mode: string; status: string;
  eventsRead: number; totalMatched: number; invalidEvents: number; coverage: unknown;
  from: string; to: string; error?: string;
};
type Alert = {
  id: string; title?: string; message?: string; indicator?: string; findingId?: string;
  createdAt?: string; timestamp?: string; priority?: number; reasons?: string[]; activity?: ActivityContext;
};
type Channel = {
  id: string; name: string; type: "webhook" | "discord" | "telegram";
  enabled: boolean; configured: boolean; url?: string;
};
type Investigation = {
  id: string; status: "pending" | "complete" | "failed" | "reduced"; briefing?: string;
  facts?: unknown[]; limitations?: string[]; steps?: unknown[]; timeline?: unknown[]; error?: string;
};
type Campaign = {
  id: string; createdAt: string; expiresAt: string; totalAvailable: number; offset: number;
  checked: number; status: string; providers: unknown; lastError?: string;
};
export type ChannelDraft = Channel & { url: string; token: string; chatId: string };
export type AgentState = {
  session?: { role: "admin" | "analyst"; user: string };
  status: {
    enabled: boolean; configured: boolean; running: boolean; lastSuccess: string | null;
    lastError: unknown; checkpoint: unknown; nextScan: string | null; heartbeat: unknown; coverage: unknown;
    paused?: boolean; dataSource?: { mode: "direct" | "browser_relay"; ready: boolean; source?: { kibanaBaseUrl: string; spaceId: string } | null; lastSeen?: string | null };
    live?: { running?: boolean; lastSuccess: string | null; lastAttempt?: string; lastError: string | null; nextScan: string | null; from?: string; to?: string; evidenceRead?: number; findings?: number; coverage?: string; stages: Record<string, { status: string; error?: string; matched?: number; evidenceRead?: number }> };
    historical?: { id: string; mode: string; from: string; to: string; eventsRead: number; totalMatched: number; paused?: boolean } | null;
  };
  config: AgentConfig; rules: WatchRule[]; findings: Finding[]; runs: Run[]; alerts: Alert[];
  deliveries: { id: string; channel: string; status: string; attempts: number; nextAttempt: string | null; error?: string }[];
  notifications: { channels: Channel[]; minPriority: number; cooldownMinutes: number };
  reputation: { pending: number; unavailable: number; scored: number; configured?: boolean; notFound?: number; source?: string }; campaigns: Campaign[];
  integrations?: Record<"gti" | "threatfox" | "malwarebazaar", { configured: boolean; source: "environment" | "server" | "missing" }>;
  investigations?: Investigation[];
};
type PublicStatus = {
  available: boolean; configured: boolean; authenticated: boolean; version: string;
  requiresNode?: string | boolean; message?: string;
};
type RequestOptions = { method?: string; body?: unknown; signal?: AbortSignal; maxBytes?: number };
type Api = <T = unknown>(path: string, options?: RequestOptions) => Promise<T>;
type Action = (key: string, path: string, body?: unknown, method?: string) => Promise<boolean>;

export function reputationSourceLabel(state: AgentState) {
  if (state.reputation.source === "server" || state.reputation.source === "browser") return state.reputation.source;
  if (state.status.dataSource?.mode === "browser_relay" && !state.status.dataSource.ready) return "relay offline";
  return state.reputation.configured === false ? "not configured" : "server";
}

export class AgentApiError extends Error {
  constructor(message: string, public status: number) { super(message); this.name = "AgentApiError"; }
}

const detectionControls = [
  { key: "scanMinAttempts", label: "Scan minimum blocked attempts", min: 5, max: 10000, step: 1, fallback: 30 },
  { key: "scanMinTargets", label: "Scan minimum targets", min: 2, max: 1000, step: 1, fallback: 5 },
  { key: "scanMinPorts", label: "Scan minimum ports", min: 3, max: 1000, step: 1, fallback: 10 },
  { key: "authFailures", label: "Failures before successful login", min: 3, max: 1000, step: 1, fallback: 10 },
  { key: "beaconMinConnections", label: "Beacon minimum connections", min: 8, max: 1000, step: 1, fallback: 8 },
  { key: "beaconMaxCv", label: "Beacon maximum interval variation", min: 0, max: 0.5, step: 0.01, fallback: 0.15 },
  { key: "exfilMinBytes", label: "Transfer minimum source bytes", min: 1048576, max: 1e12, step: 1, fallback: 52428800 },
  { key: "exfilRatio", label: "Transfer ratio over baseline", min: 2, max: 1000, step: 1, fallback: 5 }
] as const;

function record(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function message(value: unknown): string {
  if (value == null || value === "") return "Not reported";
  return typeof value === "string" ? value : JSON.stringify(value);
}
function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "The request failed. Please retry.";
}
function aborted(error: unknown): boolean { return error instanceof Error && error.name === "AbortError"; }

export async function agentRequest<T = unknown>(path: string, options: RequestOptions = {}): Promise<T> {
  const controller = new AbortController();
  const cancel = () => controller.abort();
  options.signal?.addEventListener("abort", cancel, { once: true });
  if (options.signal?.aborted) cancel();
  let timedOut = false;
  const timeout = setTimeout(() => { timedOut = true; cancel(); }, 20_000);
  try {
    const method = options.method ?? "GET";
    const body = options.body ?? (method === "GET" ? undefined : {});
    const response = await fetch(`/api/agent${path}`, {
      method, credentials: "same-origin", cache: "no-store", redirect: "error",
      headers: { Accept: "application/json", ...(body === undefined ? {} : { "Content-Type": "application/json" }) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }), signal: controller.signal
    });
    if (response.status === 401) throw new AgentApiError("Session expired or token rejected. Sign in again.", 401);
    if (response.status === 404) throw new AgentApiError("This server agent endpoint is unavailable on this deployment.", 404);
    const limit = options.maxBytes ?? 8 * 1024 * 1024;
    if (Number(response.headers.get("content-length")) > limit) throw new AgentApiError("Response exceeds the console's size limit.", response.status);
    const reader = response.body?.getReader();
    const chunks: Uint8Array[] = [];
    let length = 0;
    if (reader) {
      try {
        while (true) {
          const chunk = await reader.read();
          if (chunk.done) break;
          length += chunk.value.byteLength;
          if (length > limit) {
            await reader.cancel();
            throw new AgentApiError("Response exceeds the console's size limit.", response.status);
          }
          chunks.push(chunk.value);
        }
      } finally { reader.releaseLock(); }
    }
    const bytes = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    const text = new TextDecoder().decode(bytes);
    let payload: unknown;
    try { payload = text ? JSON.parse(text) : undefined; }
    catch { throw new AgentApiError("Server returned a non-JSON response. Check this deployment's agent API.", response.status); }
    if (!response.ok) {
      const detail = record(payload) ? payload.error ?? payload.message : undefined;
      throw new AgentApiError(detail ? message(detail).slice(0, 1000) : `Server request failed (HTTP ${response.status}).`, response.status);
    }
    if (options.signal?.aborted) throw new DOMException("Request cancelled", "AbortError");
    return payload as T;
  } catch (error) {
    if (timedOut && !options.signal?.aborted) throw new AgentApiError("Server request timed out. The operation may still be running; refresh before retrying.", 408);
    throw error;
  } finally {
    clearTimeout(timeout);
    options.signal?.removeEventListener("abort", cancel);
  }
}

export function validateConfig(config: AgentConfig): string | null {
  for (const [key, min, max] of [["liveIntervalSeconds", 30, 300], ["liveWindowMinutes", 1, 15]] as const) {
    if (config[key] !== undefined && (!Number.isInteger(config[key]) || config[key]! < min || config[key]! > max)) return `Invalid ${key}.`;
  }
  for (const { key, min, max, step } of detectionControls) {
    const value = config[key];
    if (value !== undefined && (!Number.isFinite(value) || value < min || value > max || step === 1 && !Number.isInteger(value))) return `Invalid ${key}.`;
  }
  for (const [key, min, max] of [
    ["intervalMinutes", 1, 60], ["overlapMinutes", 1, 60], ["maxEventsPerRun", 500, 100000],
    ["pageSize", 100, 1000], ["baselineDays", 3, 90], ["autoAlertMinPriority", 0, 100], ["retentionDays", 1, 90]
  ] as const) {
    if (!Number.isInteger(config[key]) || config[key] < min || config[key] > max) return `${key} must be an integer between ${min} and ${max}.`;
  }
  if (config.pageSize > config.maxEventsPerRun) return "Page size must not exceed the event limit per run.";
  for (const key of ["indexPattern", "timestampField", "infrastructureField"] as const) {
    if (!config[key].trim()) return `${key} is required.`;
  }
  try { new Intl.DateTimeFormat("en", { timeZone: config.timezone }); }
  catch { return "Enter a valid IANA timezone, such as Europe/Tirane or UTC."; }
  if (!Array.isArray(config.assets) || !Array.isArray(config.accounts)) return "Assets and accounts must be JSON arrays.";
  if (config.assets.length > 500 || config.accounts.length > 500 || (config.exceptions?.length ?? 0) > 500) return "Assets, accounts, and exceptions are limited to 500 entries each.";
  if (config.query.length > 2000) return "Query expressions are limited to 2000 characters.";
  for (const exception of config.exceptions ?? []) {
    if (!exception.indicatorValue.trim() || !exception.reason.trim()) return "Every exception needs an indicator and a reason.";
    if (exception.expiresAt && !Number.isFinite(Date.parse(exception.expiresAt))) return "Exception expiration must be a valid date and time.";
  }
  return null;
}

export function validateRule(rule: Omit<WatchRule, "id">): string | null {
  if (!rule.name.trim() || !rule.indicatorValue.trim()) return "Rule name and indicator are required.";
  const value = rule.indicatorValue.trim();
  if (rule.indicatorType === "ip") {
    const ipv4 = value.split(".");
    const isV4 = ipv4.length === 4 && ipv4.every(part => /^(0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255);
    let isV6 = false;
    if (value.includes(":")) { try { isV6 = new URL(`http://[${value}]/`).hostname.startsWith("["); } catch { /* Invalid IPv6. */ } }
    if (!isV4 && !isV6) return "Enter a valid IPv4 or IPv6 address.";
  }
  if (rule.indicatorType === "domain" && !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$/i.test(value)) return "Enter a domain name without a scheme, path, or wildcard.";
  if (rule.indicatorType === "hash" && !/^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(value)) return "Enter a hexadecimal MD5, SHA-1, or SHA-256 hash.";
  if (!Number.isInteger(rule.minEvents) || rule.minEvents < 1 || rule.minEvents > 100000) return "Minimum events must be between 1 and 100000.";
  if (!Number.isInteger(rule.minPriority) || rule.minPriority < 0 || rule.minPriority > 100) return "Minimum priority must be between 0 and 100.";
  if (!Number.isInteger(rule.cooldownMinutes) || rule.cooldownMinutes < 1 || rule.cooldownMinutes > 10080) return "Cooldown must be between 1 and 10080 minutes.";
  return null;
}

function redacted(value?: string): boolean { return !value || /\*{3}|redacted|^\[.*\]$/i.test(value); }
export function channelDraft(channel: Channel): ChannelDraft {
  return { ...channel, url: redacted(channel.url) ? "" : channel.url!, token: "", chatId: "" };
}
export function notificationPayload(channels: ChannelDraft[], minPriority: number, cooldownMinutes: number) {
  if (channels.length > 20) throw new Error("A maximum of 20 delivery channels is supported.");
  if (!Number.isInteger(minPriority) || minPriority < 0 || minPriority > 100) throw new Error("Delivery priority must be between 0 and 100.");
  if (!Number.isInteger(cooldownMinutes) || cooldownMinutes < 0) throw new Error("Delivery cooldown must be a nonnegative integer.");
  const ids = new Set<string>();
  return { minPriority, cooldownMinutes, channels: channels.map(channel => {
    if (!channel.id.trim() || !channel.name.trim() || ids.has(channel.id)) throw new Error("Every channel needs a unique ID and a name.");
    ids.add(channel.id);
    const url = channel.url.trim();
    if (url) {
      let parsed: URL;
      try { parsed = new URL(url); } catch { throw new Error(`Invalid URL for ${channel.name}.`); }
      if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.hash) throw new Error(`Use an HTTPS URL without embedded credentials or a fragment for ${channel.name}.`);
      if (channel.type === "discord" && (parsed.hostname !== "discord.com" || !parsed.pathname.startsWith("/api/webhooks/"))) throw new Error(`Enter a Discord webhook URL for ${channel.name}.`);
    }
    if (!channel.configured) {
      if (channel.type === "telegram" ? !channel.token.trim() || !channel.chatId.trim() : !url) throw new Error(`Complete credentials for ${channel.name} before enabling it.`);
    }
    return {
      id: channel.id.trim(), name: channel.name.trim(), type: channel.type, enabled: channel.enabled,
      ...(url ? { url } : {}), ...(channel.token.trim() ? { token: channel.token.trim() } : {}),
      ...(channel.chatId.trim() ? { chatId: channel.chatId.trim() } : {})
    };
  }) };
}

function alertTime(alert: Alert): number { return Date.parse(alert.createdAt ?? alert.timestamp ?? "") || 0; }
export function createAlertCursor(initial: Alert[], startedAt = Date.now()) {
  let watermark = Math.max(startedAt, ...initial.map(alertTime));
  const seen = new Set(initial.map(alert => alert.id));
  return (alerts: Alert[]) => {
    const fresh = alerts.filter(alert => alert.id && !seen.has(alert.id) && alertTime(alert) >= watermark);
    for (const alert of alerts) seen.add(alert.id);
    watermark = Math.max(watermark, ...alerts.map(alertTime));
    if (seen.size > 5000) { seen.clear(); for (const alert of alerts) seen.add(alert.id); }
    return fresh.sort((a, b) => alertTime(a) - alertTime(b));
  };
}

function date(value: unknown): string {
  if (typeof value !== "string" && typeof value !== "number") return "Not reported";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? message(value) : parsed.toLocaleString();
}
function count(value: number | undefined): string { return value == null ? "--" : value.toLocaleString(); }
function human(value?: string): string { return value ? value.replaceAll("_", " ") : "Not reported"; }
function statusTone(value = ""): Tone {
  if (/fail|error|unavailable|unauthorized|dead|malicious/.test(value)) return "error";
  if (/pending|queue|running|incomplete|partial|limit|suspicious|retry|reduced|collecting|analyzing|in_progress/.test(value)) return "warning";
  if (/complete|success|sent|delivered|resolved|healthy|scored/.test(value)) return "good";
  return "neutral";
}
function coverageIncomplete(coverage: unknown): boolean {
  return coverage === false || typeof coverage === "string" && /partial|incomplete|limit|fail|unknown|reduced|in_progress/i.test(coverage) ||
    record(coverage) && (coverage.complete === false || coverage.truncated === true || coverage.partial === true || coverage.status != null && coverageIncomplete(coverage.status));
}
export function scanHealth(state: AgentState, now = Date.now()): { label: string; detail: string; tone: Tone } {
  if (state.status.dataSource?.mode === "browser_relay" && !state.status.dataSource.ready) return { label: "Collection paused", detail: "No authenticated work browser relay is available. Connect the browser to resume collection. Retained findings and server delivery are preserved.", tone: "error" };
  const live = state.status.live;
  if (live?.running) return { label: "Live check running", detail: live.lastError ? `Previous check had reduced coverage: ${live.lastError}` : "Fresh detection is running; current coverage has not yet been confirmed.", tone: "warning" };
  if (live && !live.lastAttempt) return { label: state.config.enabled ? "Awaiting live check" : "Live monitoring paused", detail: "No live check has completed for the current source and detection settings.", tone: "warning" };
  if (live?.lastAttempt) {
    if (live.lastError) return { label: "Live coverage reduced", detail: live.lastError, tone: "error" };
    if (!state.config.enabled) return { label: "Live monitoring paused", detail: `Last manual check: ${date(live.lastAttempt)}.`, tone: "neutral" };
    if (now - Date.parse(live.lastAttempt) > Math.max(120000, (state.config.liveIntervalSeconds ?? 30) * 2000)) return { label: "Live check overdue", detail: "Fresh detection has not completed recently. Review the relay and run stages.", tone: "warning" };
    return { label: "Live checks completed", detail: "Targeted, sampled coverage. Authentication and threat evidence may be incomplete; review stage counts.", tone: "warning" };
  }
  const latest = [...state.runs].sort((a, b) => Date.parse(b.startedAt) - Date.parse(a.startedAt))[0];
  if (state.status.lastError) return { label: "Scan error", detail: message(state.status.lastError), tone: "error" };
  if (latest?.error || latest && /fail|error/.test(latest.status)) return { label: "Last scan failed", detail: latest.error ?? latest.status, tone: "error" };
  if (state.status.running) return { label: "Scan running", detail: "Current coverage is still being evaluated.", tone: "warning" };
  if (coverageIncomplete(state.status.coverage) || latest && (coverageIncomplete(latest.coverage) || /partial|incomplete|limit/.test(latest.status))) return { label: "Incomplete coverage", detail: "Some data or detection stages were unavailable or sampled. Review run coverage.", tone: "warning" };
  const heartbeat = record(state.status.heartbeat) ? state.status.heartbeat.at ?? state.status.heartbeat.timestamp ?? state.status.heartbeat.lastSeen : state.status.heartbeat;
  const heartbeatTime = typeof heartbeat === "string" || typeof heartbeat === "number" ? new Date(heartbeat).getTime() : NaN;
  if (!state.status.configured) return { label: "Configuration required", detail: "Agent data source is not configured.", tone: "warning" };
  if (!state.status.enabled) return { label: "Agent paused", detail: "Scheduled scanning is disabled.", tone: "neutral" };
  if (!Number.isFinite(heartbeatTime)) return { label: "Heartbeat not reported", detail: "Agent liveness cannot be confirmed.", tone: "warning" };
  if (now - heartbeatTime > Math.max(120_000, state.config.intervalMinutes * 120_000)) return { label: "Heartbeat stale", detail: "The server has not reported a recent heartbeat.", tone: "error" };
  if (!state.status.lastSuccess) return { label: "Awaiting successful scan", detail: "No successful scan has been reported.", tone: "warning" };
  if (state.status.coverage == null) return { label: "Coverage not reported", detail: "The latest scan's coverage cannot be confirmed.", tone: "warning" };
  return { label: "Agent healthy", detail: "A successful scan and current heartbeat are reported.", tone: "good" };
}

function Badge({ children, tone = "neutral" }: { children: React.ReactNode; tone?: Tone }) {
  return <span className={`sa-badge sa-${tone}`}>{children}</span>;
}
function Feedback({ error, success }: { error?: string | undefined; success?: string | undefined }) {
  return <>{error && <p className="sa-feedback sa-error" role="alert"><AlertTriangle size={16} aria-hidden="true" />{error}</p>}
    {success && <p className="sa-feedback sa-good" role="status"><CheckCircle2 size={16} aria-hidden="true" />{success}</p>}</>;
}
function Field({ label, children, hint, wide = false }: { label: string; children: React.ReactNode; hint?: string; wide?: boolean }) {
  return <label className={`sa-field${wide ? " sa-wide" : ""}`}><span>{label}</span>{children}{hint && <small>{hint}</small>}</label>;
}
function Toggle({ label, checked, onChange, disabled = false }: { label: string; checked: boolean; onChange: (value: boolean) => void; disabled?: boolean }) {
  return <label className="sa-toggle"><input type="checkbox" checked={checked} onChange={event => onChange(event.target.checked)} disabled={disabled} />{label}</label>;
}
function Modal({ title, children, onClose }: { title: string; children: React.ReactNode; onClose: () => void }) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  useEffect(() => {
    const previous = document.activeElement;
    ref.current?.showModal();
    return () => { ref.current?.close(); if (previous instanceof HTMLElement && previous.isConnected) previous.focus(); };
  }, []);
  return <dialog ref={ref} className="sa-modal" aria-labelledby={titleId} onCancel={event => { event.preventDefault(); onClose(); }}
    onClick={event => { if (event.target === event.currentTarget) { const bounds = event.currentTarget.getBoundingClientRect(); if (event.clientX < bounds.left || event.clientX > bounds.right || event.clientY < bounds.top || event.clientY > bounds.bottom) onClose(); } }}>
    <header><h2 id={titleId}>{title}</h2><button type="button" className="sa-icon" aria-label="Close dialog" title="Close dialog" onClick={onClose}><X size={18} /></button></header>
    <div className="sa-modal-body">{children}</div>
  </dialog>;
}

export function ServerAgent() {
  const [publicStatus, setPublicStatus] = useState<PublicStatus | null>(null);
  const [availabilityError, setAvailabilityError] = useState("");
  const [checking, setChecking] = useState(true);
  const [authenticated, setAuthenticated] = useState(false);
  const [token, setToken] = useState("");
  const [state, setState] = useState<AgentState | null>(null);
  const [tab, setTab] = useState<Tab>("Findings");
  const [retry, setRetry] = useState(0);
  const [refresh, setRefresh] = useState(0);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [pollError, setPollError] = useState("");
  const [updatedAt, setUpdatedAt] = useState<number | null>(null);
  const [busy, setBusy] = useState("");
  const [scanMode, setScanMode] = useState<ScanMode>("live");
  const [clearOpen, setClearOpen] = useState(false);
  const [cancelOpen, setCancelOpen] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [browserEnabled, setBrowserEnabled] = useState(false);
  const [browserError, setBrowserError] = useState("");
  const [permission, setPermission] = useState<NotificationPermission | "unavailable">(() => typeof Notification === "undefined" ? "unavailable" : Notification.permission);
  const mounted = useRef(false);
  const pending = useRef(false);
  const controllers = useRef(new Set<AbortController>());
  const alertCursor = useRef<ReturnType<typeof createAlertCursor> | null>(null);
  const browserActive = useRef(false);
  const browserRequestedAt = useRef(0);
  const sessionStartedAt = useRef(Date.now());

  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; for (const controller of controllers.current) controller.abort(); };
  }, []);

  useEffect(() => {
    const syncPermission = () => {
      if (typeof Notification === "undefined") return;
      setPermission(Notification.permission);
      if (browserActive.current && Notification.permission !== "granted") {
        browserActive.current = false; setBrowserEnabled(false);
        setBrowserError("Browser notification permission is no longer granted.");
      }
    };
    window.addEventListener("focus", syncPermission);
    return () => window.removeEventListener("focus", syncPermission);
  }, []);

  const api: Api = useCallback(async <T,>(path: string, options: RequestOptions = {}) => {
    const controller = new AbortController();
    controllers.current.add(controller);
    const cancel = () => controller.abort();
    options.signal?.addEventListener("abort", cancel, { once: true });
    if (options.signal?.aborted) cancel();
    try { return await agentRequest<T>(path, { ...options, signal: controller.signal }); }
    catch (caught) {
      if (mounted.current && caught instanceof AgentApiError && caught.status === 401) {
        for (const active of controllers.current) active.abort();
        setAuthenticated(false); setState(null); setToken(""); setSelectedId(null); setClearOpen(false);
        setError(caught.message); browserActive.current = false; setBrowserEnabled(false); alertCursor.current = null;
      }
      throw caught;
    } finally { controllers.current.delete(controller); options.signal?.removeEventListener("abort", cancel); }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    setChecking(true); setAvailabilityError("");
    void api<PublicStatus>("/status", { signal: controller.signal }).then(status => {
      if (!record(status) || typeof status.available !== "boolean" || typeof status.authenticated !== "boolean") throw new Error("Server returned an invalid agent status.");
      setPublicStatus(status); setAuthenticated(status.authenticated && status.available);
      sessionStartedAt.current = Date.now();
      if (!status.available) setAvailabilityError(status.message ?? "Server agent unavailable on this deployment.");
    }).catch(caught => { if (!aborted(caught)) { setPublicStatus(null); setAvailabilityError(errorMessage(caught)); } })
      .finally(() => { if (!controller.signal.aborted) setChecking(false); });
    return () => controller.abort();
  }, [api, retry]);

  useEffect(() => {
    if (!authenticated) return;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const poll = async () => {
      try {
        const next = await api<AgentState>("/state", { signal: controller.signal });
        if (!record(next) || !record(next.status) || !record(next.config) || !Array.isArray(next.findings) || !Array.isArray(next.alerts) || !Array.isArray(next.runs) || !Array.isArray(next.rules) || !record(next.notifications) || !Array.isArray(next.notifications.channels) || !Array.isArray(next.deliveries) || !record(next.reputation)) throw new Error("Server returned an invalid agent state.");
        if (controller.signal.aborted) return;
        setState(next); setPollError(""); setUpdatedAt(Date.now());
        if (!alertCursor.current) alertCursor.current = createAlertCursor(next.alerts, sessionStartedAt.current);
        else {
          const fresh = alertCursor.current(next.alerts);
          if (browserActive.current && typeof Notification !== "undefined" && Notification.permission === "granted") {
            const eligible = fresh.filter(alert => alertTime(alert) >= browserRequestedAt.current);
            try {
              if (eligible.length > 3) new Notification("SOC Watch Server Agent", { body: `${eligible.length} new alerts. Open Findings to review.`, tag: "soc-watch-agent-batch" });
              else for (const alert of eligible) new Notification(alert.title ?? "SOC Watch server alert", { body: [alert.indicator, alert.activity?.infrastructures.join(", "), alert.reasons?.join(" ") || alert.message].filter(Boolean).join(" | ").slice(0, 500), tag: `soc-watch-agent-${alert.id}` });
            } catch (caught) { setBrowserError(`Browser notification failed: ${errorMessage(caught)}`); browserActive.current = false; setBrowserEnabled(false); }
          }
        }
      } catch (caught) { if (!controller.signal.aborted && !aborted(caught)) setPollError(errorMessage(caught)); }
      finally { if (!controller.signal.aborted) timer = setTimeout(() => void poll(), 10_000); }
    };
    void poll();
    return () => { controller.abort(); clearTimeout(timer); };
  }, [authenticated, api, refresh]);

  const action: Action = async (key, path, body, method = "POST") => {
    if (state?.session?.role === "analyst" && ["/config", "/rules", "/notifications", "/clear", "/test"].some(endpoint => path === endpoint || path.startsWith(`${endpoint}/`))) {
      setError("An administrator session is required for this action."); return false;
    }
    if (pending.current) return false;
    pending.current = true; setBusy(key); setError(""); setSuccess("");
    try {
      await api(path, { method, ...(body === undefined ? {} : { body }) });
      if (!mounted.current) return false;
      setRefresh(value => value + 1);
      return true;
    } catch (caught) { if (mounted.current && !aborted(caught)) setError(errorMessage(caught)); return false; }
    finally { pending.current = false; if (mounted.current) setBusy(""); }
  };

  const login = async (event: React.FormEvent) => {
    event.preventDefault();
    if (pending.current) return;
    pending.current = true; setBusy("login"); setError("");
    const enteredToken = token; setToken("");
    try {
      await api("/login", { method: "POST", body: { token: enteredToken } });
      if (mounted.current) { sessionStartedAt.current = Date.now(); alertCursor.current = null; setAuthenticated(true); }
    } catch (caught) { if (mounted.current && !aborted(caught)) setError(errorMessage(caught)); }
    finally { pending.current = false; if (mounted.current) setBusy(""); }
  };

  const logout = async () => {
    if (await action("logout", "/logout")) {
      for (const controller of controllers.current) controller.abort();
      setAuthenticated(false); setState(null); setToken(""); setSelectedId(null); setClearOpen(false);
      setSuccess(""); setPollError(""); setUpdatedAt(null); browserActive.current = false; setBrowserEnabled(false); alertCursor.current = null;
    }
  };

  const enableBrowser = async () => {
    setBrowserError("");
    if (typeof Notification === "undefined" || !window.isSecureContext) { setBrowserError("Browser notifications are unavailable. A secure browser context is required."); return; }
    try {
      const granted = await Notification.requestPermission();
      if (!mounted.current) return;
      setPermission(granted);
      browserActive.current = granted === "granted"; setBrowserEnabled(granted === "granted"); browserRequestedAt.current = Date.now();
      if (granted !== "granted") setBrowserError(granted === "denied" ? "Browser permission denied. Change this site's notification permission in your browser." : "Notification permission was not granted.");
    } catch (caught) { if (mounted.current) setBrowserError(errorMessage(caught)); }
  };

  const health = state ? scanHealth(state) : null;
  const canAdmin = state?.session?.role !== "analyst";
  const selected = state?.findings.find(finding => finding.id === selectedId);
  const openCount = state?.findings.filter(finding => finding.status === "open" || finding.status === "acknowledged").length ?? 0;
  const tabs: { name: Tab; icon: typeof FileSearch }[] = [
    { name: "Findings", icon: FileSearch }, { name: "Watch Rules", icon: ShieldCheck },
    { name: "Agent Settings", icon: Settings }, { name: "Integrations", icon: ShieldCheck }, { name: "Delivery", icon: Send }
  ];

  return <div className="server-agent">
    <a className="sa-skip" href="#server-agent" onClick={event => { event.preventDefault(); document.getElementById("sa-content")?.focus(); }}>Skip to console</a>
    <header className="sa-header">
      <div className="sa-brand"><Server size={26} aria-hidden="true" /><div><h1>SOC Watch Server Agent</h1><span>{publicStatus?.version ? `v${publicStatus.version}` : "Server console"}</span></div></div>
      <div className="sa-actions">{authenticated && state?.session && <Badge>{state.session.user} / {state.session.role}</Badge>}<a className="sa-button" href="#"><ArrowLeft size={16} aria-hidden="true" />Back to bridge</a>
        {authenticated && <button type="button" className="sa-button" disabled={!!busy} onClick={() => void logout()}><LogOut size={16} aria-hidden="true" />{busy === "logout" ? "Signing out..." : "Log out"}</button>}</div>
    </header>
    <main id="sa-content" tabIndex={-1}>
      {!authenticated ? <section className="sa-auth">
        {checking ? <div className="sa-empty" role="status"><LoaderCircle className="sa-spin" size={24} aria-hidden="true" /><h2>Checking server agent</h2></div> : availabilityError ?
          <div className="sa-empty"><AlertTriangle size={26} className="sa-warning" aria-hidden="true" /><h2>Server agent unavailable</h2><p>{availabilityError}</p>{publicStatus?.requiresNode && <p>Required runtime: {message(publicStatus.requiresNode)}</p>}<button className="sa-button" onClick={() => setRetry(value => value + 1)}><RefreshCw size={16} aria-hidden="true" />Retry</button></div> :
          <form onSubmit={event => void login(event)}><h2><LogIn size={20} aria-hidden="true" />Server sign in</h2>
            {publicStatus?.message && <p className="sa-muted">{publicStatus.message}</p>}
            {publicStatus?.configured === false && <p className="sa-feedback sa-warning">Server data source configuration is required.</p>}
            <Field label="Server access token"><input type="password" name="server-agent-token" autoComplete="off" value={token} onChange={event => setToken(event.target.value)} required maxLength={4096} /></Field>
            <Feedback error={error} /><button className="sa-button sa-primary" disabled={!!busy || !token.trim()}><LogIn size={16} aria-hidden="true" />{busy === "login" ? "Signing in..." : "Sign in"}</button>
          </form>}
      </section> : <>
        <Feedback error={error} success={success} />
        {pollError && <p className="sa-feedback sa-error" role="alert"><AlertTriangle size={16} aria-hidden="true" />State refresh failed: {pollError}{updatedAt && ` Last update: ${date(updatedAt)}.`}</p>}
        {state && health ? <>
          {state.status.dataSource?.mode === "browser_relay" && <BrowserRelayControl api={api} config={state.config} dataSource={state.status.dataSource} canAdmin={canAdmin} onChange={() => setRefresh(value => value + 1)} onSettings={() => setTab("Agent Settings")} />}
          <section className="sa-status-strip" aria-label="Agent status">
            <div><span>Agent</span><Badge tone={health.tone}>{health.label}</Badge></div>
            <div><span>Heartbeat</span><strong>{date(record(state.status.heartbeat) ? state.status.heartbeat.at ?? state.status.heartbeat.timestamp ?? state.status.heartbeat.lastSeen : state.status.heartbeat)}</strong></div>
            <div><span>Last live success</span><strong>{date(state.status.live?.lastSuccess ?? state.status.lastSuccess)}</strong></div>
            <div><span>Next live check</span><strong>{state.config.enabled ? date(state.status.live?.nextScan ?? state.status.nextScan) : "Paused"}</strong></div>
            <div><span>Retained open findings</span><strong className="sa-number">{count(openCount)}</strong></div>
            <div><span>GTI / VirusTotal ({reputationSourceLabel(state)})</span><strong>{count(state.reputation.pending)} pending / {count(state.reputation.unavailable)} unavailable</strong></div>
          </section>
          {health.tone !== "good" && <p className={`sa-feedback sa-${health.tone}`}><Activity size={16} aria-hidden="true" />{health.detail}</p>}
          <section className="sa-section" aria-label="Live monitoring">
            <div className="sa-section-heading"><h2><Activity size={18} aria-hidden="true" />Live monitoring</h2><Toggle label="Live monitoring enabled" checked={state.config.enabled} onChange={enabled => void action("monitoring", "/config", { enabled }, "PUT")} disabled={!canAdmin || !!busy} /></div>
            <dl className="sa-facts"><div><dt>Window</dt><dd>{state.config.liveWindowMinutes ?? 5} minutes</dd></div><div><dt>Interval after check</dt><dd>{state.config.liveIntervalSeconds ?? 30} seconds</dd></div><div><dt>Evidence sampled</dt><dd>{count(state.status.live?.evidenceRead)}</dd></div><div><dt>Coverage</dt><dd>{state.status.live?.coverage ?? "Awaiting first check"}</dd></div></dl>
            {state.status.live && <details className="sa-details"><summary>Live detection stages</summary><dl className="sa-facts">{Object.entries(state.status.live.stages).map(([stage, result]) => <div key={stage}><dt>{human(stage)}</dt><dd className={result.error ? "sa-error" : ""}>{result.error ?? `${result.status} | ${count(result.matched)} matched | ${count(result.evidenceRead)} proof events`}</dd></div>)}</dl></details>}
            {state.status.historical && <div className="sa-section-heading"><p className={state.status.historical.paused ? "sa-error" : "sa-muted"}>Historical {state.status.historical.mode}: {count(state.status.historical.eventsRead)} reads / {count(state.status.historical.totalMatched)} matched. {state.status.historical.paused ? "Blocked." : "Background collection."}</p><button type="button" className="sa-button" disabled={!canAdmin || !!busy} onClick={() => setCancelOpen(true)}><Square size={16} aria-hidden="true" />Stop historical scan</button></div>}
            {!!state.status.lastError && state.status.live?.lastAttempt && <p className="sa-feedback sa-error">Historical/background error: {message(state.status.lastError)}</p>}
          </section>
          <div className="sa-console-toolbar"><nav className="sa-tabs" aria-label="Console views">{tabs.map(({ name, icon: Icon }) => <button type="button" key={name} className={tab === name ? "sa-active" : ""} aria-current={tab === name ? "page" : undefined} onClick={() => setTab(name)}><Icon size={16} aria-hidden="true" />{name}</button>)}</nav>
            <div className="sa-actions"><select aria-label="Scan mode" value={scanMode} onChange={event => setScanMode(event.target.value as ScanMode)}><option value="live">Live scan</option><option value="today">Today</option><option value="baseline">Baseline</option></select>
              <button type="button" className="sa-button sa-primary" disabled={!!busy || scanMode !== "live" && state.status.running || !state.status.configured || state.status.dataSource?.ready === false} onClick={() => void action("scan", "/scan", { mode: scanMode }).then(ok => { if (ok) setSuccess(scanMode === "live" ? "Fresh live check queued." : "Historical collection queued."); })}><Play size={16} aria-hidden="true" />{busy === "scan" ? "Queueing..." : "Scan"}</button>
              <button type="button" className="sa-icon" title="Refresh state" aria-label="Refresh state" disabled={!!busy} onClick={() => setRefresh(value => value + 1)}><RefreshCw size={17} /></button></div>
          </div>
          <div className="sa-view" aria-label={tab}>
            {tab === "Findings" && <Findings state={state} health={health} onInspect={setSelectedId} onClear={() => setClearOpen(true)} disabled={!!busy || !canAdmin} />}
            {tab === "Watch Rules" && <Rules rules={state.rules} channels={state.notifications.channels} action={action} busy={busy} mutationError={error} canAdmin={canAdmin} />}
            {tab === "Agent Settings" && <AgentSettings config={state.config} status={state.status} api={api} action={action} busy={busy} canAdmin={canAdmin} />}
            {tab === "Integrations" && <IntegrationSettings state={state} action={action} busy={busy} canAdmin={canAdmin} />}
            {tab === "Delivery" && <Delivery state={state} action={action} busy={busy} canAdmin={canAdmin} browserEnabled={browserEnabled} permission={permission} browserError={browserError} onEnable={() => void enableBrowser()} onDisable={() => { browserActive.current = false; setBrowserEnabled(false); }} />}
          </div>
          <footer className="sa-footer"><span>Updated {date(updatedAt)}</span><span>{count(state.reputation.scored)} reputation scored / {count(state.reputation.notFound)} not found / {count(state.campaigns?.length)} campaigns</span></footer>
        </> : <div className="sa-empty" role="status"><LoaderCircle className="sa-spin" size={24} aria-hidden="true" /><h2>Loading agent state</h2>{pollError && <button className="sa-button" onClick={() => setRefresh(value => value + 1)}><RefreshCw size={16} aria-hidden="true" />Retry</button>}</div>}
      </>}
    </main>
    {authenticated && selected && <FindingInspector key={selected.id} finding={selected} investigation={state?.investigations?.find(item => item.id === selected.id)} api={api} action={action} busy={busy} mutationError={error} onClose={() => setSelectedId(null)} />}
    {authenticated && canAdmin && cancelOpen && <Modal title="Stop historical collection" onClose={() => setCancelOpen(false)}><p>Stop after the current read returns? Collected proof and findings remain stored. Its checkpoint will not be advanced.</p><Feedback error={error} /><div className="sa-actions"><button className="sa-button" onClick={() => setCancelOpen(false)}>Keep collecting</button><button className="sa-button sa-danger" disabled={!!busy} onClick={() => void action("cancel", "/scan/cancel", { confirm: true }).then(ok => { if (ok) { setCancelOpen(false); setSuccess("Historical cancellation queued. Live monitoring is unchanged."); } })}><Square size={16} aria-hidden="true" />Stop collection</button></div></Modal>}
    {authenticated && canAdmin && clearOpen && <Modal title="Clear active findings" onClose={() => setClearOpen(false)}><p>Resolve and archive {count(openCount)} active findings? Audit history is retained.</p><Feedback error={error} /><div className="sa-actions"><button type="button" className="sa-button" onClick={() => setClearOpen(false)}>Cancel</button><button type="button" className="sa-button sa-danger" disabled={!!busy} onClick={() => void action("clear", "/clear", { confirm: true }).then(ok => { if (ok) { setClearOpen(false); setSuccess("Active findings archived. Audit history retained."); } })}><Trash2 size={16} aria-hidden="true" />{busy === "clear" ? "Clearing..." : "Clear active findings"}</button></div></Modal>}
  </div>;
}

export default ServerAgent;

function BrowserRelayControl({ api, config, dataSource, canAdmin, onChange, onSettings }: {
  api: Api; config: AgentConfig; dataSource: NonNullable<AgentState["status"]["dataSource"]>; canAdmin: boolean; onChange: () => void; onSettings: () => void;
}) {
  const [enabled, setEnabled] = useState(false);
  const [progress, setProgress] = useState<RelayProgress>({ state: "disconnected", message: "" });
  const scope = JSON.stringify({ indexPattern: config.indexPattern, timestampField: config.timestampField, infrastructureField: config.infrastructureField });
  const [authorizedScope, setAuthorizedScope] = useState(scope);
  const refresh = useRef(onChange); refresh.current = onChange;
  useEffect(() => {
    if (enabled && authorizedScope !== scope) {
      setEnabled(false); setProgress({ state: "disconnected", message: "Log scope changed. Connect this browser again to authorize the saved scope." });
    }
  }, [enabled, authorizedScope, scope]);
  useEffect(() => {
    if (!enabled || !canAdmin) return;
    const controller = new AbortController();
    void runBrowserRelay({ api, bridge: sendBridgeMessage, signal: controller.signal,
      policy: JSON.parse(authorizedScope),
      onProgress: next => { if (controller.signal.aborted) return; setProgress(next); if (next.retrying === false) setEnabled(false); refresh.current(); }
    });
    return () => controller.abort();
  }, [enabled, canAdmin, api, authorizedScope]);
  const connected = enabled ? progress.state === "connected" && dataSource.ready : dataSource.ready;
  return <section className="sa-relay" aria-label="Browser data source">
    <div className="sa-section-heading"><div className="sa-actions"><Activity size={18} aria-hidden="true" /><h2>Browser relay</h2><Badge tone={connected ? "good" : "error"}>{connected ? enabled ? "This browser connected" : "Another browser connected" : progress.state === "connecting" ? "Connecting" : "Disconnected"}</Badge></div>
      {canAdmin && <button className="sa-button" type="button" onClick={() => { if (!enabled) setAuthorizedScope(scope); else setProgress({ state: "disconnected", message: "" }); setEnabled(value => !value); refresh.current(); }}><Activity size={16} aria-hidden="true" />{enabled ? progress.state === "connected" ? "Disconnect browser" : "Stop reconnecting" : "Connect this browser"}</button>}</div>
    <p className="sa-muted">Keep this Server Agent page and a signed-in Kibana tab open on your work computer. Collection pauses when the browser disconnects. Returned log evidence is stored on this server; Kibana credentials stay in your browser.</p>
    {progress.message && <p className={progress.state === "disconnected" ? "sa-error" : "sa-muted"} role="status">{progress.message}{enabled && progress.state === "disconnected" && progress.retrying !== false && " Reconnecting automatically."}</p>}
    {progress.retrying === false && <button className="sa-button" type="button" onClick={onSettings}><Settings size={16} aria-hidden="true" />Review Agent Settings</button>}
    {!enabled && dataSource.source && <p className="sa-muted">{dataSource.source.kibanaBaseUrl} / {dataSource.source.spaceId}</p>}
    {!canAdmin && <p className="sa-warning">An administrator must authorize the work browser relay.</p>}
  </section>;
}

export function orderedFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => b.priority - a.priority || Date.parse(b.lastSeen) - Date.parse(a.lastSeen) || a.id.localeCompare(b.id));
}

function Findings({ state, health, onInspect, onClear, disabled }: {
  state: AgentState; health: ReturnType<typeof scanHealth>; onInspect: (id: string) => void;
  onClear: () => void; disabled: boolean;
}) {
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("active");
  const [timeScope, setTimeScope] = useState("recent");
  const [page, setPage] = useState(0);
  const rows = useMemo(() => orderedFindings(state.findings).filter(finding => {
    const matches = filter === "all" || filter === "active" && ["open", "acknowledged"].includes(finding.status) || finding.status === filter;
    const recent = timeScope === "retained" || !state.status.live || Date.parse(finding.lastSeen) >= Date.now() - (state.config.liveWindowMinutes ?? 5) * 60000;
    return matches && recent && `${finding.title} ${finding.indicator} ${finding.category} ${finding.assignedTo ?? ""}`.toLowerCase().includes(search.toLowerCase());
  }), [state.findings, filter, search, timeScope, state.status.live, state.config.liveWindowMinutes]);
  const pages = Math.max(1, Math.ceil(rows.length / 40));
  const current = Math.min(page, pages - 1);
  const runs = [...state.runs].sort((a, b) => Date.parse(b.startedAt) - Date.parse(a.startedAt)).slice(0, 12);
  return <>
    <section aria-label="Findings">
      <div className="sa-section-heading"><h2>Findings <span className="sa-muted">{count(rows.length)}</span></h2><div className="sa-actions">
        <label className="sa-search"><Search size={16} aria-hidden="true" /><input aria-label="Search findings" placeholder="Indicator, title, assignee" value={search} onChange={event => { setSearch(event.target.value); setPage(0); }} /></label>
        <select aria-label="Finding time scope" value={timeScope} onChange={event => { setTimeScope(event.target.value); setPage(0); }}><option value="recent">Recent {state.config.liveWindowMinutes ?? 5} minutes</option><option value="retained">Retained history</option></select>
        <select aria-label="Finding status filter" value={filter} onChange={event => { setFilter(event.target.value); setPage(0); }}><option value="active">Active</option><option value="all">All statuses</option><option value="open">Open</option><option value="acknowledged">Acknowledged</option><option value="resolved">Resolved</option><option value="false_positive">False positive</option></select>
        <button className="sa-icon sa-danger-text" title="Clear active findings" aria-label="Clear active findings" onClick={onClear} disabled={disabled || !state.findings.some(finding => ["open", "acknowledged"].includes(finding.status))}><Trash2 size={17} /></button>
      </div></div>
      {rows.length ? <div className="sa-table-wrap" tabIndex={0} role="region" aria-label="Findings ordered by priority"><table className="sa-table sa-findings-table"><thead><tr><th scope="col">Priority</th><th scope="col">Finding / indicator</th><th scope="col">Behavior</th><th scope="col">Confidence</th><th scope="col">Reputation</th><th scope="col">Retained proof events</th><th scope="col">Last seen</th><th scope="col">Status / assignee</th></tr></thead>
        <tbody>{rows.slice(current * 40, current * 40 + 40).map(finding => <tr key={finding.id}>
          <td><strong className="sa-number">{count(finding.priority)}</strong><Badge tone={finding.severity === "critical" || finding.severity === "high" ? "error" : finding.severity === "medium" ? "warning" : "neutral"}>{finding.severity}</Badge></td>
          <td><button className="sa-finding-link" onClick={() => onInspect(finding.id)}>{finding.title}</button><code>{finding.indicator}</code><small>{finding.category} / {finding.indicatorType}</small></td>
          <td className="sa-number">{count(finding.behaviorScore)}</td><td className="sa-number">{count(finding.confidence)}</td>
          <td>{finding.reputation ? <><Badge tone={statusTone(finding.reputation.status)}>{human(finding.reputation.status)}</Badge><small>{finding.reputation.verdict || "No verdict"} / {count(finding.reputation.score)}</small></> : <Badge>Not reported</Badge>}</td>
          <td className="sa-number">{count(finding.count)}</td><td className="sa-date">{date(finding.lastSeen)}</td>
          <td><Badge tone={statusTone(finding.status)}>{human(finding.status)}</Badge><small>{finding.assignedTo || "Unassigned"}</small></td>
        </tr>)}</tbody></table></div> : <div className="sa-empty"><FileSearch size={24} aria-hidden="true" /><h3>{search || filter !== "active" ? "No findings match these filters" : "No active findings"}</h3><p>{health.tone === "good" ? "No matching findings in the reported scan results." : `${health.label}: ${health.detail}`}</p></div>}
      {pages > 1 && <div className="sa-pagination"><span>{current * 40 + 1}-{Math.min((current + 1) * 40, rows.length)} of {count(rows.length)}</span><div className="sa-actions"><button className="sa-icon" title="Previous page" aria-label="Previous page" disabled={current === 0} onClick={() => setPage(current - 1)}><ChevronLeft size={18} /></button><span>Page {current + 1} / {pages}</span><button className="sa-icon" title="Next page" aria-label="Next page" disabled={current === pages - 1} onClick={() => setPage(current + 1)}><ChevronRight size={18} /></button></div></div>}
    </section>
    <section className="sa-section" aria-label="Run history"><div className="sa-section-heading"><h2>Recent runs</h2><span className="sa-muted">{count(state.runs.length)} recorded</span></div>
      {runs.length ? <div className="sa-table-wrap" tabIndex={0} role="region" aria-label="Recent agent runs"><table className="sa-table"><thead><tr><th scope="col">Started / mode</th><th scope="col">Status</th><th scope="col">Read / matched</th><th scope="col">Invalid</th><th scope="col">Coverage</th><th scope="col">Window / finished</th></tr></thead><tbody>{runs.map(run => <tr key={run.id}><td>{date(run.startedAt)}<small>{run.mode}</small></td><td><Badge tone={run.error ? "error" : statusTone(run.status)}>{human(run.status)}</Badge>{run.error && <small className="sa-error">{run.error}</small>}</td><td className="sa-number">{count(run.eventsRead)} / {count(run.totalMatched)}</td><td className="sa-number">{count(run.invalidEvents)}</td><td><span className={coverageIncomplete(run.coverage) ? "sa-warning" : ""}>{message(run.coverage)}</span></td><td className="sa-date">{date(run.from)} to {date(run.to)}<small>Finished: {date(run.finishedAt)}</small></td></tr>)}</tbody></table></div> : <p className="sa-empty-line">No runs reported. Scan coverage has not been established.</p>}
    </section>
    <section className="sa-section" aria-label="Feed campaigns"><div className="sa-section-heading"><h2>Feed campaigns</h2><span className="sa-muted">{count(state.campaigns?.length)} reported</span></div>
      {state.campaigns?.length ? <div className="sa-table-wrap" tabIndex={0} role="region" aria-label="Feed campaign progress"><table className="sa-table"><thead><tr><th scope="col">Campaign</th><th scope="col">Status</th><th scope="col">Checked / available</th><th scope="col">Offset</th><th scope="col">Created / expires</th><th scope="col">Providers</th></tr></thead><tbody>{state.campaigns.slice(0, 5).map(campaign => <tr key={campaign.id}><td><code>{campaign.id}</code></td><td><Badge tone={campaign.lastError ? "error" : statusTone(campaign.status)}>{human(campaign.status)}</Badge>{campaign.lastError && <small className="sa-error">{campaign.lastError}</small>}</td><td className="sa-number">{count(campaign.checked)} / {count(campaign.totalAvailable)}</td><td className="sa-number">{count(campaign.offset)}</td><td className="sa-date">{date(campaign.createdAt)}<small>Expires: {date(campaign.expiresAt)}</small></td><td><details><summary>Provider status</summary><pre>{JSON.stringify(campaign.providers, null, 2)}</pre></details></td></tr>)}</tbody></table></div> : <p className="sa-empty-line">No feed campaigns reported.</p>}
    </section>
  </>;
}

function FindingInspector({ finding, investigation, api, action, busy, mutationError, onClose }: {
  finding: Finding; investigation: Investigation | undefined; api: Api; action: Action; busy: string; mutationError: string; onClose: () => void;
}) {
  const [status, setStatus] = useState(finding.status);
  const [assignedTo, setAssignedTo] = useState(finding.assignedTo ?? "");
  const [note, setNote] = useState("");
  const [dirty, setDirty] = useState(false);
  const [saved, setSaved] = useState("");
  const [investigationQueued, setInvestigationQueued] = useState(false);
  const [proof, setProof] = useState<Evidence | null>(null);
  const [raw, setRaw] = useState<string | null>(null);
  const [proofError, setProofError] = useState("");
  const [proofLoading, setProofLoading] = useState(false);
  const [proofRetry, setProofRetry] = useState(0);
  const [proofPage, setProofPage] = useState(0);
  useEffect(() => { if (!dirty) { setStatus(finding.status); setAssignedTo(finding.assignedTo ?? ""); } }, [finding]);
  useEffect(() => {
    if (!proof) return;
    const controller = new AbortController();
    setRaw(null); setProofError(""); setProofLoading(true);
    const query = new URLSearchParams({ index: proof.index, id: proof.eventId });
    void api<{ event: unknown }>(`/evidence?${query}`, { signal: controller.signal, maxBytes: 256 * 1024 }).then(result => {
      if (!record(result) || !Object.hasOwn(result, "event")) throw new Error("Server returned an invalid evidence response.");
      setRaw(JSON.stringify(result.event, null, 2));
    }).catch(caught => { if (!aborted(caught)) setProofError(errorMessage(caught)); })
      .finally(() => { if (!controller.signal.aborted) setProofLoading(false); });
    return () => controller.abort();
  }, [api, proof, proofRetry]);
  const reputation = finding.reputation;
  const proofPages = Math.max(1, Math.ceil(finding.evidence.length / 20));
  const currentProofPage = Math.min(proofPage, proofPages - 1);
  return <Modal title={finding.title} onClose={onClose}>
    <div className="sa-inspector-summary"><code>{finding.indicator}</code><Badge>{finding.indicatorType}</Badge><Badge tone={finding.severity === "critical" || finding.severity === "high" ? "error" : "warning"}>{finding.severity}</Badge><Badge>{human(finding.status)}</Badge></div>
    <dl className="sa-facts"><div><dt>Priority</dt><dd>{finding.priority}</dd></div><div><dt>Behavior score</dt><dd>{finding.behaviorScore}</dd></div><div><dt>Confidence</dt><dd>{finding.confidence}</dd></div><div><dt>Retained proof events</dt><dd>{count(finding.count)}</dd></div><div><dt>First seen</dt><dd>{date(finding.firstSeen)}</dd></div><div><dt>Last seen</dt><dd>{date(finding.lastSeen)}</dd></div><div><dt>Category</dt><dd>{finding.category}</dd></div><div><dt>Fingerprint</dt><dd><code>{finding.fingerprint}</code></dd></div></dl>
    <section className="sa-section"><h3>Behavioral reasons</h3>{finding.reasons.length ? <ul className="sa-list">{finding.reasons.map((reason, i) => <li key={i}>{reason}</li>)}</ul> : <p className="sa-muted">No behavioral reasons reported.</p>}</section>
    {finding.activity && <section className="sa-section"><h3>Observed activity</h3><dl className="sa-facts"><div><dt>Blocked events (lower bound)</dt><dd>{count(finding.activity.blockedAttemptsLowerBound)}</dd></div><div><dt>Infrastructure in proof</dt><dd>{finding.activity.infrastructures.join(", ") || "Not recorded"}</dd></div><div><dt>Source GeoIP in proof</dt><dd>{finding.activity.countries.join(", ") || "Not recorded"}</dd></div><div><dt>Targets</dt><dd>{finding.activity.targets.join(", ") || "Not recorded"}</dd></div><div><dt>Ports</dt><dd>{finding.activity.ports.join(", ") || "Not recorded"}</dd></div><div><dt>Ports 49152-65535</dt><dd>{finding.activity.ports.filter(port => port >= 49152).join(", ") || "None in returned evidence"}</dd></div></dl>{finding.activity.allowed.length > 0 && <><h4>Accepted/allowed activity in the same window</h4><ul className="sa-list">{finding.activity.allowed.map((event, index) => <li key={index}>{date(event.timestamp)} | {event.action || "success"} | {event.destinationIp || "Unknown target"}:{event.port || "Unknown port"} | {event.infrastructure || "Unknown infrastructure"}</li>)}</ul></>}</section>}
    <section className="sa-section"><h3>Reputation</h3>{reputation ? <><div className="sa-actions"><Badge tone={statusTone(reputation.status)}>{human(reputation.status)}</Badge><span>{reputation.verdict || "No verdict reported"}</span></div><dl className="sa-facts"><div><dt>Provider</dt><dd>{reputation.source ?? "Not reported"}</dd></div><div><dt>GTI verdict</dt><dd>{reputation.gtiVerdict ?? "Not supplied by provider"}</dd></div><div><dt>Score</dt><dd>{count(reputation.score)}</dd></div><div><dt>Malicious</dt><dd>{count(reputation.malicious)}</dd></div><div><dt>Suspicious</dt><dd>{count(reputation.suspicious)}</dd></div><div><dt>Checked</dt><dd>{date(reputation.checkedAt)}</dd></div></dl></> : <p className="sa-muted">Reputation unavailable for this finding.</p>}</section>
    <section className="sa-section"><h3>Limitations</h3>{finding.limitations.length ? <ul className="sa-list sa-warning">{finding.limitations.map((limitation, i) => <li key={i}>{limitation}</li>)}</ul> : <p className="sa-muted">No limitations reported.</p>}</section>
    <section className="sa-section"><div className="sa-section-heading"><h3>Investigator</h3><div className="sa-actions">{investigation && <Badge tone={statusTone(investigation.status)}>{human(investigation.status)}</Badge>}<button type="button" className="sa-button" disabled={!!busy || investigation?.status === "pending"} onClick={() => void action("investigate", "/investigate", { findingId: finding.id }).then(ok => { if (ok) setInvestigationQueued(true); })}><FileSearch size={16} aria-hidden="true" />{busy === "investigate" ? "Queueing..." : investigation ? "Investigate again" : "Investigate"}</button></div></div>
      {investigationQueued && !investigation && <p role="status" className="sa-muted">Investigation queued. Awaiting server status.</p>}
      {investigation?.briefing && <p>{investigation.briefing}</p>}<Feedback error={investigation?.error} />
      {investigation?.facts?.length ? <details className="sa-details" open><summary>Investigation facts</summary><pre>{JSON.stringify(investigation.facts, null, 2)}</pre></details> : null}
      {investigation?.limitations?.length ? <ul className="sa-list sa-warning">{investigation.limitations.map((value, i) => <li key={i}>{value}</li>)}</ul> : null}
      {investigation?.steps?.length ? <details className="sa-details"><summary>Investigation steps</summary><pre>{JSON.stringify(investigation.steps, null, 2)}</pre></details> : null}
      {investigation?.timeline?.length ? <details className="sa-details"><summary>Investigation timeline ({investigation.timeline.length})</summary><pre>{JSON.stringify(investigation.timeline, null, 2)}</pre></details> : null}
      <Feedback error={mutationError} />
    </section>
    <section className="sa-section"><div className="sa-section-heading"><h3>Proof references</h3><span className="sa-muted">{count(finding.evidence.length)} events</span></div>
      {finding.evidence.length ? <><div className="sa-proof-list">{finding.evidence.slice(currentProofPage * 20, currentProofPage * 20 + 20).map((evidence, i) => <div className="sa-proof" key={`${evidence.index}:${evidence.eventId}:${i}`}><div><code>{evidence.index} / {evidence.eventId}</code><small>{date(evidence.timestamp)}</small><p>{evidence.reason}</p></div><button className="sa-icon" title="Inspect raw event" aria-label={`Inspect event ${evidence.eventId}`} onClick={() => { setProof(evidence); setProofRetry(value => value + 1); }} disabled={proofLoading && proof?.eventId === evidence.eventId && proof.index === evidence.index}><FileSearch size={17} /></button></div>)}</div>
        {proofPages > 1 && <div className="sa-pagination"><span>References {currentProofPage * 20 + 1}-{Math.min((currentProofPage + 1) * 20, finding.evidence.length)}</span><div className="sa-actions"><button className="sa-icon" title="Previous references" aria-label="Previous references" disabled={currentProofPage === 0} onClick={() => setProofPage(currentProofPage - 1)}><ChevronLeft size={17} /></button><button className="sa-icon" title="Next references" aria-label="Next references" disabled={currentProofPage === proofPages - 1} onClick={() => setProofPage(currentProofPage + 1)}><ChevronRight size={17} /></button></div></div>}
      </> : <p className="sa-muted">No proof references reported.</p>}
      {proof && <div className="sa-raw-event"><h4>Raw event: {proof.eventId}</h4>{proofLoading && <p role="status">Fetching event...</p>}<Feedback error={proofError} />{proofError && <button className="sa-button" onClick={() => setProofRetry(value => value + 1)}><RefreshCw size={16} aria-hidden="true" />Retry event</button>}{raw && <pre tabIndex={0}>{raw}</pre>}</div>}
    </section>
    <form className="sa-section" onSubmit={event => { event.preventDefault(); setSaved(""); void action("finding", `/findings/${encodeURIComponent(finding.id)}`, { status, assignedTo: assignedTo.trim(), ...(note.trim() ? { note: note.trim() } : {}) }, "PATCH").then(ok => { if (ok) { setNote(""); setDirty(false); setSaved("Finding updated."); } }); }}>
      <h3>Disposition</h3><div className="sa-form-grid"><Field label="Status"><select value={status} onChange={event => { setStatus(event.target.value as FindingStatus); setDirty(true); }}><option value="open">Open</option><option value="acknowledged">Acknowledged</option><option value="resolved">Resolved</option><option value="false_positive">False positive</option></select></Field><Field label="Assigned to"><input value={assignedTo} onChange={event => { setAssignedTo(event.target.value); setDirty(true); }} maxLength={200} /></Field><Field label="Add audit note" wide><textarea value={note} onChange={event => { setNote(event.target.value); setDirty(true); }} rows={3} maxLength={2000} /></Field></div>
      {finding.notes != null && <details className="sa-details"><summary>Existing notes</summary><pre>{typeof finding.notes === "string" ? finding.notes : JSON.stringify(finding.notes, null, 2)}</pre></details>}
      <Feedback error={mutationError} success={saved} /><button className="sa-button sa-primary" disabled={!!busy || !dirty}><Save size={16} aria-hidden="true" />{busy === "finding" ? "Saving..." : "Save disposition"}</button>
    </form>
  </Modal>;
}

const NEW_RULE: Omit<WatchRule, "id"> = {
  name: "", indicatorType: "ip", indicatorValue: "", includeSubdomains: false, enabled: true,
  minEvents: 1, minPriority: 50, cooldownMinutes: 60, channels: [], scope: {}, requireSuccess: false
};

function Rules({ rules, channels, action, busy, mutationError, canAdmin }: { rules: WatchRule[]; channels: Channel[]; action: Action; busy: string; mutationError: string; canAdmin: boolean }) {
  const [draft, setDraft] = useState({ ...NEW_RULE });
  const [editingId, setEditingId] = useState<string | null>(null);
  const formRef = useRef<HTMLFormElement>(null);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [remove, setRemove] = useState<WatchRule | null>(null);
  const [deleteError, setDeleteError] = useState("");
  const patch = (value: Partial<Omit<WatchRule, "id">>) => { setDraft(previous => ({ ...previous, ...value })); setSuccess(""); };
  const submit = (event: React.FormEvent) => {
    event.preventDefault(); setSuccess("");
    const clean = { ...draft, name: draft.name.trim(), indicatorValue: draft.indicatorValue.trim(), scope: { ...(draft.scope.host?.trim() ? { host: draft.scope.host.trim() } : {}), ...(draft.scope.infrastructure?.trim() ? { infrastructure: draft.scope.infrastructure.trim() } : {}) } };
    const invalid = validateRule(clean); setError(invalid ?? ""); if (invalid) return;
    void action("rule", "/rules", { ...clean, ...(editingId ? { id: editingId } : {}) }).then(ok => { if (ok) { setDraft({ ...NEW_RULE }); setEditingId(null); setSuccess(editingId ? "Watch rule updated." : "Watch rule created."); } else setError("Watch rule was not saved. Review the server error above."); });
  };
  return <>
    <section><fieldset className="sa-form-body" disabled={!canAdmin || !!busy}><div className="sa-section-heading"><h2>Watch rules</h2><span className="sa-muted">{count(rules.filter(rule => rule.enabled).length)} enabled / {count(rules.length)} total</span></div>
      {rules.length ? <div className="sa-table-wrap" tabIndex={0} role="region" aria-label="Watch rules"><table className="sa-table"><thead><tr><th scope="col">Rule / indicator</th><th scope="col">State</th><th scope="col">Scope</th><th scope="col">Threshold</th><th scope="col">Delivery</th><th scope="col">Action</th></tr></thead><tbody>{rules.map(rule => <tr key={rule.id}><td><strong>{rule.name}</strong><code>{rule.indicatorType}: {rule.indicatorValue}</code>{rule.includeSubdomains && <small>Subdomains included</small>}</td><td><Badge tone={rule.enabled ? "good" : "neutral"}>{rule.enabled ? "Enabled" : "Disabled"}</Badge></td><td>{rule.scope?.host ? `Host: ${rule.scope.host}` : "All hosts"}<small>{rule.scope?.infrastructure ? `Infrastructure: ${rule.scope.infrastructure}` : "All infrastructure"}</small></td><td>{count(rule.minEvents)} events / priority {rule.minPriority}<small>{rule.requireSuccess ? "Successful events required" : "All event outcomes"}</small></td><td>{rule.channels.map(id => channels.find(channel => channel.id === id)?.name ?? id).join(", ") || "No channels"}<small>{rule.cooldownMinutes} min cooldown</small></td><td><div className="sa-actions"><button className="sa-icon" aria-label={`Edit rule ${rule.name}`} title="Edit rule" disabled={!!busy} onClick={() => { const { id, ...fields } = rule; setDraft({ ...fields, scope: { ...fields.scope }, channels: [...fields.channels] }); setEditingId(id); setError(""); setSuccess(""); formRef.current?.scrollIntoView({ block: "start" }); formRef.current?.querySelector("input")?.focus(); }}><Pencil size={17} /></button><button className="sa-icon sa-danger-text" aria-label={`Delete rule ${rule.name}`} title="Delete rule" disabled={!!busy} onClick={() => { setRemove(rule); setDeleteError(""); }}><Trash2 size={17} /></button></div></td></tr>)}</tbody></table></div> : <p className="sa-empty-line">No watch rules configured.</p>}
    </fieldset></section>
    {canAdmin && <form className="sa-section" onSubmit={submit} ref={formRef}><fieldset className="sa-form-body" disabled={!!busy}><h2>{editingId ? "Edit watch rule" : "Add watch rule"}</h2><div className="sa-form-grid">
      <Field label="Rule name"><input required maxLength={200} value={draft.name} onChange={event => patch({ name: event.target.value })} /></Field>
      <Field label="Indicator type"><select value={draft.indicatorType} onChange={event => patch({ indicatorType: event.target.value as IndicatorType, includeSubdomains: false })}><option value="ip">IP address</option><option value="domain">Domain</option><option value="hash">File hash</option><option value="identity">Identity</option></select></Field>
      <Field label="Indicator" wide><input required maxLength={253} className="sa-mono" value={draft.indicatorValue} onChange={event => patch({ indicatorValue: event.target.value })} /></Field>
      <Field label="Host scope"><input value={draft.scope.host ?? ""} onChange={event => patch({ scope: { ...draft.scope, host: event.target.value } })} maxLength={256} /></Field>
      <Field label="Infrastructure scope"><input value={draft.scope.infrastructure ?? ""} onChange={event => patch({ scope: { ...draft.scope, infrastructure: event.target.value } })} maxLength={256} /></Field>
      <Field label="Minimum events"><input type="number" min={1} max={100000} step={1} required value={draft.minEvents} onChange={event => patch({ minEvents: Number(event.target.value) })} /></Field>
      <Field label="Minimum priority"><input type="number" min={0} max={100} step={1} required value={draft.minPriority} onChange={event => patch({ minPriority: Number(event.target.value) })} /></Field>
      <Field label="Cooldown (minutes)"><input type="number" min={1} max={10080} step={1} required value={draft.cooldownMinutes} onChange={event => patch({ cooldownMinutes: Number(event.target.value) })} /></Field>
      <div className="sa-toggle-group"><Toggle label="Enabled" checked={draft.enabled} onChange={enabled => patch({ enabled })} /><Toggle label="Require successful events" checked={draft.requireSuccess} onChange={requireSuccess => patch({ requireSuccess })} />{draft.indicatorType === "domain" && <Toggle label="Include subdomains" checked={draft.includeSubdomains} onChange={includeSubdomains => patch({ includeSubdomains })} />}</div>
      <fieldset className="sa-channel-options sa-wide"><legend>Alert channels</legend>{channels.length ? channels.map(channel => <Toggle key={channel.id} label={`${channel.name}${!channel.enabled ? " (disabled)" : !channel.configured ? " (not configured)" : ""}`} checked={draft.channels.includes(channel.id)} onChange={enabled => patch({ channels: enabled ? [...draft.channels, channel.id] : draft.channels.filter(id => id !== channel.id) })} />) : <p className="sa-muted">No delivery channels configured.</p>}</fieldset>
    </div><Feedback error={error} success={success} /><div className="sa-actions"><button className="sa-button sa-primary" disabled={!!busy || !editingId && rules.length >= 500}>{editingId ? <Save size={16} aria-hidden="true" /> : <Plus size={16} aria-hidden="true" />}{busy === "rule" ? "Saving..." : editingId ? "Save rule" : "Add rule"}</button>{editingId && <button type="button" className="sa-button" disabled={!!busy} onClick={() => { setEditingId(null); setDraft({ ...NEW_RULE }); setError(""); }}>Cancel edit</button>}</div></fieldset></form>}
    {remove && <Modal title="Delete watch rule" onClose={() => setRemove(null)}><p>Delete the rule "{remove.name}" for {remove.indicatorValue}?</p><Feedback error={mutationError || deleteError} /><div className="sa-actions"><button className="sa-button" onClick={() => setRemove(null)}>Cancel</button><button className="sa-button sa-danger" disabled={!!busy} onClick={() => void action("delete-rule", `/rules/${encodeURIComponent(remove.id)}`, undefined, "DELETE").then(ok => { if (ok) { if (editingId === remove.id) { setEditingId(null); setDraft({ ...NEW_RULE }); } setRemove(null); } else setDeleteError("Rule deletion failed."); })}><Trash2 size={16} aria-hidden="true" />{busy === "delete-rule" ? "Deleting..." : "Delete rule"}</button></div></Modal>}
  </>;
}

export function configPatch(base: AgentConfig, draft: AgentConfig, advanced: string): Partial<AgentConfig> {
  let value: unknown;
  try { value = JSON.parse(advanced); } catch { throw new Error("Advanced settings must be valid JSON."); }
  if (!record(value) || Object.keys(value).some(key => !["assets", "accounts"].includes(key)) || !Array.isArray(value.assets) || !Array.isArray(value.accounts)) throw new Error("Advanced settings must contain assets and accounts arrays only.");
  const config = { ...draft, assets: value.assets, accounts: value.accounts };
  const invalid = validateConfig(config);
  if (invalid) throw new Error(invalid);
  return Object.fromEntries(Object.entries(config).filter(([key, item]) => JSON.stringify(item) !== JSON.stringify(base[key as keyof AgentConfig]))) as Partial<AgentConfig>;
}

export function dataViewScope(raw: unknown): Pick<AgentConfig, "indexPattern" | "timestampField"> {
  const view = record(raw) && record(raw.data_view) ? raw.data_view : null;
  if (!view || typeof view.title !== "string" || typeof view.timeFieldName !== "string" || !view.timeFieldName) {
    throw new Error("This Kibana data view has no configured time field. Choose a time-based log data view or set the fields manually.");
  }
  const policy = relayPolicySchema.safeParse({ indexPattern: view.title, timestampField: view.timeFieldName, infrastructureField: "observer.name" });
  if (!policy.success) throw new Error("This data view is outside the relay's supported log scope. Enter a specific non-system index pattern and time field manually.");
  return { indexPattern: policy.data.indexPattern, timestampField: policy.data.timestampField };
}

function KibanaDataViewPicker({ onSelect }: { onSelect: (scope: Pick<AgentConfig, "indexPattern" | "timestampField">) => void }) {
  const [views, setViews] = useState<DataViewSummary[]>([]);
  const [loading, setLoading] = useState(false);
  const [selected, setSelected] = useState("");
  const [error, setError] = useState("");
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  const load = async () => {
    setLoading(true); setError("");
    try {
      const response = await sendBridgeMessage<unknown, DataViewSummary[]>("dataViews.list", {});
      if (!response.success) throw new Error(response.error.message);
      if (!Array.isArray(response.data)) throw new Error("Kibana returned an invalid data-view list.");
      const available = response.data.filter(view => record(view) && typeof view.id === "string" && typeof view.title === "string");
      if (alive.current) { setViews(available); if (!available.length) setError("No accessible Kibana data views were returned. Enter the log index and time field manually."); }
    } catch (caught) { if (alive.current) setError(errorMessage(caught)); }
    finally { if (alive.current) setLoading(false); }
  };
  const choose = async (id: string) => {
    setSelected(id); setError(""); if (!id) return;
    setLoading(true);
    try {
      const response = await sendBridgeMessage("dataViews.get", { viewId: id });
      if (!response.success) throw new Error(response.error.message);
      const scope = dataViewScope(response.data);
      if (alive.current) onSelect(scope);
    } catch (caught) { if (alive.current) setError(errorMessage(caught)); }
    finally { if (alive.current) setLoading(false); }
  };
  return <div className="sa-data-view-picker">
    <div className="sa-actions"><Field label="Kibana data view"><select aria-label="Kibana data view" value={selected} disabled={loading || !views.length} onChange={event => void choose(event.target.value)}><option value="">Select a data view</option>{views.map(view => <option key={view.id} value={view.id}>{view.name || view.title}</option>)}</select></Field><button type="button" className="sa-button" disabled={loading} onClick={() => void load()}>{loading ? <LoaderCircle className="sa-spin" size={16} aria-hidden="true" /> : <RefreshCw size={16} aria-hidden="true" />}Load Kibana data views</button></div>
    <Feedback error={error} />
  </div>;
}

function AgentSettings({ config, status, api, action, busy, canAdmin }: {
  config: AgentConfig; status: AgentState["status"]; api: Api; action: Action; busy: string; canAdmin: boolean;
}) {
  const [draft, setDraft] = useState(config);
  const [advanced, setAdvanced] = useState(JSON.stringify({ assets: config.assets, accounts: config.accounts }, null, 2));
  const [dirty, setDirty] = useState(false);
  const draftBase = useRef(config);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [evaluation, setEvaluation] = useState<string | null>(null);
  const [evaluationError, setEvaluationError] = useState("");
  const [evaluationLoading, setEvaluationLoading] = useState(false);
  const [evaluationRequest, setEvaluationRequest] = useState(0);
  useEffect(() => { if (!dirty) { draftBase.current = config; setDraft(config); setAdvanced(JSON.stringify({ assets: config.assets, accounts: config.accounts }, null, 2)); } }, [config]);
  useEffect(() => {
    if (!evaluationRequest) return;
    const controller = new AbortController(); setEvaluationLoading(true); setEvaluationError(""); setEvaluation(null);
    void api("/evaluation", { signal: controller.signal, maxBytes: 256 * 1024 }).then(result => {
      if (result == null) throw new Error("Server returned no evaluation data.");
      setEvaluation(JSON.stringify(result, null, 2));
    }).catch(caught => { if (!aborted(caught)) setEvaluationError(caught instanceof AgentApiError && caught.status === 404 ? "Evaluation is unavailable on this deployment." : errorMessage(caught)); })
      .finally(() => { if (!controller.signal.aborted) setEvaluationLoading(false); });
    return () => controller.abort();
  }, [api, evaluationRequest]);
  const patch = (value: Partial<AgentConfig>) => { setDraft(previous => ({ ...previous, ...value })); setDirty(true); setSuccess(""); };
  const submit = (event: React.FormEvent) => {
    event.preventDefault(); setError(""); setSuccess("");
    try {
      const body = configPatch(draftBase.current, draft, advanced);
      if (!Object.keys(body).length) { setDirty(false); setSuccess("Settings are already up to date."); return; }
      void action("config", "/config", body, "PUT").then(ok => { if (ok) { setDirty(false); setSuccess("Agent settings saved."); } else setError("Settings were not saved. Review the server error above."); });
    } catch (caught) { setError(errorMessage(caught)); }
  };
  const numeric: { key: keyof Pick<AgentConfig, "intervalMinutes" | "overlapMinutes" | "maxEventsPerRun" | "pageSize" | "baselineDays" | "autoAlertMinPriority" | "retentionDays" | "liveIntervalSeconds" | "liveWindowMinutes">; label: string; min: number; max: number }[] = [
    { key: "liveIntervalSeconds", label: "Live check interval (seconds)", min: 30, max: 300 },
    { key: "liveWindowMinutes", label: "Live detection window (minutes)", min: 1, max: 15 },
    { key: "intervalMinutes", label: "Watch/backfill interval (minutes)", min: 1, max: 60 },
    { key: "overlapMinutes", label: "Overlap (minutes)", min: 1, max: 60 },
    { key: "maxEventsPerRun", label: "Maximum events per run", min: 500, max: 100000 },
    { key: "pageSize", label: "Page size", min: 100, max: 1000 },
    { key: "baselineDays", label: "Baseline (days)", min: 3, max: 90 },
    { key: "autoAlertMinPriority", label: "Automatic alert minimum priority", min: 0, max: 100 },
    { key: "retentionDays", label: "Retention (days)", min: 1, max: 90 }
  ];
  return <>
    <form onSubmit={submit}><fieldset className="sa-form-body" disabled={!canAdmin || !!busy}>
      <div className="sa-section-heading"><h2>Agent settings</h2><div className="sa-actions">{dirty && <span className="sa-warning">Unsaved changes</span>}<Toggle label="Live monitoring" checked={draft.enabled} onChange={enabled => patch({ enabled })} /></div></div>
      <div className="sa-toggle-group">{typeof draft.autoInvestigate === "boolean" && <Toggle label="Automatic investigation" checked={draft.autoInvestigate} onChange={autoInvestigate => patch({ autoInvestigate })} />}{typeof draft.huntEnabled === "boolean" && <Toggle label="Feed hunting" checked={draft.huntEnabled} onChange={huntEnabled => patch({ huntEnabled })} />}</div>
      {status.dataSource?.mode === "browser_relay" && <KibanaDataViewPicker onSelect={scope => patch(scope)} />}
      <div className="sa-form-grid sa-settings-grid">
        <Field label="Index pattern"><input required value={draft.indexPattern} onChange={event => patch({ indexPattern: event.target.value })} maxLength={512} /></Field>
        <Field label="Timestamp field"><input required value={draft.timestampField} onChange={event => patch({ timestampField: event.target.value })} maxLength={128} /></Field>
        <Field label="Infrastructure field"><input required value={draft.infrastructureField} onChange={event => patch({ infrastructureField: event.target.value })} maxLength={128} /></Field>
        <Field label="Timezone"><input required value={draft.timezone} onChange={event => patch({ timezone: event.target.value })} maxLength={100} /></Field>
        {numeric.map(({ key, label, min, max }) => <Field label={label} key={key}><input type="number" min={min} max={max} step={1} required value={draft[key]} onChange={event => patch({ [key]: Number(event.target.value) })} /></Field>)}
        <Field label="Elasticsearch query_string" hint="Lucene query_string syntax; KQL is not supported." wide><textarea className="sa-mono" rows={3} value={draft.query} onChange={event => patch({ query: event.target.value })} maxLength={2000} placeholder="*" /></Field>
      </div>
      <details className="sa-details"><summary>Detection thresholds</summary><div className="sa-form-grid sa-settings-grid">{detectionControls.map(({ key, label, min, max, step, fallback }) => <Field key={key} label={label}><input type="number" required min={min} max={max} step={step} value={draft[key] ?? fallback} onChange={event => patch({ [key]: Number(event.target.value) })} /></Field>)}</div></details>
      <details className="sa-details"><summary>Advanced: assets and accounts</summary><Field label="Assets and accounts JSON"><textarea className="sa-mono" spellCheck={false} rows={12} value={advanced} maxLength={200000} onChange={event => { setAdvanced(event.target.value); setDirty(true); setSuccess(""); }} /></Field></details>
      <ExceptionEditor exceptions={draft.exceptions ?? []} onChange={exceptions => patch({ exceptions })} disabled={!!busy} />
      <Feedback error={error} success={success} /><div className="sa-actions"><button className="sa-button sa-primary" disabled={!!busy || !dirty}><Save size={16} aria-hidden="true" />{busy === "config" ? "Saving..." : "Save settings"}</button><button type="button" className="sa-button" disabled={!!busy || !dirty} onClick={() => { draftBase.current = config; setDraft(config); setAdvanced(JSON.stringify({ assets: config.assets, accounts: config.accounts }, null, 2)); setDirty(false); setError(""); setSuccess(""); }}><RefreshCw size={16} aria-hidden="true" />Reset changes</button></div>
    </fieldset></form>
    <section className="sa-section"><h2>Scan checkpoint and coverage</h2><dl className="sa-facts"><div><dt>Checkpoint</dt><dd>{message(status.checkpoint)}</dd></div><div><dt>Coverage</dt><dd>{message(status.coverage)}</dd></div><div><dt>Last error</dt><dd className={status.lastError ? "sa-error" : ""}>{status.lastError ? message(status.lastError) : "None reported"}</dd></div></dl></section>
    <section className="sa-section"><div className="sa-section-heading"><h2>Evaluation</h2><button type="button" className="sa-button" disabled={evaluationLoading} onClick={() => setEvaluationRequest(value => value + 1)}><FileSearch size={16} aria-hidden="true" />{evaluationLoading ? "Loading..." : "Load evaluation"}</button></div><Feedback error={evaluationError} />{evaluation && <pre className="sa-json" tabIndex={0}>{evaluation}</pre>}</section>
  </>;
}

function IntegrationSettings({ state, action, busy, canAdmin }: { state: AgentState; action: Action; busy: string; canAdmin: boolean }) {
  const [draft, setDraft] = useState({ gti: "", threatfox: "", malwarebazaar: "" });
  const [remove, setRemove] = useState<string[]>([]);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const fields = [["gti", "Google Threat Intelligence / VirusTotal API key"], ["threatfox", "ThreatFox Auth-Key"], ["malwarebazaar", "MalwareBazaar Auth-Key"]] as const;
  return <form className="sa-section" onSubmit={event => {
    event.preventDefault(); setError(""); setSuccess("");
    void action("integrations", "/integrations", { ...draft, remove }, "PUT").then(ok => {
      if (ok) { setDraft({ gti: "", threatfox: "", malwarebazaar: "" }); setRemove([]); setSuccess("Server integration keys saved. Blank fields left existing keys unchanged."); }
      else setError("Keys were not saved. Review the server error above.");
    });
  }}><fieldset className="sa-form-body" disabled={!canAdmin || !!busy || !state.integrations}>
    <h2>Server integrations</h2>
    <dl className="sa-facts"><div><dt>Storage</dt><dd>Protected server data directory</dd></div><div><dt>Active reputation source</dt><dd>{human(reputationSourceLabel(state))}</dd></div></dl>
    <div className="sa-form-grid">{fields.map(([id, label]) => {
      const saved = state.integrations?.[id];
      return <div key={id}><Field label={label}><input type="password" autoComplete="off" maxLength={4096} value={draft[id]}
        placeholder={saved?.configured ? "Saved; leave blank to keep" : "Not configured"} disabled={saved?.source === "environment" || remove.includes(id)}
        onChange={event => { setDraft(previous => ({ ...previous, [id]: event.target.value })); setSuccess(""); }} /></Field>
        <p className="sa-muted">{saved?.configured ? `Saved in ${saved.source === "environment" ? "service environment" : "server storage"}` : "No server key saved"}</p>
        {saved?.source === "server" && <Toggle label={`Remove saved ${id} key`} checked={remove.includes(id)} onChange={checked => {
          setRemove(previous => checked ? [...previous, id] : previous.filter(value => value !== id)); setDraft(previous => ({ ...previous, [id]: "" })); setSuccess("");
        }} />}
      </div>;
    })}</div>
    <Feedback error={error} success={success} /><button className="sa-button sa-primary" disabled={!remove.length && !Object.values(draft).some(value => value.trim())}>
      <Save size={16} aria-hidden="true" />{busy === "integrations" ? "Saving..." : "Save server keys"}
    </button>
  </fieldset></form>;
}

function Delivery({ state, action, busy, canAdmin, browserEnabled, permission, browserError, onEnable, onDisable }: {
  state: AgentState; action: Action; busy: string; canAdmin: boolean; browserEnabled: boolean;
  permission: NotificationPermission | "unavailable"; browserError: string; onEnable: () => void; onDisable: () => void;
}) {
  const [channels, setChannels] = useState<ChannelDraft[]>(() => state.notifications.channels.map(channelDraft));
  const [cooldown, setCooldown] = useState(state.notifications.cooldownMinutes ?? 60);
  const [dirty, setDirty] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  useEffect(() => {
    if (!dirty) { setChannels(state.notifications.channels.map(channelDraft)); setCooldown(state.notifications.cooldownMinutes ?? 60); }
  }, [state.notifications]);
  const patch = (id: string, value: Partial<ChannelDraft>) => { setChannels(previous => previous.map(channel => channel.id === id ? { ...channel, ...value } : channel)); setDirty(true); setSuccess(""); };
  const submit = (event: React.FormEvent) => {
    event.preventDefault(); setError(""); setSuccess("");
    try {
      const body = notificationPayload(channels, state.config.autoAlertMinPriority, cooldown);
      void action("notifications", "/notifications", body, "PUT").then(ok => {
        if (ok) { setChannels(previous => previous.map(channel => ({ ...channel, token: "", chatId: "", url: "" }))); setDirty(false); setSuccess("Delivery settings saved."); }
        else setError("Delivery settings were not saved. Review the server error above.");
      });
    } catch (caught) { setError(errorMessage(caught)); }
  };
  return <>
    <section className="sa-browser-row"><div><h2>Browser notifications</h2><p className="sa-muted">Only while this console is open. Server channels continue when the browser is closed.</p></div><div className="sa-actions"><Badge tone={browserEnabled ? "good" : permission === "denied" || permission === "unavailable" ? "warning" : "neutral"}>{browserEnabled ? "Enabled" : permission === "granted" ? "Paused" : human(permission)}</Badge>{browserEnabled ? <button className="sa-button" onClick={onDisable}><Bell size={16} aria-hidden="true" />Pause</button> : <button className="sa-button" onClick={onEnable} disabled={permission === "unavailable"}><Bell size={16} aria-hidden="true" />Enable notifications</button>}</div></section>
    <Feedback error={browserError} />
    <form className="sa-section" onSubmit={submit}><fieldset className="sa-form-body" disabled={!canAdmin || !!busy}><div className="sa-section-heading"><h2>Server delivery channels</h2><div className="sa-actions">{dirty && <span className="sa-warning">Unsaved changes</span>}<button type="button" className="sa-button" disabled={!!busy} onClick={() => { setChannels(previous => [...previous, { id: crypto.randomUUID(), name: "", type: "webhook", enabled: false, configured: false, url: "", token: "", chatId: "" }]); setDirty(true); setSuccess(""); }}><Plus size={16} aria-hidden="true" />Add channel</button></div></div>
      <div className="sa-form-grid"><div className="sa-field"><span>Automatic alert minimum priority</span><strong className="sa-number">{state.config.autoAlertMinPriority}</strong></div><Field label="Delivery cooldown (minutes)"><input type="number" min={0} step={1} required value={cooldown} onChange={event => { setCooldown(Number(event.target.value)); setDirty(true); }} /></Field></div>
      {channels.map(channel => <fieldset className="sa-channel-editor" key={channel.id}><legend>{channel.name || "New channel"}</legend><div className="sa-section-heading"><div className="sa-actions"><Badge tone={channel.configured ? "good" : "warning"}>{channel.configured ? "Configured" : "Not configured"}</Badge><Toggle label="Enabled" checked={channel.enabled} onChange={enabled => patch(channel.id, { enabled })} /></div><div className="sa-actions"><button type="button" className="sa-icon" title="Queue test notification" aria-label={`Test channel ${channel.name || channel.id}`} disabled={!!busy || dirty || !channel.configured || !channel.enabled} onClick={() => { setError(""); setSuccess(""); void action(`test-${channel.id}`, "/test", { channelId: channel.id }).then(ok => { if (ok) setSuccess(`Test queued for ${channel.name}. Check delivery attempts below.`); else setError("Test could not be queued. Review the server error above."); }); }}><Send size={17} /></button><button type="button" className="sa-icon sa-danger-text" title="Remove channel" aria-label={`Remove channel ${channel.name || channel.id}`} disabled={!!busy} onClick={() => { setChannels(previous => previous.filter(item => item.id !== channel.id)); setDirty(true); setSuccess(""); }}><Trash2 size={17} /></button></div></div>
        <div className="sa-form-grid"><Field label="Channel name"><input required value={channel.name} maxLength={200} onChange={event => patch(channel.id, { name: event.target.value })} /></Field><Field label="Channel type"><select value={channel.type} disabled={channel.configured} onChange={event => patch(channel.id, { type: event.target.value as Channel["type"], url: "", token: "", chatId: "" })}><option value="webhook">Webhook</option><option value="discord">Discord</option><option value="telegram">Telegram</option></select></Field>
          {channel.type === "telegram" ? <><Field label={channel.configured ? "Replacement bot token" : "Bot token"}><input type="password" autoComplete="off" value={channel.token} maxLength={4096} placeholder={channel.configured ? "Unchanged" : ""} onChange={event => patch(channel.id, { token: event.target.value })} /></Field><Field label={channel.configured ? "Replacement chat ID" : "Chat ID"}><input value={channel.chatId} autoComplete="off" maxLength={200} placeholder={channel.configured ? "Unchanged" : ""} onChange={event => patch(channel.id, { chatId: event.target.value })} /></Field></> : <Field label={channel.configured ? "Replacement endpoint URL" : "Endpoint URL"} wide><input type="password" autoComplete="off" value={channel.url} maxLength={4096} placeholder={channel.configured ? "Unchanged" : "https://"} onChange={event => patch(channel.id, { url: event.target.value })} /></Field>}
        </div><small className="sa-muted sa-mono">{channel.id}</small>
      </fieldset>)}
      {!channels.length && <p className="sa-empty-line">No server delivery channels configured.</p>}
      <Feedback error={error} success={success} /><div className="sa-actions"><button className="sa-button sa-primary" disabled={!!busy || !dirty}><Save size={16} aria-hidden="true" />{busy === "notifications" ? "Saving..." : "Save delivery"}</button><button type="button" className="sa-button" disabled={!!busy || !dirty} onClick={() => { setChannels(state.notifications.channels.map(channelDraft)); setCooldown(state.notifications.cooldownMinutes ?? 60); setDirty(false); setError(""); setSuccess(""); }}><RefreshCw size={16} aria-hidden="true" />Reset changes</button></div>
    </fieldset></form>
    <section className="sa-section"><div className="sa-section-heading"><h2>Delivery attempts</h2><span className="sa-muted">{count(state.deliveries.length)} reported</span></div>
      {state.deliveries.length ? <div className="sa-table-wrap" tabIndex={0} role="region" aria-label="Delivery attempts"><table className="sa-table"><thead><tr><th scope="col">Delivery ID</th><th scope="col">Channel</th><th scope="col">Status</th><th scope="col">Attempts</th><th scope="col">Next attempt</th><th scope="col">Error</th></tr></thead><tbody>{state.deliveries.slice(0, 50).map(delivery => <tr key={delivery.id}><td><code>{delivery.id}</code></td><td>{state.notifications.channels.find(channel => channel.id === delivery.channel)?.name ?? delivery.channel}</td><td><Badge tone={statusTone(delivery.status)}>{human(delivery.status)}</Badge></td><td className="sa-number">{count(delivery.attempts)}</td><td className="sa-date">{date(delivery.nextAttempt)}</td><td className={delivery.error ? "sa-error" : "sa-muted"}>{delivery.error || "None reported"}</td></tr>)}</tbody></table></div> : <p className="sa-empty-line">No delivery attempts reported.</p>}
    </section>
    <section className="sa-section"><div className="sa-section-heading"><h2>Recent alerts</h2><span className="sa-muted">{count(state.alerts.length)} reported</span></div>{state.alerts.length ? <div className="sa-alert-list">{[...state.alerts].sort((a, b) => alertTime(b) - alertTime(a)).slice(0, 30).map(alert => <div key={alert.id}><Bell size={16} aria-hidden="true" /><div><strong>{alert.title ?? alert.indicator ?? alert.id}</strong>{alert.message && <p>{alert.message}</p>}<small>{date(alert.createdAt ?? alert.timestamp)}</small></div><span className="sa-number">{count(alert.priority)}</span></div>)}</div> : <p className="sa-empty-line">No alerts reported.</p>}</section>
  </>;
}

function localDateTime(value?: string): string {
  if (!value) return "";
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime())) return "";
  return new Date(parsed.getTime() - parsed.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
}

function ExceptionEditor({ exceptions, onChange, disabled }: { exceptions: AgentException[]; onChange: (value: AgentException[]) => void; disabled: boolean }) {
  const patch = (index: number, value: Partial<AgentException>) => onChange(exceptions.map((exception, i) => i === index ? { ...exception, ...value } : exception));
  return <section className="sa-section"><div className="sa-section-heading"><h2>Allowlist exceptions</h2><button type="button" className="sa-button" disabled={disabled || exceptions.length >= 500} onClick={() => onChange([...exceptions, { indicatorType: "ip", indicatorValue: "", reason: "", enabled: true }])}><Plus size={16} aria-hidden="true" />Add exception</button></div>
    {exceptions.length ? exceptions.map((exception, index) => <div className="sa-exception" key={index}>
      <div className="sa-section-heading"><div className="sa-actions"><Toggle label="Enabled" checked={exception.enabled !== false} onChange={enabled => patch(index, { enabled })} disabled={disabled} />{exception.expiresAt && Date.parse(exception.expiresAt) <= Date.now() && <Badge tone="warning">Expired</Badge>}</div><button type="button" className="sa-icon sa-danger-text" title="Remove exception" aria-label={`Remove exception ${exception.indicatorValue || index + 1}`} disabled={disabled} onClick={() => onChange(exceptions.filter((_, i) => i !== index))}><Trash2 size={17} /></button></div>
      <div className="sa-form-grid"><Field label="Exception indicator type"><select value={exception.indicatorType} onChange={event => patch(index, { indicatorType: event.target.value as IndicatorType })} disabled={disabled}><option value="ip">IP address</option><option value="domain">Domain</option><option value="hash">File hash</option><option value="identity">Identity</option></select></Field><Field label="Exception indicator"><input required maxLength={253} value={exception.indicatorValue} onChange={event => patch(index, { indicatorValue: event.target.value })} disabled={disabled} /></Field><Field label="Exception host scope"><input maxLength={256} value={exception.host ?? ""} onChange={event => patch(index, { host: event.target.value })} disabled={disabled} /></Field><Field label="Exception infrastructure scope"><input maxLength={256} value={exception.infrastructure ?? ""} onChange={event => patch(index, { infrastructure: event.target.value })} disabled={disabled} /></Field><Field label="Exception reason" wide><textarea required maxLength={2000} rows={2} value={exception.reason} onChange={event => patch(index, { reason: event.target.value })} disabled={disabled} /></Field><Field label="Expires at (local time, optional)"><input type="datetime-local" value={localDateTime(exception.expiresAt)} onChange={event => patch(index, { expiresAt: event.target.value ? new Date(event.target.value).toISOString() : "" })} disabled={disabled} /></Field></div>
    </div>) : <p className="sa-empty-line">No allowlist exceptions configured.</p>}
  </section>;
}
