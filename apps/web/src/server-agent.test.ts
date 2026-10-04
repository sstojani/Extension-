import { afterEach, describe, expect, it, vi } from "vitest";
import {
  agentRequest, AgentApiError, channelDraft, configPatch, createAlertCursor,
  notificationPayload, orderedFindings, scanHealth, validateConfig, validateRule, dataViewScope, reputationSourceLabel,
  type AgentConfig, type AgentState, type Finding, type WatchRule
} from "./ServerAgent";

const config: AgentConfig = {
  enabled: true, intervalMinutes: 5, overlapMinutes: 5, maxEventsPerRun: 25000,
  pageSize: 500, timezone: "Europe/Tirane", baselineDays: 7, indexPattern: "logs-*",
  timestampField: "@timestamp", infrastructureField: "observer.name", autoAlertMinPriority: 80,
  retentionDays: 30, query: "", assets: [], accounts: [], exceptions: []
};
const rule: Omit<WatchRule, "id"> = {
  name: "Observed IP", indicatorType: "ip", indicatorValue: "8.8.8.8", includeSubdomains: false,
  enabled: true, minEvents: 1, minPriority: 50, cooldownMinutes: 60, channels: [], scope: {}, requireSuccess: false
};
const at = "2026-10-02T10:00:00.000Z";
function state(): AgentState {
  return {
    status: { enabled: true, configured: true, running: false, lastSuccess: at,
      lastError: null, checkpoint: at, nextScan: at, heartbeat: at, coverage: { status: "complete" } },
    config, rules: [], findings: [], runs: [], alerts: [], deliveries: [],
    notifications: { channels: [], minPriority: 80, cooldownMinutes: 60 },
    reputation: { pending: 0, unavailable: 0, scored: 0 }, campaigns: []
  };
}

it("distinguishes an offline browser reputation source from a confirmed missing key", () => {
  const snapshot = state(); snapshot.reputation.configured = false; snapshot.reputation.source = "missing";
  snapshot.status.dataSource = { mode: "browser_relay", ready: false };
  expect(reputationSourceLabel(snapshot)).toBe("relay offline");
  snapshot.status.dataSource.ready = true;
  expect(reputationSourceLabel(snapshot)).toBe("not configured");
  snapshot.reputation.source = "browser";
  expect(reputationSourceLabel(snapshot)).toBe("browser");
  snapshot.reputation.source = "server"; snapshot.status.dataSource.ready = false;
  expect(reputationSourceLabel(snapshot)).toBe("server");
});

it("never reports healthy or running collection for a disconnected browser relay", () => {
  const snapshot = state();
  snapshot.status.running = true;
  snapshot.status.dataSource = { mode: "browser_relay", ready: false };
  expect(scanHealth(snapshot, Date.parse(at))).toMatchObject({ label: "Collection paused", tone: "error" });
});
it("keeps live status distinct from failed historical collection and detects stale live checks", () => {
  const snapshot = state();
  snapshot.status.lastError = "Historical search HTTP 403";
  snapshot.status.live = { lastAttempt: at, lastSuccess: at, nextScan: at, lastError: null, stages: {}, coverage: "sampled" };
  expect(scanHealth(snapshot, Date.parse(at))).toMatchObject({ label: "Live checks completed", tone: "warning" });
  expect(scanHealth(snapshot, Date.parse(at) + 121000).label).toBe("Live check overdue");
  snapshot.status.live.lastError = "security: HTTP 403";
  expect(scanHealth(snapshot, Date.parse(at))).toMatchObject({ label: "Live coverage reduced", tone: "error" });
  snapshot.status.live.running = true;
  expect(scanHealth(snapshot, Date.parse(at)).label).toBe("Live check running");
  snapshot.status.live = { lastSuccess: null, nextScan: null, lastError: null, stages: {} };
  expect(scanHealth(snapshot, Date.parse(at))).toMatchObject({ label: "Awaiting live check", tone: "warning" });
});
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); vi.useRealTimers(); });

describe("server agent transport", () => {
  it("uses the same-origin cookie session and sends the token only in the login body", async () => {
    const fetcher = vi.fn().mockResolvedValue(new Response('{"authenticated":true}'));
    vi.stubGlobal("fetch", fetcher);
    vi.stubGlobal("localStorage", { setItem: () => { throw new Error("Do not persist tokens"); } });
    await agentRequest("/login", { method: "POST", body: { token: "memory-only" } });
    expect(fetcher).toHaveBeenCalledWith("/api/agent/login", expect.objectContaining({
      credentials: "same-origin", redirect: "error", cache: "no-store", body: '{"token":"memory-only"}',
      headers: { Accept: "application/json", "Content-Type": "application/json" }
    }));
    expect(fetcher.mock.calls[0]?.[1].headers).not.toHaveProperty("Authorization");
  });

  it.each(["POST", "DELETE"])("sends an empty JSON body for %s without a payload", async method => {
    const fetcher = vi.fn().mockResolvedValue(new Response("{}")); vi.stubGlobal("fetch", fetcher);
    await agentRequest(method === "POST" ? "/logout" : "/rules/id", { method });
    expect(fetcher.mock.calls[0]?.[1]).toMatchObject({ method, body: "{}", headers: { "Content-Type": "application/json" } });
  });

  it("handles old static-host HTML 404 responses", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("<html>Not found</html>", { status: 404 })));
    await expect(agentRequest("/status")).rejects.toMatchObject({ status: 404, message: expect.stringContaining("unavailable") });
  });

  it("rejects an HTML fallback returned as HTTP 200", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("<html>App shell</html>")));
    await expect(agentRequest("/status")).rejects.toThrow("non-JSON");
  });

  it("reports authentication expiration and server validation errors", async () => {
    const fetcher = vi.fn().mockResolvedValueOnce(new Response("{}", { status: 401 }))
      .mockResolvedValueOnce(new Response('{"error":"Invalid query_string expression."}', { status: 400 }));
    vi.stubGlobal("fetch", fetcher);
    await expect(agentRequest("/state")).rejects.toBeInstanceOf(AgentApiError);
    await expect(agentRequest("/config", { method: "PUT", body: { query: "broken" } })).rejects.toThrow("Invalid query_string expression.");
  });

  it("bounds proof retrieval even without a content-length header", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ event: "x".repeat(500) }))));
    await expect(agentRequest("/evidence?index=logs&id=1", { maxBytes: 64 })).rejects.toThrow("size limit");
  });

  it("keeps the console size safeguard and cancels oversized advertised responses before reading", async () => {
    const cancel = vi.fn();
    const response = new Response(new ReadableStream({ cancel }), { headers: { "content-length": String(9 * 1024 * 1024) } });
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response));
    await expect(agentRequest("/state")).rejects.toThrow("size limit");
    expect(cancel).toHaveBeenCalledOnce();
  });

  it("loads individual finding details using the same cookie session and preserved size bound", async () => {
    const item: Finding = { id: "stored/one", fingerprint: "stored/one", title: "Retained finding", category: "scan", indicator: "185.220.101.4", indicatorType: "ip",
      priority: 90, severity: "high", behaviorScore: 80, confidence: 85, reputation: null, status: "open", count: 40,
      firstSeen: at, lastSeen: at, evidence: [{ index: "logs-network", eventId: "proof", timestamp: at, reason: "Blocked" }], reasons: ["Corroborated fanout"], limitations: ["Sampled"] };
    const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify({ finding: item, investigation: { id: item.id, status: "complete", timeline: ["Retained"] } })));
    vi.stubGlobal("fetch", fetcher);
    const result = await agentRequest(`/findings/${encodeURIComponent(item.id)}`);
    expect(fetcher.mock.calls[0]?.[0]).toBe("/api/agent/findings/stored%2Fone");
    expect(fetcher.mock.calls[0]?.[1]).toMatchObject({ method: "GET", credentials: "same-origin", cache: "no-store" });
    expect(result).toMatchObject({ finding: { evidence: item.evidence, reasons: item.reasons }, investigation: { timeline: ["Retained"] } });
  });

  it("forwards aborts to the transport", async () => {
    const source = new AbortController();
    vi.stubGlobal("fetch", vi.fn((_url, options: RequestInit) => new Promise((_resolve, reject) => {
      options.signal?.addEventListener("abort", () => reject(new DOMException("Cancelled", "AbortError")), { once: true });
    })));
    const pending = agentRequest("/state", { signal: source.signal });
    const assertion = expect(pending).rejects.toMatchObject({ name: "AbortError" });
    source.abort(); await assertion;
  });

  it("times out a stalled request and clears its timer", async () => {
    vi.useFakeTimers();
    vi.stubGlobal("fetch", vi.fn((_url, options: RequestInit) => new Promise((_resolve, reject) => {
      options.signal?.addEventListener("abort", () => reject(new DOMException("Cancelled", "AbortError")), { once: true });
    })));
    const assertion = expect(agentRequest("/state")).rejects.toThrow("timed out");
    await vi.advanceTimersByTimeAsync(20_000); await assertion;
    expect(vi.getTimerCount()).toBe(0);
  });

  it("keeps fingerprint IDs encoded as a single route segment", async () => {
    const fetcher = vi.fn().mockResolvedValue(new Response("{}")); vi.stubGlobal("fetch", fetcher);
    await agentRequest(`/findings/${encodeURIComponent("scan|host/a|8.8.8.8")}`, { method: "PATCH", body: { status: "false_positive" } });
    expect(fetcher.mock.calls[0]?.[0]).toBe("/api/agent/findings/scan%7Chost%2Fa%7C8.8.8.8");
    expect(JSON.parse(fetcher.mock.calls[0]?.[1].body)).toEqual({ status: "false_positive" });
  });
});

describe("configuration and rules", () => {
  it("copies the explicitly selected data view's index and time field without guessing or taking other settings", () => {
    expect(dataViewScope({ data_view: { title: "firewall-*,logs-*", timeFieldName: "event.created", name: "Network" } })).toEqual({ indexPattern: "firewall-*,logs-*", timestampField: "event.created" });
    for (const data_view of [{ title: "logs-*" }, { title: "*", timeFieldName: "@timestamp" }, { title: ".security", timeFieldName: "@timestamp" }, { title: "logs-*", timeFieldName: "invalid field" }]) {
      expect(() => dataViewScope({ data_view })).toThrow();
    }
    expect(() => dataViewScope(null)).toThrow("no configured time field");
  });
  it("validates editable detector thresholds independently of the scheduler", () => {
    expect(validateConfig({ ...config, scanMinAttempts: 30, beaconMaxCv: 0.15, exfilRatio: 5 })).toBeNull();
    expect(validateConfig({ ...config, scanMinAttempts: 4 })).toContain("scanMinAttempts");
    expect(validateConfig({ ...config, beaconMaxCv: 0.6 })).toContain("beaconMaxCv");
    expect(validateConfig({ ...config, authFailures: 3.5 })).toContain("authFailures");
  });
  it("sends partial configuration and preserves Elasticsearch query_string syntax", () => {
    const query = 'event.action:(allow OR deny) AND destination.port:443';
    expect(configPatch(config, { ...config, query }, '{"assets":[],"accounts":[]}')).toEqual({ query });
  });
  it("validates timezone, scan bounds, JSON lists, and exception rationale", () => {
    expect(validateConfig(config)).toBeNull();
    expect(validateConfig({ ...config, timezone: "invalid-zone" })).toContain("timezone");
    expect(validateConfig({ ...config, pageSize: 1001 })).toContain("pageSize");
    expect(() => configPatch(config, config, '{"assets":{}}')).toThrow("arrays");
    expect(() => configPatch(config, config, '{bad')).toThrow("valid JSON");
    expect(validateConfig({ ...config, exceptions: [{ indicatorType: "ip", indicatorValue: "8.8.8.8", reason: "" }] })).toContain("reason");
    expect(validateConfig({ ...config, exceptions: [{ indicatorType: "ip", indicatorValue: "8.8.8.8", reason: "Approved probe", expiresAt: "invalid" }] })).toContain("expiration");
  });
  it("retains narrowly scoped exceptions and expiry in a partial update", () => {
    const exceptions = [{ indicatorType: "ip" as const, indicatorValue: "8.8.8.8", host: "probe-1", reason: "Approved probe", expiresAt: "2026-10-03T10:00:00Z" }];
    expect(configPatch(config, { ...config, exceptions }, '{"assets":[],"accounts":[]}')).toEqual({ exceptions });
  });
  it("accepts IP, domain, hash, and identity rules and rejects malformed values", () => {
    expect(validateRule(rule)).toBeNull();
    expect(validateRule({ ...rule, indicatorValue: "2001:4860:4860::8888" })).toBeNull();
    expect(validateRule({ ...rule, indicatorValue: "999.1.1.1" })).toContain("IPv4");
    expect(validateRule({ ...rule, indicatorType: "domain", indicatorValue: "example.org", includeSubdomains: true })).toBeNull();
    expect(validateRule({ ...rule, indicatorType: "domain", indicatorValue: "https://example.org" })).toContain("domain");
    expect(validateRule({ ...rule, indicatorType: "hash", indicatorValue: "a".repeat(64) })).toBeNull();
    expect(validateRule({ ...rule, indicatorType: "hash", indicatorValue: "abc" })).toContain("hash");
    expect(validateRule({ ...rule, indicatorType: "identity", indicatorValue: "soc@example.org" })).toBeNull();
  });
});

describe("delivery and notification behavior", () => {
  it("omits blank secrets and redacted URLs to preserve server credentials", () => {
    const channels = [channelDraft({ id: "webhook", name: "Ops", type: "webhook", enabled: true, configured: true, url: "[REDACTED]" }),
      channelDraft({ id: "telegram", name: "On-call", type: "telegram", enabled: true, configured: true })];
    const payload = notificationPayload(channels, config.autoAlertMinPriority, 60);
    expect(payload.channels).toEqual([
      { id: "webhook", name: "Ops", type: "webhook", enabled: true },
      { id: "telegram", name: "On-call", type: "telegram", enabled: true }
    ]);
    expect(payload.minPriority).toBe(config.autoAlertMinPriority);
  });
  it("includes explicitly entered replacement secrets", () => {
    const draft = channelDraft({ id: "telegram", name: "On-call", type: "telegram", enabled: true, configured: true });
    expect(notificationPayload([{ ...draft, token: "123:new", chatId: "-100" }], 80, 60).channels[0]).toMatchObject({ token: "123:new", chatId: "-100" });
  });
  it("validates endpoint protocol and new channel credentials", () => {
    const draft = channelDraft({ id: "ops", name: "Ops", type: "webhook", enabled: true, configured: false });
    expect(() => notificationPayload([draft], 80, 60)).toThrow("credentials");
    expect(() => notificationPayload([{ ...draft, url: "http://example.org/hook" }], 80, 60)).toThrow("HTTPS");
  });
  it("ignores historical alerts, deduplicates, and tolerates response ordering", () => {
    const initial = [{ id: "history", createdAt: "2026-10-02T09:00:00Z" }];
    const next = createAlertCursor(initial, Date.parse(at));
    expect(next(initial)).toEqual([]);
    const newest = { id: "new", createdAt: "2026-10-02T10:00:10Z" };
    expect(next([newest, ...initial])).toEqual([newest]);
    expect(next([newest, ...initial])).toEqual([]);
    expect(next([{ id: "older-page", createdAt: "2026-10-02T09:30:00Z" }])).toEqual([]);
  });
});

describe("scan truth and finding order", () => {
  it("does not report healthy no-findings while scans fail, coverage is reduced, or heartbeat is stale", () => {
    const value = state(); const now = Date.parse(at);
    expect(scanHealth(value, now).tone).toBe("good");
    expect(scanHealth({ ...value, status: { ...value.status, lastError: "Elastic unavailable" } }, now).tone).toBe("error");
    expect(scanHealth({ ...value, status: { ...value.status, coverage: { status: "reduced" } } }, now).label).toBe("Incomplete coverage");
    expect(scanHealth({ ...value, status: { ...value.status, running: true } }, now).label).toBe("Scan running");
    expect(scanHealth(value, now + 20 * 60_000).label).toBe("Heartbeat stale");
    expect(scanHealth({ ...value, status: { ...value.status, heartbeat: null } }, now).tone).toBe("warning");
  });
  it("orders by descending priority without mutating server results", () => {
    const rows = [{ id: "low", priority: 30, lastSeen: at }, { id: "high", priority: 95, lastSeen: at }] as Finding[];
    expect(orderedFindings(rows).map(item => item.id)).toEqual(["high", "low"]);
    expect(rows[0]?.id).toBe("low");
  });
});
