import { afterEach, describe, expect, it, vi } from "vitest";
import { buildQuery, kibanaApiPath, relayFieldCapsPath } from "@soc-watch/protocol";
import { kibanaFetchJson } from "../src/kibana";
import { ServerBrowserRelay } from "../src/server-relay";

const config = { kibanaBaseUrl: "https://kibana.internal", spaceId: "soc" };
const policy = { indexPattern: "logs-*", timestampField: "@timestamp", infrastructureField: "observer.name" };
const proxy = (path = "/logs-*/_pit?keep_alive=1m", method = "POST") => kibanaApiPath(`console/proxy${buildQuery({ path, method })}`, config.spaceId);
const json = (body: unknown, status = 200, proxyStatus?: string) => new Response(JSON.stringify(body), {
  status, headers: { "content-type": "application/json", ...(proxyStatus === undefined ? {} : { "x-console-proxy-status-code": proxyStatus }) }
});
const sensitiveReason = "authorization denied for user private-analyst with token=DO_NOT_DISPLAY";

function transport(tabFallback: boolean) {
  const fetcher = vi.fn<typeof fetch>();
  if (tabFallback) fetcher.mockRejectedValueOnce(new TypeError("Background fetch blocked"));
  const executeScript = vi.fn(async (injection: { func: (...args: any[]) => Promise<unknown>; args: unknown[] }) => [{ result: await injection.func(...injection.args) }]);
  vi.stubGlobal("fetch", fetcher);
  vi.stubGlobal("chrome", { tabs: { query: vi.fn(async () => [{ id: 1, url: `${config.kibanaBaseUrl}/app/discover` }]) }, scripting: { executeScript } });
  return { fetcher, executeScript };
}
afterEach(() => vi.unstubAllGlobals());

describe.each([false, true])("Kibana JSON transport (tab fallback: %s)", tabFallback => {
  it.each([
    [401, "security_exception", "KIBANA_AUTH_REQUIRED"],
    [403, "security_exception", "KIBANA_FORBIDDEN"],
    [400, "illegal_argument_exception", "INVALID_REQUEST"],
    [404, "index_not_found_exception", "INVALID_REQUEST"],
    [405, "method_not_allowed_exception", "INVALID_REQUEST"],
    [429, "es_rejected_execution_exception", "RATE_LIMITED"],
    [503, "unavailable_shards_exception", "KIBANA_UNREACHABLE"]
  ])("rejects Elasticsearch HTTP %s hidden by an outer HTTP 200", async (status, type, code) => {
    const { fetcher, executeScript } = transport(tabFallback);
    fetcher.mockResolvedValueOnce(json({ error: { type, reason: sensitiveReason }, status }, 200, String(status)));
    const failure = await kibanaFetchJson(config, proxy(), { method: "POST" }, { timeoutMs: 5000, maxBytes: 4096 }).catch(error => error);
    expect(failure).toMatchObject({ code, message: expect.stringContaining(`HTTP ${status}`), details: { status, upstream: true, errorType: type } });
    expect(JSON.stringify(failure)).not.toContain("DO_NOT_DISPLAY");
    if (!(failure instanceof Error)) throw new Error("Expected a typed transport failure");
    expect(failure.message).not.toContain("private-analyst");
    expect(executeScript).toHaveBeenCalledTimes(tabFallback ? 1 : 0);
  });

  it("accepts real successes without treating a 200 transport response as proof on its own", async () => {
    const { fetcher } = transport(tabFallback);
    fetcher.mockResolvedValueOnce(json({ id: "real-pit" }, 200, "200"));
    await expect(kibanaFetchJson(config, proxy(), { method: "POST" })).resolves.toEqual({ id: "real-pit" });
  });

  it("detects an error body from older proxies without the status header", async () => {
    const { fetcher } = transport(tabFallback);
    fetcher.mockResolvedValueOnce(json({ error: { type: "security_exception" }, status: 403 }));
    await expect(kibanaFetchJson(config, proxy())).rejects.toMatchObject({ code: "KIBANA_FORBIDDEN", details: { status: 403 } });
  });

  it("does not accept an error body just because the header says 200", async () => {
    const { fetcher } = transport(tabFallback);
    fetcher.mockResolvedValueOnce(json({ error: "failure" }, 200, "200"));
    await expect(kibanaFetchJson(config, proxy())).rejects.toMatchObject({ code: "KIBANA_UNREACHABLE" });
  });

  it("rejects malformed upstream status headers", async () => {
    const { fetcher } = transport(tabFallback);
    fetcher.mockResolvedValueOnce(json({ id: "pit" }, 200, "not-a-status"));
    await expect(kibanaFetchJson(config, proxy())).rejects.toMatchObject({ code: "KIBANA_UNREACHABLE", message: expect.stringContaining("invalid Elasticsearch status header") });
  });

  it("preserves outer Kibana permission denial instead of trusting a success header", async () => {
    const { fetcher } = transport(tabFallback);
    fetcher.mockResolvedValueOnce(json({ error: "Forbidden" }, 403, "200"));
    await expect(kibanaFetchJson(config, proxy())).rejects.toMatchObject({ code: "KIBANA_FORBIDDEN", details: { status: 403, upstream: false } });
  });

  it("retains the upstream error status even if its body is not JSON", async () => {
    const { fetcher } = transport(tabFallback);
    fetcher.mockResolvedValueOnce(new Response("failure", { headers: { "content-type": "application/json", "x-console-proxy-status-code": "403" } }));
    await expect(kibanaFetchJson(config, proxy())).rejects.toMatchObject({ code: "KIBANA_FORBIDDEN", details: { status: 403 } });
  });

  it("does not return raw non-JSON bodies in diagnostics", async () => {
    const { fetcher } = transport(tabFallback);
    fetcher.mockResolvedValueOnce(new Response(sensitiveReason, { headers: { "content-type": "application/json" } }));
    const failure = await kibanaFetchJson(config, proxy()).catch(error => error);
    expect(failure).toMatchObject({ code: "KIBANA_UNREACHABLE", message: expect.stringContaining("not valid JSON") });
    expect(JSON.stringify(failure)).not.toContain("DO_NOT_DISPLAY");
  });

  it.each(["search_context_missing_exception", "search_phase_execution_exception", "resource_not_found_exception"])("keeps expired PIT searches recoverable with %s", async type => {
    const { fetcher } = transport(tabFallback);
    fetcher.mockResolvedValueOnce(json({ error: { type }, status: 404 }, 200, "404"));
    await expect(kibanaFetchJson(config, proxy("/_search"))).rejects.toMatchObject({ code: "KIBANA_UNREACHABLE", message: expect.stringContaining("expired") });
  });

  it("does not apply Console proxy headers to a regular Kibana API", async () => {
    const { fetcher } = transport(tabFallback);
    fetcher.mockResolvedValueOnce(json({ data_view: [] }, 200, "403"));
    await expect(kibanaFetchJson(config, kibanaApiPath("data_views", config.spaceId))).resolves.toEqual({ data_view: [] });
  });
});

it("does not register a relay lease when real transport metadata works but Elasticsearch rejects PIT access", async () => {
  const { fetcher } = transport(false);
  fetcher.mockResolvedValueOnce(json({ fields: { "@timestamp": { date: { searchable: true } } } }, 200, "200"));
  fetcher.mockResolvedValueOnce(json({ error: { type: "security_exception", reason: sensitiveReason }, status: 403 }, 200, "403"));
  const relay = new ServerBrowserRelay({ config: async () => config, tabs: async () => [{ url: `${config.kibanaBaseUrl}/app/discover` }], request: kibanaFetchJson, clock: Date.now, reputationConfigured: async () => false, reputationRevision: async () => undefined, reputation: async () => ({ status: "not_configured" as const, verdict: "unknown" as const }) });
  await expect(relay.handle("agent.relay.connect", policy, "console-tab")).rejects.toMatchObject({ code: "KIBANA_FORBIDDEN", message: expect.stringContaining("open a log snapshot") });
  expect(fetcher).toHaveBeenCalledTimes(2);
  const first = new URL(String(fetcher.mock.calls[0]![0]));
  expect(first.pathname).toBe("/s/soc/api/console/proxy");
  expect(first.searchParams.get("path")).toBe(relayFieldCapsPath(policy.indexPattern, [policy.timestampField]));
});

it("opens and closes a proof snapshot through real JSON transport before registering a relay", async () => {
  const { fetcher } = transport(false);
  fetcher.mockResolvedValueOnce(json({ fields: { "@timestamp": { date: { searchable: true } } } }, 200, "200"));
  fetcher.mockResolvedValueOnce(json({ id: "proof-pit", _shards: { failed: 0 } }, 200, "200"));
  fetcher.mockResolvedValueOnce(json({ succeeded: true }, 200, "200"));
  const relay = new ServerBrowserRelay({ config: async () => config, tabs: async () => [{ url: `${config.kibanaBaseUrl}/app/discover` }], request: kibanaFetchJson, clock: Date.now, reputationConfigured: async () => false, reputationRevision: async () => undefined, reputation: async () => ({ status: "not_configured" as const, verdict: "unknown" as const }) });
  await expect(relay.handle("agent.relay.connect", policy, "console-tab")).resolves.toHaveProperty("relayId");
  expect(JSON.parse(String(fetcher.mock.calls[2]![1]?.body))).toEqual({ id: "proof-pit" });
});
