import { describe, it, expect, vi } from "vitest";
import { ServerBrowserRelay } from "../src/server-relay";

const policy = { indexPattern: "logs-*", timestampField: "@timestamp", infrastructureField: "observer.name" };
const owner = "https://socwatch.internal#1";
function fixture() {
  let now = 1000;
  const config = vi.fn(async () => ({ kibanaBaseUrl: "https://kibana.internal", spaceId: "default" }));
  const tabs = vi.fn(async () => [{ id: 1, url: "https://kibana.internal/app/discover" }]);
  const request = vi.fn(async (_config: unknown, path: string, init: RequestInit = {}): Promise<unknown> => {
    const endpoint = new URL(`https://kibana.internal${path}`).searchParams.get("path");
    if (endpoint?.includes("_field_caps")) {
      const query = new URL(endpoint, "https://elastic.internal").searchParams;
      if (!query.get("fields") || query.get("include_unmapped") !== "true" || init.body !== undefined) throw new Error("Field capabilities must use query parameters, not a JSON body.");
      return { indices: ["logs-network-default"], fields: { "@timestamp": { date: { searchable: true } } } };
    }
    if (endpoint?.includes("_pit?")) return { id: "pit" };
    if (endpoint === "/_search") return { pit_id: "pit-2", hits: { hits: [{ _index: ".ds-logs-network-default-2026.10.02-000001" }] } };
    return { succeeded: true };
  });
  const relay = new ServerBrowserRelay({ config, tabs, request, clock: () => now });
  return { relay, config, tabs, request, expire: () => { now += 90001; } };
}
const body = { pit: { id: "pit", keep_alive: "10m" }, size: 500, track_total_hits: true, timeout: "20s",
  query: { bool: { filter: [{ range: { "@timestamp": { gte: "2026-10-02T10:00:00Z", lte: "2026-10-02T10:05:00Z" } } }] } },
  sort: [{ "@timestamp": { order: "asc", unmapped_type: "date" } }, { _shard_doc: "asc" }] };

describe("extension server relay", () => {
  it("uses portable field-capabilities query parameters for connection, heartbeat and jobs", async () => {
    const { relay, request } = fixture();
    const connection = await relay.handle("agent.relay.connect", policy, owner) as { relayId: string };
    await relay.handle("agent.relay.heartbeat", connection, owner);
    await relay.handle("agent.relay.execute", { relayId: connection.relayId, jobId: crypto.randomUUID(), operation: { kind: "fieldCaps", indexPattern: policy.indexPattern, fields: ["@timestamp", "source.ip"] } }, owner);
    const calls = request.mock.calls.filter(([, path]) => path.includes("_field_caps"));
    expect(calls).toHaveLength(3);
    const last = new URL(new URL(`https://kibana.internal${calls[2]![1]}`).searchParams.get("path")!, "https://elastic.internal");
    expect(last.searchParams.get("fields")).toBe("@timestamp,source.ip");
    expect(calls.every(([, , init]) => init?.body === undefined)).toBe(true);
  });
  it.each([
    [{ indices: [], fields: {} }, "No accessible indexes"],
    [{ indices: ["logs-one"], fields: {} }, "not mapped"],
    [{ fields: { "@timestamp": { unmapped: { searchable: false } } } }, "not mapped"],
    [{ fields: { "@timestamp": { keyword: { searchable: true } } } }, "incompatible types"],
    [{ fields: { "@timestamp": { date: { searchable: false } } } }, "not searchable"],
    [{ fields: { "@timestamp": { date: { searchable: true }, keyword: { searchable: true } } } }, "incompatible types"]
  ])("reports a settings failure without claiming an authentication failure", async (result, message) => {
    const { relay, request } = fixture(); request.mockResolvedValueOnce(result);
    await expect(relay.handle("agent.relay.connect", policy, owner)).rejects.toMatchObject({ code: "INVALID_REQUEST", message: expect.stringContaining(message) });
    expect(request).toHaveBeenCalledTimes(1);
  });
  it("accepts date_nanos plus unmapped indexes and does not assume a malformed response proves permission denial", async () => {
    const { relay, request } = fixture();
    request.mockResolvedValueOnce({ fields: { "@timestamp": { date_nanos: { searchable: true }, unmapped: { searchable: false } } } });
    await expect(relay.handle("agent.relay.connect", policy, owner)).resolves.toHaveProperty("relayId");
    request.mockResolvedValueOnce({});
    await expect(relay.handle("agent.relay.connect", policy, owner)).rejects.toMatchObject({ code: "KIBANA_UNREACHABLE" });
  });
  it("rechecks timestamp capabilities on heartbeat instead of refreshing an invalid proof", async () => {
    const { relay, request } = fixture();
    const connection = await relay.handle("agent.relay.connect", policy, owner) as { relayId: string };
    request.mockResolvedValueOnce({ indices: ["logs-one"], fields: {} });
    await expect(relay.handle("agent.relay.heartbeat", connection, owner)).rejects.toMatchObject({ code: "INVALID_REQUEST" });
  });
  it("requires a real open Kibana tab and authenticated searchable field proof", async () => {
    const { relay, tabs, request } = fixture(); tabs.mockResolvedValueOnce([]);
    await expect(relay.handle("agent.relay.connect", policy, owner)).rejects.toThrow("signed-in Kibana tab");
    expect(request).not.toHaveBeenCalled();
    request.mockRejectedValueOnce(new Error("Kibana authentication is required"));
    await expect(relay.handle("agent.relay.connect", policy, owner)).rejects.toThrow("authentication");
  });
  it("does not authorize metadata-only access when the user cannot open a read snapshot", async () => {
    const { relay, request } = fixture();
    request.mockResolvedValueOnce({ fields: { "@timestamp": { date: { searchable: true } } } });
    request.mockRejectedValueOnce(new Error("Read permission denied"));
    await expect(relay.handle("agent.relay.connect", policy, owner)).rejects.toThrow("Read permission denied");
  });
  it("limits reads to authorized snapshots and indexes, deduplicates job delivery and tracks PIT rotation", async () => {
    const { relay, request } = fixture();
    const connection = await relay.handle("agent.relay.connect", policy, owner) as { relayId: string };
    const execute = (operation: unknown, jobId = crypto.randomUUID()) => relay.handle("agent.relay.execute", { relayId: connection.relayId, jobId, operation }, owner);
    await expect(execute({ kind: "search", body })).rejects.toThrow("not owned");
    await execute({ kind: "openPit", indexPattern: "logs-*" });
    const id = crypto.randomUUID(); const operation = { kind: "search", body };
    const a = execute(operation, id), b = execute(operation, id);
    expect(await a).toEqual(await b);
    expect(request.mock.calls.filter(call => new URL(`https://kibana.internal${call[1]}`).searchParams.get("path") === "/_search")).toHaveLength(1);
    await expect(execute({ kind: "closePit", id: "pit" })).rejects.toThrow("not owned");
    await execute({ kind: "closePit", id: "pit-2" });
    await expect(execute({ kind: "evidence", index: ".security", id: "private" })).rejects.toThrow();
    await expect(execute({ kind: "search", body: { ...body, script_fields: {} } })).rejects.toThrow();
    await expect(execute({ kind: "openPit", indexPattern: "finance-*" })).rejects.toThrow("scope changed");
  });
  it("rejects foreign tabs, expired authorization and changed Kibana sessions", async () => {
    const { relay, config, expire } = fixture();
    const connection = await relay.handle("agent.relay.connect", policy, owner) as { relayId: string };
    await expect(relay.handle("agent.relay.heartbeat", connection, `${owner}-other`)).rejects.toMatchObject({ code: "INVALID_ORIGIN" });
    config.mockResolvedValueOnce({ kibanaBaseUrl: "https://other.internal", spaceId: "default" });
    await expect(relay.handle("agent.relay.heartbeat", connection, owner)).rejects.toThrow("configuration changed");
    expire(); await expect(relay.handle("agent.relay.heartbeat", connection, owner)).rejects.toMatchObject({ code: "KIBANA_UNREACHABLE", message: expect.stringContaining("expired") });
  });
});
