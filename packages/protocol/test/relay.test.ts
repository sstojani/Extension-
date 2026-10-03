import { describe, expect, it } from "vitest";
import { RELAY_MAX_PIT_ID_BYTES, relayPitIdSchema, validateRelayOperation, relayLiveSearch } from "../src/index";

const policy = { indexPattern: "logs-*", timestampField: "@timestamp", infrastructureField: "observer.name" };
const search = (id: string) => ({ kind: "search", body: {
  pit: { id, keep_alive: "10m" }, size: 500, track_total_hits: true, timeout: "20s",
  query: { bool: { filter: [{ range: { "@timestamp": { gte: "2026-10-03T10:00:00Z", lte: "2026-10-03T10:05:00Z" } } }] } },
  sort: [{ "@timestamp": { order: "asc", unmapped_type: "date" } }, { _shard_doc: "asc" }]
} });

describe("relay snapshot limits", () => {
  it.each([16385, 128 * 1024, RELAY_MAX_PIT_ID_BYTES])("preserves a %i-byte opaque ID in searches and cleanup", size => {
    const id = "p".repeat(size);
    expect(relayPitIdSchema.parse(id)).toBe(id);
    expect(validateRelayOperation(search(id), policy)).toEqual(search(id));
    expect(validateRelayOperation({ kind: "closePit", id }, policy)).toEqual({ kind: "closePit", id });
  });

  it("rejects IDs over the byte bound, including multibyte strings", () => {
    const multibyte = "\u00e9".repeat(RELAY_MAX_PIT_ID_BYTES / 2);
    expect(relayPitIdSchema.parse(multibyte)).toBe(multibyte);
    for (const id of ["", "p".repeat(RELAY_MAX_PIT_ID_BYTES + 1), multibyte + "p"]) {
      expect(relayPitIdSchema.safeParse(id).success).toBe(false);
      expect(() => validateRelayOperation(search(id), policy)).toThrow();
      expect(() => validateRelayOperation({ kind: "closePit", id }, policy)).toThrow();
    }
  });

  it("does not widen page, query or index permissions for large IDs", () => {
    const operation = search("p".repeat(128 * 1024));
    expect(() => validateRelayOperation({ ...operation, body: { ...operation.body, size: 501 } }, policy)).toThrow();
    expect(() => validateRelayOperation({ ...operation, body: { ...operation.body, query: { match_all: {} } } }, policy)).toThrow();
    expect(() => validateRelayOperation({ kind: "openPit", indexPattern: "finance-*" }, policy)).toThrow();
  });
});

describe("fixed live templates", () => {
  const operation = { kind: "live", indexPattern: "logs-*", stage: "scans", from: "2026-10-03T10:00:00.000Z", to: "2026-10-03T10:05:00.000Z", query: "observer.name:edge-a" };
  it("builds bounded evidence aggregation without PIT, scripts or caller-supplied DSL", () => {
    const body = relayLiveSearch(operation, policy) as any;
    expect(body.size).toBe(0); expect(body.timeout).toBe("15s"); expect(body.pit).toBeUndefined();
    expect(body.aggs.sources.terms.size).toBe(32);
    expect(body.aggs.sources.aggs.proof.top_hits.size).toBe(5);
    expect(body.query.bool.filter.at(-1).bool.must_not).toContainEqual({ term: { "source.ip": "10.0.0.0/8" } });
    expect(body.query.bool.filter.at(-1).bool.must_not).toContainEqual({ term: { "destination.port": 53 } });
    expect(body.query.bool.filter).toContainEqual({ query_string: { query: operation.query, lenient: false, allow_leading_wildcard: false } });
    expect(() => relayLiveSearch({ ...operation, aggs: { arbitrary: {} } }, policy)).toThrow();
  });
  it("bounds window, index and candidate scopes and samples authentication separately", () => {
    for (const bad of [ { ...operation, from: operation.to }, { ...operation, to: "2026-10-03T10:16:00.000Z" },
      { ...operation, indexPattern: "finance-*" }, { ...operation, sources: ["1.2.3.4"] },
      { ...operation, stage: "context", sources: [] }, { ...operation, stage: "context", sources: ["not-an-ip"] },
      { ...operation, stage: "context", sources: Array(33).fill("1.2.3.4") } ]) expect(() => relayLiveSearch(bad, policy)).toThrow();
    const body = relayLiveSearch({ ...operation, stage: "security" }, policy) as any;
    expect(body.aggs.authentication.aggs.users.aggs.proof.top_hits.size).toBe(20);
    expect(body.aggs.signals.aggs.proof.top_hits.size).toBe(100);
  });
});
