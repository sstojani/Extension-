import { describe, expect, it } from "vitest";
import { RELAY_MAX_PIT_ID_BYTES, relayPitIdSchema, validateRelayOperation } from "../src/index";

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
