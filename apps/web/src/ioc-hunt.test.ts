import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { huntFailure, loadIocHuntOffset, saveIocHuntOffset, saveIocHuntCampaign, loadIocHuntCampaignId, resetIocHuntCampaign } from "./ioc-hunt";

const scope = { indexPattern: "logs-*", timestampField: "@timestamp", from: "now/d", to: "now" };
let saved: string | null;
beforeEach(() => {
  saved = null;
  vi.stubGlobal("localStorage", { getItem: () => saved, setItem: (_key: string, value: string) => { saved = value; } });
});
afterEach(() => vi.unstubAllGlobals());

describe("IOC hunt query-scoped progress", () => {
  it("keeps type cursors independent across reloads", () => {
    saveIocHuntOffset(scope, 500, "ip");
    saveIocHuntOffset(scope, 1000, "domain");
    saveIocHuntOffset(scope, 500, "hash");
    expect(loadIocHuntOffset(scope, "ip")).toBe(500);
    expect(loadIocHuntOffset(scope, "domain")).toBe(1000);
    expect(loadIocHuntOffset(scope, "hash")).toBe(500);
    expect(loadIocHuntOffset(scope, "url")).toBe(0);
    expect(loadIocHuntOffset({ ...scope, from: "now-7d" }, "domain")).toBe(0);
  });
  it("retains exhausted cursors and clears all types only on Fresh Scan", () => {
    const progress = { totalAvailable: 500, checked: 500, excluded: 0, nextBatchOffset: 500, hasMore: false };
    const id = "75e1b6f4-7097-4212-8b8e-ef81029c9177";
    saveIocHuntCampaign(scope, id, { all: progress, ip: progress, domain: progress, hash: progress, url: progress });
    expect(loadIocHuntCampaignId(scope)).toBe(id);
    expect(loadIocHuntOffset(scope, "domain")).toBe(500);
    resetIocHuntCampaign(scope);
    expect(loadIocHuntCampaignId(scope)).toBeUndefined();
    for (const group of ["ip", "domain", "hash", "url"] as const) expect(loadIocHuntOffset(scope, group)).toBe(0);
  });
  it("retains progress after reload for the exact query", () => {
    saveIocHuntOffset(scope, 500);
    expect(loadIocHuntOffset({ ...scope })).toBe(500);
  });
  it.each([{ indexPattern: "logs-firewall-*" }, { timestampField: "event.created" }, { from: "now-7d" }, { to: "now/d" }])("does not reuse another query's cursor: %j", (change) => {
    saveIocHuntOffset(scope, 500);
    expect(loadIocHuntOffset({ ...scope, ...change })).toBe(0);
    expect(loadIocHuntOffset(scope)).toBe(500);
  });
  it("tracks only the current campaign, matching extension storage", () => {
    saveIocHuntOffset(scope, 500);
    const other = { ...scope, from: "now-7d" };
    saveIocHuntOffset(other, 1000);
    expect(loadIocHuntOffset(scope)).toBe(0);
    expect(loadIocHuntOffset(other)).toBe(1000);
  });
  it.each(['{"today":500}', "invalid", "null"])("ignores unscoped legacy or invalid cursors: %s", (value) => {
    saved = value;
    expect(loadIocHuntOffset(scope)).toBe(0);
  });
  it("handles unavailable storage without breaking the hunt", () => {
    vi.stubGlobal("localStorage", { getItem: () => { throw new Error("denied"); }, setItem: () => { throw new Error("denied"); } });
    expect(loadIocHuntOffset(scope)).toBe(0);
    expect(() => saveIocHuntOffset(scope, 500)).not.toThrow();
  });
  it("only accepts bounded authoritative retry offsets", () => {
    expect(huntFailure({ code: "INVALID_REQUEST", message: "Retry offset 1000", details: { huntRecovery: "retry", nextBatchOffset: 1000 } }).nextBatchOffset).toBe(1000);
    expect(huntFailure({ code: "INVALID_REQUEST", message: "Changed scope", details: { huntRecovery: "fresh_scan", nextBatchOffset: -1 } })).toEqual({ message: "Changed scope", recovery: "fresh_scan" });
    expect(huntFailure({ code: "KIBANA_AUTH_REQUIRED", message: "Sign in" })).toEqual({ message: "Sign in", recovery: "retry" });
  });
});
