import { beforeEach, afterEach, it, expect, vi } from "vitest";
import { lookupRelayReputation, resetGtiLookupState } from "../src/kibana";

let saved: Record<string, unknown>;
beforeEach(() => {
  saved = { googleThreatIntelApiKey: "browser-private-test-key" }; resetGtiLookupState();
  vi.stubGlobal("chrome", { storage: { local: {
    get: async () => saved, set: async (value: Record<string, unknown>) => { Object.assign(saved, value); }
  } } });
});
afterEach(() => vi.unstubAllGlobals());

it("uses and caches the browser key without exporting it in a GTI result", async () => {
  const fetcher = vi.fn(async (_url: unknown, _init: unknown) => Response.json({ data: { attributes: {
    last_analysis_stats: { malicious: 5, harmless: 80 }, gti_assessment: { verdict: { value: "VERDICT_MALICIOUS" }, threat_score: { value: 88 } }
  } } })); vi.stubGlobal("fetch", fetcher);
  const target = { type: "ip", value: "185.220.101.4" };
  const first = await lookupRelayReputation(target);
  expect(first).toMatchObject({ status: "scored", verdict: "malicious", score: 88, malicious: 5 });
  expect(fetcher.mock.calls[0]![1]).toMatchObject({ headers: { "x-apikey": "browser-private-test-key", "x-tool": "SOC-WatchBridge" } });
  expect(JSON.stringify(first)).not.toContain("browser-private-test-key");
  expect(await lookupRelayReputation(target)).toMatchObject({ cached: true, checkedAt: first.checkedAt }); expect(fetcher).toHaveBeenCalledTimes(1);
  expect(first.checkedAt).toEqual(expect.any(String));
});

it.each([401, 404, 429])("returns HTTP %i provider status without a fake verdict or Kibana disconnect", async status => {
  vi.stubGlobal("fetch", vi.fn(async () => new Response("", { status })));
  const result = await lookupRelayReputation({ type: "domain", value: "dangerous.com" });
  expect(result.verdict).toBe("unknown"); expect(result.status).toBe(({ 401: "unauthorized", 404: "not_found", 429: "rate_limited" })[status]);
});

it("does not call GTI for private targets, missing keys, or claim an empty assessment is benign", async () => {
  const fetcher = vi.fn(async () => Response.json({ data: { attributes: { gti_assessment: { nonsense: true } } } })); vi.stubGlobal("fetch", fetcher);
  await expect(lookupRelayReputation({ type: "domain", value: "internal.local" })).rejects.toThrow(); expect(fetcher).not.toHaveBeenCalled();
  saved.googleThreatIntelApiKey = "";
  expect(await lookupRelayReputation({ type: "domain", value: "dangerous.com" })).toMatchObject({ status: "not_configured", verdict: "unknown" }); expect(fetcher).not.toHaveBeenCalled();
  saved.googleThreatIntelApiKey = "key";
  expect(await lookupRelayReputation({ type: "domain", value: "dangerous.com" })).toMatchObject({ status: "unavailable", verdict: "unknown" });
});
