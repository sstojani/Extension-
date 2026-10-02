import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { type BridgeResponse } from "@soc-watch/protocol";
import { isExcludedCandidate, type CandidateException } from "../src/candidate-exclusions";
import {
  HUNT_BATCH_LIMIT,
  HUNT_CAMPAIGN_KEY,
  HUNT_CAMPAIGN_LEASE_KEY,
  HUNT_CAMPAIGN_LEASE_MS,
  HUNT_CAMPAIGN_MAX_BYTES,
  HUNT_CAMPAIGN_TTL_MS,
  runHuntCampaignBatch,
  type HuntCampaignBatch,
  type HuntCampaign,
  type HuntCampaignParams
} from "../src/hunt-campaign";
import { collectThreatIntelSnapshot, prioritizeThreatIntel, type ThreatIntelIOC } from "../src/threat-intel";

vi.mock("../src/threat-intel", async (importOriginal) => ({
  ...await importOriginal<typeof import("../src/threat-intel")>(),
  collectThreatIntelSnapshot: vi.fn()
}));

vi.mock("../src/kibana", async (importOriginal) => ({
  ...await importOriginal<typeof import("../src/kibana")>(),
  searchIOCBatch: vi.fn()
}));

const NOW = Date.parse("2026-10-02T12:00:00Z");
const params: HuntCampaignParams = {
  indexPattern: "logs-*",
  timestampField: "@timestamp",
  from: "now-30d",
  to: "now",
  maxIocs: 3,
  batchOffset: 0
};
const provider = { name: "Feodo Tracker", status: "healthy" as const, collected: 8, byType: { domain: 8 } };
const collect = vi.mocked(collectThreatIntelSnapshot);
const query = vi.fn(async (iocs: ThreatIntelIOC[]) => iocs.map((ioc) => ioc.normalized));
let storage: Record<string, unknown>;
let feed: ThreatIntelIOC[];
let locked: boolean;

function makeFeed(count = 8): ThreatIntelIOC[] {
  return prioritizeThreatIntel(Array.from({ length: count }, (_, index) => ({
    value: `ioc-${index}.example.test`,
    source: "Feodo Tracker",
    threatType: "botnet_c2"
  })), NOW);
}

function storedCampaign(): HuntCampaign {
  return structuredClone(storage[HUNT_CAMPAIGN_KEY]) as HuntCampaign;
}

function run(batchOffset = 0, overrides: Partial<HuntCampaignParams> = {}, include = (_ioc: ThreatIntelIOC) => true) {
  return runHuntCampaignBatch({ ...params, ...overrides, batchOffset }, { include, query });
}

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((complete) => { resolve = complete; });
  return { promise, resolve };
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(NOW);
  storage = {};
  feed = makeFeed();
  locked = false;
  query.mockReset().mockImplementation(async (iocs) => iocs.map((ioc) => ioc.normalized));
  collect.mockReset().mockImplementation(async (include = () => true) => {
    const iocs = feed.filter(include);
    return { iocs, providers: [provider], totalAvailable: iocs.length, excluded: feed.length - iocs.length };
  });
  vi.stubGlobal("chrome", {
    storage: {
      local: {
        get: vi.fn(async (keys: string | string[]) => Object.fromEntries(
          (Array.isArray(keys) ? keys : [keys]).map((key) => [key, structuredClone(storage[key])])
        )),
        set: vi.fn(async (values: Record<string, unknown>) => { Object.assign(storage, structuredClone(values)); }),
        remove: vi.fn(async (key: string) => { delete storage[key]; })
      }
    }
  });
  vi.stubGlobal("navigator", {
    locks: {
      request: vi.fn(async (_name: string, _options: unknown, callback: (lock: object | null) => Promise<unknown>) => {
        if (locked) return callback(null);
        locked = true;
        try {
          return await callback({ name: HUNT_CAMPAIGN_KEY, mode: "exclusive" });
        } finally {
          locked = false;
        }
      })
    }
  });
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("immutable IOC hunt campaigns", () => {
  it("persists the fresh normalized, ranked snapshot before the first SIEM query", async () => {
    query.mockImplementationOnce(async (iocs) => {
      expect(storedCampaign().iocs).toEqual(feed);
      expect(storedCampaign().progress.nextBatchOffset).toBe(0);
      return iocs.map((ioc) => ioc.normalized);
    });
    const batch = await run();
    expect(batch.results).toEqual(feed.slice(0, 3).map((ioc) => ioc.normalized));
    expect(batch).toMatchObject({
      campaignId: storedCampaign().campaignId,
      createdAt: new Date(NOW).toISOString(),
      batchNumber: 1,
      batchOffset: 0,
      batchSize: 3,
      nextBatchOffset: 3,
      totalAvailable: 8,
      hasMore: true,
      retryBatchOffset: null,
      progress: { checked: 3, excluded: 0, completedBatches: 1, retry: null }
    });
    expect(Date.parse(batch.expiresAt) - Date.parse(batch.createdAt)).toBe(HUNT_CAMPAIGN_TTL_MS);
    expect(storage[HUNT_CAMPAIGN_LEASE_KEY]).toBeUndefined();
  });

  it("uses non-overlapping batches from the same snapshot despite feed and ranking changes", async () => {
    const original = structuredClone(feed);
    const first = await run();
    feed = prioritizeThreatIntel([{ value: "new.example.test", source: "ThreatFox", confidence: 100 }], NOW);
    const second = await run(first.nextBatchOffset);
    const last = await run(second.nextBatchOffset);
    expect(collect).toHaveBeenCalledTimes(1);
    expect(second.campaignId).toBe(first.campaignId);
    expect(second.createdAt).toBe(first.createdAt);
    expect(second.batchNumber).toBe(2);
    expect([...first.results, ...second.results, ...last.results]).toEqual(original.map((ioc) => ioc.normalized));
    expect(new Set([...first.results, ...second.results, ...last.results]).size).toBe(8);
    expect(storedCampaign().iocs).toEqual(original);
    expect(last).toMatchObject({ batchSize: 2, nextBatchOffset: 8, hasMore: false, progress: { checked: 8 } });
  });

  it("offset zero explicitly replaces the campaign with fresh intelligence", async () => {
    const first = await run();
    feed = prioritizeThreatIntel([{ value: "replacement.example.test", source: "ThreatFox" }], NOW);
    vi.setSystemTime(NOW + 1000);
    const fresh = await run();
    expect(collect).toHaveBeenCalledTimes(2);
    expect(fresh.campaignId).not.toBe(first.campaignId);
    expect(fresh.createdAt).toBe(new Date(NOW + 1000).toISOString());
    expect(fresh.results).toEqual(["replacement.example.test"]);
    expect(fresh.progress.checked).toBe(1);
  });

  it("resumes from local storage after the campaign module restarts", async () => {
    const first = await run();
    vi.resetModules();
    const restarted = await import("../src/hunt-campaign");
    const second = await restarted.runHuntCampaignBatch({ ...params, batchOffset: 3 }, { include: () => true, query });
    expect(second.campaignId).toBe(first.campaignId);
    expect(second.results).toEqual(feed.slice(3, 6).map((ioc) => ioc.normalized));
    expect(second.nextBatchOffset).toBe(6);
    expect(collect).toHaveBeenCalledTimes(1);
  });

  it("does not commit progress while the SIEM query is still running", async () => {
    await run();
    const started = deferred();
    const finish = deferred();
    query.mockImplementationOnce(async (iocs) => {
      started.resolve();
      await finish.promise;
      return iocs.map((ioc) => ioc.normalized);
    });
    const pending = run(3);
    await started.promise;
    expect(storedCampaign().progress).toMatchObject({ nextBatchOffset: 3, checked: 3 });
    finish.resolve();
    expect((await pending).nextBatchOffset).toBe(6);
  });

  it("preserves the failed offset and retries the same batch after restart and feed changes", async () => {
    const first = await run();
    const snapshot = storedCampaign().iocs;
    query.mockRejectedValueOnce(new Error("SIEM unavailable"));
    const failed = await run(3);
    expect(failed).toMatchObject({
      error: "SIEM unavailable",
      results: [],
      batchOffset: 3,
      batchSize: 3,
      nextBatchOffset: 3,
      retryBatchOffset: 3,
      hasMore: true,
      progress: { checked: 3, completedBatches: 1, retry: { batchOffset: 3, batchSize: 3 } }
    });
    expect(storedCampaign().iocs).toEqual(snapshot);
    feed = makeFeed(1);
    vi.resetModules();
    const restarted = await import("../src/hunt-campaign");
    const retry = await restarted.runHuntCampaignBatch({ ...params, maxIocs: 1, batchOffset: 3 }, { include: () => true, query });
    expect(retry.campaignId).toBe(first.campaignId);
    expect(retry.results).toEqual(failed.iocs.map((ioc) => ioc.normalized));
    expect(retry).toMatchObject({ nextBatchOffset: 6, retryBatchOffset: null, progress: { checked: 6, retry: null } });
    expect(collect).toHaveBeenCalledTimes(1);
  });

  it("keeps the first snapshot and zero progress when the first query fails", async () => {
    query.mockRejectedValueOnce(new Error("SIEM unavailable"));
    const failed = await run();
    expect(failed).toMatchObject({ nextBatchOffset: 0, retryBatchOffset: 0, progress: { checked: 0 } });
    expect(storedCampaign().iocs).toEqual(feed);
    expect(storedCampaign().progress.retry?.batchOffset).toBe(0);
  });

  it("treats an incomplete SIEM batch as a retryable failure", async () => {
    await run();
    query.mockResolvedValueOnce([]);
    const failed = await run(3);
    expect(failed.error).toContain("incomplete batch");
    expect(failed.nextBatchOffset).toBe(3);
    expect(storedCampaign().progress.checked).toBe(3);
  });

  it("returns exhaustion without another query, refetch, or progress increment", async () => {
    feed = makeFeed(3);
    const first = await run();
    const campaign = storedCampaign();
    const exhausted = await run(3);
    expect(exhausted).toMatchObject({ campaignId: first.campaignId, batchSize: 0, nextBatchOffset: 3, hasMore: false, results: [] });
    expect(storedCampaign()).toEqual(campaign);
    expect(query).toHaveBeenCalledTimes(1);
    expect(collect).toHaveBeenCalledTimes(1);
  });

  it("handles a fresh empty snapshot without querying all SIEM events", async () => {
    feed = [];
    const empty = await run();
    expect(empty).toMatchObject({ batchSize: 0, totalAvailable: 0, nextBatchOffset: 0, hasMore: false });
    expect(query).not.toHaveBeenCalled();
    expect(storedCampaign().progress.completedBatches).toBe(0);
  });

  it.each([
    { indexPattern: "other-*" },
    { timestampField: "event.created" },
    { from: "now-7d" },
    { to: "now/d" }
  ])("rejects mismatched query settings %j without fetching feeds", async (changes) => {
    await run();
    const original = storedCampaign();
    await expect(run(3, changes)).rejects.toThrow("does not match");
    expect(storedCampaign()).toEqual(original);
    expect(collect).toHaveBeenCalledTimes(1);
    expect(query).toHaveBeenCalledTimes(1);
  });

  it.each([1, 2, 4, 100])("rejects stale or skipped offset %i", async (offset) => {
    await run();
    await expect(run(offset)).rejects.toThrow("Retry offset 3");
    expect(collect).toHaveBeenCalledTimes(1);
    expect(query).toHaveBeenCalledTimes(1);
    expect(storedCampaign().progress.nextBatchOffset).toBe(3);
  });

  it("requires a fresh scan when a subsequent offset has no stored campaign", async () => {
    await expect(run(3)).rejects.toThrow("missing or invalid");
    expect(collect).not.toHaveBeenCalled();
    expect(query).not.toHaveBeenCalled();
    expect(storage[HUNT_CAMPAIGN_LEASE_KEY]).toBeUndefined();
  });

  it("expires at 24 hours without silently refreshing, and permits an explicit fresh scan", async () => {
    await run();
    vi.setSystemTime(NOW + HUNT_CAMPAIGN_TTL_MS - 1);
    expect((await run(3)).nextBatchOffset).toBe(6);
    vi.setSystemTime(NOW + HUNT_CAMPAIGN_TTL_MS);
    await expect(run(6)).rejects.toThrow("expired");
    expect(collect).toHaveBeenCalledTimes(1);
    await run();
    expect(collect).toHaveBeenCalledTimes(2);
  });

  it.each(["version", "progress", "ioc", "duplicates", "expiry", "stats"])("rejects corrupt stored %s without refetching", async (corruption) => {
    await run();
    const campaign = storedCampaign();
    if (corruption === "version") Object.assign(campaign, { schemaVersion: 2 });
    if (corruption === "progress") campaign.progress.checked = 100;
    if (corruption === "ioc") campaign.iocs[0]!.normalized = "modified.example.test";
    if (corruption === "duplicates") campaign.iocs[1] = campaign.iocs[0]!;
    if (corruption === "expiry") campaign.expiresAt = new Date(NOW + HUNT_CAMPAIGN_TTL_MS + 1).toISOString();
    if (corruption === "stats") campaign.stats.totalAvailable = 100;
    storage[HUNT_CAMPAIGN_KEY] = campaign;
    await expect(run(3)).rejects.toThrow("missing or invalid");
    expect(collect).toHaveBeenCalledTimes(1);
    expect(query).toHaveBeenCalledTimes(1);
  });

  it("caps a protocol-valid request for 5000 IOCs at 500 per SIEM batch", async () => {
    feed = makeFeed(1200);
    const first = await run(0, { maxIocs: 5000 });
    const second = await run(first.nextBatchOffset, { maxIocs: 5000 });
    expect(query.mock.calls.map(([iocs]) => iocs.length)).toEqual([HUNT_BATCH_LIMIT, HUNT_BATCH_LIMIT]);
    expect(second.nextBatchOffset).toBe(1000);
    expect(first.batchSize).toBe(500);
  });

  it("bounds serialized storage while preserving the highest ranked prefix and reporting truncation", async () => {
    feed = makeFeed(6000).map((ioc) => ({ ...ioc, riskReasons: ["x".repeat(1600)] }));
    const original = structuredClone(feed);
    const first = await run();
    const campaign = storedCampaign();
    expect(new TextEncoder().encode(JSON.stringify(campaign)).byteLength).toBeLessThanOrEqual(HUNT_CAMPAIGN_MAX_BYTES);
    expect(campaign.iocs).toEqual(original.slice(0, campaign.iocs.length));
    expect(first.stats.truncated).toBeGreaterThan(0);
    expect(first.stats.totalFetched).toBe(6000);
    expect(first.stats.totalAvailable + first.stats.truncated).toBe(6000);
    expect((await run(3)).campaignId).toBe(first.campaignId);
  });

  it("applies initial allowlists during collection and later changes only to the selected batch", async () => {
    const original = structuredClone(feed);
    const initiallyExcluded = original[0]!.normalized;
    let exclusions = [`domain:${initiallyExcluded}`];
    let exceptions: CandidateException[] = [];
    const include = (ioc: ThreatIntelIOC) => !isExcludedCandidate({ type: ioc.type, normalized: ioc.normalized }, exclusions, exceptions, Date.now());
    const first = await run(0, {}, include);
    const snapshot = storedCampaign().iocs;
    expect(snapshot).toEqual(original.slice(1));
    expect(first.stats).toMatchObject({ totalFetched: 8, totalAvailable: 7, excludedAtCreation: 1 });
    exclusions = [];
    exceptions = [{ id: "new-exception", scope: "domain", value: snapshot[3]!.normalized, enabled: true, createdAt: new Date(NOW).toISOString() }];
    const second = await run(3, {}, include);
    expect(second.results).toEqual(snapshot.slice(4, 6).map((ioc) => ioc.normalized));
    expect(second).toMatchObject({ batchOffset: 3, batchSize: 3, nextBatchOffset: 6, progress: { checked: 5, excluded: 1 } });
    exceptions = [];
    const last = await run(6, {}, include);
    expect(last.results).toEqual(snapshot.slice(6).map((ioc) => ioc.normalized));
    expect(storedCampaign().iocs).toEqual(snapshot);
    expect(collect).toHaveBeenCalledTimes(1);
    expect([...first.results, ...second.results, ...last.results]).not.toContain(initiallyExcluded);
  });

  it("advances only excluded positions when the selected batch is entirely allowlisted", async () => {
    await run();
    const snapshot = storedCampaign().iocs;
    const skipped = await run(3, {}, () => false);
    expect(skipped).toMatchObject({ iocs: [], results: [], batchSize: 3, nextBatchOffset: 6, progress: { checked: 3, excluded: 3 } });
    expect(query).toHaveBeenCalledTimes(1);
    expect(storedCampaign().iocs).toEqual(snapshot);
    expect((await run(6)).results).toEqual(snapshot.slice(6).map((ioc) => ioc.normalized));
  });

  it("does not let the SIEM callback mutate the saved snapshot", async () => {
    const original = structuredClone(feed);
    query.mockImplementationOnce(async (iocs) => {
      const values = iocs.map((ioc) => ioc.normalized);
      iocs[0]!.normalized = "changed.example.test";
      iocs[0]!.sources.push("Changed");
      return values;
    });
    await run();
    expect(storedCampaign().iocs).toEqual(original);
  });

  it("rejects concurrent calls, including from a restarted module, before collecting or querying twice", async () => {
    const started = deferred();
    const finish = deferred();
    query.mockImplementationOnce(async (iocs) => {
      started.resolve();
      await finish.promise;
      return iocs.map((ioc) => ioc.normalized);
    });
    const pending = run();
    await started.promise;
    await expect(run()).rejects.toThrow("already running");
    vi.resetModules();
    const restarted = await import("../src/hunt-campaign");
    await expect(restarted.runHuntCampaignBatch({ ...params, batchOffset: 3 }, { include: () => true, query })).rejects.toThrow("already running");
    finish.resolve();
    await pending;
    expect(collect).toHaveBeenCalledTimes(1);
    expect(query).toHaveBeenCalledTimes(1);
  });

  it("blocks an unexpired persisted busy lease after a worker restart and recovers when it expires", async () => {
    const first = await run();
    storage[HUNT_CAMPAIGN_LEASE_KEY] = { token: crypto.randomUUID(), expiresAt: NOW + HUNT_CAMPAIGN_LEASE_MS };
    await expect(run(3)).rejects.toThrow("busy lease expires");
    vi.setSystemTime(NOW + HUNT_CAMPAIGN_LEASE_MS);
    const next = await run(3);
    expect(next.campaignId).toBe(first.campaignId);
    expect(next.nextBatchOffset).toBe(6);
    expect(collect).toHaveBeenCalledTimes(1);
  });

  it("renews the lease for a long query and releases it afterward", async () => {
    const started = deferred();
    const finish = deferred();
    query.mockImplementationOnce(async (iocs) => {
      started.resolve();
      await finish.promise;
      return iocs.map((ioc) => ioc.normalized);
    });
    const pending = run();
    await started.promise;
    const lease = structuredClone(storage[HUNT_CAMPAIGN_LEASE_KEY]) as { token: string; expiresAt: number };
    await vi.advanceTimersByTimeAsync(HUNT_CAMPAIGN_LEASE_MS * 2);
    expect(storage[HUNT_CAMPAIGN_LEASE_KEY]).toMatchObject({ token: lease.token, expiresAt: Date.now() + HUNT_CAMPAIGN_LEASE_MS });
    await expect(run()).rejects.toThrow("already running");
    finish.resolve();
    expect((await pending).nextBatchOffset).toBe(3);
    expect(storage[HUNT_CAMPAIGN_LEASE_KEY]).toBeUndefined();
  });

  it("fences a stale lease owner from committing or releasing another owner's lease", async () => {
    await run();
    const started = deferred();
    const finish = deferred();
    query.mockImplementationOnce(async (iocs) => {
      started.resolve();
      await finish.promise;
      return iocs.map((ioc) => ioc.normalized);
    });
    const pending = run(3).catch((error: unknown) => error);
    await started.promise;
    const replacement = { token: crypto.randomUUID(), expiresAt: NOW + HUNT_CAMPAIGN_LEASE_MS };
    storage[HUNT_CAMPAIGN_LEASE_KEY] = replacement;
    finish.resolve();
    expect(await pending).toMatchObject({ message: expect.stringContaining("lease was lost") });
    expect(storedCampaign().progress.nextBatchOffset).toBe(3);
    expect(storage[HUNT_CAMPAIGN_LEASE_KEY]).toEqual(replacement);
  });

  it("does not query if the fresh snapshot cannot be persisted", async () => {
    await run();
    const original = storedCampaign();
    const set = vi.mocked(chrome.storage.local.set);
    set.mockImplementation(async (values) => {
      if (HUNT_CAMPAIGN_KEY in values) throw new Error("Storage quota exceeded");
      Object.assign(storage, structuredClone(values));
    });
    await expect(run()).rejects.toThrow("quota exceeded");
    expect(storedCampaign()).toEqual(original);
    expect(query).toHaveBeenCalledTimes(1);
    expect(storage[HUNT_CAMPAIGN_LEASE_KEY]).toBeUndefined();
  });

  it("leaves committed progress unchanged if writing successful query progress fails", async () => {
    await run();
    const original = storedCampaign();
    const set = vi.mocked(chrome.storage.local.set);
    set.mockImplementationOnce(async (values) => { Object.assign(storage, structuredClone(values)); });
    set.mockRejectedValueOnce(new Error("Storage unavailable"));
    await expect(run(3)).rejects.toThrow("Storage unavailable");
    expect(storedCampaign()).toEqual(original);
    const retried = await run(3);
    expect(retried.nextBatchOffset).toBe(6);
    expect(collect).toHaveBeenCalledTimes(1);
  });

  it("fails closed if the browser cannot provide an exclusive campaign lock", async () => {
    vi.stubGlobal("navigator", {});
    await expect(run()).rejects.toThrow("locking is unavailable");
    expect(collect).not.toHaveBeenCalled();
    expect(query).not.toHaveBeenCalled();
  });
});

describe("threat-intel snapshot collection", () => {
  it("fetches full feeds once and preserves existing normalization, deduplication, ranking, and exclusions", async () => {
    const actual = await vi.importActual<typeof import("../src/threat-intel")>("../src/threat-intel");
    const fetchFeed = vi.fn(async (url: string) => {
      const body = url.includes("ipblocklist.csv")
        ? "2026-10-02,203.0.113.8,443,online,Dridex"
        : url.includes("openphish.com")
          ? "https://PHISH.example.test/a\nhttps://phish.example.test/b"
          : url.includes("IP-High-Confidence")
            ? "203.0.113.8\n198.51.100.9"
            : url.includes("DOMAIN-High-Confidence")
              ? "PHISH[.]example[.]test\nexcluded.example.test"
              : "# empty feed";
      return new Response(body);
    });
    vi.stubGlobal("fetch", fetchFeed);
    const snapshot = await actual.collectThreatIntelSnapshot((ioc) => ioc.normalized !== "excluded.example.test");
    expect(fetchFeed).toHaveBeenCalledTimes(6);
    expect(snapshot.iocs).toHaveLength(5);
    expect(snapshot).toMatchObject({ totalAvailable: 5, excluded: 1 });
    expect(snapshot.iocs[0]?.normalized).toBe("203.0.113.8");
    expect(snapshot.iocs[0]?.sources).toEqual(["Feodo Tracker", "ThreatView IP"]);
    expect(snapshot.iocs.find((ioc) => ioc.type === "domain" && ioc.normalized === "phish.example.test")?.sources).toEqual(["OpenPhish", "ThreatView Domain"]);
    expect(snapshot.providers.filter((item) => item.status === "skipped").map((item) => item.name)).toEqual(["ThreatFox", "MalwareBazaar"]);
    expect(new Set(snapshot.iocs.map((ioc) => `${ioc.type}:${ioc.normalized}`)).size).toBe(snapshot.iocs.length);
    const batch = await actual.collectDailyThreatIntel(2, 2, (ioc) => ioc.normalized !== "excluded.example.test");
    expect(batch.iocs).toEqual(snapshot.iocs.slice(2, 4));
    expect(batch).toMatchObject({ totalAvailable: 5, batchOffset: 2, batchSize: 2, hasMore: true });
  });
});

describe("IOC hunt bridge responses", () => {
  type HuntUiResult = HuntCampaignBatch<unknown> & {
    hunted: number;
    collected: number;
    alertsCreated: number;
    notificationsSent: number;
    notificationsFailed: number;
    alertError?: string;
  };
  let sendHunt: (batchOffset?: number, maxIocs?: number) => Promise<HuntUiResult>;
  let search: ReturnType<typeof vi.mocked<typeof import("../src/kibana").searchIOCBatch>>;

  beforeEach(async () => {
    vi.resetModules();
    const event = () => ({ addListener: vi.fn() });
    Object.assign(chrome, {
      runtime: {
        onMessageExternal: event(),
        onConnectExternal: event(),
        onConnect: event(),
        onMessage: event(),
        onInstalled: event(),
        onStartup: event()
      },
      tabs: { query: vi.fn(async () => []) },
      alarms: { onAlarm: event(), get: vi.fn(async () => undefined), create: vi.fn(), clear: vi.fn(async () => true) },
      action: { setBadgeText: vi.fn(), setBadgeBackgroundColor: vi.fn(), setTitle: vi.fn(), setIcon: vi.fn() }
    });
    storage.threatRadarAgentConfig = { enabled: false };
    storage.threatAlertConfig = { browserNotifications: false };
    search = vi.mocked((await import("../src/kibana")).searchIOCBatch);
    search.mockReset().mockImplementation(async ({ iocs }) => ({
      timed_out: false,
      _shards: { failed: 0 },
      aggregations: {
        ioc_matches: { buckets: Object.fromEntries(iocs.map((_ioc, index) => [`ioc_${index}`, { doc_count: 0 }])) }
      }
    }));
    await import("../src/service-worker");
    const listener = vi.mocked(chrome.runtime.onMessage.addListener).mock.calls[0]![0];
    sendHunt = async (batchOffset = 0, maxIocs = 3) => {
      const response = await new Promise<BridgeResponse<HuntUiResult>>((resolve) => {
        listener({
          version: 1,
          requestId: crypto.randomUUID(),
          action: "threatIntel.dailyHunt",
          params: { ...params, batchOffset, maxIocs, size: 5 }
        }, {}, resolve);
      });
      if (!response.success) throw new Error(JSON.stringify(response.error));
      return response.data;
    };
  });

  it("returns the existing batch fields and immutable campaign metadata, and enforces 500 in the actual SIEM call", async () => {
    feed = makeFeed(600);
    const first = await sendHunt(0, 5000);
    expect(first).toMatchObject({ batchSize: 500, hunted: 500, collected: 500, totalAvailable: 600, nextBatchOffset: 500, hasMore: true });
    expect(search.mock.calls[0]![0].iocs).toHaveLength(500);
    feed = makeFeed(1);
    const second = await sendHunt(500, 5000);
    expect(second).toMatchObject({ campaignId: first.campaignId, createdAt: first.createdAt, batchSize: 100, nextBatchOffset: 600, hasMore: false });
    expect(collect).toHaveBeenCalledTimes(1);
  });

  it("returns per-IOC errors with zero hunted and the unchanged retry offset on SIEM failure", async () => {
    const first = await sendHunt();
    search.mockRejectedValueOnce(new Error("SIEM unavailable"));
    const failed = await sendHunt(3);
    expect(failed).toMatchObject({
      campaignId: first.campaignId,
      error: "SIEM unavailable",
      nextBatchOffset: 3,
      retryBatchOffset: 3,
      hasMore: true,
      hunted: 0,
      alertsCreated: 0,
      notificationsSent: 0,
      progress: { checked: 3 }
    });
    expect(failed.results).toHaveLength(3);
    expect(failed.results.every((result) => (result as { error: string }).error === "SIEM unavailable")).toBe(true);
    expect(failed.providers[0]).toMatchObject({ checked: 0, matched: 0 });
    expect((await sendHunt(3)).nextBatchOffset).toBe(6);
    expect(collect).toHaveBeenCalledTimes(1);
  });

  it.each([
    { timed_out: true },
    { _shards: { failed: 1 } },
    { error: { reason: "search failed" } },
    { aggregations: {} },
    { aggregations: { ioc_matches: { buckets: { ioc_0: { doc_count: 0 } } } } }
  ])("does not commit an HTTP-success response with failed, partial, or missing results: %j", async (invalid) => {
    await sendHunt();
    search.mockResolvedValueOnce(invalid);
    const failed = await sendHunt(3);
    expect(failed.error).toBeDefined();
    expect(failed).toMatchObject({ nextBatchOffset: 3, retryBatchOffset: 3, hunted: 0 });
    expect(storedCampaign().progress.checked).toBe(3);
    expect((await sendHunt(3)).nextBatchOffset).toBe(6);
  });

  it("returns committed progress even if alert processing fails after a successful SIEM query", async () => {
    feed = feed.map((ioc) => ({ ...ioc, riskScore: 90, riskLevel: "critical" }));
    search.mockImplementationOnce(async ({ iocs }) => ({
      aggregations: { ioc_matches: { buckets: Object.fromEntries(iocs.map((_ioc, index) => [`ioc_${index}`, { doc_count: 2 }])) } }
    }));
    vi.mocked(chrome.storage.local.get).mockImplementation(async (keys) => {
      const selectedKeys: string[] = typeof keys === "string" ? [keys] : Array.isArray(keys) ? keys : [];
      if (selectedKeys.includes("threatAlertHistory")) throw new Error("Alert storage unavailable");
      return Object.fromEntries(selectedKeys.map((key) => [key, structuredClone(storage[key])]));
    });
    const first = await sendHunt();
    expect(first).toMatchObject({ nextBatchOffset: 3, hunted: 3, alertError: "Alert storage unavailable", alertsCreated: 0 });
    expect(storedCampaign().progress.nextBatchOffset).toBe(3);
  });
});
