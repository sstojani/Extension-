import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { Readable } from "node:stream";
import { test } from "node:test";
import { AgentWorker } from "../worker.mjs";
import { Store } from "../store.mjs";
import { ElasticClient } from "../elastic.mjs";
import { createAgentApi } from "../api.mjs";
import { validateConfig } from "../config.mjs";
import { validateRule } from "../alerts.mjs";
import { rankFeedIndicators } from "../feeds.mjs";

const NOW = "2026-10-02T20:00:00.000Z";
const EVENT_TIME = "2026-10-02T19:59:00.000Z";
const DOMAIN = "watched.evil.com";
const CHANNEL = { id: "soc", enabled: true, type: "webhook", url: "https://notify.invalid/hook" };

function hit(id, fields = {}, time = EVENT_TIME) {
  return { _id: String(id), _index: "logs-security", _source: {
    "@timestamp": time, "event.category": ["network"], "event.action": "allowed", "event.outcome": "success",
    "source.ip": "10.0.0.7", "destination.ip": "10.0.0.8", "host.name": "workstation-1", "observer.name": "edge-a", ...fields
  } };
}

function hits(count) { return Array.from({ length: count }, (_, i) => hit(`event-${i}`)); }

function scope(runtime, config) {
  return createHash("sha256").update(JSON.stringify([runtime.elasticUrl, config.indexPattern, config.timestampField, config.query])).digest("hex");
}

function fakeElastic(rows = []) {
  const calls = { pages: [], watched: [], closed: [], probes: [], evidence: [] };
  let pits = 0;
  return {
    calls, rows, watchRows: [], watchTotal: null, pageFailures: new Map(), watchFailure: null, probeFailure: null, beforePage: null,
    async page(config, from, to, cursor = null, extraQuery = null) {
      const call = { config: structuredClone(config), from, to, cursor: structuredClone(cursor), extraQuery: structuredClone(extraQuery) };
      calls.pages.push(call);
      if (this.beforePage) this.beforePage(call);
      const failure = this.pageFailures.get(calls.pages.length);
      if (failure) throw failure;
      const start = cursor?.after ? cursor.after[1] + 1 : 0;
      const pageHits = this.rows.slice(start, start + config.pageSize).map((row, i) => ({
        ...structuredClone(row), sort: [Date.parse(row._source["@timestamp"]) || Date.parse(EVENT_TIME), start + i]
      }));
      const pageCursor = { pit: cursor?.pit || `pit-${++pits}`, after: pageHits.at(-1)?.sort || cursor?.after };
      call.returnedIds = pageHits.map(row => row._id);
      call.complete = pageHits.length < config.pageSize;
      return { hits: pageHits, total: this.rows.length, cursor: pageCursor, complete: call.complete };
    },
    async closePit(pit) { calls.closed.push(pit); },
    async probe(config) {
      calls.probes.push(structuredClone(config));
      if (this.probeFailure) throw this.probeFailure;
      return { [config.timestampField]: true, "source.ip": true };
    },
    async watched(config, rule, from, to) {
      calls.watched.push({ config: structuredClone(config), rule: structuredClone(rule), from, to });
      if (this.watchFailure) throw this.watchFailure;
      return { hits: structuredClone(this.watchRows), total: this.watchTotal ?? this.watchRows.length, complete: true, cursor: { pit: "watch-pit" } };
    },
    async evidence(index, id) {
      calls.evidence.push({ index, id });
      const row = [...this.rows, ...this.watchRows].find(row => row._index === index && row._id === id);
      if (!row) throw new Error("Evidence not found");
      return structuredClone(row);
    }
  };
}

function fixture(t, { rows = [], config = {}, runtime = {} } = {}) {
  t.mock.timers.enable({ apis: ["Date"], now: Date.parse(NOW) });
  const store = new Store(":memory:");
  t.after(() => store.close());
  const settings = validateConfig({ enabled: false, autoInvestigate: false, huntEnabled: false, pageSize: 100, maxEventsPerRun: 500, ...config });
  store.set("config", settings);
  store.set("notifications", { channels: [], cooldownMinutes: 60 });
  const credentials = { elasticUrl: "https://elastic.invalid", elasticApiKey: "test", gtiKey: "", feeds: { threatfox: "", malwarebazaar: "" },
    token: "t".repeat(40), publicOrigin: "https://socwatch.internal", ...runtime };
  const elastic = fakeElastic(rows);
  const fetchCalls = [];
  const responses = { reputation: [], delivery: [], feodo: [] };
  const fetcher = async (url, init = {}) => {
    fetchCalls.push({ url, init });
    if (url.startsWith("https://www.virustotal.com/")) {
      return responses.reputation.shift() || Response.json({ data: { attributes: { last_analysis_stats: { malicious: 5 } } } });
    }
    if (url === CHANNEL.url) return responses.delivery.shift() || new Response("", { status: 200 });
    if (url.includes("feodotracker.abuse.ch/")) return Response.json(responses.feodo);
    if (url.includes("openphish.com/")) return new Response("");
    throw new Error(`Unexpected fake fetch: ${url}`);
  };
  const clock = () => new Date().toISOString();
  const restart = () => new AgentWorker(store, elastic, credentials, { fetcher, clock });
  return { store, config: settings, runtime: credentials, elastic, fetchCalls, responses, clock, restart, worker: restart() };
}

function watch(store, options = {}) {
  const rule = validateRule({ id: "watch-domain", name: "Explicit IOC", indicatorType: "domain", indicatorValue: DOMAIN, ...options });
  store.record("rule", rule);
  return rule;
}

function checkpoint(f) { return f.store.get(`checkpoint:${scope(f.runtime, f.config)}`); }
function events(f) { return f.store.events("1970-01-01T00:00:00.000Z", f.clock()); }

async function apiRequest(api, runtime, route, body, cookie = "") {
  const request = Readable.from([Buffer.from(JSON.stringify(body))]);
  Object.assign(request, { url: `/api/agent/${route}`, method: "POST", socket: { encrypted: false, remoteAddress: "127.0.0.1" },
    headers: { host: "socwatch.internal", origin: runtime.publicOrigin, "content-type": "application/json", cookie } });
  let reply;
  const response = { writeHead(status, headers) { reply = { status, headers }; }, end(body) { reply.body = JSON.parse(body); } };
  assert.equal(await api(request, response), true);
  return reply;
}

async function clearFindings(f, worker = f.worker) {
  const api = createAgentApi(worker, f.runtime);
  const login = await apiRequest(api, f.runtime, "login", { token: f.runtime.token });
  assert.equal(login.status, 200);
  const cleared = await apiRequest(api, f.runtime, "clear", { confirm: true }, login.headers["Set-Cookie"].split(";")[0]);
  assert.equal(cleared.status, 200);
  return cleared.body.cleared;
}

test("paginated live window commits its checkpoint and success only after EOF", async t => {
  const f = fixture(t, { rows: hits(250) });
  const previous = "2026-10-02T19:55:00.000Z";
  f.store.set(`checkpoint:${scope(f.runtime, f.config)}`, previous);
  f.elastic.beforePage = () => {
    assert.equal(checkpoint(f), previous);
    assert.equal(f.store.get("lastSuccess"), null);
    assert.notEqual(f.store.list("run")[0].status, "complete");
  };
  f.worker.request("live");
  await f.worker.tick();
  assert.deepEqual(f.elastic.calls.pages.map(page => page.returnedIds.length), [100, 100, 50]);
  assert.deepEqual(f.elastic.calls.pages.map(page => page.complete), [false, false, true]);
  assert.deepEqual(f.elastic.calls.pages[1].cursor.after, [Date.parse(EVENT_TIME), 99]);
  assert.equal(new Set(f.elastic.calls.pages.map(page => `${page.from}|${page.to}`)).size, 1);
  assert.equal(checkpoint(f), NOW);
  assert.equal(f.store.get("lastSuccess"), NOW);
  assert.equal(f.store.get("scan"), null);
  assert.equal(events(f).length, 250);
  assert.equal(f.store.list("run")[0].coverage, "complete");
  assert.equal(f.worker.state().status.coverage.analysisEvents, 250);
  assert.equal(f.elastic.calls.closed.length, 1);
});

test("a full final page is not EOF; the empty trailing page establishes completion", async t => {
  const f = fixture(t, { rows: hits(100) });
  f.elastic.beforePage = () => assert.equal(checkpoint(f), null);
  f.worker.request();
  await f.worker.tick();
  assert.deepEqual(f.elastic.calls.pages.map(page => page.returnedIds.length), [100, 0]);
  assert.equal(checkpoint(f), NOW);
  assert.equal(events(f).length, 100);
});

test("transient page failure preserves the fixed window and checkpoint, and replay deduplicates", async t => {
  const f = fixture(t, { rows: hits(250) });
  f.elastic.pageFailures.set(2, new Error("Transient page HTTP 503"));
  f.worker.request();
  await f.worker.tick();
  const failed = f.store.get("scan");
  assert.equal(checkpoint(f), null);
  assert.equal(f.store.get("lastSuccess"), null);
  assert.equal(f.store.list("run")[0].status, "retrying");
  assert.equal(failed.cursor, null);
  assert.equal(events(f).length, 100);
  assert.match(f.worker.state().status.lastError, /503/);
  t.mock.timers.tick(20000);
  const restarted = f.restart();
  await restarted.tick();
  assert.equal(f.elastic.calls.pages[2].cursor, null);
  assert.equal(f.elastic.calls.pages[2].from, failed.from);
  assert.equal(f.elastic.calls.pages[2].to, failed.to);
  assert.equal(checkpoint(f), failed.to);
  assert.equal(events(f).length, 250);
  assert.equal(f.store.list("run")[0].uniqueEvents, 250);
  assert.equal(f.store.get("scan"), null);
});

test("raw-event budget continuation reaches EOF across restarts without dropping invalid rows or tie cursors", async t => {
  const rows = hits(1100);
  for (let i = 0; i < rows.length; i += 5) delete rows[i]._source["@timestamp"];
  rows[501] = structuredClone(rows[1]);
  rows[1001] = structuredClone(rows[1]);
  const f = fixture(t, { rows });
  f.worker.request();
  await f.worker.tick();
  const first = f.store.get("scan");
  assert.equal(first.eventsRead, 500);
  assert.equal(first.invalidEvents, 100);
  assert.deepEqual(first.cursor.after, [Date.parse(EVENT_TIME), 499]);
  assert.equal(checkpoint(f), null);
  assert.equal(f.worker.state().status.coverage.status, "in_progress");
  assert.notEqual(f.store.list("run")[0].status, "complete");
  const second = f.restart();
  t.mock.timers.tick(20000);
  await second.tick();
  assert.equal(f.store.get("scan").eventsRead, 1000);
  assert.equal(checkpoint(f), null);
  const third = f.restart();
  t.mock.timers.tick(20000);
  await third.tick();
  assert.equal(f.store.get("scan"), null);
  assert.equal(checkpoint(f), first.to);
  const run = f.store.list("run")[0];
  assert.equal(run.eventsRead, 1100);
  assert.equal(run.invalidEvents, 220);
  assert.equal(run.uniqueEvents, 878);
  assert.equal(run.coverage, "reduced");
  assert.equal(events(f).length, 878);
  assert.equal(new Set(f.elastic.calls.pages.map(page => `${page.from}|${page.to}`)).size, 1);
  assert.equal(f.elastic.calls.pages.at(-1).complete, true);
  assert.equal(f.elastic.calls.pages.flatMap(page => page.returnedIds).length, 1100);
});

test("a non-divisible page size cannot exceed maxEventsPerRun or consume unsaved tail rows", async t => {
  const f = fixture(t, { rows: hits(1001), config: { pageSize: 300, maxEventsPerRun: 500 } });
  f.worker.request();
  await f.worker.tick();
  const scan = f.store.get("scan");
  assert.ok(scan.eventsRead <= 500, `Read ${scan.eventsRead} raw events against a 500-event budget`);
  assert.equal(scan.eventsRead, 500);
  assert.equal(f.elastic.calls.pages[1].config.pageSize, 200);
  assert.equal(checkpoint(f), null);
  for (let i = 0; i < 4 && f.worker.scan; i++) await f.worker.tick();
  assert.equal(f.worker.scan, null);
  assert.equal(events(f).length, 1001);
  assert.equal(new Set(f.elastic.calls.pages.flatMap(page => page.returnedIds)).size, 1001);
});

test("coverage analysisEvents counts distinct window events rather than repeated correlation overlap", async t => {
  const f = fixture(t, { rows: hits(600) });
  f.worker.request();
  await f.worker.tick();
  await f.worker.tick();
  assert.equal(f.store.get("scan"), null);
  assert.equal(events(f).length, 600);
  assert.equal(f.worker.state().status.coverage.analysisEvents, 600);
  assert.equal(f.store.list("run")[0].analysisEvents, 600);
});

test("malformed Elasticsearch hits cannot be interpreted as successful empty-window EOF", async t => {
  const f = fixture(t);
  const calls = [];
  const fetcher = async (url, init) => {
    calls.push({ url, init });
    if (url.includes("/_pit?")) return Response.json({ id: "malformed-pit" });
    if (url.endsWith("/_search")) return Response.json({ _shards: { failed: 0 }, hits: { total: { value: 25, relation: "eq" } } });
    if (url.includes("/_field_caps")) return Response.json({ fields: {} });
    return Response.json({ succeeded: true });
  };
  const worker = new AgentWorker(f.store, new ElasticClient(f.runtime, fetcher), f.runtime, { fetcher: f.worker.fetcher, clock: f.clock });
  worker.request("today");
  await worker.tick();
  assert.equal(calls.filter(call => call.url.endsWith("/_search")).length, 1);
  assert.equal(checkpoint(f), null, "Missing hits.hits must fail the page instead of advancing the checkpoint");
  assert.equal(f.store.get("lastSuccess"), null);
  assert.notEqual(f.store.list("run")[0].status, "complete");
});

test("a failed capability probe cannot report complete coverage or erase its stage error", async t => {
  const f = fixture(t, { rows: hits(1) });
  f.elastic.probeFailure = new Error("Field capabilities forbidden");
  f.worker.request();
  await f.worker.tick();
  assert.notEqual(f.worker.state().status.coverage?.status, "complete");
  assert.notEqual(f.store.list("run")[0].coverage, "complete");
  assert.match(f.worker.state().status.lastError || JSON.stringify(f.worker.state().status.coverage), /forbidden/);
});

test("a failed explicit watch stage cannot be overwritten by a complete scan status", async t => {
  const f = fixture(t, { rows: hits(1) });
  watch(f.store);
  f.elastic.watchFailure = new Error("Watch query HTTP 503");
  f.worker.request();
  await f.worker.tick();
  assert.equal(f.elastic.calls.watched.length, 1);
  assert.match(f.worker.state().status.lastError || "", /watch/i);
  assert.notEqual(f.store.list("run")[0].coverage, "complete");
  assert.notEqual(f.worker.state().status.coverage?.status, "complete");
});

test("explicit watches repeat during historical continuation independently of automatic promotion and broad query gates", async t => {
  const f = fixture(t, { rows: hits(1100), config: { query: "event.category:malware", autoAlertMinPriority: 100 } });
  watch(f.store, { minEvents: 10 });
  f.elastic.watchRows = [hit("watched-proof", { "dns.question.name": DOMAIN })];
  f.elastic.watchTotal = 12;
  f.worker.request("baseline");
  await f.worker.tick();
  assert.equal(f.elastic.calls.watched.length, 1);
  const finding = f.store.list("finding").find(finding => finding.category === "watched_indicator");
  assert.equal(finding.priority, 50);
  assert.equal(finding.reputation.verdict, "unknown");
  assert.equal(finding.events, 12);
  assert.equal(finding.evidence.length, 1);
  assert.equal(f.store.list("alert").length, 1);
  assert.equal(checkpoint(f), null);
  for (let i = 0; i < 2; i++) { t.mock.timers.tick(20000); await f.worker.tick(); }
  assert.equal(f.elastic.calls.watched.length, 3);
  assert.equal(f.elastic.calls.pages.every(page => page.config.query === "event.category:malware"), true);
  assert.equal(f.store.list("finding").filter(finding => finding.category === "watched_indicator").length, 1);
  assert.equal(f.store.list("alert").length, 1);
  assert.equal(checkpoint(f), null, "Baseline scans must not replace the live checkpoint");
  assert.equal(f.store.get("scan"), null);
});

test("reputation and delivery retries survive a worker restart and retain the delivery idempotency key", async t => {
  const f = fixture(t, { runtime: { gtiKey: "test" } });
  watch(f.store);
  f.elastic.watchRows = [hit("queued-proof", { "dns.question.name": DOMAIN })];
  f.store.set("notifications", { channels: [CHANNEL], cooldownMinutes: 60 });
  f.responses.reputation.push(new Response("", { status: 429, headers: { "retry-after": "60" } }));
  f.responses.delivery.push(new Response("", { status: 503 }));
  f.worker.request();
  await f.worker.tick();
  assert.equal(f.store.reputationMap()[`domain|${DOMAIN}`].status, "rate_limited");
  const firstDelivery = f.store.deliveries()[0];
  assert.equal(firstDelivery.status, "retry");
  const firstRequest = f.fetchCalls.find(call => call.url === CHANNEL.url);
  t.mock.timers.tick(61000);
  const restarted = f.restart();
  await restarted.tick();
  assert.equal(f.elastic.calls.watched.length, 1);
  assert.equal(f.store.reputationMap()[`domain|${DOMAIN}`].verdict, "malicious");
  const delivery = f.store.deliveries()[0];
  assert.equal(delivery.id, firstDelivery.id);
  assert.equal(delivery.status, "delivered");
  assert.equal(delivery.attempts, 2);
  const requests = f.fetchCalls.filter(call => call.url === CHANNEL.url);
  assert.equal(requests.length, 2);
  assert.equal(requests[1].init.headers["Idempotency-Key"], firstRequest.init.headers["Idempotency-Key"]);
  assert.equal(f.store.list("alert").length, 1);
});

test("cleared watch findings remain resolved when identical evidence is rechecked after restart and cooldown", async t => {
  const f = fixture(t);
  watch(f.store, { cooldownMinutes: 1 });
  f.elastic.watchRows = [hit("same-proof", { "dns.question.name": DOMAIN })];
  f.worker.request();
  await f.worker.tick();
  const id = f.store.list("finding")[0].id;
  assert.equal(await clearFindings(f), 1);
  t.mock.timers.tick(61000);
  const restarted = f.restart();
  restarted.request();
  await restarted.tick();
  const finding = f.store.one("finding", id);
  assert.equal(finding.status, "resolved");
  assert.equal(finding.reopened, false);
  assert.equal(finding.evidence.length, 1);
  assert.equal(f.store.list("alert").length, 1);
});

test("reputation promotion of cleared watch evidence must not enqueue another alert", async t => {
  const f = fixture(t, { runtime: { gtiKey: "test" } });
  watch(f.store, { cooldownMinutes: 1 });
  f.elastic.watchRows = [hit("same-proof", { "dns.question.name": DOMAIN })];
  f.store.set("notifications", { channels: [CHANNEL] });
  f.responses.reputation.push(new Response("", { status: 429, headers: { "retry-after": "60" } }));
  f.worker.request();
  await f.worker.tick();
  const id = f.store.list("finding")[0].id;
  assert.equal(await clearFindings(f), 1);
  t.mock.timers.tick(61000);
  const restarted = f.restart();
  await restarted.tick();
  assert.equal(f.store.reputationMap()[`domain|${DOMAIN}`].verdict, "malicious");
  restarted.request();
  await restarted.tick();
  assert.equal(f.store.one("finding", id).status, "resolved");
  assert.equal(f.store.list("alert").length, 1, "Higher reputation alone must not recreate an alert for cleared proof");
  assert.equal(f.store.deliveries().length, 1);
});

test("watched totals stay distinct from retained proof samples and deduplicated event-ID counts", async t => {
  const f = fixture(t);
  watch(f.store);
  f.elastic.watchRows = [hit("sample-proof", { "dns.question.name": DOMAIN })];
  f.elastic.watchTotal = 1200;
  f.worker.request();
  await f.worker.tick();
  const finding = f.store.list("finding")[0];
  assert.equal(finding.events, 1200);
  assert.equal(finding.observedEvents, 1200);
  assert.equal(finding.evidence.length, 1);
  assert.equal(finding.count, 1, "Only one distinct matched event ID was retrieved");
  f.elastic.watchRows.push(hit("second-proof", { "dns.question.name": DOMAIN }));
  f.worker.request();
  await f.worker.tick();
  const updated = f.store.one("finding", finding.id);
  assert.equal(updated.events, 1200);
  assert.equal(updated.observedEvents, 1200);
  assert.equal(updated.count, 2, "Replayed samples must not increase the distinct event-ID count");
  assert.equal(updated.evidence.length, 2);
});

test("persisted behavioral finding retains the engine's event count beyond its 30-proof sample", async t => {
  const rows = Array.from({ length: 80 }, (_, i) => hit(`blocked-${i}`, {
    "source.ip": "45.77.22.99", "destination.ip": `10.0.1.${i % 5 + 1}`, "destination.port": 22,
    "event.action": "denied", "event.outcome": "failure", "observer.name": `edge-${i % 2}`
  }));
  const f = fixture(t, { rows });
  f.worker.request();
  await f.worker.tick();
  const finding = f.store.list("finding").find(finding => finding.category === "scan");
  assert.ok(finding, "Blocked cross-infrastructure scan should produce a behavioral finding");
  assert.equal(finding.events, 80);
  assert.equal(finding.evidence.length, 30);
  assert.equal(finding.observedEvents, 80);
  assert.equal(finding.count, 80, "Saving the finding must not replace the engine's count with the sampled proof length");
});

test("feed batch advances checked indicators only at EOF and retries using the saved feed snapshot", async t => {
  const rows = Array.from({ length: 125 }, (_, i) => hit(`feed-${i}`, { "destination.ip": "45.77.22.99" }));
  const f = fixture(t, { rows, config: { huntEnabled: true } });
  f.responses.feodo.push({ ip_address: "45.77.22.99", first_seen: EVENT_TIME });
  await f.worker.tick();
  const id = f.store.get("activeCampaign");
  const first = f.store.one("campaign", id);
  assert.equal(first.totalAvailable, 1);
  assert.equal(first.offset, 0);
  assert.equal(first.checked, 0);
  assert.equal(first.status, "checking");
  assert.deepEqual(first.cursor.after, [Date.parse(EVENT_TIME), 99]);
  f.elastic.pageFailures.set(2, new Error("Feed page HTTP 503"));
  await f.worker.tick();
  const failed = f.store.one("campaign", id);
  assert.equal(failed.status, "retrying");
  assert.equal(failed.offset, 0);
  assert.equal(failed.checked, 0);
  assert.equal(failed.cursor, null);
  assert.deepEqual(failed.iocs, first.iocs);
  const restarted = f.restart();
  await restarted.tick();
  await restarted.tick();
  const complete = f.store.one("campaign", id);
  assert.equal(complete.status, "complete");
  assert.equal(complete.offset, 1);
  assert.equal(complete.checked, 1);
  assert.equal(complete.cursor, null);
  assert.deepEqual(complete.iocs, first.iocs);
  assert.equal(events(f).length, 125);
  const finding = f.store.list("finding").find(finding => finding.category === "feed_sighting");
  assert.equal(finding.count, 125, "Feed replays must count unique proof IDs beyond the retained sample");
  assert.ok(finding.evidence.length <= 50);
  assert.equal(f.fetchCalls.filter(call => call.url.includes("feodotracker.abuse.ch")).length, 1);
  assert.equal(f.elastic.calls.pages.every(page => page.config.query === ""), true);
});

test("feed pagination replay after clear cannot reopen a finding from the same evidence IDs", async t => {
  const rows = Array.from({ length: 100 }, (_, i) => hit(`feed-${i}`, { "url.domain": DOMAIN },
    new Date(Date.parse(EVENT_TIME) + i * 100).toISOString()));
  const f = fixture(t, { rows, config: { huntEnabled: true } });
  const iocs = rankFeedIndicators([{ type: "domain", value: DOMAIN, provider: "fixture", context: "phishing" }], NOW);
  f.store.record("campaign", { id: "saved-feed", createdAt: NOW, expiresAt: "2026-10-03T20:00:00.000Z", iocs,
    totalAvailable: 1, offset: 0, checked: 0, status: "ready", from: EVENT_TIME, to: NOW, config: f.config });
  f.store.set("activeCampaign", "saved-feed");
  await f.worker.tick();
  const initial = f.store.list("finding")[0];
  assert.equal(initial.status, "open");
  assert.equal(await clearFindings(f), 1);
  f.elastic.pageFailures.set(2, new Error("PIT expired"));
  await f.worker.tick();
  assert.equal(f.store.one("finding", initial.id).status, "resolved");
  const restarted = f.restart();
  await restarted.tick();
  const replayed = f.store.one("finding", initial.id);
  assert.equal(events(f).length, 100);
  assert.equal(replayed.lastSeen, initial.lastSeen);
  assert.equal(replayed.status, "resolved", "Replaying older proof before the previously newest proof must not reopen a cleared finding");
});

test("a failed broad page does not prevent independent explicit watch queries from running", async t => {
  const f = fixture(t);
  watch(f.store);
  f.elastic.watchRows = [hit("independent-proof", { "dns.question.name": DOMAIN })];
  f.elastic.pageFailures.set(1, new Error("Broad query timeout"));
  f.worker.request();
  await f.worker.tick();
  assert.equal(checkpoint(f), null);
  assert.equal(f.elastic.calls.watched.length, 1, "An independent exact IOC query must still run when broad collection fails");
  assert.equal(f.store.list("finding").some(finding => finding.category === "watched_indicator"), true);
  assert.notEqual(f.store.list("run")[0].status, "complete");
});

test("retention pruning removes orphaned proof counts before a later finding with the same fingerprint", async t => {
  const f = fixture(t, { config: { retentionDays: 1 } });
  watch(f.store);
  f.elastic.watchRows = [hit("expired-proof", { "dns.question.name": DOMAIN })];
  f.worker.request();
  await f.worker.tick();
  const original = f.store.list("finding")[0];
  assert.equal(original.count, 1);
  t.mock.timers.tick(2 * 86400000);
  await f.worker.tick();
  assert.equal(f.store.one("finding", original.id), null);
  f.elastic.watchRows = [hit("new-proof", { "dns.question.name": DOMAIN }, f.clock())];
  f.worker.request();
  await f.worker.tick();
  const current = f.store.one("finding", original.id);
  assert.equal(current.evidence.length, 1);
  assert.equal(current.evidence[0].eventId, "new-proof");
  assert.equal(current.count, 1, "Expired finding-event links must not inflate a new finding's proof count");
});

test("a queued notification is still delivered when broad Elasticsearch collection throws", async t => {
  const f = fixture(t);
  f.store.set("notifications", { channels: [CHANNEL], cooldownMinutes: 60 });
  const alert = f.store.record("alert", { id: "already-queued-alert", title: "Previously observed IOC", indicatorType: "domain",
    indicator: DOMAIN, priority: 50, severity: "medium", reasons: ["Independent earlier watch proof"], evidence: [], createdAt: NOW });
  f.store.queueDelivery(alert, CHANNEL, NOW);
  assert.equal(f.store.deliveries()[0].status, "pending");
  f.elastic.pageFailures.set(1, new Error("Broad Elasticsearch HTTP 503"));
  f.worker.request();
  await f.worker.tick();
  assert.equal(checkpoint(f), null);
  assert.equal(f.store.list("run")[0].status, "retrying");
  assert.match(f.worker.state().status.lastError || "", /503/);
  const delivery = f.store.deliveries()[0];
  assert.equal(delivery.status, "delivered", "Broad collection failure must not starve the persistent delivery queue");
  assert.equal(delivery.attempts, 1);
  const requests = f.fetchCalls.filter(call => call.url === CHANNEL.url);
  assert.equal(requests.length, 1);
  assert.equal(requests[0].init.headers["Idempotency-Key"], delivery.id);
  assert.equal(f.store.list("alert").length, 1);
});

test("a due persistent GTI retry still runs when broad Elasticsearch collection throws", async t => {
  const f = fixture(t, { runtime: { gtiKey: "test" } });
  f.store.queueReputation("domain", DOMAIN, NOW);
  const job = f.store.reputationJobs(NOW)[0];
  f.store.reputationResult(job, { verdict: "unknown", status: "unavailable", error: "Earlier GTI timeout", checkedAt: NOW }, NOW);
  f.elastic.pageFailures.set(1, new Error("Broad Elasticsearch HTTP 503"));
  f.worker.request();
  await f.worker.tick();
  assert.equal(checkpoint(f), null);
  assert.equal(f.store.list("run")[0].status, "retrying");
  const reputation = f.store.reputationMap()[`domain|${DOMAIN}`];
  assert.equal(reputation.status, "scored", "Broad collection failure must not starve due reputation retries");
  assert.equal(reputation.verdict, "malicious");
  assert.equal(f.fetchCalls.filter(call => call.url.startsWith("https://www.virustotal.com/")).length, 1);
});

test("a watch retry covers the earliest failed window even after later broad checkpoints advance", async t => {
  const f = fixture(t, { config: { enabled: true } });
  watch(f.store);
  f.elastic.watchRows = [hit("proof-from-failed-window", { "dns.question.name": DOMAIN })];
  f.elastic.watchFailure = new Error("Independent watch query HTTP 503");
  f.worker.request();
  await f.worker.tick();
  const earliestFrom = f.elastic.calls.watched[0].from;
  t.mock.timers.tick(6 * 60000);
  await f.worker.tick();
  assert.equal(f.elastic.calls.watched.length, 2);
  f.elastic.watchFailure = null;
  t.mock.timers.tick(6 * 60000);
  await f.worker.tick();
  assert.equal(f.elastic.calls.watched.length, 3);
  const retry = f.elastic.calls.watched[2];
  assert.equal(retry.from, earliestFrom, "Advancing broad checkpoints must not discard an unqueried IOC watch interval");
  assert.equal(retry.to, f.clock());
  assert.equal(f.store.list("finding").some(finding => finding.category === "watched_indicator"), true);
});

test("late reputation enriches historical retained evidence without requiring a new SIEM sighting", async t => {
  const hash = "a".repeat(64);
  const f = fixture(t, { runtime: { gtiKey: "test" } });
  const old = hit("old-execution", { "event.category": ["process"], "event.type": ["start"], "event.action": "process_started", "process.hash.sha256": hash }, "2026-10-02T07:00:00.000Z");
  const { normalizeEvent } = await import("../intelligence.mjs");
  f.store.addEvents([normalizeEvent(old, f.config)]);
  f.store.queueReputation("hash", hash, NOW);
  await f.worker.tick();
  const finding = f.store.list("finding").find(f => f.indicator === hash);
  assert.ok(finding);
  assert.equal(finding.reputation.verdict, "malicious");
  assert.match(finding.title, /Execution/);
  assert.equal(finding.lastSeen, "2026-10-02T07:00:00.000Z");
  assert.equal(f.store.list("alert").length, 1);
  assert.equal(f.elastic.calls.pages.length, 0);
});

test("a rolled-back page cannot advance persisted distinct-event coverage before retry", async t => {
  const f = fixture(t, { rows: hits(250) });
  const record = f.store.record;
  let fail = true;
  t.mock.method(f.store, "record", function (kind, body) {
    if (fail && kind === "run" && body.status === "collecting") {
      fail = false;
      throw new Error("Injected page transaction failure");
    }
    return record.call(this, kind, body);
  });
  f.worker.request();
  await f.worker.tick();
  const failed = f.store.get("scan");
  assert.equal(events(f).length, 0, "The page's event inserts were rolled back");
  assert.equal(checkpoint(f), null);
  assert.equal(failed.cursor, null);
  assert.equal(f.store.list("run")[0].status, "retrying");
  const restarted = f.restart();
  await restarted.tick();
  assert.equal(events(f).length, 250);
  assert.equal(checkpoint(f), failed.to);
  const complete = f.store.list("run")[0];
  assert.equal(complete.uniqueEvents, 250, "Rolled-back inserts must not survive in the scan counters");
  assert.equal(complete.analysisEvents, 250);
  assert.equal(failed.uniqueEvents, 0);
  assert.equal(failed.analysisEvents || 0, 0);
});

for (const field of ["client.ip", "server.ip"]) {
  test(`a feed query matching only ${field} retains the IOC sighting before marking it checked`, async t => {
    const indicator = "45.77.22.99";
    const f = fixture(t, { rows: [hit("endpoint-proof", { [field]: indicator })], config: { huntEnabled: true } });
    f.responses.feodo.push({ ip_address: indicator, first_seen: EVENT_TIME });
    await f.worker.tick();
    const query = f.elastic.calls.pages[0].extraQuery;
    assert.ok(query.bool.should.some(clause => clause.terms?.[field]?.includes(indicator)), "The feed query explicitly searches this ECS field");
    const campaign = f.store.one("campaign", f.store.get("activeCampaign"));
    assert.equal(campaign.status, "complete");
    assert.equal(campaign.checked, 1);
    const finding = f.store.list("finding").find(item => item.category === "feed_sighting" && item.indicator === indicator);
    assert.ok(finding, "A successfully queried IOC hit must not be silently discarded by normalization or matching");
    assert.equal(finding.count, 1);
    assert.deepEqual(finding.evidence.map(proof => proof.eventId), ["endpoint-proof"]);
    assert.equal(f.store.reputationMap()[`ip|${indicator}`].status, "pending");
  });
}

test("an unscoped watch keeps separate hosts' evidence and distinct-event counts separate", async t => {
  const f = fixture(t);
  watch(f.store);
  f.elastic.watchRows = [
    hit("alpha-proof", { "host.name": "alpha", "dns.question.name": DOMAIN }),
    hit("beta-proof", { "host.name": "beta", "dns.question.name": DOMAIN })
  ];
  f.worker.request();
  await f.worker.tick();
  const findings = f.store.list("finding").filter(item => item.category === "watched_indicator");
  const proofHost = new Map([["alpha-proof", "alpha"], ["beta-proof", "beta"]]);
  for (const finding of findings) {
    assert.equal(finding.evidence.every(proof => proofHost.get(proof.eventId) === finding.host), true,
      `Evidence attached to ${finding.host} must belong to that host`);
    assert.equal(finding.count, 1);
  }
  assert.deepEqual(findings.map(item => item.host).sort(), ["alpha", "beta"]);
});
