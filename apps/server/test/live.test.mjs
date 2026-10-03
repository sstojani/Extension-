import assert from "node:assert/strict";
import { test } from "node:test";
import { randomUUID } from "node:crypto";
import { Store } from "../store.mjs";
import { AgentWorker } from "../worker.mjs";
import { ElasticClient } from "../elastic.mjs";
import { BrowserRelay } from "../relay.mjs";
import { defaults } from "../config.mjs";
import { analyzeEvidence, normalizeEvent, liveScanCandidates, analyzeLiveScans, analyzeSiemAlerts } from "../intelligence.mjs";

const NOW = "2026-10-03T10:00:00.000Z", FROM = "2026-10-03T09:55:00.000Z";
const IP = "45.77.22.99";
const config = { ...defaults, enabled: true, autoInvestigate: false };
const policy = { indexPattern: "logs-*", timestampField: "@timestamp", infrastructureField: "observer.name" };
const hit = (id, fields = {}) => ({ _id: id, _index: "logs-network", _source: {
  "@timestamp": "2026-10-03T09:59:00.000Z", "event.category": ["network"], "event.action": "denied", "event.outcome": "failure",
  "source.ip": IP, "destination.ip": "10.0.0.7", "destination.port": 22, "observer.name": "edge-a", ...fields
} });
const proof = hits => ({ hits: { hits } });
const raw = (key = IP, fields = {}) => ({ hits: { total: { value: 615783, relation: "eq" } }, hitsRead: 2, aggregations: { sources: { sum_other_doc_count: 100, buckets: [{
  key, doc_count: 200, doc_count_error_upper_bound: 0, ports: { buckets: Array.from({ length: 10 }, (_, i) => ({ key: 49000 + i, doc_count: 20 })) },
  targets: { buckets: [{ key: "10.0.0.7", doc_count: 200 }] }, proof: proof([hit("deny-1", { "source.ip": key, ...fields }), hit("deny-2", { "source.ip": key, ...fields })])
}] } } });
const context = () => ({ hits: { total: { value: 1, relation: "eq" } }, hitsRead: 1, aggregations: { sources: { buckets: [{ key: IP, doc_count: 1,
  proof: proof([hit("accept", { "event.action": "accept", "event.outcome": "success", "destination.port": 49876, "source.geo.country_name": "Kazakhstan" })]) }] } } });
const security = (hits = []) => ({ hits: { total: { value: hits.length, relation: "eq" } }, hitsRead: hits.length, aggregations: {
  authentication: { users: { buckets: [], sum_other_doc_count: 0 } }, signals: { doc_count: hits.length, proof: proof(hits) }
} });

test("fresh aggregate scan has lower-bound counts, real accepted actions, country and proof, without a C2 claim", () => {
  const [finding] = analyzeLiveScans(raw(), context(), config, {}, FROM, NOW);
  assert.ok(finding.priority >= 80); assert.equal(finding.count, 3);
  assert.equal(finding.activity.blockedAttemptsLowerBound, 200);
  assert.deepEqual(finding.activity.countries, ["Kazakhstan"]);
  assert.equal(finding.activity.allowed[0].timestamp, "2026-10-03T09:59:00.000Z");
  assert.equal(finding.activity.allowed[0].action, "accept");
  assert.ok(finding.activity.ports.includes(49876));
  assert.match(finding.limitations.join(" "), /not proof/);
  assert.doesNotMatch(finding.title, /C2|command and control|compromise/);
  assert.deepEqual(analyzeLiveScans(raw(), null, config, {}, FROM, NOW)[0].activity.countries, []);
});

test("normal DNS, private sources, stale evidence, insufficient fanout and exceptions do not become scan findings", () => {
  for (const source of ["1.1.1.1", "8.8.8.8", "10.0.0.7"]) assert.equal(liveScanCandidates(raw(source), config, FROM, NOW).length, 0);
  const stale = raw(); stale.aggregations.sources.buckets[0].proof = proof([hit("old", { "@timestamp": "2026-10-02T10:00:00.000Z" })]);
  assert.equal(liveScanCandidates(stale, config, FROM, NOW).length, 0);
  const noFanout = raw(); noFanout.aggregations.sources.buckets[0].ports.buckets = [{ key: 443, doc_count: 200 }];
  assert.equal(liveScanCandidates(noFanout, config, FROM, NOW).length, 0);
  assert.equal(liveScanCandidates(raw(), { ...config, exceptions: [{ enabled: true, indicatorType: "ip", indicatorValue: IP, reason: "Authorized scanner" }] }, FROM, NOW).length, 0);
  assert.equal(liveScanCandidates(raw(), { ...config, exceptions: [{ indicatorType: "ip", indicatorValue: IP, reason: "Expired approval", expiresAt: "2026-10-03T11:00:00+02:00" }] }, FROM, NOW).length, 1);
  const responses = raw(IP, { "source.port": 443 }); responses.aggregations.sources.buckets[0].ports.buckets = Array.from({ length: 10 }, (_, i) => ({ key: 50000 + i, doc_count: 20 }));
  assert.equal(liveScanCandidates(responses, config, FROM, NOW).length, 0);
});

test("sampled events cannot teach a normal baseline; later full collection upgrades them", () => {
  const event = { ...normalizeEvent(hit("sample", { "source.ip": "10.0.0.5", "event.action": "accept", "event.outcome": "success", "host.name": "workstation" })), sampled: true };
  assert.equal(analyzeEvidence([event], { now: NOW }).coverage.baselineTrackedEvents, 0);
  const store = new Store(":memory:");
  try {
    store.addEvents([event]); store.addEvents([{ ...event, sampled: false }]);
    const [saved] = store.events(FROM, NOW);
    assert.equal(saved.sampled, false);
    assert.equal(analyzeEvidence([saved], { now: NOW }).coverage.baselineTrackedEvents, 1);
  } finally { store.close(); }
});

test("only explicit high-severity ELK alerts are forwarded and remain attributed to ELK", () => {
  const event = normalizeEvent(hit("alert", { "event.kind": "alert", "kibana.alert.severity": "high", "kibana.alert.rule.name": "C2 investigation", "file.hash.sha256": "a".repeat(64) }));
  const [finding] = analyzeSiemAlerts([event], config);
  assert.equal(finding.indicatorType, "hash"); assert.match(finding.title, /ELK security alert/);
  assert.match(finding.limitations[0], /not independently/);
  assert.equal(analyzeSiemAlerts([normalizeEvent(hit("normal"))], config).length, 0);
});

test("live detection completes and sends an alert while a 615k-event old raw page is still waiting", async () => {
  const store = new Store(":memory:"); store.set("config", config);
  store.set("notifications", { cooldownMinutes: 60, channels: [{ id: "soc", type: "webhook", url: "https://notify.invalid", enabled: true }] });
  let releasePage, pageCalls = 0, deliveries = 0;
  const elastic = { ready: () => true, sourceIdentity: () => "fixture", closePit: async () => {},
    live: async (_, from, to, stage) => { assert.equal(from, FROM); assert.equal(to, NOW); return stage === "scans" ? raw() : stage === "context" ? context() : security(); },
    page: async () => { pageCalls++; return new Promise(resolve => { releasePage = resolve; }); },
    watched: async () => { throw new Error("No rules"); }
  };
  const worker = new AgentWorker(store, elastic, { dataSource: "browser_relay" }, { clock: () => NOW, fetcher: async () => { deliveries++; return new Response("", { status: 200 }); } });
  worker.scan = { id: "old", mode: "live", from: "2026-10-02T10:00:00.000Z", to: "2026-10-02T10:05:00.000Z", startedAt: FROM, config, source: "fixture", scope: "old", cursor: null, eventsRead: 300500, uniqueEvents: 0, totalMatched: 615783, invalidEvents: 0 };
  store.set("scan", worker.scan);
  const historical = worker.tick();
  try {
    for (let i = 0; i < 100 && !worker.liveStatus.lastSuccess; i++) await new Promise(resolve => setTimeout(resolve, 1));
    assert.equal(worker.running, true); assert.equal(pageCalls, 1); assert.equal(worker.liveStatus.lastSuccess, NOW);
    assert.equal(store.list("finding").length, 1); assert.equal(deliveries, 1);
    assert.equal(store.list("alert")[0].activity.allowed[0].action, "accept");
    assert.equal(store.get("checkpoint:old"), null);
    const savedCount = store.list("finding")[0].count;
    worker.request("live"); await worker.liveTick();
    assert.equal(store.list("finding")[0].count, savedCount); assert.equal(deliveries, 1);
    worker.cancelScan();
    releasePage({ hits: [], total: 615783, cursor: { pit: "old-pit" }, complete: false });
    await historical;
    assert.equal(worker.scan, null); assert.equal(store.get("checkpoint:old"), null);
    assert.equal(store.one("run", "old").status, "cancelled"); assert.equal(store.list("finding").length, 1);
  } finally { if (worker.running) { worker.cancelScan(); releasePage?.({ hits: [], total: 0, cursor: { pit: "pit" }, complete: false }); await historical; } await worker.stop(); store.close(); }
});

test("partial live stages preserve valid scan findings and do not mark full success", async () => {
  const store = new Store(":memory:"); store.set("config", config);
  const worker = new AgentWorker(store, { ready: () => true, live: async (_, __, ___, stage) => {
    if (stage === "security") throw Object.assign(new Error("HTTP 403 security_exception"), { code: "KIBANA_FORBIDDEN" });
    return stage === "scans" ? raw() : context();
  } }, { dataSource: "browser_relay" }, { clock: () => NOW });
  try {
    await worker.liveTick(); assert.equal(worker.liveStatus.lastSuccess, null);
    assert.match(worker.liveStatus.lastError, /security: HTTP 403/); assert.equal(store.list("finding").length, 1);
    assert.equal(worker.liveStatus.stages.security.errorCode, "KIBANA_FORBIDDEN");
    assert.equal(store.get("liveRetry"), false);
  } finally { await worker.stop(); store.close(); }
});

test("policy changes invalidate old live health and reject in-flight proof under the superseded policy", async () => {
  const store = new Store(":memory:"); store.set("config", config);
  let changeDuringRead = false;
  const worker = new AgentWorker(store, { ready: () => true, sourceIdentity: () => "fixture", live: async (_, __, ___, stage) => {
    if (changeDuringRead && stage === "scans") store.set("config", { ...config, query: "observer.name:edge-b" });
    return stage === "scans" ? raw() : stage === "context" ? context() : security();
  } }, { dataSource: "browser_relay" }, { clock: () => NOW });
  try {
    await worker.liveTick(); assert.equal(worker.state().status.live.lastSuccess, NOW);
    store.set("config", { ...config, query: "observer.name:edge-a" });
    assert.equal(worker.state().status.live.lastSuccess, null);
    store.db.prepare("DELETE FROM records WHERE kind='finding'").run();
    changeDuringRead = true;
    await worker.liveTick();
    assert.equal(store.list("finding").length, 0); assert.equal(worker.state().status.live.lastSuccess, null);
    assert.equal(store.get("liveRequest"), true);
    changeDuringRead = false; await worker.liveTick(); assert.equal(worker.state().status.live.lastSuccess, NOW);
    store.set("config", { ...worker.config(), exceptions: [{ indicatorType: "ip", indicatorValue: IP, reason: "Authorized source" }] });
    assert.equal(worker.state().findings.length, 0); assert.equal(store.list("finding").length, 1);
  } finally { await worker.stop(); store.close(); }
});

test("older historical evidence cannot replace a fresh finding's analysis, activity or priority", () => {
  const store = new Store(":memory:");
  try {
    const [fresh] = analyzeLiveScans(raw(), context(), config, {}, FROM, NOW);
    store.upsertFinding(fresh);
    store.upsertFinding({ ...fresh, title: "Old historical probing", lastSeen: "2026-10-02T10:00:00.000Z", firstSeen: "2026-10-02T10:00:00.000Z", priority: 40, activity: undefined, reasons: ["Old analysis"] });
    const saved = store.one("finding", fresh.fingerprint);
    assert.equal(saved.title, fresh.title); assert.equal(saved.priority, fresh.priority);
    assert.equal(saved.activity.allowed[0].action, "accept"); assert.equal(saved.firstSeen, "2026-10-02T10:00:00.000Z");
    assert.equal(saved.lastSeen, fresh.lastSeen); assert.deepEqual(saved.reasons, fresh.reasons);
  } finally { store.close(); }
});

test("overlapping live and background delivery cannot send the same job concurrently", async () => {
  const store = new Store(":memory:");
  const channel = { id: "soc", type: "webhook", url: "https://notify.invalid", enabled: true };
  store.set("notifications", { channels: [channel] });
  store.queueDelivery({ id: "incident", title: "Probing", indicator: IP, indicatorType: "ip", priority: 90, reasons: ["Actual proof"] }, channel, NOW);
  let release, calls = 0;
  const worker = new AgentWorker(store, {}, {}, { clock: () => NOW, fetcher: async () => { calls++; return new Promise(resolve => { release = resolve; }); } });
  const first = worker.deliver();
  try {
    await worker.deliver(); assert.equal(calls, 1);
    release(new Response("", { status: 200 })); await first;
    await worker.deliver(); assert.equal(calls, 1);
  } finally { release?.(new Response("", { status: 200 })); await first; await worker.stop(); store.close(); }
});

test("live reads use no PIT, preserve the query, reject shard failures and malformed/out-of-scope proof", async () => {
  const elastic = new ElasticClient({ dataSource: "browser_relay" }); let operation, response = raw();
  elastic.relay.execute = async value => { operation = value; return response; };
  assert.equal((await elastic.live({ ...config, query: "observer.name:edge-a" }, FROM, NOW, "scans")).hitsRead, 2);
  assert.equal(operation.kind, "live"); assert.equal(operation.query, "observer.name:edge-a"); assert.equal(operation.pit, undefined);
  response = { ...raw(), _shards: { failed: 1 } }; await assert.rejects(elastic.live(config, FROM, NOW, "scans"), /incomplete/);
  response = raw(); response.aggregations.sources.buckets[0].proof.hits.hits[0]._index = "finance-secret";
  await assert.rejects(elastic.live(config, FROM, NOW, "scans"), /Malformed/);
  response = raw(); response.aggregations.sources.buckets[0].ports.buckets = undefined;
  await assert.rejects(elastic.live(config, FROM, NOW, "scans"), /counts/);
});

test("relay assigns fresh detection before queued history and preserves a denied-request code", async () => {
  const relay = new BrowserRelay(), client = randomUUID();
  relay.connect("owner", client, { kibanaBaseUrl: "https://kibana.internal", spaceId: "default", policy });
  const old = relay.execute({ kind: "openPit", indexPattern: "logs-*" });
  const live = relay.execute({ kind: "live", indexPattern: "logs-*", stage: "scans", from: FROM, to: NOW, query: "" });
  const rejection = assert.rejects(live, error => error.code === "KIBANA_FORBIDDEN");
  const job = relay.poll("owner", client).job; assert.equal(job.operation.kind, "live");
  relay.result("owner", client, { id: job.id, success: false, error: "Read denied", errorCode: "KIBANA_FORBIDDEN" });
  await rejection;
  const history = relay.poll("owner", client).job;
  relay.result("owner", client, { id: history.id, success: true, data: { id: "pit" } }); await old;
  relay.disconnect("owner", client);
});
