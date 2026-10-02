import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID, createHash } from "node:crypto";
import { createServer } from "node:http";
import { BrowserRelay } from "../relay.mjs";
import { ElasticClient } from "../elastic.mjs";
import { AgentWorker } from "../worker.mjs";
import { Store } from "../store.mjs";
import { defaults, runtimeConfig } from "../config.mjs";
import { createAgentApi } from "../api.mjs";
import { validateRelayOperation, relayIndexAllowed } from "@soc-watch/protocol";

const policy = { indexPattern: "logs-*", timestampField: "@timestamp", infrastructureField: "observer.name" };
const source = { kibanaBaseUrl: "https://kibana.internal:8888", spaceId: "default", policy };
const search = { kind: "search", body: { pit: { id: "pit", keep_alive: "10m" }, size: 500, timeout: "20s", track_total_hits: true,
  query: { bool: { filter: [{ range: { "@timestamp": { gte: "2026-10-02T10:00:00Z", lte: "2026-10-02T10:05:00Z" } } }] } },
  sort: [{ "@timestamp": { order: "asc", unmapped_type: "date" } }, { _shard_doc: "asc" }] } };

test("browser mode ignores unreachable direct credentials and never calls server fetch", async () => {
  const runtime = runtimeConfig({ SOC_WATCH_DATA_SOURCE: "browser_relay", SOC_WATCH_ELASTIC_URL: "http://10.10.254.202:8888", SOC_WATCH_ELASTIC_API_KEY: "obsolete" });
  assert.equal(runtime.elasticUrl, "");
  assert.equal(runtimeConfig({}).dataSource, "browser_relay");
  assert.equal(runtimeConfig({ SOC_WATCH_ELASTIC_API_KEY: "key" }).dataSource, "direct");
  assert.throws(() => runtimeConfig({ SOC_WATCH_DATA_SOURCE: "invalid" }));
  const elastic = new ElasticClient(runtime, () => { throw new Error("Must not reach private ELK from the home server"); });
  await assert.rejects(elastic.request("/_search", search.body), /disconnected/);
});

test("relay read grammar rejects writes, scripts, broad queries and system indexes", () => {
  assert.equal(validateRelayOperation(search, policy).kind, "search");
  for (const bad of [
    { kind: "delete", path: "/logs-*/_delete_by_query" },
    { ...search, body: { ...search.body, script_fields: { leak: {} } } },
    { ...search, body: { ...search.body, size: 501 } },
    { ...search, body: { ...search.body, query: { script: { script: "evil" } } } },
    { ...search, body: { ...search.body, query: { bool: { filter: [] } } } },
    { kind: "evidence", index: ".security-7", id: "secret" },
    { kind: "evidence", index: "finance", id: "secret" },
    { kind: "openPit", indexPattern: "*" }
  ]) assert.throws(() => validateRelayOperation(bad, policy));
  assert.equal(relayIndexAllowed(".ds-logs-network-default-2026.10.02-000001", "logs-*"), true);
  assert.equal(relayIndexAllowed(".ds-logs-network-default-2026.10.02-000001", "logs-network-default"), true);
  assert.equal(relayIndexAllowed(".ds-finance-default-2026.10.02-000001", "logs-*"), false);
  assert.equal(relayIndexAllowed(".security", "logs-*"), false);
});

test("relay ownership, late/duplicate results, abort, timeout and expiry fail closed", async () => {
  let now = 1000;
  const relay = new BrowserRelay({ clock: () => now, timeout: 20, ttl: 60 }), client = randomUUID();
  relay.connect("owner", client, source);
  assert.throws(() => relay.connect("other", randomUUID(), source), /Another browser/);
  const result = relay.execute({ kind: "openPit", indexPattern: "logs-*" });
  assert.throws(() => relay.poll("other", client), /another session/);
  const job = relay.poll("owner", client).job;
  assert.equal(relay.poll("owner", client).job, null);
  assert.throws(() => relay.result("other", client, { id: job.id, success: true, data: { id: "stolen" } }), /another session/);
  relay.result("owner", client, { id: job.id, success: true, data: { id: "pit" } });
  assert.deepEqual(await result, { id: "pit" });
  assert.throws(() => relay.result("owner", client, { id: job.id, success: true, data: {} }), /completed/);
  const controller = new AbortController(), cancelled = relay.execute({ kind: "openPit", indexPattern: "logs-*" }, controller.signal);
  controller.abort(); await assert.rejects(cancelled, /cancelled/);
  await assert.rejects(relay.execute({ kind: "openPit", indexPattern: "logs-*" }), /timed out/);
  const disconnected = relay.execute({ kind: "openPit", indexPattern: "logs-*" });
  now += 61; assert.equal(relay.status().ready, false);
  await assert.rejects(disconnected, /paused/);
  assert.equal(relay.jobs.size, 0);
});

test("worker resumes a paginated relay scan, watches indicators and reads proof without a direct key", async () => {
  const store = new Store(":memory:"), runtime = runtimeConfig({ SOC_WATCH_DATA_SOURCE: "browser_relay" });
  const config = { ...defaults, ...policy, pageSize: 100, autoInvestigate: false };
  store.set("config", config);
  store.record("rule", { id: "watch", enabled: true, name: "Host", indicatorType: "ip", indicatorValue: "203.0.113.5", minEvents: 1, minPriority: 0, cooldownMinutes: 60, channels: [], scope: {} });
  const elastic = new ElasticClient(runtime, () => { throw new Error("No direct request allowed"); });
  const worker = new AgentWorker(store, elastic, runtime, { clock: () => "2026-10-02T10:05:00.000Z" });
  assert.equal(worker.state().status.paused, true);
  assert.throws(() => worker.request(), /disconnected/);
  const client = randomUUID(); elastic.relay.connect("session", client, source);
  const rows = Array.from({ length: 101 }, (_, i) => ({ _id: `${i}`, _index: ".ds-logs-network-default-2026.10.02-000001", sort: ["2026-10-02T10:04:00.000Z", i],
    _source: { "@timestamp": "2026-10-02T10:04:00.000Z", "source.ip": "203.0.113.5", "destination.ip": "10.0.0.2", "observer.name": "edge" } }));
  const kinds = []; let working = true, failSecondPage = true;
  const pump = (async () => {
    while (working) {
      if (!elastic.ready()) { await new Promise(r => setTimeout(r, 1)); continue; }
      const job = elastic.relay.poll("session", client).job;
      if (!job) { await new Promise(r => setTimeout(r, 1)); continue; }
      const operation = job.operation; kinds.push(operation.kind);
      if (operation.kind === "search" && operation.body.search_after && failSecondPage) {
        failSecondPage = false;
        elastic.relay.result("session", client, { id: job.id, success: false, error: "Kibana temporary failure" }); continue;
      }
      const data = operation.kind === "openPit" ? { id: "pit" } : operation.kind === "closePit" ? { succeeded: true }
        : operation.kind === "fieldCaps" ? { fields: Object.fromEntries(operation.fields.map(field => [field, { keyword: { searchable: true } }])) }
        : operation.kind === "evidence" ? rows[0]
        : { hits: { total: { value: rows.length, relation: "eq" }, hits: rows.slice(operation.body.search_after ? Number(operation.body.search_after[1]) + 1 : 0, (operation.body.search_after ? Number(operation.body.search_after[1]) + 1 : 0) + operation.body.size) } };
      elastic.relay.result("session", client, { id: job.id, success: true, data });
    }
  })();
  try {
    worker.request("live"); await worker.tick();
    assert.ok(worker.scan); assert.equal(worker.scan.cursor, null);
    const originalWindow = [worker.scan.from, worker.scan.to];
    assert.equal(store.get(`checkpoint:${worker.scan.scope}`), null);
    elastic.relay.disconnect("session", client); await worker.tick();
    assert.deepEqual([worker.scan.from, worker.scan.to], originalWindow);
    elastic.relay.connect("session", client, source); await worker.tick();
    assert.equal(worker.scan, null);
    assert.equal(worker.state().status.coverage.eventsRead, 201); // Physical reads include the replayed first page.
    assert.equal(worker.state().status.coverage.analysisEvents, 101);
    assert.equal(store.list("finding").some(f => f.category === "watched_indicator"), true);
    assert.equal((await elastic.evidence(rows[0]._index, "0"))._id, "0");
    const scope = createHash("sha256").update(JSON.stringify([elastic.sourceIdentity(), config.indexPattern, config.timestampField, config.query])).digest("hex");
    assert.equal(store.get(`checkpoint:${scope}`), "2026-10-02T10:05:00.000Z");
    assert.ok(kinds.filter(kind => kind === "search").length >= 3);
    elastic.relay.disconnect("session", client);
    store.set("scanRequest", { mode: "today" }); await worker.tick();
    assert.ok(store.get("scanRequest")); assert.equal(worker.state().status.running, false);
    elastic.relay.connect("session", client, source);
    await worker.tick(); assert.equal(store.get("scanRequest"), null);
  } finally { working = false; await pump; await worker.stop(); store.close(); }
});

test("relay API requires a same-origin administrator session, owns jobs and disconnects on logout", async () => {
  const store = new Store(":memory:"), runtime = { ...runtimeConfig({ SOC_WATCH_DATA_SOURCE: "browser_relay" }), token: "a".repeat(40), analysts: [{ name: "analyst", token: "b".repeat(40) }] };
  const elastic = new ElasticClient(runtime);
  const worker = { store, elastic, configured: () => true, state: () => ({}), config: () => ({ ...defaults, ...policy }), tick: async () => {} };
  const api = createAgentApi(worker, runtime), server = createServer((req, res) => void api(req, res));
  await new Promise(r => server.listen(0, "127.0.0.1", r));
  const origin = `http://127.0.0.1:${server.address().port}`, clientId = randomUUID();
  const post = (route, body, cookie = "", requestOrigin = origin) => fetch(`${origin}/api/agent/${route}`, { method: "POST", headers: { cookie, origin: requestOrigin, "content-type": "application/json" }, body: JSON.stringify(body) });
  const login = async token => (await post("login", { token })).headers.get("set-cookie").split(";")[0];
  try {
    assert.equal((await post("relay/connect", { clientId, source })).status, 401);
    const analyst = await login(runtime.analysts[0].token);
    assert.equal((await post("relay/connect", { clientId, source }, analyst)).status, 403);
    const cookie = await login(runtime.token);
    assert.equal((await post("relay/connect", { clientId, source }, cookie, "https://evil.com")).status, 403);
    assert.equal((await post("relay/connect", { clientId, source }, cookie)).status, 200);
    const pending = elastic.request(`/${encodeURIComponent("logs-*")}/_pit?keep_alive=10m`, null);
    const { job } = await (await post("relay/poll", { clientId }, cookie)).json();
    const other = await login(runtime.token);
    assert.equal((await post("relay/result", { clientId, id: job.id, success: true, data: { id: "wrong" } }, other)).status, 400);
    assert.equal((await post("relay/result", { clientId, id: job.id, success: true, data: { id: "pit" } }, cookie)).status, 200);
    assert.deepEqual(await pending, { id: "pit" });
    await post("logout", {}, cookie); assert.equal(elastic.ready(), false);
    assert.equal((await post("relay/connect", { clientId, source: { ...source, kibanaBaseUrl: "https://another.internal" } }, other)).status, 400);
  } finally { await new Promise(r => server.close(r)); store.close(); }
});
