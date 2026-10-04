import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Integrations } from "../integrations.mjs";
import { loadServerEnvironment } from "../../../scripts/server-env.mjs";
import { runtimeConfig } from "../config.mjs";
import { Store } from "../store.mjs";
import { enrichQueue, classifyReputation, reputationSource } from "../reputation.mjs";

function directory(t) { const dir = mkdtempSync(join(tmpdir(), "soc-watch-integrations-")); t.after(() => rmSync(dir, { recursive: true, force: true })); return dir; }
const runtime = dataDir => ({ dataDir, gtiKey: "", feeds: { threatfox: "", malwarebazaar: "" } });
const NOW = "2026-10-04T10:00:00.000Z";

test("all integration keys survive service restart; blank submissions preserve keys and removal is explicit", t => {
  const dir = directory(t), first = runtime(dir), integrations = new Integrations(first);
  integrations.save({ gti: " gti-test-key ", threatfox: "fox-test-key", malwarebazaar: "bazaar-test-key" });
  integrations.save({ gti: "", threatfox: "  " });
  const second = runtime(dir), restarted = new Integrations(second);
  assert.equal(second.gtiKey, "gti-test-key"); assert.deepEqual(second.feeds, { threatfox: "fox-test-key", malwarebazaar: "bazaar-test-key" });
  assert.deepEqual(restarted.status().gti, { configured: true, source: "server" });
  assert.ok(!JSON.stringify(restarted.status()).includes("test-key"));
  if (process.platform !== "win32") assert.equal(statSync(join(dir, "integrations.json")).mode & 0o777, 0o600);
  restarted.save({ remove: ["gti"] });
  assert.equal(new Integrations(runtime(dir)).status().gti.configured, false);
  assert.equal(JSON.parse(readFileSync(join(dir, "integrations.json"))).threatfox, "fox-test-key");
});

test("service environment has explicit priority and cannot be silently replaced by UI keys", t => {
  const dir = directory(t); new Integrations(runtime(dir)).save({ gti: "saved-key" });
  const processRuntime = { ...runtime(dir), gtiKey: "environment-key" }, integrations = new Integrations(processRuntime);
  assert.equal(processRuntime.gtiKey, "environment-key"); assert.equal(integrations.status().gti.source, "environment");
  assert.throws(() => integrations.save({ gti: "replacement" }), /service environment/);
  assert.throws(() => integrations.save({ remove: ["gti"] }), /service environment/);
});

test("invalid and unwritable saves do not erase working runtime credentials", t => {
  const dir = directory(t), r = runtime(dir), integrations = new Integrations(r);
  integrations.save({ gti: "original" });
  for (const body of [{ gti: "bad\nkey" }, { gti: null }, { extra: "secret" }, { remove: ["elastic"] }, { remove: "gti" }, { remove: ["gti"], gti: "replacement" }]) assert.throws(() => integrations.save(body));
  assert.equal(r.gtiKey, "original");
  integrations.path = join(dir, "nonexistent", "integrations.json");
  assert.throws(() => integrations.save({ gti: "new" }), /could not be saved/); assert.equal(r.gtiKey, "original");
});

test("corrupt saved keys fail loudly instead of resetting themselves", t => {
  const dir = directory(t); writeFileSync(join(dir, "integrations.json"), "{broken");
  assert.throws(() => new Integrations(runtime(dir)), /keys have not been reset/);
  assert.equal(readFileSync(join(dir, "integrations.json"), "utf8"), "{broken");
});

test("server .env is loaded at startup without overriding systemd; explicit missing file fails safely", t => {
  const dir = directory(t), env = { SOC_WATCH_GTI_API_KEY: "service-key" };
  writeFileSync(join(dir, ".env"), 'SOC_WATCH_GTI_API_KEY=file-key\nSOC_WATCH_THREATFOX_KEY="fox-key"\nSOC_WATCH_SERVER_AGENT=true\n');
  loadServerEnvironment(dir, env);
  const config = runtimeConfig(env); assert.equal(config.gtiKey, "service-key"); assert.equal(config.feeds.threatfox, "fox-key");
  assert.equal(env.SOC_WATCH_SERVER_AGENT, "true");
  assert.throws(() => loadServerEnvironment(dir, { SOC_WATCH_ENV_FILE: join(dir, "missing.env") }), /does not exist/);
});

test("server GTI requests IP/domain/hash reports with assessment header and unwraps genuine GTI values", async () => {
  const store = new Store(":memory:");
  try {
    for (const [type, value] of [["ip", "185.220.101.4"], ["domain", "dangerous.com"], ["hash", "a".repeat(64)]]) store.queueReputation(type, value, NOW);
    const urls = [];
    await enrichQueue(store, { gtiKey: "private-test-key" }, async (url, init) => {
      assert.equal(init.headers["x-apikey"], "private-test-key"); assert.equal(init.headers["x-tool"], "SOC-WatchServer"); urls.push(url);
      return Response.json({ data: { attributes: { gti_assessment: { verdict: { value: "VERDICT_MALICIOUS" }, severity: { value: "SEVERITY_HIGH" }, threat_score: { value: 85 } } } } });
    }, NOW);
    assert.ok(urls.some(url => url.includes("ip_addresses/"))); assert.ok(urls.some(url => url.includes("domains/"))); assert.ok(urls.some(url => url.includes("files/")));
    for (const rep of Object.values(store.reputationMap())) { assert.equal(rep.verdict, "malicious"); assert.equal(rep.score, 85); assert.equal(rep.assessment, "gti"); }
    assert.equal(classifyReputation({ gti_assessment: { verdict: { value: "VERDICT_UNKNOWN" } } }).verdict, "unknown");
    assert.equal(classifyReputation({ gti_assessment: { severity: { value: "SEVERITY_MEDIUM" } } }).verdict, "suspicious");
  } finally { store.close(); }
});

test("agent uses browser-held GTI key without reading or transporting secrets and prioritizes active findings", async () => {
  const store = new Store(":memory:");
  try {
    store.queueReputation("ip", "89.1.2.3", NOW); store.queueReputation("ip", "185.220.101.4", NOW);
    store.record("finding", { id: "f", status: "open", indicatorType: "ip", indicator: "185.220.101.4" });
    const operations = [], relay = { status: () => ({ ready: true, source: { reputationConfigured: true } }), execute: async operation => {
      operations.push(operation); return { status: "scored", verdict: "malicious", score: 90, malicious: 10, suspicious: 1, vendors: 89, gtiVerdict: "VERDICT_MALICIOUS" };
    } };
    const result = await enrichQueue(store, { gtiKey: "" }, () => { throw new Error("Do not use server HTTP"); }, NOW, relay);
    assert.equal(result.processed, 2); assert.equal(operations[0].target.value, "185.220.101.4");
    assert.deepEqual(Object.keys(operations[0]), ["kind", "target"]); assert.equal(store.reputationMap()["ip|185.220.101.4"].verdict, "malicious");
    assert.equal(reputationSource({ gtiKey: "" }, relay), "browser"); assert.equal(reputationSource({ gtiKey: "server-key" }, relay), "server");
    assert.equal(reputationSource({}, { status: () => ({ ready: false }) }), "missing");
  } finally { store.close(); }
});

test("rate limits back off the entire persistent queue, not just a single IOC", async () => {
  const store = new Store(":memory:"); let calls = 0;
  try {
    store.queueReputation("ip", "185.220.101.4", NOW); store.queueReputation("ip", "89.1.2.3", NOW);
    const fetcher = async () => { calls++; return new Response("", { status: 429, headers: { "retry-after": "120" } }); };
    await enrichQueue(store, { gtiKey: "key" }, fetcher, NOW);
    await enrichQueue(store, { gtiKey: "key" }, fetcher, "2026-10-04T10:01:00.000Z"); assert.equal(calls, 1);
    await enrichQueue(store, { gtiKey: "replacement" }, fetcher, "2026-10-04T10:01:00.000Z"); assert.equal(calls, 2);
    assert.equal(Object.values(store.reputationMap()).some(rep => rep.verdict === "benign"), false);
  } finally { store.close(); }
});
