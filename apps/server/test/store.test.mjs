import { test } from "node:test";
import assert from "node:assert/strict";
import { Store } from "../store.mjs";
import { classifyReputation, publicIndicator, enrichQueue } from "../reputation.mjs";
import { validateConfig } from "../config.mjs";
import { validateRule, validateNotifications, recordAlert, deliverQueue } from "../alerts.mjs";

test("transactions rollback and event IDs deduplicate overlap", () => {
  const s = new Store(":memory:");
  assert.throws(() => s.transaction(() => { s.set("checkpoint", "bad"); throw new Error("failed"); }));
  assert.equal(s.get("checkpoint"), null);
  const e = { id: "1", index: "logs-one", timestamp: "2026-10-02T00:00:00.000Z" };
  assert.equal(s.addEvents([e,e]), 1); assert.equal(s.addEvents([e]), 0); s.close();
});
test("no detection is undetected, not clean; adverse votes never masked by benign verdict", () => {
  assert.equal(classifyReputation({ last_analysis_stats: { undetected: 80 } }).verdict, "undetected");
  assert.equal(classifyReputation({ gti_assessment: { verdict: "benign" }, last_analysis_stats: { malicious: 14 } }).verdict, "malicious");
  assert.equal(classifyReputation({ last_analysis_stats: { malicious: 1 } }).verdict, "suspicious");
  assert.equal(classifyReputation({ gti_assessment: { verdict: "suspicious", threat_score: { value: 25 } } }).verdict, "suspicious");
});
test("internal identities, local names and special addresses never submitted to GTI", () => {
  for (const value of ["b'foo@apdurres'", "foo.local", "foo.internal", "x", "a..com"]) assert.equal(publicIndicator("domain", value), false);
  for (const value of ["10.0.0.1", "192.168.1.1", "100.64.0.1", "::1", "2001:db8::1", "127.0.0.1"]) assert.equal(publicIndicator("ip", value), false);
  assert.equal(publicIndicator("ip", "1.1.1.1"), true);
});
test("reputation queue persists errors and retries without relabeling them clean", async () => {
  const s = new Store(":memory:"), now = "2026-10-02T00:00:00.000Z";
  s.queueReputation("ip", "152.32.140.22", now);
  await enrichQueue(s, { gtiKey: "test" }, async () => new Response("", { status: 429, headers: { "retry-after": "120" } }), now);
  assert.equal(s.reputationMap()["ip|152.32.140.22"].status, "rate_limited");
  assert.equal(s.reputationJobs("2026-10-02T00:01:00.000Z").length, 0);
  assert.equal(s.reputationJobs("2026-10-02T00:02:00.000Z").length, 1); s.close();
});
test("delivery idempotency, retries and eventual confirmation", async () => {
  const s = new Store(":memory:"), now = "2026-10-02T00:00:00.000Z", channel = { id: "team", type: "webhook", enabled: true, url: "https://example.com/hook" };
  const f = { id: "incident", fingerprint: "incident", title: "Suspicious", indicator: "bad.example.com", indicatorType: "domain", priority: 90, severity: "high", reasons: ["Evidence"], evidence: [], lastSeen: now };
  assert.ok(recordAlert(s, f, { channels: [channel], now }));
  assert.equal(recordAlert(s, f, { channels: [channel], now }), null);
  await deliverQueue(s, { channels: [channel] }, async () => new Response("", { status: 503 }), now);
  assert.equal(s.deliveries()[0].status, "retry");
  await deliverQueue(s, { channels: [channel] }, async () => new Response("", { status: 200 }), "2026-10-02T00:01:00.000Z");
  assert.equal(s.deliveries()[0].status, "delivered"); s.close();
});
test("late reputation escalation upgrades an existing alert without duplicating it", () => {
  const s = new Store(":memory:"), now = "2026-10-02T00:00:00.000Z";
  const base = { id: "incident", fingerprint: "incident", title: "Watched indicator", indicator: "152.32.140.22", indicatorType: "ip", priority: 55, severity: "medium", reasons: ["Unknown reputation"], evidence: [], lastSeen: now };
  const first = recordAlert(s, base, { channels: [], now });
  const upgraded = recordAlert(s, { ...base, priority: 90, severity: "critical", reasons: ["GTI malicious reputation"] }, { channels: [], now });
  assert.equal(s.list("alert").length, 1);
  assert.equal(upgraded.id, first.id);
  assert.equal(s.one("alert", first.id).priority, 90);
  s.close();
});
test("settings and watch rules reject malformed inputs", () => {
  assert.throws(() => validateConfig({ query: {}, timezone: "fake" }));
  assert.throws(() => validateRule({ indicatorType: "domain", indicatorValue: "user@local" }));
  assert.equal(validateRule({ indicatorType: "domain", indicatorValue: "EVIL[.]COM." }).indicatorValue, "evil.com");
  assert.throws(() => validateNotifications({ channels: [{ id: "a", type: "webhook", enabled: true, url: "http://example.com/" }] }));
});

test("a successful HTTP response without GTI assessment is unavailable, never undetected", async () => {
  const s = new Store(":memory:"), now = "2026-10-02T00:00:00.000Z";
  s.queueReputation("domain", "malicious.example.com", now);
  const result = await enrichQueue(s, { gtiKey: "test" }, async () => Response.json({ data: {} }), now);
  assert.equal(s.reputationMap()["domain|malicious.example.com"].status, "unavailable");
  assert.equal(s.reputationMap()["domain|malicious.example.com"].verdict, "unknown");
  assert.deepEqual(result.changed, []);
  s.close();
});
