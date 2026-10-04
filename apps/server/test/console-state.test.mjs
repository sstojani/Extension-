import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { Store } from "../store.mjs";
import { AgentWorker } from "../worker.mjs";
import { createAgentApi } from "../api.mjs";
import { findingOverview, findingSummary, FINDING_OVERVIEW_LIMIT } from "../console-state.mjs";

const now = "2026-10-04T10:00:00.000Z";
function finding(id) {
  return { id, fingerprint: id, indicatorType: "ip", indicator: "185.220.101.4", title: "Suspicious observed activity", category: "scan",
    status: "open", firstSeen: now, lastSeen: now, priority: 92, severity: "critical", behaviorScore: 85, confidence: 90, count: 1234,
    evidence: [{ index: "logs-network", eventId: "proof-1", timestamp: now, reason: "Observed accept" }],
    reasons: ["Corroborated fanout"], limitations: ["Evidence is sampled"], reputation: { verdict: "malicious", status: "scored", source: "server", score: 88, gtiVerdict: "VERDICT_MALICIOUS" },
    assignedTo: "analyst", notes: [{ text: "Retained review note" }] };
}

test("large retained proof/investigations no longer overflow state; authenticated details remain complete", async t => {
  const store = new Store(":memory:");
  const runtime = { token: "a".repeat(40), publicOrigin: "", elasticUrl: "https://elastic.invalid", elasticApiKey: "read-only" };
  const worker = new AgentWorker(store, {}, runtime, { clock: () => now });
  const proof = "p".repeat(150000);
  store.transaction(() => {
    for (let i = 0; i < 80; i++) store.record("finding", { ...finding(`finding-${i}`), notes: [{ text: proof }], evidence: [{ index: "logs-network", eventId: "proof-1", timestamp: now, reason: proof }] });
    for (let i = 0; i < 30; i++) store.record("investigation", { id: `finding-${i}`, status: "complete", completedAt: now,
      briefing: "Retained investigation briefing", facts: [{ claim: proof }], timeline: [{ action: proof }] });
    store.record("run", { id: "legacy-run", mode: "today", status: "retrying", startedAt: now, eventsRead: 10500, totalMatched: 615783,
      coverage: "in_progress", cursor: { pit: proof }, config: { query: proof }, findings: [{ eventKeys: [proof] }] });
    store.record("alert", { id: "new-alert", findingId: "finding-0", title: "Active probing", createdAt: now, indicator: "185.220.101.4", priority: 92,
      reasons: ["Accepted activity at the observed timestamp"], evidence: [{ reason: proof }], activity: { infrastructures: ["edge-a"], countries: ["Kazakhstan"], allowed: [{ action: "accept", timestamp: now }] } });
  });
  const legacyBytes = Buffer.byteLength(JSON.stringify({ findings: store.list("finding"), investigations: store.list("investigation"), runs: store.list("run"), alerts: store.list("alert") }));
  assert.ok(legacyBytes > 8 * 1024 * 1024, "Fixture must reproduce the old console limit failure");
  const api = createAgentApi(worker, runtime), server = createServer(async (req, res) => { await api(req, res); });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => { await new Promise(resolve => server.close(resolve)); store.close(); });
  const origin = `http://127.0.0.1:${server.address().port}`, base = `${origin}/api/agent`;
  const login = async token => (await fetch(`${base}/login`, { method: "POST", headers: { origin, "content-type": "application/json" }, body: JSON.stringify({ token }) })).headers.get("set-cookie").split(";")[0];
  const cookie = await login(runtime.token);
  const response = await fetch(`${base}/state`, { headers: { cookie } });
  assert.equal(response.status, 200); assert.equal(response.headers.get("cache-control"), "no-store");
  const payload = await response.text(), state = JSON.parse(payload);
  assert.equal(Number(response.headers.get("content-length")), Buffer.byteLength(payload));
  assert.ok(Buffer.byteLength(payload) < 128 * 1024, "Overview must not transfer retained detail bundles");
  assert.equal(state.findings.length, 80); assert.equal(state.findings[0].count, 1234);
  assert.deepEqual(state.findingWindow, { limit: 2000, returned: 80, retained: 80, limited: false });
  assert.ok(!payload.includes(proof)); assert.ok(!Object.hasOwn(state.findings[0], "evidence"));
  assert.ok(!Object.hasOwn(state.investigations[0], "timeline")); assert.ok(!Object.hasOwn(state.runs[0], "cursor"));
  assert.equal(state.runs[0].eventsRead, 10500); assert.equal(state.runs[0].totalMatched, 615783);
  assert.equal(state.alerts[0].activity.allowed[0].action, "accept"); assert.deepEqual(state.alerts[0].activity.countries, ["Kazakhstan"]);
  assert.equal((await fetch(`${base}/findings/finding-0`)).status, 401);
  assert.equal((await fetch(`${base}/findings/unknown`, { headers: { cookie } })).status, 404);
  const detail = await (await fetch(`${base}/findings/finding-0`, { headers: { cookie } })).json();
  assert.equal(detail.finding.evidence[0].reason, proof); assert.equal(detail.finding.notes[0].text, proof);
  assert.equal(detail.investigation.timeline[0].action, proof); assert.equal(detail.investigation.briefing, "Retained investigation briefing");
  const review = await fetch(`${base}/findings/finding-0`, { method: "PATCH", headers: { cookie, origin, "content-type": "application/json" }, body: JSON.stringify({ status: "acknowledged", note: "New note" }) });
  assert.equal(review.status, 200); assert.ok(!(await review.text()).includes(proof));
  assert.equal(store.one("finding", "finding-0").notes[0].text, proof);
  assert.equal(store.one("finding", "finding-0").notes.at(-1).text, "New note");
  assert.equal(store.one("finding", "finding-0").status, "acknowledged");
  runtime.analysts = [{ name: "reviewer", token: "b".repeat(40) }];
  const analyst = await login(runtime.analysts[0].token);
  assert.equal((await fetch(`${base}/findings/finding-0`, { headers: { cookie: analyst } })).status, 200);
});

test("overview size budget and record window are explicit, do not delete or truncate stored findings", () => {
  const records = Array.from({ length: 4 }, (_, i) => ({ ...finding(`id-${i}`), title: "x".repeat(800000) }));
  const overview = findingOverview(records, 4);
  assert.equal(overview.findings.length, 2); assert.equal(overview.findingWindow.limited, true);
  assert.equal(overview.findingWindow.retained, 4); assert.equal(records[3].title.length, 800000);
  assert.ok(Buffer.byteLength(JSON.stringify(overview.findings)) < 2 * 1024 * 1024);
  assert.equal(findingOverview([finding("one")], FINDING_OVERVIEW_LIMIT + 1).findingWindow.limited, true);
  assert.deepEqual(findingSummary(finding("one")).reputation, { verdict: "malicious", score: 88, status: "scored", source: "server", gtiVerdict: "VERDICT_MALICIOUS" });
});

test("projected iteration preserves ordering and full records; scoped exceptions still suppress the overview", () => {
  const store = new Store(":memory:");
  try {
    store.record("finding", { ...finding("excluded"), host: "allowed-host", infrastructure: "edge-a" });
    store.record("finding", { ...finding("visible"), host: "other-host", infrastructure: "edge-a" });
    store.set("config", { exceptions: [{ indicatorType: "ip", indicatorValue: "185.220.101.4", host: "allowed-host", reason: "Authorized activity" }] });
    const worker = new AgentWorker(store, {}, { dataSource: "browser_relay" }, { clock: () => now });
    assert.deepEqual(store.list("finding", 1, value => value.id), store.list("finding", 1).map(value => value.id));
    const state = worker.state();
    assert.deepEqual(state.findings.map(value => value.id), ["visible"]);
    assert.equal(state.findingWindow.retained, 2); assert.equal(state.findingWindow.limited, false);
    assert.equal(store.list("finding").length, 2); assert.equal(store.one("finding", "visible").evidence.length, 1);
  } finally { store.close(); }
});
