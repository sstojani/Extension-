import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Store } from "../apps/server/store.mjs";

// Real production web/API/worker with a deterministic extension transport fixture.
const { chromium } = await import(process.env.SOC_WATCH_PLAYWRIGHT_MODULE || "playwright");
const root = fileURLToPath(new URL("..", import.meta.url));
const data = resolve(root, ".data", `relay-browser-${Date.now()}`);
await mkdir(data, { recursive: true });
const fixtureStore = new Store(resolve(data, "soc-watch.sqlite"));
const retainedAt = new Date(Date.now() - 8 * 3600000).toISOString();
try {
  fixtureStore.transaction(() => {
    for (let i = 0; i < 96; i++) fixtureStore.record("finding", { id: `retained-${i}`, fingerprint: `retained-${i}`, title: `Retained fixture finding ${i}`, indicatorType: "ip", indicator: "185.220.101.4",
      category: "fixture_history", priority: 40, confidence: 70, behaviorScore: 30, severity: "medium", status: "open", count: 50, reputation: null,
      firstSeen: retainedAt, lastSeen: retainedAt, reasons: ["Retained fixture reason"], limitations: ["Fixture evidence is sampled"],
      evidence: [{ index: "logs-network", eventId: "retained-proof", timestamp: retainedAt, reason: "Retained proof" }],
      notes: Array.from({ length: 100 }, (_, n) => ({ text: `Note ${n}: `.padEnd(2000, "x") })) });
    fixtureStore.record("investigation", { id: "retained-0", status: "complete", completedAt: retainedAt, briefing: "Retained fixture investigation briefing", facts: [{ claim: "Retained fixture fact" }], timeline: [{ eventId: "retained-proof" }] });
  });
  assert.ok(Buffer.byteLength(JSON.stringify(fixtureStore.list("finding"))) > 8 * 1024 * 1024, "Stored detail fixture must exceed the old state limit");
} finally { fixtureStore.close(); }
const token = "browser-regression-only-".repeat(3), port = process.env.SOC_WATCH_TEST_PORT || "5197";
const origin = `http://127.0.0.1:${port}`;
const server = spawn(process.execPath, ["scripts/serve-web.mjs"], { cwd: root, windowsHide: true, stdio: "pipe", env: {
  ...process.env, SOC_WATCH_PORT: port, SOC_WATCH_HOST: "127.0.0.1", SOC_WATCH_SERVER_AGENT: "true",
  SOC_WATCH_DATA_SOURCE: "browser_relay", SOC_WATCH_DATA_DIR: data, SOC_WATCH_PUBLIC_ORIGIN: origin, SOC_WATCH_AGENT_TOKEN: token,
  SOC_WATCH_GTI_API_KEY: "", SOC_WATCH_THREATFOX_KEY: "", SOC_WATCH_MALWAREBAZAAR_KEY: ""
} });
let output = "", browser, page;
server.stdout.on("data", chunk => { output += chunk; }); server.stderr.on("data", chunk => { output += chunk; });
try {
  for (let i = 0; i < 100; i++) {
    if (server.exitCode !== null) throw new Error(output);
    try { if ((await fetch(`${origin}/api/agent/status`)).ok) break; } catch { /* Wait for local startup. */ }
    await new Promise(r => setTimeout(r, 100));
  }
  browser = await chromium.launch({ headless: true });
  page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  const waitState = async (predicate, timeout = 30000) => {
    const deadline = Date.now() + timeout; let state;
    do {
      state = await page.evaluate(async () => (await (await fetch("/api/agent/state")).json()));
      if (predicate(state)) return state;
      await new Promise(resolve => setTimeout(resolve, 150));
    } while (Date.now() < deadline);
    throw new Error(`Timed out waiting for agent state: ${JSON.stringify(state.status)}`);
  };
  const errors = []; page.on("pageerror", error => errors.push(error.message));
  const stateSizes = [], detailRequests = [];
  page.on("response", response => { if (response.url().endsWith("/api/agent/state")) stateSizes.push(Number(response.headers()["content-length"])); });
  page.on("request", request => { if (request.url().includes("/api/agent/findings/")) detailRequests.push(request.url()); });
  await page.addInitScript(() => {
    window.fixtureNotifications = [];
    window.Notification = class {
      static permission = "default";
      static async requestPermission() { this.permission = "granted"; return this.permission; }
      constructor(title, options) { window.fixtureNotifications.push({ title, ...options }); }
    };
    window.fixtureAuthenticated = true;
    window.fixtureSettingsError = true;
    window.fixtureConnections = 0;
    window.fixturePermissionError = false;
    window.fixtureRotations = 0;
    window.fixtureClosedPits = 0;
    window.fixtureGtiConfigured = false;
    let sequence = 0;
    const pits = new Set();
    const newPit = () => `fixture-pit-${++sequence}-`.padEnd(128 * 1024, "p");
    const rows = Array.from({ length: 120 }, (_, i) => ({ _id: `${i}`, _index: ".ds-logs-network-default-2026.10.02-000001",
      sort: [new Date(Date.now() - 60000).toISOString(), i], _source: { "@timestamp": new Date(Date.now() - 60000).toISOString(),
        "source.ip": "185.220.101.4", "destination.ip": `10.0.0.${i % 10 + 1}`, "destination.port": 22,
        "event.created": new Date(Date.now() - 60000).toISOString(), "event.category": ["network"], "event.action": "denied", "event.outcome": "failure", "observer.name": `edge-${i % 3}`, "host.name": "target" } }));
    window.addEventListener("message", event => {
      if (event.source !== window || event.data?.source !== "soc-watch-web") return;
      const request = event.data.message;
      if (!request?.action?.startsWith("agent.relay.") && !request?.action?.startsWith("dataViews.")) return;
      let data;
      if (request.action === "dataViews.list") data = [{ id: "logs-view", title: "logs-network-*", name: "Network logs" }];
      else if (request.action === "dataViews.get") data = { data_view: { title: "logs-network-*", timeFieldName: "event.created" } };
      else if (request.action === "agent.relay.connect" && window.fixtureSettingsError) {
        window.fixtureConnections++;
        window.postMessage({ source: "soc-watch-content", message: { type: "soc-watch.response", response: { version: 1, requestId: request.requestId,
          success: false, error: { code: "INVALID_REQUEST", message: 'Timestamp field "@timestamp" is not mapped in "logs-*". Select your Kibana Discover data view\'s time field in Agent Settings.' } } } }, window.location.origin); return;
      }
      else if (request.action === "agent.relay.disconnect") { pits.clear(); data = { disconnected: true }; }
      else if (request.action === "agent.relay.connect" && window.fixturePermissionError) {
        window.fixtureConnections++;
        window.postMessage({ source: "soc-watch-content", message: { type: "soc-watch.response", response: { version: 1, requestId: request.requestId,
          success: false, error: { code: "KIBANA_FORBIDDEN", message: "Elasticsearch rejected the request to open a log snapshot (HTTP 403; security_exception). Use a data view your account can read, or ask your ELK administrator to check its read permissions." } } } }, window.location.origin); return;
      }
      else if (!window.fixtureAuthenticated) {
        window.postMessage({ source: "soc-watch-content", message: { type: "soc-watch.response", response: { version: 1, requestId: request.requestId,
          success: false, error: { code: "KIBANA_AUTH_REQUIRED", message: "Kibana authentication is required." } } } }, window.location.origin); return;
      } else if (request.action === "agent.relay.connect") {
        pits.clear();
        data = { relayId: crypto.randomUUID(), source: { kibanaBaseUrl: "https://kibana.internal:8888", spaceId: "default", policy: request.params,
          reputationConfigured: window.fixtureGtiConfigured, reputationRevision: "57cc97aa-ea99-4c1a-bcd5-59b493536c67" } };
      }
      else if (request.action === "agent.relay.heartbeat") data = { ready: true, reputationConfigured: window.fixtureGtiConfigured, reputationRevision: "57cc97aa-ea99-4c1a-bcd5-59b493536c67" };
      else {
        const operation = request.params.operation;
        if (operation.kind === "reputation") data = { status: "scored", verdict: "malicious", score: 88, malicious: 5, suspicious: 0, vendors: 89, gtiVerdict: "VERDICT_MALICIOUS" };
        else if (operation.kind === "openPit") { const id = newPit(); pits.add(id); data = { id }; }
        else if (operation.kind === "closePit") {
          if (!pits.delete(operation.id)) throw new Error("Cleanup did not use an owned, current snapshot ID");
          window.fixtureClosedPits++; data = { succeeded: true };
        }
        else if (operation.kind === "fieldCaps") data = { fields: Object.fromEntries(operation.fields.map(field => [field, { keyword: { searchable: true } }])) };
        else if (operation.kind === "evidence") data = rows.find(row => row._id === operation.id);
        else if (operation.kind === "live") {
          const proof = hits => ({ hits: { hits } });
          const accepted = { ...rows.at(-1), _id: "accepted-context", _source: { ...rows.at(-1)._source, "event.action": "accept", "event.outcome": "success", "destination.port": 49876, "source.geo.country_name": "Kazakhstan" } };
          data = { hits: { total: { value: rows.length, relation: "eq" }, hits: [] }, aggregations: operation.stage === "security"
            ? { authentication: { users: { buckets: [], sum_other_doc_count: 0 } }, signals: { doc_count: 0, proof: proof([]) } }
            : { sources: { sum_other_doc_count: 0, buckets: [{ key: "185.220.101.4", doc_count: operation.stage === "context" ? 1 : 120, doc_count_error_upper_bound: 0,
              ports: { buckets: [{ key: 22, doc_count: 120 }] }, targets: { buckets: Array.from({ length: 10 }, (_, i) => ({ key: `10.0.0.${i + 1}`, doc_count: 12 })) },
              proof: proof(operation.stage === "context" ? [accepted] : rows.slice(-5)) }] } } };
        }
        else {
          if (!pits.delete(operation.body.pit.id)) throw new Error("Paging did not use an owned, current snapshot ID");
          const id = newPit(); pits.add(id); window.fixtureRotations++;
          const start = operation.body.search_after ? operation.body.search_after[1] + 1 : 0;
          data = { pit_id: id, hits: { total: { value: rows.length, relation: "eq" }, hits: rows.slice(start, start + operation.body.size) } };
        }
      }
      window.postMessage({ source: "soc-watch-content", message: { type: "soc-watch.response", response: { version: 1, requestId: request.requestId, success: true, data } } }, window.location.origin);
    });
  });
  await page.goto(`${origin}/#server-agent`);
  await page.getByLabel("Server access token").fill(token);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await page.getByText("Collection paused", { exact: true }).first().waitFor();
  assert.equal(await page.getByRole("button", { name: "Scan", exact: true }).isDisabled(), true);
  await page.screenshot({ path: resolve(data, "desktop-disconnected.png"), fullPage: true });
  await page.getByRole("button", { name: "Connect this browser", exact: true }).click();
  await page.getByRole("button", { name: "Review Agent Settings", exact: true }).waitFor();
  assert.equal(await page.getByRole("button", { name: "Disconnect browser", exact: true }).count(), 0);
  assert.equal(await page.getByText("Reconnecting automatically.", { exact: false }).count(), 0);
  assert.equal(await page.getByRole("button", { name: "Scan", exact: true }).isDisabled(), true);
  await page.screenshot({ path: resolve(data, "desktop-settings-error.png"), fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: resolve(data, "mobile-settings-error.png"), fullPage: true });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, "Mobile settings-error overflow");
  await page.getByRole("button", { name: "Review Agent Settings", exact: true }).click();
  await page.getByRole("button", { name: "Load Kibana data views", exact: true }).click();
  await page.getByLabel("Kibana data view", { exact: true }).selectOption("logs-view");
  await page.getByLabel("Timestamp field", { exact: true }).waitFor();
  await page.waitForFunction(() => [...document.querySelectorAll("input")].some(input => input.value === "event.created"));
  assert.equal(await page.getByLabel("Index pattern", { exact: true }).inputValue(), "logs-network-*");
  const unsaved = await page.evaluate(async () => (await (await fetch("/api/agent/state")).json()).config);
  assert.equal(unsaved.indexPattern, "logs-*");
  assert.equal(unsaved.timestampField, "@timestamp");
  assert.equal(await page.evaluate(() => window.fixtureConnections), 1, "Settings failures must not loop");
  await page.screenshot({ path: resolve(data, "mobile-data-view.png"), fullPage: true });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, "Mobile data-view overflow");
  await page.getByRole("button", { name: "Save settings", exact: true }).click();
  await waitState(state => state.config.indexPattern === "logs-network-*" && state.config.timestampField === "event.created");
  await page.evaluate(() => { window.fixtureSettingsError = false; window.fixturePermissionError = true; });
  await page.getByRole("button", { name: "Findings", exact: true }).click();
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.getByRole("button", { name: "Connect this browser", exact: true }).click();
  await page.getByText("Elasticsearch rejected the request to open a log snapshot", { exact: false }).waitFor();
  assert.equal(await page.getByRole("button", { name: "Scan", exact: true }).isDisabled(), true);
  assert.equal(await page.getByRole("button", { name: "Disconnect browser", exact: true }).count(), 0);
  assert.equal((await page.evaluate(async () => (await (await fetch("/api/agent/state")).json()))).status.dataSource.ready, false);
  await page.screenshot({ path: resolve(data, "desktop-permission-denied.png"), fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: resolve(data, "mobile-permission-denied.png"), fullPage: true });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, "Mobile permission-denial overflow");
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.evaluate(() => { window.fixturePermissionError = false; });
  await page.evaluate(async () => {
    const state = await (await fetch("/api/agent/state")).json();
    const save = await fetch("/api/agent/config", { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ ...state.config, pageSize: 100, autoInvestigate: false }) });
    if (!save.ok) throw new Error(await save.text());
    const rule = await fetch("/api/agent/rules", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ name: "Relay watch", indicatorType: "ip", indicatorValue: "185.220.101.4", minPriority: 0, minEvents: 1, channels: [] }) });
    if (!rule.ok) throw new Error(await rule.text());
  });
  await page.getByRole("button", { name: "Refresh state", exact: true }).click();
  await page.getByRole("button", { name: "Connect this browser", exact: true }).click();
  await page.getByText("This browser connected", { exact: true }).waitFor();
  await page.getByRole("button", { name: "Delivery", exact: true }).click();
  await page.getByRole("button", { name: "Enable notifications", exact: true }).click();
  assert.equal(await page.evaluate(() => Notification.permission), "granted");
  await page.getByRole("button", { name: "Findings", exact: true }).click();
  await page.getByLabel("Scan mode", { exact: true }).selectOption("today");
  await page.getByRole("button", { name: "Scan", exact: true }).click();
  await waitState(state => state.runs.some(run => run.status === "complete"));
  await page.getByRole("button", { name: "Refresh state", exact: true }).click();
  await page.getByRole("button", { name: "Watched indicator observed: Relay watch", exact: true }).first().waitFor();
  const before = await page.evaluate(async () => (await (await fetch("/api/agent/state")).json()));
  assert.equal(before.runs[0].eventsRead, 120); assert.ok(before.alerts.length > 0);
  assert.ok(await page.evaluate(() => window.fixtureRotations >= 2), "Large snapshot IDs must rotate during pagination");
  assert.ok(await page.evaluate(() => window.fixtureClosedPits >= 2), "Rotated snapshots must be closed after collection and watch checks");
  await page.getByLabel("Scan mode", { exact: true }).selectOption("live");
  await page.getByRole("button", { name: "Scan", exact: true }).click();
  await waitState(state => state.status.live.lastSuccess && state.runs.some(run => run.mode === "live_detection" && run.status === "complete"));
  await page.getByRole("button", { name: "Refresh state", exact: true }).click();
  const fresh = await page.evaluate(async () => (await (await fetch("/api/agent/state")).json()));
  assert.equal(fresh.status.live.evidenceRead, 6);
  const probing = fresh.findings.find(finding => finding.category === "scan");
  assert.equal(probing.activity, undefined, "Overview must not repeat full evidence details");
  assert.equal(detailRequests.length, 0, "Detailed findings must load only on inspection");
  await page.waitForFunction(() => window.fixtureNotifications.some(item => item.title === "Active probing with accepted network activity"));
  const notification = await page.evaluate(() => window.fixtureNotifications.find(item => item.title === "Active probing with accepted network activity"));
  assert.match(notification.body, /edge-/); assert.match(notification.body, /Kazakhstan/); assert.match(notification.body, /accept/);
  await page.getByRole("button", { name: "Active probing with accepted network activity", exact: true }).click();
  await page.getByRole("heading", { name: "Observed activity", exact: true }).waitFor();
  const detail = await page.evaluate(async id => (await (await fetch(`/api/agent/findings/${encodeURIComponent(id)}`)).json()), probing.id);
  assert.equal(detail.finding.activity.allowed[0].action, "accept");
  assert.deepEqual(detail.finding.activity.countries, ["Kazakhstan"]);
  const proofId = detail.finding.evidence[0].eventId;
  await page.getByRole("button", { name: `Inspect event ${proofId}`, exact: true }).click();
  await page.getByRole("heading", { name: `Raw event: ${proofId}`, exact: true }).waitFor();
  await page.waitForFunction(() => document.querySelector(".sa-raw-event pre")?.textContent.includes("source.ip"));
  await page.screenshot({ path: resolve(data, "desktop-live-evidence.png"), fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: resolve(data, "mobile-live-evidence.png"), fullPage: true });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, "Mobile live-evidence overflow");
  await page.getByRole("button", { name: "Close dialog", exact: true }).click();
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.screenshot({ path: resolve(data, "desktop-connected.png"), fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: resolve(data, "mobile-connected.png"), fullPage: true });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, "Mobile page overflow");
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.evaluate(() => { window.fixtureGtiConfigured = true; });
  const scored = await waitState(state => state.findings.some(finding => finding.reputation?.status === "scored"));
  assert.equal(scored.reputation.source, "browser");
  assert.ok(scored.findings.some(finding => finding.reputation?.gtiVerdict === "VERDICT_MALICIOUS"), "Browser GTI assessment must enrich a real worker finding");
  await page.evaluate(() => { window.fixtureAuthenticated = false; });
  await page.getByRole("button", { name: "Scan", exact: true }).click();
  await waitState(state => state.status.paused);
  await page.getByRole("button", { name: "Refresh state", exact: true }).click();
  await page.getByText("Collection paused", { exact: true }).first().waitFor();
  assert.equal(await page.getByRole("button", { name: "Scan", exact: true }).isDisabled(), true);
  await page.screenshot({ path: resolve(data, "authentication-lost.png"), fullPage: true });
  await page.evaluate(() => { window.fixtureAuthenticated = true; });
  await waitState(state => state.status.dataSource.ready && state.runs.filter(run => run.status === "complete").length >= 3, 45000);
  const after = await page.evaluate(async () => (await (await fetch("/api/agent/state")).json()));
  assert.equal(after.findings.find(f => f.category === "watched_indicator").count, before.findings.find(f => f.category === "watched_indicator").count);
  // Scope changes need fresh consent, rather than silently broadening browser access.
  await waitState(state => !state.status.running && !state.status.live.running && state.status.dataSource.ready);
  await page.evaluate(async () => {
    const saved = await fetch("/api/agent/config", { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ indexPattern: "logs-network-default" }) });
    if (!saved.ok) throw new Error(await saved.text());
  });
  await page.getByRole("button", { name: "Refresh state", exact: true }).click();
  await page.getByRole("button", { name: "Connect this browser", exact: true }).waitFor();
  assert.equal((await page.evaluate(async () => (await (await fetch("/api/agent/state")).json()))).status.dataSource.ready, false);
  await page.getByRole("button", { name: "Integrations", exact: true }).click();
  await page.getByLabel("ThreatFox Auth-Key", { exact: true }).fill("fixture-threatfox-secret");
  await page.getByLabel("MalwareBazaar Auth-Key", { exact: true }).fill("fixture-malwarebazaar-secret");
  await page.getByRole("button", { name: "Save server keys", exact: true }).click();
  await page.getByText("Server integration keys saved.", { exact: false }).waitFor();
  const saved = await waitState(state => state.integrations.threatfox.configured && state.integrations.malwarebazaar.configured);
  assert.equal(JSON.stringify(saved).includes("fixture-threatfox-secret"), false, "API must never echo integration credentials");
  assert.equal(await page.getByLabel("ThreatFox Auth-Key", { exact: true }).inputValue(), "");
  await page.screenshot({ path: resolve(data, "desktop-integrations.png"), fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: resolve(data, "mobile-integrations.png"), fullPage: true });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, "Mobile integration form overflow");
  await page.reload();
  await page.getByRole("button", { name: "Integrations", exact: true }).click();
  await page.getByLabel("Remove saved threatfox key", { exact: true }).waitFor();
  await page.getByText("GTI / VirusTotal (relay offline)", { exact: true }).waitFor();
  assert.equal(await page.getByLabel("ThreatFox Auth-Key", { exact: true }).inputValue(), "");
  assert.equal(await page.getByLabel("ThreatFox Auth-Key", { exact: true }).getAttribute("placeholder"), "Saved; leave blank to keep");
  assert.equal(await page.evaluate(() => JSON.stringify(localStorage).includes("fixture-threatfox-secret")), false);
  await page.getByRole("button", { name: "Findings", exact: true }).click();
  await page.getByLabel("Finding time scope", { exact: true }).selectOption("retained");
  let failDetails = true, delayDetails = true;
  await page.route("**/api/agent/findings/retained-0", async route => {
    if (failDetails) return route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ error: "Fixture detail temporarily unavailable" }) });
    if (delayDetails) { delayDetails = false; await new Promise(resolve => setTimeout(resolve, 11000)); }
    return route.continue();
  });
  await page.getByRole("button", { name: "Retained fixture finding 0", exact: true }).click();
  await page.getByText("Fixture detail temporarily unavailable", { exact: true }).waitFor();
  assert.equal(await page.getByText("State refresh failed", { exact: false }).count(), 0, "Detail failures must not break state refresh");
  failDetails = false;
  await page.getByRole("button", { name: "Retry details", exact: true }).click();
  await page.getByText("Retained fixture investigation briefing", { exact: true }).waitFor();
  await page.getByRole("heading", { name: "Proof references", exact: true }).waitFor();
  failDetails = true;
  await page.getByLabel("Add audit note", { exact: true }).fill("Unsaved review survives refresh");
  await page.getByText("Detail refresh failed. Showing previously loaded details. Fixture detail temporarily unavailable", { exact: true }).waitFor();
  assert.equal(await page.getByLabel("Add audit note", { exact: true }).inputValue(), "Unsaved review survives refresh");
  assert.equal(await page.getByText("Retained fixture investigation briefing", { exact: true }).count(), 1);
  failDetails = false;
  await page.getByRole("button", { name: "Retry details", exact: true }).click();
  await page.getByText("Detail refresh failed.", { exact: false }).waitFor({ state: "hidden" });
  await page.getByLabel("Add audit note", { exact: true }).fill("Browser retained-detail regression note");
  await page.getByRole("button", { name: "Save disposition", exact: true }).click();
  await page.getByText("Finding updated.", { exact: true }).waitFor();
  const retainedDetail = await page.evaluate(async () => (await (await fetch("/api/agent/findings/retained-0")).json()));
  assert.equal(retainedDetail.finding.notes.length, 100); assert.equal(retainedDetail.finding.notes.at(-1).text, "Browser retained-detail regression note");
  await page.screenshot({ path: resolve(data, "mobile-retained-details.png"), fullPage: true });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, "Mobile retained-detail overflow");
  await page.getByRole("button", { name: "Close dialog", exact: true }).click();
  assert.ok(stateSizes.length > 5 && stateSizes.every(size => size > 0 && size < 8 * 1024 * 1024), `State responses must stay bounded: ${stateSizes}`);
  assert.deepEqual(errors, []);
  console.log(`Browser relay regression passed: desktop/mobile, oversized retained-history overview, on-demand details, detail retry and disposition, raw proof, integration persistence/privacy, browser GTI enrichment, bounded fresh detection with accepted-event context, instrumented browser notifications, settings/permission failures, explicit data-view selection, large/rotated snapshot pagination, watch alert, auth loss and automatic recovery. Maximum state bytes: ${Math.max(...stateSizes)}. Screenshots: ${data}`);
} catch (error) {
  await page?.screenshot({ path: resolve(data, "failure.png"), fullPage: true }).catch(() => {});
  console.error(`Browser test failure screenshot: ${data}`);
  throw error;
} finally {
  await browser?.close();
  server.kill();
  if (server.exitCode === null) await new Promise(resolve => server.once("exit", resolve));
}
