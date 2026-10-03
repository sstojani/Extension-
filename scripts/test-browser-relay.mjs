import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

// Real production web/API/worker with a deterministic extension transport fixture.
const { chromium } = await import(process.env.SOC_WATCH_PLAYWRIGHT_MODULE || "playwright");
const root = fileURLToPath(new URL("..", import.meta.url));
const data = resolve(root, ".data", `relay-browser-${Date.now()}`);
await mkdir(data, { recursive: true });
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
  await page.addInitScript(() => {
    window.fixtureAuthenticated = true;
    window.fixtureSettingsError = true;
    window.fixtureConnections = 0;
    window.fixturePermissionError = false;
    const rows = Array.from({ length: 120 }, (_, i) => ({ _id: `${i}`, _index: ".ds-logs-network-default-2026.10.02-000001",
      sort: [new Date(Date.now() - 60000).toISOString(), i], _source: { "@timestamp": new Date(Date.now() - 60000).toISOString(),
        "source.ip": "185.220.101.4", "destination.ip": `10.0.0.${i % 10 + 1}`, "destination.port": 22,
        "event.created": new Date(Date.now() - 60000).toISOString(), "event.action": "denied", "event.outcome": "failure", "observer.name": `edge-${i % 3}`, "host.name": "target" } }));
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
      else if (request.action === "agent.relay.disconnect") data = { disconnected: true };
      else if (request.action === "agent.relay.connect" && window.fixturePermissionError) {
        window.fixtureConnections++;
        window.postMessage({ source: "soc-watch-content", message: { type: "soc-watch.response", response: { version: 1, requestId: request.requestId,
          success: false, error: { code: "KIBANA_FORBIDDEN", message: "Elasticsearch rejected the request to open a log snapshot (HTTP 403; security_exception). Use a data view your account can read, or ask your ELK administrator to check its read permissions." } } } }, window.location.origin); return;
      }
      else if (!window.fixtureAuthenticated) {
        window.postMessage({ source: "soc-watch-content", message: { type: "soc-watch.response", response: { version: 1, requestId: request.requestId,
          success: false, error: { code: "KIBANA_AUTH_REQUIRED", message: "Kibana authentication is required." } } } }, window.location.origin); return;
      } else if (request.action === "agent.relay.connect") data = { relayId: crypto.randomUUID(), source: { kibanaBaseUrl: "https://kibana.internal:8888", spaceId: "default", policy: request.params } };
      else if (request.action === "agent.relay.heartbeat") data = { ready: true };
      else {
        const operation = request.params.operation;
        if (operation.kind === "openPit") data = { id: "fixture-pit" };
        else if (operation.kind === "closePit") data = { succeeded: true };
        else if (operation.kind === "fieldCaps") data = { fields: Object.fromEntries(operation.fields.map(field => [field, { keyword: { searchable: true } }])) };
        else if (operation.kind === "evidence") data = rows.find(row => row._id === operation.id);
        else {
          const start = operation.body.search_after ? operation.body.search_after[1] + 1 : 0;
          data = { hits: { total: { value: rows.length, relation: "eq" }, hits: rows.slice(start, start + operation.body.size) } };
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
  await page.getByRole("button", { name: "Scan", exact: true }).click();
  await waitState(state => state.runs.some(run => run.status === "complete"));
  await page.getByRole("button", { name: "Refresh state", exact: true }).click();
  await page.getByRole("button", { name: "Watched indicator observed: Relay watch", exact: true }).first().waitFor();
  const before = await page.evaluate(async () => (await (await fetch("/api/agent/state")).json()));
  assert.equal(before.runs[0].eventsRead, 120); assert.ok(before.alerts.length > 0);
  await page.screenshot({ path: resolve(data, "desktop-connected.png"), fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: resolve(data, "mobile-connected.png"), fullPage: true });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, "Mobile page overflow");
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.evaluate(() => { window.fixtureAuthenticated = false; });
  await page.getByRole("button", { name: "Scan", exact: true }).click();
  await waitState(state => state.status.paused);
  await page.getByRole("button", { name: "Refresh state", exact: true }).click();
  await page.getByText("Collection paused", { exact: true }).first().waitFor();
  assert.equal(await page.getByRole("button", { name: "Scan", exact: true }).isDisabled(), true);
  await page.screenshot({ path: resolve(data, "authentication-lost.png"), fullPage: true });
  await page.evaluate(() => { window.fixtureAuthenticated = true; });
  await waitState(state => state.status.dataSource.ready && state.runs.filter(run => run.status === "complete").length >= 2, 45000);
  const after = await page.evaluate(async () => (await (await fetch("/api/agent/state")).json()));
  assert.equal(after.findings.find(f => f.category === "watched_indicator").count, before.findings.find(f => f.category === "watched_indicator").count);
  // Scope changes need fresh consent, rather than silently broadening browser access.
  await waitState(state => !state.status.running && state.status.dataSource.ready);
  await page.evaluate(async () => {
    const saved = await fetch("/api/agent/config", { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ indexPattern: "logs-network-default" }) });
    if (!saved.ok) throw new Error(await saved.text());
  });
  await page.getByRole("button", { name: "Refresh state", exact: true }).click();
  await page.getByRole("button", { name: "Connect this browser", exact: true }).waitFor();
  assert.equal((await page.evaluate(async () => (await (await fetch("/api/agent/state")).json()))).status.dataSource.ready, false);
  assert.deepEqual(errors, []);
  console.log(`Browser relay regression passed: desktop/mobile, settings/permission failures, explicit data-view selection, paginated scan, watch alert, auth loss and automatic recovery. Screenshots: ${data}`);
} catch (error) {
  await page?.screenshot({ path: resolve(data, "failure.png"), fullPage: true }).catch(() => {});
  console.error(`Browser test failure screenshot: ${data}`);
  throw error;
} finally {
  await browser?.close();
  server.kill();
  if (server.exitCode === null) await new Promise(resolve => server.once("exit", resolve));
}
