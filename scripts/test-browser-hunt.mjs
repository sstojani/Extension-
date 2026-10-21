import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdir, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

// Production web UI with a deterministic bridge fixture; real ELK is not contacted.
const { chromium } = await import(process.env.SOC_WATCH_PLAYWRIGHT_MODULE || "playwright");
const root = fileURLToPath(new URL("..", import.meta.url));
const version = JSON.parse(await readFile(resolve(root, "package.json"), "utf8")).version;
const artifacts = resolve(root, ".data", `hunt-browser-${Date.now()}`);
await mkdir(artifacts, { recursive: true });
const port = process.env.SOC_WATCH_TEST_PORT || "5198", origin = `http://127.0.0.1:${port}`;
const server = spawn(process.execPath, ["scripts/serve-web.mjs"], { cwd: root, windowsHide: true, stdio: "pipe", env: {
  ...process.env, SOC_WATCH_HOST: "127.0.0.1", SOC_WATCH_PORT: port, SOC_WATCH_SERVER_AGENT: "false"
} });
let output = "", browser, page;
server.stdout.on("data", chunk => { output += chunk; });
server.stderr.on("data", chunk => { output += chunk; });
try {
  let ready = false;
  for (let i = 0; i < 100; i++) {
    if (server.exitCode !== null) throw new Error(output);
    try { if ((await fetch(origin)).ok) { ready = true; break; } } catch { /* Wait for startup. */ }
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  assert.ok(ready, "Production server must start");
  browser = await chromium.launch({ headless: true });
  page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  const errors = [];
  page.on("pageerror", error => errors.push(error.message));
  await page.addInitScript(({ version }) => {
    window.huntRequests = [];
    window.huntFixtureMode = "success";
    window.huntConfigReads = 0;
    window.huntSavedPolicy = null;
    window.huntPending = null;
    window.huntFixtureCoverage = null;
    window.huntFixtureCampaignId = null;
    const post = message => window.postMessage({ source: "soc-watch-content", message }, location.origin);
    window.huntSnapshot = () => post({ type: "soc-watch.snapshot", snapshot: {
      state: "connected", updatedAt: new Date().toISOString(), kibana: { overall: "available" }, fleet: { online: 31, offline: 1, error: 0, inactive: 0 }, agents: []
    } });
    const success = (request, data) => post({ type: "soc-watch.response", response: { version: 1, requestId: request.requestId, success: true, data } });
    const fail = (request, message, details) => post({ type: "soc-watch.response", response: { version: 1, requestId: request.requestId, success: false,
      error: { code: "INVALID_REQUEST", message, details } } });
    window.addEventListener("message", event => {
      if (event.source !== window || event.data?.source !== "soc-watch-web") return;
      const request = event.data.message;
      if (request?.type === "soc-watch.hello") {
        post({ type: "soc-watch.relay-ready", extensionId: "abcdefghijklmnopabcdefghijklmnop", extensionName: "SOC Watch Bridge", extensionVersion: version });
        setTimeout(window.huntSnapshot, 0);
        return;
      }
      if (!request?.action) return;
      if (request.action === "config.get") { window.huntConfigReads++; success(request, { extensionVersion: version, threatRadarAgent: {
        enabled: false, intervalMinutes: 5, indexPattern: "logs-original-*", timestampField: "event.created", historyRetentionHours: 24
      }, threatRadarAgentState: {} }); }
      else if (request.action === "threatRadar.agent.configure") {
        window.huntSavedPolicy = request.params; success(request, { config: request.params, state: {} });
      }
      else if (request.action === "dataViews.list") success(request, [
        { id: "metrics", name: "Metrics", title: "metrics-*", timeFieldName: "@timestamp" },
        { id: "network", name: "Network", title: "logs-network-*", timeFieldName: "event.ingested" }
      ]);
      else if (request.action === "threatIntel.dailyHunt") {
        window.huntRequests.push(request.params);
        if (window.huntFixtureMode === "changed") {
          fail(request, "IOC hunt query does not match the saved campaign. The index, time field or time range changed. Start a Fresh Scan.", { huntRecovery: "fresh_scan" }); return;
        }
        if (window.huntFixtureMode === "stale") {
          fail(request, "IOC hunt offset does not match campaign progress. Retry offset 500, or start a Fresh Scan.", { huntRecovery: "retry", nextBatchOffset: 500 }); return;
        }
        const failed = window.huntFixtureMode === "search_failure";
        const offset = request.params.batchOffset;
        const group = request.params.indicatorGroup;
        if (!request.params.resumeCampaign || !window.huntFixtureCoverage) {
          window.huntFixtureCampaignId = crypto.randomUUID();
          window.huntFixtureCoverage = Object.fromEntries(Object.entries({ all: 3102, ip: 1500, domain: 1001, hash: 601, url: 0 }).map(([key, count]) =>
            [key, { totalAvailable: count, checked: 0, excluded: 0, nextBatchOffset: 0, hasMore: count > 0 }]));
        }
        const queue = window.huntFixtureCoverage[group], count = Math.min(500, queue.totalAvailable - offset);
        if (!failed) Object.assign(queue, { checked: offset + count, nextBatchOffset: offset + count, hasMore: offset + count < queue.totalAvailable });
        const data = { campaignId: window.huntFixtureCampaignId, indicatorGroup: group, coverage: structuredClone(window.huntFixtureCoverage), stats: { totalAvailable: 3102 },
          providers: [{ name: "Fixture feed", status: "healthy", collected: 3102, checked: failed ? 0 : count, matched: failed ? 0 : 1, byType: { ip: 1500, domain: 1001, sha256: 601 } }],
          collected: count, hunted: failed ? 0 : count, matched: failed ? 0 : 1, siemEvents: failed ? 0 : 7, batchNumber: offset / 500 + 1,
          batchOffset: offset, batchSize: count, totalAvailable: queue.totalAvailable, nextBatchOffset: queue.nextBatchOffset,
          hasMore: queue.hasMore, alertsCreated: 0, notificationsSent: 0, notificationsFailed: 0,
          ...(failed ? { error: "IOC hunt search failed or returned partial results. Retry this batch." } : {}),
          results: Array.from({ length: count }, (_, i) => {
            const value = group === "ip" ? `203.0.${Math.floor((offset + i) / 256)}.${(offset + i) % 256}`
              : group === "domain" ? `ioc-${offset + i}.example.test` : (offset + i + 1).toString(16).padStart(64, "0");
            return { ioc: { original: value, normalized: value, type: group === "hash" ? "sha256" : group,
              sources: ["Fixture feed"], sourceCount: 1, riskScore: 80, riskLevel: "high", riskReasons: [] }, total: !failed && i === 0 ? 7 : 0,
              hits: !failed && i === 0 ? [{ index: request.params.indexPattern, timestamp: "2026-10-11T08:00:00Z", message: "Exact fixture match" }] : [],
              ...(failed ? { error: "Search incomplete" } : {}) };
          }) };
        if (window.huntFixtureMode === "delayed") window.huntPending = () => success(request, data);
        else success(request, data);
      } else success(request, {});
    });
  }, { version });
  await page.goto(origin);
  await page.getByRole("button", { name: "IOC Hunt", exact: true }).first().waitFor();
  await page.getByRole("button", { name: "IOC Hunt", exact: true }).first().click();
  await page.getByRole("button", { name: "Fresh Scan", exact: true }).click();
  await page.getByRole("button", { name: "Run Again", exact: true }).waitFor();
  let requests = await page.evaluate(() => window.huntRequests);
  assert.equal(requests[0].indexPattern, "logs-original-*");
  assert.equal(requests[0].timestampField, "event.created");
  assert.equal(requests[0].batchOffset, 0);
  assert.equal(requests[0].indicatorGroup, "ip");
  assert.equal(await page.getByRole("region", { name: "Current SOC Watch status" }).count(), 0, "Redundant connection tiles must be removed from IOC Hunt");
  await page.getByRole("button", { name: "Run Again", exact: true }).click();
  await page.waitForFunction(() => window.huntRequests.length === 2);
  await page.getByRole("button", { name: "Run Again", exact: true }).waitFor();
  assert.equal((await page.evaluate(() => window.huntRequests.at(-1))).batchOffset, 500);

  await page.getByRole("button", { name: /^Search Domains/ }).click();
  await page.getByRole("button", { name: "Run Again", exact: true }).waitFor();
  let request = await page.evaluate(() => window.huntRequests.at(-1));
  assert.deepEqual([request.indicatorGroup, request.batchOffset, request.from, request.to, request.resumeCampaign], ["domain", 0, requests[0].from, requests[0].to, true]);
  await page.getByRole("button", { name: /^Search Hashes/ }).click();
  await page.getByRole("button", { name: "Run Again", exact: true }).waitFor();
  request = await page.evaluate(() => window.huntRequests.at(-1));
  assert.deepEqual([request.indicatorGroup, request.batchOffset, request.from, request.to, request.campaignId], ["hash", 0, requests[0].from, requests[0].to, (await page.evaluate(() => window.huntRequests.at(-2))).campaignId]);
  assert.ok(await page.getByRole("button", { name: /^Search URLs/ }).isDisabled(), "Empty feed type must not claim a search");
  assert.equal(await page.locator(".compact-metrics .status").last().locator("strong").innerText(), "4", "Matches must accumulate across IP/domain/hash batches");
  await page.screenshot({ path: resolve(artifacts, "desktop-types.png"), fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: resolve(artifacts, "mobile-types.png"), fullPage: true });
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), "Type controls must fit mobile");
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.getByRole("button", { name: /^Search IPs/ }).click();
  await page.getByRole("button", { name: "Batch Complete", exact: true }).waitFor();
  assert.equal((await page.evaluate(() => window.huntRequests.at(-1))).batchOffset, 1000);
  assert.ok(await page.getByRole("button", { name: /^Search IPs/ }).isDisabled());
  assert.ok(await page.getByRole("button", { name: "Batch Complete", exact: true }).isDisabled());
  await page.getByRole("button", { name: /^Search Domains/ }).click();
  await page.getByRole("button", { name: "Run Again", exact: true }).waitFor();
  assert.equal((await page.evaluate(() => window.huntRequests.at(-1))).batchOffset, 500);

  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await page.getByRole("tab", { name: "Data Views", exact: true }).click();
  await page.getByRole("button", { name: "Load Data Views", exact: true }).click();
  await page.getByRole("button", { name: "Use logs-network-*", exact: true }).waitFor();
  assert.equal(await page.getByLabel("Selected index pattern").inputValue(), "logs-original-*");
  await page.getByRole("button", { name: "Use logs-network-*", exact: true }).click();
  assert.equal(await page.getByLabel("Query timestamp field").inputValue(), "event.ingested");
  const configReads = await page.evaluate(() => window.huntConfigReads);
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await page.waitForFunction(count => window.huntConfigReads > count, configReads);
  await page.getByRole("tab", { name: "Threat Radar Agent", exact: true }).click();
  await page.getByLabel("Scan interval").selectOption("15");
  await page.getByRole("button", { name: "Save Agent", exact: true }).click();
  await page.waitForFunction(() => window.huntSavedPolicy !== null);
  assert.equal((await page.evaluate(() => window.huntSavedPolicy)).timestampField, "event.ingested", "Unrelated policy changes must retain the selected query time field");
  await page.getByRole("button", { name: "IOC Hunt", exact: true }).first().click();
  await page.getByRole("button", { name: "Fresh Scan", exact: true }).click();
  await page.getByRole("button", { name: "Run Again", exact: true }).waitFor();
  requests = await page.evaluate(() => window.huntRequests);
  assert.deepEqual([requests.at(-1).indexPattern, requests.at(-1).timestampField, requests.at(-1).batchOffset], ["logs-network-*", "event.ingested", 0]);

  await page.evaluate(() => { window.huntFixtureMode = "changed"; });
  await page.getByRole("button", { name: "Run Again", exact: true }).click();
  const notice = page.getByRole("alert", { name: "IOC Hunt error" });
  await notice.waitFor();
  assert.match(await notice.innerText(), /Start a Fresh Scan/);
  assert.ok(await page.getByRole("button", { name: "Retry Batch", exact: true }).isDisabled());
  await page.evaluate(() => window.huntSnapshot());
  assert.ok(await notice.isVisible(), "Healthy connection updates must not erase hunt failures");
  assert.equal(await page.getByText("Kibana authentication required or bridge unavailable", { exact: true }).count(), 0);
  await page.screenshot({ path: resolve(artifacts, "desktop-error.png"), fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: resolve(artifacts, "mobile-error.png"), fullPage: true });
  assert.ok(await page.getByRole("button", { name: "Fresh Scan", exact: true }).isVisible());
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), "Mobile recovery must not overflow horizontally");

  await page.evaluate(() => { window.huntFixtureMode = "search_failure"; });
  await page.getByRole("button", { name: "Fresh Scan", exact: true }).click();
  await page.getByRole("button", { name: "Retry Batch", exact: true }).waitFor();
  assert.match(await page.locator(".hunt-batch-summary").innerText(), /0 IOCs checked/);
  await page.evaluate(() => { window.huntFixtureMode = "success"; });
  await page.getByRole("button", { name: "Retry Batch", exact: true }).click();
  await page.getByRole("button", { name: "Run Again", exact: true }).waitFor();
  const retry = await page.evaluate(() => window.huntRequests.at(-1));
  assert.equal(retry.batchOffset, 0); assert.equal(retry.resumeCampaign, true);
  assert.equal(await notice.count(), 0);

  await page.evaluate(() => { window.huntFixtureMode = "stale"; });
  await page.getByRole("button", { name: "Run Again", exact: true }).click();
  await notice.waitFor();
  await page.evaluate(() => { window.huntFixtureMode = "success"; });
  await page.getByRole("button", { name: "Retry Batch", exact: true }).click();
  await page.getByRole("button", { name: "Run Again", exact: true }).waitFor();
  assert.equal((await page.evaluate(() => window.huntRequests.at(-1))).batchOffset, 500);

  await page.evaluate(() => { window.huntFixtureMode = "delayed"; });
  await page.getByRole("button", { name: "Run Again", exact: true }).click();
  await page.waitForFunction(() => window.huntPending !== null);
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await page.getByRole("tab", { name: "Data Views", exact: true }).click();
  await page.getByRole("button", { name: "Use metrics-*", exact: true }).click();
  await page.getByRole("button", { name: "IOC Hunt", exact: true }).first().click();
  await page.evaluate(() => window.huntPending());
  await page.getByRole("region", { name: "Start IOC Hunt" }).waitFor();
  assert.equal(await page.getByRole("button", { name: "Restart Batches", exact: true }).count(), 0, "Superseded responses must not replace the new query");
  assert.deepEqual(errors, []);
  console.log(JSON.stringify({ passed: true, requests: (await page.evaluate(() => window.huntRequests)).length, artifacts }));
} catch (error) {
  await page?.screenshot({ path: resolve(artifacts, "failure.png"), fullPage: true }).catch(() => {});
  console.error(`Browser artifacts: ${artifacts}`);
  throw error;
} finally {
  await browser?.close();
  server.kill();
  await new Promise(resolve => { if (server.exitCode !== null) resolve(); else server.once("exit", resolve); });
}
