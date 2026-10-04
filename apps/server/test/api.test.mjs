import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { Store } from "../store.mjs";
import { createAgentApi } from "../api.mjs";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Integrations } from "../integrations.mjs";

test("only administrators may persist integration keys; responses and audit never echo credentials", async t => {
  const dir = mkdtempSync(join(tmpdir(), "soc-watch-api-keys-")), store = new Store(":memory:");
  const runtime = { dataDir: dir, gtiKey: "", feeds: {}, token: "a".repeat(40), analysts: [{ name: "reviewer", token: "b".repeat(40) }], publicOrigin: "" };
  runtime.integrations = new Integrations(runtime);
  const worker = { store, configured: () => true, state: () => ({ integrations: runtime.integrations.status() }), tick: async () => {} };
  const api = createAgentApi(worker, runtime), server = createServer(async (req, res) => { await api(req, res); });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => { await new Promise(resolve => server.close(resolve)); store.close(); rmSync(dir, { recursive: true, force: true }); });
  const origin = `http://127.0.0.1:${server.address().port}`, base = `${origin}/api/agent`;
  const login = async token => (await fetch(`${base}/login`, { method: "POST", headers: { origin, "content-type": "application/json" }, body: JSON.stringify({ token }) })).headers.get("set-cookie").split(";")[0];
  const save = (cookie, body, requestOrigin = origin) => fetch(`${base}/integrations`, { method: "PUT", headers: { cookie, origin: requestOrigin, "content-type": "application/json" }, body: JSON.stringify(body) });
  assert.equal((await save("", { gti: "private-key" })).status, 401);
  assert.equal((await save(await login(runtime.analysts[0].token), { gti: "private-key" })).status, 403);
  const cookie = await login(runtime.token);
  assert.equal((await save(cookie, { gti: "private-key" }, "https://evil.com")).status, 403);
  const response = await save(cookie, { gti: "private-key", threatfox: "private-fox" }); assert.equal(response.status, 200);
  assert.ok(!(await response.text()).includes("private-")); assert.equal(runtime.gtiKey, "private-key");
  assert.equal((await save(cookie, { gti: "" })).status, 200); assert.equal(runtime.gtiKey, "private-key");
  const state = await (await fetch(`${base}/state`, { headers: { cookie } })).text(); assert.ok(!state.includes("private-"));
  const audit = store.db.prepare("SELECT body FROM audit WHERE action='integrations.saved'").all(); assert.ok(!JSON.stringify(audit).includes("private-"));
  assert.equal((await save(cookie, { remove: ["gti"] })).status, 200); assert.equal(runtime.gtiKey, "");
});

test("API fails closed: login, cookie authentication, CSRF and redacted runtime secrets", async () => {
  const store = new Store(":memory:");
  let cancelled = 0;
  const worker = { store, configured: () => true, state: () => ({ secret: false }), config: () => ({}), cancelScan: () => { cancelled++; }, tick: async () => {} };
  const runtime = { token: "a".repeat(40), analysts: [{ name: "reviewer", token: "b".repeat(40) }], publicOrigin: "" };
  const api = createAgentApi(worker, runtime);
  const server = createServer(async (req,res) => { if (!await api(req,res)) { res.statusCode = 404; res.end(); } });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${server.address().port}/api/agent`, origin = base.replace("/api/agent", "");
  try {
    assert.equal((await fetch(`${base}/state`)).status, 401);
    const status = await (await fetch(`${base}/status`)).json(); assert.equal(status.authenticated, false); assert.equal(JSON.stringify(status).includes(runtime.token), false);
    assert.equal((await fetch(`${base}/login`, { method: "POST", headers: { "content-type": "application/json", origin: "https://evil.com" }, body: JSON.stringify({ token: runtime.token }) })).status, 403);
    const login = await fetch(`${base}/login`, { method: "POST", headers: { "content-type": "application/json", origin }, body: JSON.stringify({ token: runtime.token }) });
    assert.equal(login.status, 200); const cookie = login.headers.get("set-cookie").split(";")[0];
    assert.match(login.headers.get("set-cookie"), /HttpOnly; SameSite=Strict/);
    assert.equal((await fetch(`${base}/state`, { headers: { cookie } })).status, 200);
    assert.equal((await fetch(`${base}/config`, { method: "PUT", headers: { cookie, "content-type": "application/json", origin: "https://evil.com" }, body: "{}" })).status, 403);
    const cancel = (session, body) => fetch(`${base}/scan/cancel`, { method: "POST", headers: { cookie: session, "content-type": "application/json", origin }, body: JSON.stringify(body) });
    assert.equal((await cancel(cookie, {})).status, 400); assert.equal(cancelled, 0);
    assert.equal((await cancel(cookie, { confirm: true })).status, 202); assert.equal(cancelled, 1);
    const analyst = await fetch(`${base}/login`, { method: "POST", headers: { "content-type": "application/json", origin }, body: JSON.stringify({ token: runtime.analysts[0].token }) });
    assert.equal((await cancel(analyst.headers.get("set-cookie").split(";")[0], { confirm: true })).status, 403); assert.equal(cancelled, 1);
  } finally { await new Promise(resolve => server.close(resolve)); store.close(); }
});
