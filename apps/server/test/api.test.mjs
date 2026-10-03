import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { Store } from "../store.mjs";
import { createAgentApi } from "../api.mjs";

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
