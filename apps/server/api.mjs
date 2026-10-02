import { randomBytes, timingSafeEqual, randomUUID } from "node:crypto";
import { validateConfig } from "./config.mjs";
import { validateRule, validateNotifications } from "./alerts.mjs";

export function createAgentApi(worker, runtime, version = "0.14.0") {
  const sessions = new Map(), failures = new Map();
  const store = worker.store;
  if (runtime.token && runtime.token.length < 32) throw new Error("SOC_WATCH_AGENT_TOKEN must contain at least 32 characters.");
  if (!Array.isArray(runtime.analysts || []) || (runtime.analysts || []).some(a => typeof a.name !== "string" || typeof a.token !== "string" || a.token.length < 32)) throw new Error("Analyst tokens require a name and at least 32 random characters.");
  const equal = (a,b) => {
    const left = Buffer.from(a || ""), right = Buffer.from(b || "");
    return left.length === right.length && left.length > 0 && timingSafeEqual(left, right);
  };
  const cookie = request => /(?:^|;\s*)soc_watch_session=([a-f0-9]{64})(?:;|$)/.exec(request.headers.cookie || "")?.[1];
  const authenticated = request => {
    const id = cookie(request), session = sessions.get(id);
    if (session && session.expiration > Date.now()) return session;
    if (id) sessions.delete(id);
    return false;
  };
  return async function handle(request, response) {
    let url;
    try { url = new URL(request.url || "/", "http://localhost"); } catch { return false; }
    if (!url.pathname.startsWith("/api/agent/")) return false;
    const json = (status, body, headers = {}) => {
      response.writeHead(status, { "Content-Type": "application/json", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", ...headers });
      response.end(JSON.stringify(body)); return true;
    };
    const route = url.pathname.slice("/api/agent/".length);
    if (route === "status" && request.method === "GET") return json(200, { available: true, configured: worker.configured(), authenticated: Boolean(authenticated(request)), version,
      message: runtime.token ? undefined : "Server agent login is not configured. Set SOC_WATCH_AGENT_TOKEN in the protected service environment." });
    if (!["GET", "POST", "PUT", "PATCH", "DELETE"].includes(request.method)) return json(405, { error: "Method not allowed" });
    if (request.method !== "GET") {
      const expected = runtime.publicOrigin || `${request.socket.encrypted ? "https" : "http"}://${request.headers.host}`;
      if (request.headers.origin !== expected || request.headers["sec-fetch-site"] === "cross-site") return json(403, { error: "Same-origin requests are required. Set SOC_WATCH_PUBLIC_ORIGIN to your exact HTTPS console origin." });
      if (request.method !== "DELETE" && !String(request.headers["content-type"] || "").startsWith("application/json")) return json(415, { error: "JSON body required" });
    }
    try {
      if (route === "login" && request.method === "POST") {
        if (!runtime.token) return json(503, { error: "Server login is not configured." });
        const address = request.socket.remoteAddress;
        const attempts = failures.get(address) || { count: 0, reset: Date.now() + 60000 };
        if (attempts.reset < Date.now()) { attempts.count = 0; attempts.reset = Date.now() + 60000; }
        if (attempts.count >= 5) return json(429, { error: "Too many login attempts. Retry in one minute." });
        const body = await readBody(request);
        const analyst = (runtime.analysts || []).find(a => equal(body.token, a.token));
        const admin = typeof body.token === "string" && equal(body.token, runtime.token);
        if (!admin && !analyst) {
          attempts.count++; failures.set(address, attempts); if (failures.size > 10000) failures.clear();
          return json(401, { error: "Invalid server access token." });
        }
        for (const [key, value] of sessions) if (value.expiration < Date.now()) sessions.delete(key);
        if (sessions.size >= 1000) return json(503, { error: "Session capacity reached." });
        const session = randomBytes(32).toString("hex"); sessions.set(session, { expiration: Date.now() + 8 * 3600000, role: admin ? "admin" : "analyst", user: admin ? "administrator" : analyst.name });
        const secure = runtime.publicOrigin.startsWith("https:") || request.socket.encrypted;
        store.audit("session.login", { user: admin ? "administrator" : analyst.name });
        return json(200, { authenticated: true }, { "Set-Cookie": `soc_watch_session=${session}; HttpOnly; SameSite=Strict; Path=/api/agent; Max-Age=28800${secure ? "; Secure" : ""}` });
      }
      const session = authenticated(request);
      if (!session) return json(401, { error: "Server agent login required." });
      if (request.method !== "GET" && ["config", "notifications", "rules", "clear"].some(r => route === r || route.startsWith(`${r}/`)) && session.role !== "admin") return json(403, { error: "An administrator token is required to change policy, rules or delivery settings." });
      if (route === "logout" && request.method === "POST") { sessions.delete(cookie(request)); return json(200, { authenticated: false }, { "Set-Cookie": "soc_watch_session=; HttpOnly; SameSite=Strict; Path=/api/agent; Max-Age=0" }); }
      if (route === "state" && request.method === "GET") return json(200, { ...worker.state(), session: { role: session.role, user: session.user } });
      if (route === "investigate" && request.method === "POST") {
        const id = (await readBody(request)).findingId;
        if (!store.one("finding", id)) throw new Error("Finding not found.");
        store.record("investigation", { id, status: "pending" }); store.audit("investigation.requested", { id });
        void worker.tick(); return json(202, { queued: true });
      }
      if (route === "config" && request.method === "PUT") {
        const config = validateConfig({ ...worker.config(), ...await readBody(request) });
        store.set("config", config); store.audit("config.saved", config);
        return json(200, { config });
      }
      if (route === "scan" && request.method === "POST") {
        worker.request((await readBody(request)).mode);
        void worker.tick(); return json(202, { queued: true });
      }
      if (route === "rules" && request.method === "POST") {
        const rule = validateRule(await readBody(request));
        if (!store.one("rule", rule.id) && store.list("rule", 501).length >= 500) return json(400, { error: "Watch rule limit reached (500)." });
        store.record("rule", rule); store.audit("rule.saved", rule); return json(200, { rule });
      }
      if (route.startsWith("rules/") && request.method === "DELETE") {
        const id = decodeURIComponent(route.slice(6)); store.remove("rule", id); store.audit("rule.removed", { id }); return json(200, { removed: true });
      }
      if (route.startsWith("findings/") && request.method === "PATCH") {
        const id = decodeURIComponent(route.slice(9)), finding = store.one("finding", id);
        if (!finding) return json(404, { error: "Finding not found" });
        const body = await readBody(request);
        if (body.status && !["open", "acknowledged", "resolved", "false_positive"].includes(body.status)) throw new Error("Invalid finding status.");
        if (body.assignedTo !== undefined && (typeof body.assignedTo !== "string" || body.assignedTo.length > 200)) throw new Error("Invalid assignee.");
        if (body.note !== undefined && (typeof body.note !== "string" || body.note.length > 2000)) throw new Error("Invalid note.");
        if (body.status) finding.status = body.status;
        if (body.assignedTo !== undefined) finding.assignedTo = body.assignedTo;
        if (body.note) finding.notes = [...finding.notes, { text: body.note, at: new Date().toISOString() }].slice(-100);
        store.record("finding", finding); store.audit("finding.reviewed", { id, actor: session.user, ...body });
        return json(200, { finding });
      }
      if (route === "clear" && request.method === "POST") {
        if ((await readBody(request)).confirm !== true) throw new Error("Confirm clearing findings.");
        let count = 0;
        store.transaction(() => {
          for (const f of store.list("finding", 100000)) if (["open", "acknowledged"].includes(f.status)) { store.record("finding", { ...f, status: "resolved", clearedAt: new Date().toISOString() }); count++; }
          store.audit("findings.cleared", { count });
        });
        return json(200, { cleared: count });
      }
      if (route === "notifications" && request.method === "PUT") {
        const settings = validateNotifications(await readBody(request), store.get("notifications", { channels: [] }));
        store.set("notifications", settings); store.audit("notifications.saved", { channels: settings.channels.map(c => ({ id: c.id, type: c.type, enabled: c.enabled })) });
        if (settings.minPriority !== undefined) store.set("config", validateConfig({ ...worker.config(), autoAlertMinPriority: settings.minPriority }));
        return json(200, { saved: true });
      }
      if (route === "test" && request.method === "POST") {
        const body = await readBody(request);
        const selected = store.get("notifications", { channels: [] }).channels.find(c => c.id === body.channelId && c.enabled);
        if (!selected) throw new Error("Choose an enabled notification channel.");
        const alert = { id: randomUUID(), title: "Notification delivery test", indicator: "test", indicatorType: "test", priority: 0, severity: "low", reasons: ["User-requested delivery test"], createdAt: new Date().toISOString() };
        store.queueDelivery(alert, selected); void worker.tick(); return json(202, { queued: true });
      }
      if (route === "evidence" && request.method === "GET") {
        const index = url.searchParams.get("index"), id = url.searchParams.get("id");
        // Only fetch proof IDs already retained in a finding, never expose an arbitrary Elasticsearch proxy.
        if (!index || !id || !store.list("finding", 100000).some(f => f.evidence.some(e => e.index === index && e.eventId === id))) return json(403, { error: "Not an authorized evidence reference." });
        const event = await worker.elastic.evidence(index, id);
        return json(200, { event: event._source, index, id });
      }
      if (route === "evaluation" && request.method === "GET") return json(200, store.get("evaluation", { available: false, message: "Run npm run evaluate -w apps/server to execute the offline regression scenarios." }));
      return json(404, { error: "Unknown server agent endpoint" });
    } catch (error) { return json(error.status || 400, { error: error.message || "Request failed" }); }
  };
}

async function readBody(request) {
  let length = 0, chunks = [];
  for await (const chunk of request) {
    length += chunk.length;
    if (length > 1048576) { const error = new Error("Request too large (maximum 1 MB)."); error.status = 413; throw error; }
    chunks.push(chunk);
  }
  const result = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
  if (!result || typeof result !== "object" || Array.isArray(result)) throw new Error("JSON object required.");
  return result;
}
