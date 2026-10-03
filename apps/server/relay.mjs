import { randomUUID } from "node:crypto";
import { relaySourceSchema, validateRelayOperation, RELAY_MAX_BYTES } from "@soc-watch/protocol";

export class BrowserRelay {
  constructor({ clock = Date.now, ttl = 60000, timeout = 55000, queueTimeout = 120000 } = {}) {
    this.clock = clock; this.ttl = ttl; this.timeout = timeout; this.queueTimeout = queueTimeout; this.jobs = new Map(); this.lease = null;
  }
  status() {
    const ready = Boolean(this.lease && this.lease.expiresAt > this.clock());
    if (!ready && this.lease) this.disconnect(this.lease.session, this.lease.clientId);
    return { mode: "browser_relay", ready, source: this.lease?.source || null, lastSeen: this.lease?.lastSeen || null };
  }
  connect(session, clientId, source) {
    if (!/^[a-f0-9-]{36}$/i.test(clientId || "")) throw new Error("Invalid browser relay client ID.");
    source = relaySourceSchema.parse(source);
    this.status();
    if (this.lease && (this.lease.session !== session || this.lease.clientId !== clientId)) throw new Error("Another browser is providing the relay. Disconnect it or wait for its lease to expire.");
    this.lease = { session, clientId, source, expiresAt: this.clock() + this.ttl, lastSeen: new Date(this.clock()).toISOString() };
    return this.status();
  }
  require(session, clientId) {
    if (!this.status().ready || this.lease.session !== session || this.lease.clientId !== clientId) throw new Error("Browser relay lease expired or belongs to another session.");
    return this.lease;
  }
  poll(session, clientId) {
    const lease = this.require(session, clientId);
    lease.expiresAt = this.clock() + this.ttl; lease.lastSeen = new Date(this.clock()).toISOString();
    const queued = [...this.jobs.values()].filter(job => !job.assigned);
    const job = queued.find(job => job.operation.kind === "live") || queued[0];
    if (!job) return { job: null };
    job.assigned = true;
    clearTimeout(job.timer); job.timer = setTimeout(() => { this.jobs.delete(job.id); job.reject(new Error("Browser relay response timed out. Keep the work browser and Server Agent tab open.")); }, this.timeout);
    return { job: { id: job.id, operation: job.operation } };
  }
  result(session, clientId, body) {
    const lease = this.require(session, clientId);
    const job = this.jobs.get(body.id);
    if (!job?.assigned) throw new Error("Unknown, expired or completed relay job.");
    if (typeof body.success !== "boolean") throw new Error("Invalid relay result.");
    if (Buffer.byteLength(JSON.stringify(body)) > RELAY_MAX_BYTES) throw new Error("Relay result exceeds 8 MB.");
    lease.expiresAt = this.clock() + this.ttl; lease.lastSeen = new Date(this.clock()).toISOString();
    clearTimeout(job.timer); this.jobs.delete(job.id);
    if (body.success) job.resolve(body.data);
    else job.reject(Object.assign(new Error(typeof body.error === "string" ? body.error.slice(0, 1000) : "Browser relay read failed."), {
      code: ["KIBANA_FORBIDDEN", "KIBANA_AUTH_REQUIRED", "INVALID_REQUEST", "KIBANA_NOT_FOUND", "RESULT_TOO_LARGE"].includes(body.errorCode) ? body.errorCode : "KIBANA_UNREACHABLE"
    }));
    return { accepted: true };
  }
  disconnect(session, clientId) {
    if (!this.lease || this.lease.session !== session || clientId && this.lease.clientId !== clientId) return;
    this.lease = null;
    for (const job of this.jobs.values()) { clearTimeout(job.timer); job.reject(new Error("Browser relay disconnected. Collection is paused; the checkpoint was not advanced.")); }
    this.jobs.clear();
  }
  execute(operation, signal) {
    if (!this.status().ready) return Promise.reject(new Error("Browser relay disconnected. Connect an authenticated work browser first."));
    operation = validateRelayOperation(operation, this.lease.source.policy);
    if (this.jobs.size >= 8) return Promise.reject(new Error("Browser relay queue is full. Retry shortly."));
    return new Promise((resolve, reject) => {
      const id = randomUUID();
      const finish = (callback, value) => { signal?.removeEventListener("abort", abort); callback(value); };
      const abort = () => { const job = this.jobs.get(id); if (job) { clearTimeout(job.timer); this.jobs.delete(id); finish(reject, new Error("Browser relay operation cancelled.")); } };
      const timer = setTimeout(() => { this.jobs.delete(id); finish(reject, new Error("Browser relay queue timed out before assignment; coverage was not completed.")); }, this.queueTimeout);
      this.jobs.set(id, { id, operation, assigned: false, timer, resolve: value => finish(resolve, value), reject: error => finish(reject, error) });
      signal?.addEventListener("abort", abort, { once: true });
      if (signal?.aborted) abort();
    });
  }
}
