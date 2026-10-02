import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { randomUUID } from "node:crypto";
import { eventIndicators } from "./intelligence.mjs";

export class Store {
  constructor(path) {
    if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    this.db = new DatabaseSync(path);
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, body TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, body TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS event_time ON events(timestamp);
      CREATE TABLE IF NOT EXISTS event_indicators (type TEXT NOT NULL, value TEXT NOT NULL, event TEXT NOT NULL, PRIMARY KEY(type,value,event));
      CREATE TABLE IF NOT EXISTS records (kind TEXT NOT NULL, id TEXT NOT NULL, updated TEXT NOT NULL, body TEXT NOT NULL, PRIMARY KEY(kind,id));
      CREATE INDEX IF NOT EXISTS record_kind_time ON records(kind,updated);
      CREATE TABLE IF NOT EXISTS finding_events (finding TEXT NOT NULL, event TEXT NOT NULL, PRIMARY KEY(finding,event));
      CREATE TABLE IF NOT EXISTS scan_events (scan TEXT NOT NULL, event TEXT NOT NULL, PRIMARY KEY(scan,event));
      CREATE TABLE IF NOT EXISTS reputations (key TEXT PRIMARY KEY, type TEXT NOT NULL, value TEXT NOT NULL, status TEXT NOT NULL, next TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, body TEXT NOT NULL, last_seen TEXT NOT NULL DEFAULT '');
      CREATE TABLE IF NOT EXISTS deliveries (id TEXT PRIMARY KEY, status TEXT NOT NULL, next TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, body TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, action TEXT NOT NULL, body TEXT NOT NULL);`);
    if (!this.db.prepare("PRAGMA table_info(reputations)").all().some(c => c.name === "last_seen")) this.db.exec("ALTER TABLE reputations ADD COLUMN last_seen TEXT NOT NULL DEFAULT ''");
  }
  get(key, fallback = null) { const row = this.db.prepare("SELECT body FROM kv WHERE key=?").get(key); return row ? JSON.parse(row.body) : fallback; }
  set(key, body) { this.db.prepare("INSERT INTO kv VALUES (?,?) ON CONFLICT(key) DO UPDATE SET body=excluded.body").run(key, JSON.stringify(body)); }
  transaction(fn) { this.db.exec("BEGIN IMMEDIATE"); try { const result = fn(); this.db.exec("COMMIT"); return result; } catch (error) { this.db.exec("ROLLBACK"); throw error; } }
  record(kind, body) {
    const id = body.id || randomUUID();
    const result = { ...body, id };
    this.db.prepare("INSERT INTO records VALUES (?,?,?,?) ON CONFLICT(kind,id) DO UPDATE SET updated=excluded.updated,body=excluded.body").run(kind, id, new Date().toISOString(), JSON.stringify(result));
    return result;
  }
  one(kind, id) { const row = this.db.prepare("SELECT body FROM records WHERE kind=? AND id=?").get(kind, id); return row ? JSON.parse(row.body) : null; }
  list(kind, limit = 1000) { return this.db.prepare("SELECT body FROM records WHERE kind=? ORDER BY updated DESC LIMIT ?").all(kind, limit).map(row => JSON.parse(row.body)); }
  remove(kind, id) { this.db.prepare("DELETE FROM records WHERE kind=? AND id=?").run(kind, id); }
  audit(action, body) { this.db.prepare("INSERT INTO audit(timestamp,action,body) VALUES (?,?,?)").run(new Date().toISOString(), action, JSON.stringify(body)); }
  addEvents(events) {
    const insert = this.db.prepare("INSERT OR IGNORE INTO events VALUES (?,?,?)");
    const indicator = this.db.prepare("INSERT OR IGNORE INTO event_indicators VALUES (?,?,?)");
    let added = 0;
    for (const event of events) {
      const key = JSON.stringify([event.index, event.id]);
      added += Number(insert.run(key, event.timestamp, JSON.stringify(event)).changes);
      for (const [type, values] of eventIndicators(event)) {
        for (const value of values.filter(Boolean)) indicator.run(type, value.toLowerCase(), key);
      }
    }
    return added;
  }
  events(from, to, limit = 100000) { return this.db.prepare("SELECT body FROM events WHERE timestamp>=? AND timestamp<=? ORDER BY timestamp DESC LIMIT ?").all(from, to, limit).map(row => JSON.parse(row.body)).reverse(); }
  indicatorEvents(keys, limit = 10001) {
    if (!keys.length) return [];
    const clauses = keys.map(() => "(i.type=? AND i.value=?)").join(" OR ");
    const params = keys.flatMap(key => { const split = key.indexOf("|"); return [key.slice(0, split), key.slice(split + 1)]; });
    return this.db.prepare(`SELECT DISTINCT e.id,e.timestamp,e.body FROM events e JOIN event_indicators i ON i.event=e.id WHERE ${clauses} ORDER BY e.timestamp DESC LIMIT ?`).all(...params, limit).map(row => JSON.parse(row.body)).reverse();
  }
  addScanEvents(scan, events) {
    const insert = this.db.prepare("INSERT OR IGNORE INTO scan_events VALUES (?,?)");
    let added = 0;
    for (const event of events) added += Number(insert.run(scan, JSON.stringify([event.index, event.id])).changes);
    return added;
  }
  upsertFinding(finding) {
    const old = this.one("finding", finding.fingerprint);
    const evidence = [...new Map([...(old?.evidence || []), ...finding.evidence].map(e => [`${e.index}|${e.eventId}`, e])).values()].slice(-50);
    const newer = !old || finding.lastSeen > old.lastSeen;
    const reopens = newer && ["resolved", "false_positive"].includes(old?.status);
    const eventKeys = finding.eventKeys || finding.evidence.map(e => JSON.stringify([e.index, e.eventId]));
    const link = this.db.prepare("INSERT OR IGNORE INTO finding_events VALUES (?,?)");
    for (const key of eventKeys) link.run(finding.fingerprint, key);
    const count = this.db.prepare("SELECT COUNT(*) AS count FROM finding_events WHERE finding=?").get(finding.fingerprint).count;
    const { eventKeys: omitted, ...details } = finding;
    return this.record("finding", {
      ...old, ...details, id: finding.fingerprint, evidence,
      firstSeen: old?.firstSeen < finding.firstSeen ? old.firstSeen : finding.firstSeen,
      lastSeen: old?.lastSeen > finding.lastSeen ? old.lastSeen : finding.lastSeen,
      count, observedEvents: finding.count || finding.events,
      status: reopens ? "open" : old?.status || "open", assignedTo: old?.assignedTo || "", notes: old?.notes || [],
      reopened: reopens, updatedAt: new Date().toISOString()
    });
  }
  queueReputation(type, value, now = new Date().toISOString()) {
    const key = `${type}|${value.toLowerCase()}`;
    this.db.prepare("INSERT INTO reputations(key,type,value,status,next,body,last_seen) VALUES (?,?,?,'pending',?,?,?) ON CONFLICT(key) DO UPDATE SET last_seen=excluded.last_seen").run(key, type, value, now, JSON.stringify({ verdict: "unknown", status: "pending" }), now);
  }
  reputationMap() {
    return Object.fromEntries(this.db.prepare("SELECT key,body FROM reputations").all().map(row => [row.key, JSON.parse(row.body)]));
  }
  reputationJobs(now, limit = 10) { return this.db.prepare("SELECT * FROM reputations WHERE next<=? ORDER BY next LIMIT ?").all(now, limit).map(row => ({ ...row, body: JSON.parse(row.body) })); }
  reputationResult(job, result, next) { this.db.prepare("UPDATE reputations SET status=?,next=?,attempts=?,body=? WHERE key=?").run(result.status, next, result.status === "scored" ? 0 : job.attempts + 1, JSON.stringify(result), job.key); }
  queueDelivery(alert, channel, now = new Date().toISOString()) {
    const id = `${alert.id}|${channel.id}`;
    this.db.prepare("INSERT OR IGNORE INTO deliveries VALUES (?,'pending',?,0,?)").run(id, now, JSON.stringify({ alert, channelId: channel.id }));
  }
  deliveryJobs(now, limit = 10) { return this.db.prepare("SELECT * FROM deliveries WHERE status IN ('pending','retry') AND next<=? ORDER BY next LIMIT ?").all(now, limit).map(row => ({ ...row, body: JSON.parse(row.body) })); }
  finishDelivery(job, status, error = "", next = new Date().toISOString()) { this.db.prepare("UPDATE deliveries SET status=?,attempts=?,next=?,body=? WHERE id=?").run(status, job.attempts + 1, next, JSON.stringify({ ...job.body, error }), job.id); }
  deliveries() { return this.db.prepare("SELECT * FROM deliveries ORDER BY next DESC LIMIT 200").all().map(row => ({ id: row.id, status: row.status, channel: row.body && JSON.parse(row.body).channelId, attempts: row.attempts, nextAttempt: row.next, error: JSON.parse(row.body).error || "" })); }
  prune(cutoff) {
    this.db.prepare("DELETE FROM events WHERE timestamp<?").run(cutoff);
    this.db.exec("DELETE FROM event_indicators WHERE event NOT IN (SELECT id FROM events)");
    this.db.prepare("DELETE FROM audit WHERE timestamp<?").run(cutoff);
    this.db.prepare("DELETE FROM records WHERE kind='run' AND updated<?").run(cutoff);
    this.db.prepare("DELETE FROM records WHERE kind='finding' AND updated<?").run(cutoff);
    this.db.prepare("DELETE FROM records WHERE kind='alert' AND updated<?").run(cutoff);
    this.db.prepare("DELETE FROM records WHERE kind='investigation' AND updated<?").run(cutoff);
    this.db.prepare("DELETE FROM records WHERE kind='campaign' AND updated<?").run(cutoff);
    this.db.prepare("DELETE FROM reputations WHERE last_seen<?").run(cutoff);
    this.db.exec("DELETE FROM finding_events WHERE finding NOT IN (SELECT id FROM records WHERE kind='finding')");
    this.db.exec("DELETE FROM scan_events WHERE scan NOT IN (SELECT id FROM records WHERE kind='run')");
    this.db.prepare("DELETE FROM deliveries WHERE status IN ('delivered','failed','cancelled') AND next<?").run(cutoff);
  }
  close() { this.db.close(); }
}
