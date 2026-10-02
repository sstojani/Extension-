import { createHash, randomUUID } from "node:crypto";
import { normalizeEvent, analyzeEvidence, eventIndicators } from "./intelligence.mjs";
import { defaults } from "./config.mjs";
import { enrichQueue, publicIndicator } from "./reputation.mjs";
import { excluded, recordAlert, deliverQueue } from "./alerts.mjs";
import { investigateFinding } from "./investigator.mjs";
import { collectFeeds, campaignBatch, feedMatchQuery } from "./feeds.mjs";

export function dayStart(now, timezone) {
  const formatter = new Intl.DateTimeFormat("en-GB", { timeZone: timezone, year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23" });
  const parts = date => Object.fromEntries(formatter.formatToParts(new Date(date)).filter(p => p.type !== "literal").map(p => [p.type, Number(p.value)]));
  const p = parts(now), midnight = Date.UTC(p.year, p.month - 1, p.day);
  let candidate = midnight;
  for (let i = 0; i < 3; i++) {
    const local = parts(candidate);
    candidate += midnight - Date.UTC(local.year, local.month - 1, local.day, local.hour, local.minute, local.second);
  }
  return new Date(candidate).toISOString();
}

export class AgentWorker {
  constructor(store, elastic, runtime, { fetcher = fetch, clock = () => new Date().toISOString() } = {}) {
    this.store = store; this.elastic = elastic; this.runtime = runtime; this.clock = clock;
    this.shutdown = new AbortController(); this.elastic.signal = this.shutdown.signal;
    this.fetcher = (url, init = {}) => fetcher(url, { ...init, signal: init.signal ? AbortSignal.any([this.shutdown.signal, init.signal]) : this.shutdown.signal });
    this.running = false; this.scan = store.get("scan");
    this.status = { running: false, lastSuccess: store.get("lastSuccess"), lastError: null,
      checkpoint: null, heartbeat: null, coverage: null, nextScan: null };
  }
  config() { return { ...defaults, ...this.store.get("config", {}) }; }
  configured() { return Boolean(this.runtime.elasticUrl && this.runtime.elasticApiKey); }
  request(mode = "live") {
    if (!["live", "today", "baseline"].includes(mode)) throw new Error("Invalid scan mode.");
    if (!this.configured()) throw new Error("Configure server read-only Elasticsearch credentials first.");
    if (this.scan || this.store.get("scanRequest")) throw new Error("A scan is already queued or running.");
    this.store.set("scanRequest", { mode, requestedAt: this.clock() });
    this.store.audit("scan.requested", { mode });
  }
  start() { this.timer = setInterval(() => void this.tick(), 20000); this.timer.unref(); void this.tick(); }
  async stop() { this.stopping = true; clearInterval(this.timer); this.shutdown.abort(); while (this.running) await new Promise(resolve => setTimeout(resolve, 50)); }
  async tick() {
    if (this.running || this.stopping) return;
    this.running = true; this.status.running = true; this.status.heartbeat = this.clock();
    try {
      const config = this.config(), now = this.clock();
      const request = this.store.get("scanRequest");
      try {
        if (this.scan || request || (config.enabled && this.configured() && (!this.status.nextScan || this.status.nextScan <= now))) await this.scanWindow(config, request?.mode || "live", now);
      } catch (error) {
        this.status.lastError = error.message;
        if (this.scan) {
          this.store.record("run", { ...this.scan, cursor: undefined, config: undefined, status: "retrying", error: error.message });
          if (this.scan.cursor?.pit) await this.elastic.closePit(this.scan.cursor.pit);
          this.scan.cursor = null; this.store.set("scan", this.scan);
        }
        if (!this.stopping) await this.watchRules(config, new Date(Date.parse(now) - config.intervalMinutes * 60000).toISOString(), now);
      }
      if (this.stopping) return;
      if (this.configured() && this.store.get("watchPending", 0) > 0 && this.store.get("watchLastAttempt") !== now) {
        await this.watchRules(config, new Date(Date.parse(now) - config.intervalMinutes * 60000).toISOString(), now);
      }
      const enrichment = await enrichQueue(this.store, this.runtime, this.fetcher, this.clock());
      if (enrichment.changed?.length) this.reconsiderIndicators(enrichment.changed, this.config(), this.clock());
      if (this.stopping) return;
      try { await this.investigationQueue(); } catch (error) { this.store.audit("investigation.failed", { error: error.message }); }
      if (this.stopping) return;
      if (config.huntEnabled && this.configured()) { try { await this.huntTick(config, now); } catch (error) { this.store.audit("hunt.failed", { error: error.message }); } }
      await deliverQueue(this.store, this.store.get("notifications", { channels: [] }), this.fetcher, this.clock());
      this.store.prune(new Date(Date.parse(now) - config.retentionDays * 86400000).toISOString());
    } catch (error) {
      this.status.lastError = error.message;
    } finally { this.running = false; this.status.running = false; this.status.heartbeat = this.clock(); }
  }
  async scanWindow(config, mode, now) {
    const scope = createHash("sha256").update(JSON.stringify([this.runtime.elasticUrl, config.indexPattern, config.timestampField, config.query])).digest("hex");
    const checkpoint = this.store.get(`checkpoint:${scope}`);
    this.status.checkpoint = checkpoint;
    if (!this.scan) {
      const from = mode === "today" ? dayStart(now, config.timezone) : mode === "baseline"
        ? new Date(Date.parse(now) - config.baselineDays * 86400000).toISOString()
        : new Date(Date.parse(checkpoint || now) - (checkpoint ? config.overlapMinutes : config.intervalMinutes) * 60000).toISOString();
      this.scan = { id: randomUUID(), mode, from, to: now, startedAt: now, status: "running", eventsRead: 0, uniqueEvents: 0, invalidEvents: 0, totalMatched: 0, cursor: null, scope, config };
      this.store.set("scanRequest", null); this.store.set("scan", this.scan);
      this.store.record("run", this.scan);
    }
    const scan = this.scan;
    const tickStarted = Date.now();
    let readThisTick = 0;
    while (readThisTick < scan.config.maxEventsPerRun && Date.now() - tickStarted < 20000 && !this.stopping) {
      const page = await this.elastic.page({ ...scan.config, pageSize: Math.min(scan.config.pageSize, scan.config.maxEventsPerRun - readThisTick) }, scan.from, scan.to, scan.cursor);
      const events = page.hits.map(hit => normalizeEvent(hit, scan.config)).filter(Boolean);
      const next = { ...scan };
      this.store.transaction(() => {
        next.uniqueEvents += this.store.addEvents(events);
        next.analysisEvents = (next.analysisEvents || 0) + this.store.addScanEvents(next.id, events);
        next.eventsRead += page.hits.length; next.invalidEvents += page.hits.length - events.length;
        next.totalMatched = page.total; next.cursor = page.cursor;
        this.queueIndicators(events);
        this.store.set("scan", next);
        this.store.record("run", { ...next, cursor: undefined, config: undefined, status: page.complete ? "analyzing" : "collecting", coverage: "in_progress" });
      });
      Object.assign(scan, next);
      readThisTick += page.hits.length; this.status.heartbeat = this.clock();
      if (!page.complete) continue;
      await this.elastic.closePit(page.cursor.pit);
      const capabilities = await this.elastic.probe(scan.config).catch(error => ({ error: error.message }));
      const missingFields = Object.keys(capabilities).filter(field => capabilities[field] === false);
      const analysis = this.investigate(scan.config, scan.to, scan.analysisFrom || scan.from);
      const watchCoverage = await this.watchRules(scan.config, scan.from, scan.to);
      this.store.transaction(() => {
        if (scan.mode === "live") this.store.set(`checkpoint:${scan.scope}`, scan.to);
        this.store.set("lastSuccess", this.clock());
        this.store.record("run", { ...scan, config: undefined, cursor: undefined, status: "complete", finishedAt: this.clock(), capabilities,
          coverage: analysis.truncated || scan.analysisTruncated || scan.invalidEvents || capabilities.error || missingFields.length || watchCoverage.failed || watchCoverage.pending ? "reduced" : "complete", missingFields, watchCoverage, analysisEvents: scan.analysisEvents, findings: analysis.findings });
        this.store.set("scan", null);
      });
      this.status.lastSuccess = this.clock(); this.status.lastError = watchCoverage.failed ? `${watchCoverage.failed} watch queries failed; see the audit/run coverage.` : capabilities.error || null;
      this.status.coverage = { eventsRead: scan.eventsRead, totalMatched: scan.totalMatched, invalidEvents: scan.invalidEvents,
        status: analysis.truncated || scan.analysisTruncated || scan.invalidEvents || capabilities.error || missingFields.length || watchCoverage.failed || watchCoverage.pending ? "reduced" : "complete", analysisEvents: scan.analysisEvents, capabilities, missingFields, analysis: this.store.get("analysisCoverage"), watchCoverage };
      this.status.checkpoint = this.store.get(`checkpoint:${scan.scope}`);
      this.status.nextScan = new Date(Date.parse(this.clock()) + config.intervalMinutes * 60000).toISOString();
      this.scan = null;
      return;
    }
    const through = scan.cursor.after?.[0];
    const analysisTo = typeof through === "number" ? new Date(through).toISOString() : typeof through === "string" && Number.isFinite(Date.parse(through)) ? new Date(through).toISOString() : scan.to;
    const analysis = this.investigate(scan.config, analysisTo, scan.analysisFrom || scan.from);
    scan.analysisFrom = analysisTo; scan.analysisTruncated ||= analysis.truncated;
    this.store.set("scan", scan);
    // Explicit watch rules are queried even while a broad historical/backfill scan is still collecting.
    await this.watchRules(scan.config, new Date(Date.parse(this.clock()) - config.intervalMinutes * 60000).toISOString(), this.clock());
    this.status.coverage = { status: "in_progress", eventsRead: scan.eventsRead, totalMatched: scan.totalMatched, invalidEvents: scan.invalidEvents };
    // Fixed-window PIT pagination continues at the next tick. A cap is a budget, not successful coverage.
  }
  queueIndicators(events) {
    for (const e of events) {
      for (const [type, values] of eventIndicators(e)) {
        for (const value of values.filter(Boolean)) if (publicIndicator(type, value)) this.store.queueReputation(type, value);
      }
    }
  }
  investigate(config, to, from = new Date(Date.parse(to) - 3600000).toISOString()) {
    const start = new Date(Math.max(0, Date.parse(from) - 15 * 60000)).toISOString();
    const events = this.store.events(start, to, 100001);
    const truncated = events.length > 100000;
    return this.analyzeEvents(events.slice(-100000), config, to, truncated, events.length);
  }
  analyzeEvents(events, config, to, truncated = false, observed = events.length) {
    const report = analyzeEvidence(events, { reputations: this.store.reputationMap(), baselines: this.store.get("baselines", {}), config, now: to });
    const notifications = this.store.get("notifications", { channels: [], minPriority: config.autoAlertMinPriority, cooldownMinutes: 60 });
    this.store.transaction(() => {
      this.store.set("baselines", report.baselines);
      this.store.set("analysisCoverage", report.coverage);
      for (const finding of report.findings) {
        if (excluded(finding, config, Date.parse(to))) continue;
        if (truncated) finding.limitations.push("Analysis event budget reached; this is not complete window coverage.");
        const saved = this.store.upsertFinding(finding);
        if (config.autoInvestigate && saved.priority >= 70 && !this.store.one("investigation", saved.id)) this.store.record("investigation", { id: saved.id, status: "pending" });
        if (saved.priority >= config.autoAlertMinPriority && saved.confidence >= 70 && saved.status === "open") {
          recordAlert(this.store, saved, { channels: notifications.channels, cooldownMinutes: notifications.cooldownMinutes, now: this.clock() });
        }
      }
    });
    return { truncated, events: observed, findings: report.findings.length };
  }
  reconsiderIndicators(keys, config, now) {
    const reps = this.store.reputationMap(), changed = new Set(keys);
    const notifications = this.store.get("notifications", { channels: [], cooldownMinutes: 60 });
    for (const finding of this.store.list("finding", 100000)) {
      const key = `${finding.indicatorType}|${finding.indicator.toLowerCase()}`;
      if (!changed.has(key)) continue;
      const reputation = reps[key];
      const boost = verdict => verdict === "malicious" ? 15 : verdict === "suspicious" ? 7 : 0;
      const saved = { ...finding, reputation, priority: Math.max(0, Math.min(100, finding.priority - boost(finding.reputation?.verdict) + boost(reputation.verdict))) };
      if (["watched_indicator", "feed_sighting"].includes(saved.category)) {
        saved.priority = reputation.verdict === "malicious" ? 95 : reputation.verdict === "suspicious" ? 80 : saved.category === "watched_indicator" ? 50 : Math.min(70, saved.behaviorScore || 0);
        saved.severity = saved.priority >= 90 ? "critical" : saved.priority >= 70 ? "high" : "medium";
      }
      if (saved.category === "intelligence" && !["malicious", "suspicious"].includes(reputation.verdict) && saved.status === "open") {
        saved.status = "resolved"; saved.resolutionReason = "The latest provider assessment no longer supports this reputation-only finding.";
      }
      this.store.record("finding", saved);
      if (saved.category === "watched_indicator") {
        const rule = this.store.one("rule", saved.fingerprint.split("|")[1]);
        if (rule?.enabled && saved.priority >= rule.minPriority) recordAlert(this.store, saved, { rule, channels: notifications.channels, cooldownMinutes: rule.cooldownMinutes, now });
      } else if (saved.priority >= config.autoAlertMinPriority && saved.confidence >= 70) recordAlert(this.store, saved, { channels: notifications.channels, cooldownMinutes: notifications.cooldownMinutes, now });
    }
    const events = this.store.indicatorEvents(keys);
    this.analyzeEvents(events.slice(-10000), config, now, events.length > 10000);
    this.store.audit("reputation.reconsidered", { indicators: keys.length, retainedEvents: Math.min(events.length, 10000), truncated: events.length > 10000 });
  }
  async watchRules(config, from, to) {
    this.store.set("watchLastAttempt", this.clock());
    let failed = 0, checked = 0;
    const notifications = this.store.get("notifications", { channels: [] });
    const rules = this.store.list("rule").filter(r => r.enabled).sort((a,b) => a.id.localeCompare(b.id));
    const keyFor = rule => `watch-window:${createHash("sha256").update(JSON.stringify([config.indexPattern, config.timestampField, rule])).digest("hex")}`;
    for (const rule of rules) if (!this.store.get(keyFor(rule))) this.store.set(keyFor(rule), from);
    const start = this.store.get("watchNextIndex", 0) % (rules.length || 1), begun = Date.now();
    for (let offset = 0; offset < rules.length; offset++) {
      if (this.stopping || Date.now() - begun >= 20000) break;
      const index = (start + offset) % rules.length, rule = rules[index], key = keyFor(rule);
      this.store.set("watchNextIndex", (index + 1) % rules.length);
      const pending = this.store.get(key);
      const watchFrom = pending && pending < from ? pending : from;
      try {
        checked++;
        const page = await this.elastic.watched(config, rule, watchFrom, to);
        this.store.set(key, new Date(Date.parse(to) - config.overlapMinutes * 60000).toISOString());
        const events = page.hits.map(hit => normalizeEvent(hit, config)).filter(Boolean);
        if (page.total < rule.minEvents || !events.length) continue;
        const reputation = this.store.reputationMap()[`${rule.indicatorType}|${rule.indicatorValue}`] || { verdict: "unknown", status: "pending" };
        const priority = reputation.verdict === "malicious" ? 95 : reputation.verdict === "suspicious" ? 80 : 50;
        if (priority < rule.minPriority) continue;
        const groups = new Map();
        for (const e of events) {
          const scope = JSON.stringify([e.host || e.sourceIp || "unknown", e.infrastructure || "unknown"]);
          if (!groups.has(scope)) groups.set(scope, []);
          groups.get(scope).push(e);
        }
        for (const [scope, sampled] of groups) {
        const e = sampled.at(-1), finding = { fingerprint: `watch|${rule.id}|${scope}`, category: "watched_indicator", title: `Watched indicator observed: ${rule.name}`,
          indicatorType: rule.indicatorType, indicator: rule.indicatorValue, host: e.host, infrastructure: e.infrastructure,
          sourceIp: e.sourceIp, destinationIp: e.destinationIp, priority, confidence: 100, behaviorScore: 0, reputation,
          severity: priority >= 90 ? "critical" : priority >= 70 ? "high" : "medium", firstSeen: sampled[0].timestamp,
          lastSeen: e.timestamp, events: page.total, queryTotal: page.total, count: page.total, status: "open",
          reasons: [`The independent watch query matched ${page.total} log events across its scope. ${sampled.length} sampled events belong to this host/infrastructure. A sighting does not itself prove compromise.`],
          limitations: [...(page.total > events.length ? ["Only the first page of evidence is sampled; other hosts may not be represented."] : []), "Query totals cover the whole watch scope, not this host alone. Distinct evidence counts are per host/infrastructure."],
          evidence: sampled.slice(-30).map(e => ({ eventId: e.id, index: e.index, timestamp: e.timestamp, reason: `${e.action || "sighting"} / ${e.outcome || "unknown outcome"}` })) };
        finding.eventKeys = sampled.map(e => JSON.stringify([e.index, e.id]));
        if (excluded(finding, config, Date.parse(to))) continue;
        this.store.transaction(() => {
          this.store.addEvents(sampled); this.queueIndicators(sampled);
          const saved = this.store.upsertFinding(finding);
          recordAlert(this.store, saved, { rule, channels: notifications.channels, cooldownMinutes: rule.cooldownMinutes, now: this.clock() });
        });
        }
      } catch (error) { failed++; this.store.set(key, watchFrom); this.status.lastError = `Watch rule ${rule.name}: ${error.message}`; this.store.audit("watch.failed", { ruleId: rule.id, error: error.message }); }
    }
    this.store.set("watchPending", rules.length - checked + failed);
    return { checked, failed, pending: rules.length - checked };
  }
  state() {
    const config = this.config(), reps = Object.values(this.store.reputationMap());
    const notifications = this.store.get("notifications", { channels: [], minPriority: config.autoAlertMinPriority, cooldownMinutes: 60 });
    return { status: { ...this.status, enabled: config.enabled, configured: this.configured(), running: Boolean(this.scan) || this.running }, config,
      rules: this.store.list("rule"), findings: this.store.list("finding", 2000).sort((a,b) => b.priority - a.priority),
      alerts: this.store.list("alert", 200), runs: this.store.list("run", 30), deliveries: this.store.deliveries(),
      notifications: { ...notifications, channels: notifications.channels.map(({ url, token, chatId, ...c }) => ({ ...c, configured: Boolean(url || (token && chatId)) })) },
      reputation: { configured: Boolean(this.runtime.gtiKey), pending: reps.filter(r => r.status === "pending").length,
        unavailable: reps.filter(r => ["unavailable", "unauthorized", "rate_limited"].includes(r.status)).length,
        scored: reps.filter(r => r.status === "scored").length, notFound: reps.filter(r => r.status === "not_found").length },
      campaigns: this.store.list("campaign", 5).map(({ iocs, cursor, config, ...c }) => c), investigations: this.store.list("investigation", 100) };
  }
  async investigationQueue() {
    for (const job of this.store.list("investigation", 1000).filter(j => j.status === "pending").slice(-2)) {
      const finding = this.store.one("finding", job.id);
      if (!finding) { this.store.remove("investigation", job.id); continue; }
      try { this.store.record("investigation", await investigateFinding(finding, this.elastic, this.config(), this.store.reputationMap())); }
      catch (error) { this.store.record("investigation", { ...job, status: "failed", error: error.message }); }
    }
  }
  async huntTick(config, now) {
    let campaign = this.store.one("campaign", this.store.get("activeCampaign"));
    if (!campaign || campaign.expiresAt <= now) {
      campaign = await collectFeeds(this.runtime, this.fetcher, now);
      campaign.from = new Date(Date.parse(now) - 86400000).toISOString(); campaign.to = now; campaign.config = config;
      this.store.record("campaign", campaign); this.store.set("activeCampaign", campaign.id);
    }
    if (campaign.offset >= campaign.totalAvailable) return;
    const batch = campaignBatch(campaign), byKey = new Map(batch.map(i => [i.key, i]));
    try {
      const page = await this.elastic.page({ ...campaign.config, query: "" }, campaign.from, campaign.to, campaign.cursor, feedMatchQuery(batch));
      const events = page.hits.map(h => normalizeEvent(h, campaign.config)).filter(Boolean);
      this.store.addEvents(events); this.queueIndicators(events);
      for (const e of events) {
        const values = eventIndicators(e);
        for (const [type, indicators] of values) for (const value of indicators.filter(Boolean)) {
          const ioc = byKey.get(`${type}|${value.toLowerCase()}`);
          if (!ioc) continue;
          const rep = this.store.reputationMap()[ioc.key] || { verdict: "unknown", status: "pending" };
          const priority = rep.verdict === "malicious" ? 95 : rep.verdict === "suspicious" ? 80 : Math.min(70, ioc.priority);
          const f = { fingerprint: `feed|${ioc.key}|${e.host || e.sourceIp || "unknown"}`, category: "feed_sighting", title: "Threat-feed indicator observed",
            indicatorType: type, indicator: value, host: e.host, infrastructure: e.infrastructure, sourceIp: e.sourceIp, destinationIp: e.destinationIp,
            priority, behaviorScore: 0, confidence: 85, reputation: rep, severity: priority >= 90 ? "critical" : priority >= 75 ? "high" : "medium",
            firstSeen: e.timestamp, lastSeen: e.timestamp, count: 1, events: 1, status: "open",
            reasons: [`Observed ${e.action || "event"} (${e.outcome || "unknown outcome"}) matching ${ioc.sources.map(s => s.provider).join(", ")}.`],
            limitations: ["A feed match is a sighting, not proof of compromise. Feed priority is not a GTI verdict."],
            feedSources: ioc.sources, evidence: [{ eventId: e.id, index: e.index, timestamp: e.timestamp, reason: e.action || "IOC sighting" }] };
          f.eventKeys = [JSON.stringify([e.index, e.id])];
          if (excluded(f, config, Date.parse(now))) continue;
          const saved = this.store.upsertFinding(f);
          if (priority >= config.autoAlertMinPriority) recordAlert(this.store, saved, { channels: this.store.get("notifications", { channels: [] }).channels, now });
        }
      }
      campaign.cursor = page.cursor; campaign.status = "checking"; campaign.lastError = null;
      if (page.complete) {
        await this.elastic.closePit(page.cursor.pit);
        campaign.offset += batch.length; campaign.checked += batch.length; campaign.cursor = null;
        campaign.status = campaign.offset >= campaign.totalAvailable ? "complete" : "ready";
      }
      this.store.record("campaign", campaign);
    } catch (error) {
      if (campaign.cursor?.pit) await this.elastic.closePit(campaign.cursor.pit);
      campaign.cursor = null; campaign.status = "retrying"; campaign.lastError = error.message;
      this.store.record("campaign", campaign);
    }
  }
}
