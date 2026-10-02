import { randomUUID } from "node:crypto";
import { isIP } from "node:net";
import { publicIndicator } from "./reputation.mjs";

export function validateRule(input) {
  const r = { id: randomUUID(), name: "Watched indicator", enabled: true, includeSubdomains: false,
    minEvents: 1, minPriority: 0, cooldownMinutes: 60, channels: [], scope: {}, requireSuccess: false, ...input };
  if (!/^[a-zA-Z0-9_-]{1,128}$/.test(r.id) || !["ip","domain","hash","identity"].includes(r.indicatorType)) throw new Error("Invalid watch rule type or id.");
  if (typeof r.indicatorValue !== "string") throw new Error("An indicator is required.");
  r.indicatorValue = r.indicatorValue.trim().replace(/\[\.\]/g, ".").replace(/\.$/, "").toLowerCase();
  if (r.indicatorType !== "identity" && !(r.indicatorType === "ip" ? isIP(r.indicatorValue) : publicIndicator(r.indicatorType, r.indicatorValue))) throw new Error("Watch rules require a valid IP, public domain or hash.");
  if (!r.indicatorValue || r.indicatorValue.length > 253 || typeof r.name !== "string" || r.name.length > 200) throw new Error("Invalid watch rule name/value.");
  for (const key of ["enabled", "includeSubdomains", "requireSuccess"]) if (typeof r[key] !== "boolean") throw new Error(`Invalid ${key}.`);
  for (const [key,min,max] of [["minEvents",1,100000], ["minPriority",0,100], ["cooldownMinutes",1,10080]]) {
    if (!Number.isInteger(r[key]) || r[key] < min || r[key] > max) throw new Error(`Invalid ${key}.`);
  }
  if (!Array.isArray(r.channels) || r.channels.length > 20 || r.channels.some(c => typeof c !== "string" || c.length > 128)) throw new Error("Invalid delivery channels.");
  if (!r.scope || Object.keys(r.scope).some(k => !["host", "infrastructure"].includes(k)) || Object.values(r.scope).some(v => typeof v !== "string" || v.length > 256)) throw new Error("Invalid watch scope.");
  return r;
}

export function excluded(finding, config, now = Date.now()) {
  return (config.exceptions || []).some(e => e.enabled !== false && (!e.expiresAt || Date.parse(e.expiresAt) > now)
    && e.indicatorType === finding.indicatorType && e.indicatorValue.toLowerCase() === finding.indicator.toLowerCase()
    && (!e.host || e.host === finding.host) && (!e.infrastructure || e.infrastructure === finding.infrastructure));
}

export function recordAlert(store, finding, { rule = null, channels, cooldownMinutes = 60, now = new Date().toISOString() }) {
  if (finding.status && !["open", "acknowledged"].includes(finding.status)) return null;
  const key = `${rule?.id || "automatic"}|${finding.fingerprint}`;
  const previous = store.get(`alert:${key}`);
  if (previous && Date.parse(now) - Date.parse(previous.at) < cooldownMinutes * 60000 && previous.priority >= finding.priority) return null;
  // Re-evaluating old evidence after a reputation retry must not create a new incident repeatedly.
  if (previous && previous.lastSeen >= finding.lastSeen) {
    // A late reputation result may materially raise an existing incident's priority.
    // Upgrade the durable alert in place so the SOC sees the better classification
    // without receiving duplicate notifications for the same evidence.
    if (finding.priority > previous.priority) {
      const existing = previous.alertId
        ? store.one("alert", previous.alertId)
        : store.list("alert", 1000).find(item => item.idempotencyKey === key);
      if (existing) {
        const updated = store.record("alert", {
          ...existing,
          priority: finding.priority,
          severity: finding.severity,
          reasons: finding.reasons,
          evidence: finding.evidence,
          updatedAt: now,
        });
        store.set(`alert:${key}`, { at: now, priority: finding.priority, lastSeen: finding.lastSeen, alertId: updated.id });
        store.audit("alert.updated", { id: updated.id, indicator: updated.indicator, rule: rule?.id, reason: "priority_escalation" });
        return updated;
      }
    }
    return null;
  }
  const alert = store.record("alert", { id: randomUUID(), findingId: finding.id || finding.fingerprint,
    title: rule ? `Watched indicator: ${rule.name}` : finding.title, indicator: finding.indicator,
    indicatorType: finding.indicatorType, priority: finding.priority, severity: finding.severity,
    host: finding.host, sourceIp: finding.sourceIp, destinationIp: finding.destinationIp,
    reasons: finding.reasons, evidence: finding.evidence, createdAt: now, ruleId: rule?.id || null,
    idempotencyKey: key, status: "open" });
  store.set(`alert:${key}`, { at: now, priority: finding.priority, lastSeen: finding.lastSeen, alertId: alert.id });
  for (const channel of channels.filter(c => c.enabled && (!rule?.channels?.length || rule.channels.includes(c.id)))) store.queueDelivery(alert, channel, now);
  store.audit("alert.created", { id: alert.id, indicator: alert.indicator, rule: rule?.id });
  return alert;
}

export function validateNotifications(input, previous = { channels: [] }) {
  for (const [key, min, max] of [["minPriority", 0, 100], ["cooldownMinutes", 1, 10080]]) {
    if (input[key] !== undefined && (!Number.isInteger(input[key]) || input[key] < min || input[key] > max)) throw new Error(`Invalid notification ${key}.`);
  }
  if (!Array.isArray(input.channels) || input.channels.length > 20) throw new Error("Invalid notification channels.");
  return { ...previous, ...input, channels: input.channels.map(c => {
    const old = previous.channels.find(x => x.id === c.id) || {};
    const channel = { ...old, ...c };
    if (!/^[a-zA-Z0-9_-]{1,128}$/.test(channel.id) || !["webhook", "discord", "telegram"].includes(channel.type)) throw new Error("Invalid channel id/type.");
    if (typeof channel.enabled !== "boolean") throw new Error("Invalid channel enabled value.");
    if (channel.type === "telegram") {
      if (!/^[0-9]+:[a-zA-Z0-9_-]+$/.test(channel.token || "") || !/^-?[0-9]+$/.test(channel.chatId || "")) throw new Error("Telegram needs a bot token and numeric chat ID.");
    } else {
      const url = new URL(channel.url);
      if (url.protocol !== "https:" || url.username || url.password || url.hash) throw new Error("Notification endpoints must use HTTPS without embedded credentials.");
      if (channel.type === "discord" && (url.hostname !== "discord.com" || !url.pathname.startsWith("/api/webhooks/"))) throw new Error("Invalid Discord webhook URL.");
    }
    return channel;
  }) };
}

export async function deliverQueue(store, notifications, fetcher = fetch, now = new Date().toISOString()) {
  for (const job of store.deliveryJobs(now, 10)) {
    const channel = notifications.channels.find(c => c.id === job.body.channelId && c.enabled);
    if (!channel) { store.finishDelivery(job, "cancelled", "Channel removed or disabled"); continue; }
    const alert = job.body.alert;
    const text = `SOC Watch: ${alert.title}\n${alert.indicatorType}: ${alert.indicator}\nPriority ${alert.priority}/100\n${alert.reasons.join("; ")}`.slice(0, 1900);
    const url = channel.type === "telegram" ? `https://api.telegram.org/bot${channel.token}/sendMessage` : channel.url;
    const body = channel.type === "telegram" ? { chat_id: channel.chatId, text }
      : channel.type === "discord" ? { content: text, allowed_mentions: { parse: [] } } : { source: "soc-watch", alert };
    try {
      const response = await fetcher(url, { method: "POST", headers: { "content-type": "application/json", "Idempotency-Key": job.id }, body: JSON.stringify(body), signal: AbortSignal.timeout(10000), redirect: "error" });
      if (response.ok) { store.finishDelivery(job, "delivered"); continue; }
      const permanent = response.status >= 400 && response.status < 500 && ![408,429].includes(response.status);
      const retry = Math.max(30 * 2 ** job.attempts, Math.min(86400, Number(response.headers.get("retry-after")) || 0));
      store.finishDelivery(job, permanent || job.attempts >= 7 ? "failed" : "retry", `Provider HTTP ${response.status}`, new Date(Date.parse(now) + retry * 1000).toISOString());
    } catch { store.finishDelivery(job, job.attempts >= 7 ? "failed" : "retry", "Notification request failed or timed out", new Date(Date.parse(now) + 30000 * 2 ** job.attempts).toISOString()); }
  }
}
