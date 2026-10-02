import { randomUUID } from "node:crypto";
import { publicIndicator } from "./reputation.mjs";
import { INDICATOR_FIELDS } from "./intelligence.mjs";

export function rankFeedIndicators(records, now = new Date().toISOString()) {
  const map = new Map();
  for (const r of records) {
    const value = String(r.value || "").trim().toLowerCase().replace(/\.$/, "");
    if (!publicIndicator(r.type, value)) continue;
    const key = `${r.type}|${value}`, old = map.get(key);
    const score = /botnet|c2|command.*control/i.test(r.context || "") ? 90 : r.type === "hash" ? 80 : 65;
    const source = { provider: r.provider, observedAt: now, reference: r.reference, firstSeen: r.firstSeen, context: r.context, confidence: r.confidence || null };
    if (old) {
      if (!old.sources.some(s => s.provider === r.provider)) old.sources.push(source);
      old.priority = Math.max(old.priority, score); // Copied feeds are not counted as independent confidence votes.
    } else map.set(key, { key, value, type: r.type, priority: score, sources: [source], expiresAt: new Date(Date.parse(now) + 86400000).toISOString() });
  }
  return [...map.values()].sort((a,b) => b.priority - a.priority || a.key.localeCompare(b.key)).slice(0, 100000);
}

export async function collectFeeds(runtime, fetcher = fetch, now = new Date().toISOString()) {
  const request = async (url, options = {}) => {
    const response = await fetcher(url, { ...options, signal: AbortSignal.timeout(15000), redirect: "error" });
    if (!response.ok) throw new Error(`Provider returned HTTP ${response.status}`);
    let length = 0, chunks = [];
    for await (const chunk of response.body) { length += chunk.length; if (length > 16 * 1024 * 1024) throw new Error("Provider exceeded 16 MB response budget"); chunks.push(chunk); }
    return Buffer.concat(chunks).toString("utf8");
  };
  const providers = [
    { name: "Feodo Tracker", collect: async () => JSON.parse(await request("https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json")).map(r => ({ value: r.ip_address, type: "ip", provider: "Feodo Tracker", context: "reported active botnet C2", firstSeen: r.first_seen, reference: "https://feodotracker.abuse.ch/blocklist/" })) },
    { name: "OpenPhish", collect: async () => (await request("https://openphish.com/feed.txt")).split(/\r?\n/).flatMap(line => {
      try { const url = new URL(line.trim()); return [{ value: url.hostname, type: "domain", provider: "OpenPhish", context: "reported phishing URL host", reference: url.href }]; } catch { return []; }
    }) },
    { name: "ThreatFox", collect: async () => {
      if (!runtime.feeds.threatfox) throw new Error("API key not configured");
      const json = JSON.parse(await request("https://threatfox-api.abuse.ch/api/v1/", { method: "POST", headers: { "Auth-Key": runtime.feeds.threatfox, "content-type": "application/json" }, body: JSON.stringify({ query: "get_iocs", days: 1 }) }));
      if (!["ok", "no_result"].includes(json.query_status)) throw new Error(`ThreatFox: ${json.query_status}`);
      return (Array.isArray(json.data) ? json.data : []).flatMap(r => {
        let value = String(r.ioc || ""), type = r.ioc_type === "ip:port" ? "ip" : /sha|md5/.test(r.ioc_type) ? "hash" : r.ioc_type;
        if (type === "ip") value = value.replace(/:\d+$/, "");
        if (type === "url") { try { value = new URL(value).hostname; type = "domain"; } catch { return []; } }
        return [{ value, type, provider: "ThreatFox", context: r.threat_type_desc || r.threat_type, confidence: r.confidence_level, firstSeen: r.first_seen, reference: r.reference }];
      });
    } },
    { name: "MalwareBazaar", collect: async () => {
      if (!runtime.feeds.malwarebazaar) throw new Error("API key not configured");
      const json = JSON.parse(await request("https://mb-api.abuse.ch/api/v1/", { method: "POST", headers: { "Auth-Key": runtime.feeds.malwarebazaar, "content-type": "application/x-www-form-urlencoded" }, body: "query=get_recent&selector=100" }));
      if (!["ok", "no_results"].includes(json.query_status)) throw new Error(`MalwareBazaar: ${json.query_status}`);
      return (Array.isArray(json.data) ? json.data : []).map(r => ({ value: r.sha256_hash, type: "hash", provider: "MalwareBazaar", context: `reported malware sample ${r.signature || ""}`, firstSeen: r.first_seen }));
    } }
  ];
  const outcomes = await Promise.all(providers.map(async p => {
    try { const records = await p.collect(); return { records, provider: { name: p.name, status: "healthy", collected: records.length, checkedAt: now } }; }
    catch (error) { return { records: [], provider: { name: p.name, status: error.message.includes("not configured") ? "skipped" : "error", collected: 0, error: error.message, checkedAt: now } }; }
  }));
  const iocs = rankFeedIndicators(outcomes.flatMap(o => o.records), now);
  return { id: randomUUID(), createdAt: now, expiresAt: new Date(Date.parse(now) + 86400000).toISOString(),
    iocs, totalAvailable: iocs.length, providers: outcomes.map(o => o.provider), offset: 0, checked: 0, status: "ready" };
}

export function campaignBatch(campaign, count = 500) {
  if (count < 1 || count > 500 || !Number.isInteger(count)) throw new Error("IOC batches must contain 1-500 indicators.");
  return campaign.iocs.slice(campaign.offset, campaign.offset + count);
}

export function feedMatchQuery(batch) {
  const fields = INDICATOR_FIELDS;
  const should = [];
  for (const [type, names] of Object.entries(fields)) {
    const values = batch.filter(i => i.type === type).map(i => i.value);
    if (values.length) for (const field of names) should.push({ terms: { [field]: values } });
  }
  return { bool: { should, minimum_should_match: 1 } };
}
