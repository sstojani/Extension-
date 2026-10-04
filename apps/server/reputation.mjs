import { createHash } from "node:crypto";
import { relayReputationResultSchema, isPublicReputationTarget, hasUsableGtiAssessment } from "@soc-watch/protocol";

export function publicIndicator(type, value) {
  return typeof value === "string" && isPublicReputationTarget(type, value);
}

export function classifyReputation(attributes, now = new Date().toISOString()) {
  const a = attributes || {};
  const stats = a.last_analysis_stats || {};
  const malicious = Number(stats.malicious || 0), suspicious = Number(stats.suspicious || 0);
  const gti = a.gti_assessment || {};
  const wrapped = value => typeof value === "string" ? value : typeof value?.value === "string" ? value.value : "";
  const text = wrapped(gti.verdict).toLowerCase();
  const severity = wrapped(gti.severity || gti.threat_severity).toLowerCase();
  const score = Number(gti.threat_score?.value ?? gti.threat_score ?? a.threat_score ?? 0);
  const verdict = /malicious/.test(text) || /critical|high/.test(severity) || malicious >= 3 || score >= 70 ? "malicious"
    : /suspicious/.test(text) || /medium/.test(severity) || malicious > 0 || suspicious > 0 || score >= 20 || Number(a.reputation || 0) < 0 ? "suspicious"
      : /benign|harmless/.test(text) ? "benign" : /unknown/.test(text) ? "unknown" : "undetected";
  return { verdict, score: Number.isFinite(score) ? score : null, malicious, suspicious,
    vendors: Object.values(stats).reduce((total, count) => total + Number(count || 0), 0),
    communityReputation: Number(a.reputation || 0), status: "scored", checkedAt: now,
    analysisAt: a.last_analysis_date ? new Date(a.last_analysis_date * 1000).toISOString() : null,
    source: "Google Threat Intelligence / VirusTotal", gtiVerdict: text || null, gtiSeverity: severity || null,
    assessment: Object.keys(gti).length ? "gti" : "virustotal" };
}

export function reputationSource(runtime, relay) {
  if (runtime.gtiKey) return "server";
  const status = relay?.status();
  return status?.ready && status.source?.reputationConfigured ? "browser" : "missing";
}

export async function enrichQueue(store, runtime, fetcher = fetch, now = new Date().toISOString(), relay) {
  const source = reputationSource(runtime, relay), apiKey = runtime.gtiKey;
  if (source === "missing") return { configured: false, processed: 0 };
  const credential = createHash("sha256").update(source === "server" ? apiKey : "browser").digest("hex");
  const backoff = store.get("reputationBackoff");
  if (backoff?.credential === credential && backoff.until > now) return { configured: true, processed: 0, changed: [] };
  let processed = 0;
  const changed = [];
  const priorityKeys = store.list("finding", 500).filter(finding => ["open", "acknowledged"].includes(finding.status)).map(finding => `${finding.indicatorType}|${finding.indicator.toLowerCase()}`);
  for (const job of store.reputationJobs(now, source === "browser" ? 2 : 8, priorityKeys)) {
    const endpoint = { ip: "ip_addresses", domain: "domains", hash: "files" }[job.type];
    let result, retrySeconds = Math.min(3600, 30 * 2 ** Math.min(job.attempts, 7));
    try {
      if (source === "browser") {
        const report = relayReputationResultSchema.parse(await relay.execute({ kind: "reputation", target: { type: job.type, value: job.value } }));
        result = { ...report, checkedAt: report.checkedAt || now, source: "Google Threat Intelligence / VirusTotal (browser bridge)" };
        if (["pending", "rate_limited"].includes(result.status)) retrySeconds = 300;
        else if (["unauthorized", "not_found"].includes(result.status)) retrySeconds = 3600;
        else if (result.status === "scored") { retrySeconds = result.verdict === "undetected" ? 21600 : 3600; changed.push(job.key); }
      } else {
        const response = await fetcher(`https://www.virustotal.com/api/v3/${endpoint}/${encodeURIComponent(job.value)}`, {
          headers: { "x-apikey": apiKey, "x-tool": "SOC-WatchServer", accept: "application/json" }, signal: AbortSignal.timeout(10000), redirect: "error"
        });
        if (response.status === 404) { result = { verdict: "unknown", status: "not_found", checkedAt: now }; retrySeconds = 3600; }
        else if (response.status === 429) { result = { ...job.body, status: "rate_limited", error: "GTI rate limit", checkedAt: now }; retrySeconds = Math.max(retrySeconds, 60, Math.min(86400, Number(response.headers.get("retry-after")) || 0)); }
        else if (response.status === 401 || response.status === 403) { result = { ...job.body, status: "unauthorized", error: "GTI key or entitlement rejected", checkedAt: now }; retrySeconds = 3600; }
        else if (!response.ok) throw new Error(`GTI HTTP ${response.status}`);
        else {
          const attributes = (await response.json()).data?.attributes;
          if (!hasUsableGtiAssessment(attributes)) {
            throw new Error("GTI returned no usable assessment; the lookup is not a clean verdict.");
          }
          result = classifyReputation(attributes, now); retrySeconds = result.verdict === "undetected" ? 21600 : 3600;
          relayReputationResultSchema.parse({ status: result.status, verdict: result.verdict, score: result.score, malicious: result.malicious, suspicious: result.suspicious, vendors: result.vendors });
          changed.push(job.key);
        }
      }
    } catch { result = { ...job.body, status: "unavailable", error: "GTI lookup failed; retry scheduled.", checkedAt: now }; }
    if (source === "server" && runtime.gtiKey !== apiKey) break;
    store.reputationResult(job, result, new Date(Date.parse(now) + retrySeconds * 1000).toISOString());
    processed++;
    if (["rate_limited", "unauthorized", "pending", "not_configured"].includes(result.status)) {
      store.set("reputationBackoff", { credential, until: new Date(Date.parse(now) + retrySeconds * 1000).toISOString() }); break;
    }
  }
  return { configured: true, processed, changed };
}
