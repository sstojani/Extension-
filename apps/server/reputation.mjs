import { isIP } from "node:net";

export function publicIndicator(type, value) {
  if (typeof value !== "string" || value.length > 253) return false;
  if (type === "hash") return /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(value);
  if (type === "domain") return /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(value)
    && !/\.(?:local|internal|lan|home|test|invalid|example)$/i.test(value) && !value.includes("@");
  if (type !== "ip" || !isIP(value)) return false;
  if (isIP(value) === 6) return !/^(?:::|::1$|f[cd]|fe[89ab]|ff|2001:db8:|::ffff:)/i.test(value);
  const [a,b,c] = value.split(".").map(Number);
  return !(a === 0 || a === 10 || a === 127 || a >= 224 || (a === 169 && b === 254)
    || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)
    || (a === 100 && b >= 64 && b <= 127) || (a === 198 && [18,19].includes(b))
    || (a === 192 && b === 0) || (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113));
}

export function classifyReputation(attributes, now = new Date().toISOString()) {
  const a = attributes || {};
  const stats = a.last_analysis_stats || {};
  const malicious = Number(stats.malicious || 0), suspicious = Number(stats.suspicious || 0);
  const gti = a.gti_assessment || {};
  const text = JSON.stringify(gti.verdict || gti.threat_severity || "").toLowerCase();
  const score = Number(gti.threat_score?.value ?? gti.threat_score ?? a.threat_score ?? 0);
  const verdict = /malicious/.test(text) || malicious >= 3 || score >= 70 ? "malicious"
    : /suspicious/.test(text) || malicious > 0 || suspicious > 0 || score >= 20 || Number(a.reputation || 0) < 0 ? "suspicious"
      : /benign|harmless/.test(text) ? "benign" : "undetected";
  return { verdict, score: Number.isFinite(score) ? score : null, malicious, suspicious,
    vendors: Object.values(stats).reduce((total, count) => total + Number(count || 0), 0),
    communityReputation: Number(a.reputation || 0), status: "scored", checkedAt: now,
    analysisAt: a.last_analysis_date ? new Date(a.last_analysis_date * 1000).toISOString() : null,
    source: "Google Threat Intelligence / VirusTotal", gtiVerdict: text || null };
}

export async function enrichQueue(store, runtime, fetcher = fetch, now = new Date().toISOString()) {
  if (!runtime.gtiKey) return { configured: false, processed: 0 };
  let processed = 0;
  const changed = [];
  for (const job of store.reputationJobs(now, 8)) {
    const endpoint = { ip: "ip_addresses", domain: "domains", hash: "files" }[job.type];
    let result, retrySeconds = Math.min(3600, 30 * 2 ** Math.min(job.attempts, 7));
    try {
      const response = await fetcher(`https://www.virustotal.com/api/v3/${endpoint}/${encodeURIComponent(job.value)}`, {
        headers: { "x-apikey": runtime.gtiKey }, signal: AbortSignal.timeout(10000), redirect: "error"
      });
      if (response.status === 404) { result = { verdict: "unknown", status: "not_found", checkedAt: now }; retrySeconds = 3600; }
      else if (response.status === 429) { result = { ...job.body, status: "rate_limited", error: "GTI rate limit", checkedAt: now }; retrySeconds = Math.max(retrySeconds, 60, Math.min(86400, Number(response.headers.get("retry-after")) || 0)); }
      else if (response.status === 401 || response.status === 403) { result = { ...job.body, status: "unauthorized", error: "GTI key or entitlement rejected", checkedAt: now }; retrySeconds = 3600; }
      else if (!response.ok) throw new Error(`GTI HTTP ${response.status}`);
      else {
        const attributes = (await response.json()).data?.attributes;
        if (!attributes || typeof attributes !== "object" || Array.isArray(attributes)
          || !(attributes.last_analysis_stats && typeof attributes.last_analysis_stats === "object" || attributes.gti_assessment && typeof attributes.gti_assessment === "object")) {
          throw new Error("GTI returned no usable assessment; the lookup is not a clean verdict.");
        }
        result = classifyReputation(attributes, now); retrySeconds = result.verdict === "undetected" ? 21600 : 3600;
        changed.push(job.key);
      }
    } catch (error) { result = { ...job.body, status: "unavailable", error: error.message, checkedAt: now }; }
    store.reputationResult(job, result, new Date(Date.parse(now) + retrySeconds * 1000).toISOString());
    processed++;
    if (["rate_limited", "unauthorized"].includes(result.status)) break;
  }
  return { configured: true, processed, changed };
}
