import { fileURLToPath } from "node:url";

export const defaults = {
  enabled: false, intervalMinutes: 5, overlapMinutes: 5, maxEventsPerRun: 25000,
  pageSize: 500, timezone: "Europe/Tirane", baselineDays: 7, retentionDays: 30,
  indexPattern: "logs-*", timestampField: "@timestamp", infrastructureField: "observer.name",
  autoAlertMinPriority: 80, autoInvestigate: true, huntEnabled: false, query: "", assets: [], accounts: [], exceptions: [],
  scanMinAttempts: 30, scanMinTargets: 5, scanMinPorts: 10, authFailures: 10,
  beaconMinConnections: 8, beaconMaxCv: 0.15, exfilMinBytes: 52428800, exfilRatio: 5
};

export function validateConfig(value) {
  const c = { ...defaults, ...value };
  const allowed = new Set(Object.keys(defaults));
  if (Object.keys(value).some(key => !allowed.has(key))) throw new Error("Unknown agent setting.");
  for (const [name, min, max] of [["intervalMinutes", 1, 60], ["overlapMinutes", 1, 60],
    ["maxEventsPerRun", 500, 100000], ["pageSize", 100, 1000], ["baselineDays", 3, 90],
    ["retentionDays", 1, 90], ["autoAlertMinPriority", 0, 100], ["scanMinAttempts", 5, 10000],
    ["scanMinTargets", 2, 1000], ["scanMinPorts", 3, 1000], ["authFailures", 3, 1000],
    ["beaconMinConnections", 8, 1000], ["exfilMinBytes", 1048576, 1e12], ["exfilRatio", 2, 1000]]) {
    if (!Number.isInteger(c[name]) || c[name] < min || c[name] > max) throw new Error(`Invalid ${name}: expected ${min}-${max}.`);
  }
  if (typeof c.enabled !== "boolean") throw new Error("enabled must be boolean.");
  if (typeof c.autoInvestigate !== "boolean") throw new Error("autoInvestigate must be boolean.");
  if (typeof c.huntEnabled !== "boolean") throw new Error("huntEnabled must be boolean.");
  if (typeof c.beaconMaxCv !== "number" || c.beaconMaxCv < 0 || c.beaconMaxCv > 0.5) throw new Error("Invalid beaconMaxCv.");
  if (!/^[a-zA-Z0-9_.*,-]{1,512}$/.test(c.indexPattern) || c.indexPattern.startsWith(".")) throw new Error("Invalid log index pattern.");
  for (const key of ["timestampField", "infrastructureField"]) {
    if (!/^[a-zA-Z0-9_.@-]{1,128}$/.test(c[key])) throw new Error(`Invalid ${key}.`);
  }
  new Intl.DateTimeFormat("en", { timeZone: c.timezone }).format();
  if (typeof c.query !== "string" || c.query.length > 2000) throw new Error("Invalid query_string expression.");
  for (const key of ["assets", "accounts", "exceptions"]) {
    if (!Array.isArray(c[key]) || c[key].length > 500) throw new Error(`Invalid ${key} list (maximum 500).`);
  }
  for (const a of c.assets) {
    if (typeof a.name !== "string" || !Array.isArray(a.ips) || a.ips.some(ip => typeof ip !== "string")) throw new Error("Assets require a name and IP list.");
  }
  for (const a of c.accounts) {
    if (typeof a.identity !== "string" || !["human", "service"].includes(a.kind)) throw new Error("Accounts require identity and human/service kind.");
  }
  for (const e of c.exceptions) {
    if (!["ip", "domain", "hash", "identity"].includes(e.indicatorType) || typeof e.indicatorValue !== "string" || !e.reason) throw new Error("Exceptions require type, value and reason.");
    if (e.expiresAt && !Number.isFinite(Date.parse(e.expiresAt))) throw new Error("Invalid exception expiration.");
  }
  return c;
}

export function runtimeConfig(env = process.env) {
  const elasticUrl = env.SOC_WATCH_ELASTIC_URL || "";
  if (elasticUrl) {
    const url = new URL(elasticUrl);
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.search || url.hash) throw new Error("Invalid Elasticsearch URL.");
    if (url.protocol === "http:" && env.SOC_WATCH_ALLOW_HTTP_ELASTIC !== "true") throw new Error("Use HTTPS Elasticsearch, or explicitly set SOC_WATCH_ALLOW_HTTP_ELASTIC=true on a trusted private network.");
  }
  return {
    elasticUrl: elasticUrl.replace(/\/$/, ""), elasticApiKey: env.SOC_WATCH_ELASTIC_API_KEY || "",
    gtiKey: env.SOC_WATCH_GTI_API_KEY || "", token: env.SOC_WATCH_AGENT_TOKEN || "",
    analysts: JSON.parse(env.SOC_WATCH_ANALYST_TOKENS || "[]"),
    dataDir: env.SOC_WATCH_DATA_DIR || fileURLToPath(new URL("../../.data/", import.meta.url)),
    publicOrigin: env.SOC_WATCH_PUBLIC_ORIGIN || "", feeds: {
      threatfox: env.SOC_WATCH_THREATFOX_KEY || "", malwarebazaar: env.SOC_WATCH_MALWAREBAZAAR_KEY || ""
    }
  };
}
