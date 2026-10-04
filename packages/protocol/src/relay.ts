import { z } from "zod";

const field = z.string().regex(/^[a-zA-Z0-9.@-][a-zA-Z0-9_.@-]{0,127}$/);
export const RELAY_MAX_PIT_ID_BYTES = 1024 * 1024;
// PIT IDs are opaque and grow with shard coverage; bound bytes, not index count.
export const relayPitIdSchema = z.string().min(1).max(RELAY_MAX_PIT_ID_BYTES)
  .refine(value => new TextEncoder().encode(value).length <= RELAY_MAX_PIT_ID_BYTES, "Snapshot ID exceeds the byte limit");
export const relayPolicySchema = z.object({
  indexPattern: z.string().min(1).max(512).refine(value => value.split(",").every(part => /^[a-zA-Z0-9_][a-zA-Z0-9_.*-]*$/.test(part))),
  timestampField: field,
  infrastructureField: field
}).strict();
export type RelayPolicy = z.infer<typeof relayPolicySchema>;

export function hasUsableGtiAssessment(value: unknown): boolean {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const a = value as Record<string, unknown>;
  const stats = a.last_analysis_stats as Record<string, unknown> | undefined;
  const gti = a.gti_assessment as Record<string, unknown> | undefined;
  const unwrap = (v: unknown): unknown => v && typeof v === "object" ? (v as Record<string, unknown>).value : v;
  return !!stats && !Array.isArray(stats) && ["malicious", "suspicious", "harmless", "undetected"].some(name => typeof stats[name] === "number" && Number.isInteger(stats[name]) && stats[name]! >= 0)
    || !!gti && !Array.isArray(gti) && (/^(?:VERDICT_)?(?:UNKNOWN|BENIGN|UNDETECTED|SUSPICIOUS|MALICIOUS)$/i.test(String(unwrap(gti.verdict) ?? ""))
      || typeof unwrap(gti.threat_score) === "number" && Number.isFinite(unwrap(gti.threat_score)) && Number(unwrap(gti.threat_score)) >= 0 && Number(unwrap(gti.threat_score)) <= 100);
}

export function isPublicReputationTarget(type: string, value: string): boolean {
  if (value.length > 253) return false;
  if (type === "hash") return /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(value);
  if (type === "domain") return /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(value)
    && !/\.(?:local|internal|lan|home|test|invalid|example)$/i.test(value);
  if (type !== "ip" || !z.string().ip().safeParse(value).success) return false;
  if (value.includes(":")) {
    const canonical = new URL(`http://[${value}]`).hostname.slice(1, -1);
    return !/^(?:::|f[cd]|fe[89ab]|ff|2001:db8:)/i.test(canonical);
  }
  const [a, b, c] = value.split(".").map(Number);
  return !(a === 0 || a === 10 || a === 127 || a! >= 224 || (a === 169 && b === 254)
    || (a === 172 && b! >= 16 && b! <= 31) || (a === 192 && b === 168) || (a === 100 && b! >= 64 && b! <= 127)
    || (a === 198 && [18, 19].includes(b!)) || (a === 192 && b === 0) || (a === 198 && b === 51 && c === 100)
    || (a === 203 && b === 0 && c === 113));
}
export const relayReputationTargetSchema = z.object({ type: z.enum(["ip", "domain", "hash"]), value: z.string().min(1).max(253) })
  .strict().refine(target => isPublicReputationTarget(target.type, target.value), "Only public IPs, domains and hashes may be looked up");
export const relayReputationResultSchema = z.object({
  status: z.enum(["scored", "not_found", "not_configured", "pending", "rate_limited", "unauthorized", "unavailable"]),
  verdict: z.enum(["unknown", "benign", "undetected", "suspicious", "malicious"]),
  score: z.number().min(0).max(100).nullable().optional(), malicious: z.number().int().nonnegative().max(10000).optional(),
  suspicious: z.number().int().nonnegative().max(10000).optional(), vendors: z.number().int().nonnegative().max(10000).optional(),
  gtiVerdict: z.string().max(200).nullable().optional(), cached: z.boolean().optional(), checkedAt: z.string().datetime().optional()
}).strict().refine(result => result.status !== "scored" || result.score !== undefined && result.malicious !== undefined && result.suspicious !== undefined,
  "A scored report requires assessment fields");

const scalar = (value: unknown) => typeof value === "string" && value.length <= 2048 || typeof value === "number" && Number.isFinite(value) || typeof value === "boolean";
const object = (value: unknown): value is Record<string, unknown> => !!value && typeof value === "object" && !Array.isArray(value);
// Accept only the small query DSL used by collection, watches and investigations.
function readQuery(value: unknown, depth = 0, budget = { nodes: 0 }): boolean {
  if (++budget.nodes > 4096 || depth > 12 || !object(value) || Object.keys(value).length !== 1) return false;
  const [kind, params] = Object.entries(value)[0]!;
  if (!object(params)) return false;
  if (kind === "bool") return Object.entries(params).every(([key, clauses]) => {
    if (key === "minimum_should_match") return clauses === 1;
    return ["filter", "must", "must_not", "should"].includes(key) && Array.isArray(clauses) && clauses.length <= 1000
      && clauses.every(clause => readQuery(clause, depth + 1, budget));
  });
  if (kind === "query_string") return typeof params.query === "string" && params.query.length <= 2000
    && params.lenient === false && params.allow_leading_wildcard === false && Object.keys(params).length === 3;
  if (!["range", "term", "terms", "wildcard"].includes(kind) || Object.keys(params).length !== 1) return false;
  const [name, term] = Object.entries(params)[0]!;
  if (!field.safeParse(name).success) return false;
  if (kind === "terms") return Array.isArray(term) && term.length <= 500 && term.every(scalar);
  if (kind === "range") return object(term) && Object.keys(term).length > 0
    && Object.entries(term).every(([key, v]) => ["gte", "lte", "gt", "lt"].includes(key) && scalar(v));
  return scalar(term) || object(term) && scalar(term.value)
    && Object.entries(term).every(([key, v]) => key === "value" || key === "case_insensitive" && typeof v === "boolean");
}
export const relayOperationSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("reputation"), target: relayReputationTargetSchema }).strict(),
  z.object({ kind: z.literal("openPit"), indexPattern: relayPolicySchema.shape.indexPattern }).strict(),
  z.object({ kind: z.literal("closePit"), id: relayPitIdSchema }).strict(),
  z.object({ kind: z.literal("fieldCaps"), indexPattern: relayPolicySchema.shape.indexPattern, fields: z.array(field).min(1).max(100) }).strict(),
  z.object({ kind: z.literal("evidence"), index: z.string().max(255).regex(/^(?:[a-zA-Z0-9_]|\.ds-)[a-zA-Z0-9_.-]+$/), id: z.string().min(1).max(2048) }).strict(),
  z.object({ kind: z.literal("live"), indexPattern: relayPolicySchema.shape.indexPattern,
    stage: z.enum(["scans", "context", "security"]), from: z.string().datetime(), to: z.string().datetime(),
    query: z.string().max(2000), sources: z.array(z.string().ip()).max(32).optional()
  }).strict(),
  z.object({ kind: z.literal("search"), body: z.object({
    pit: z.object({ id: relayPitIdSchema, keep_alive: z.literal("10m") }).strict(),
    size: z.number().int().min(1).max(500), track_total_hits: z.literal(true), timeout: z.literal("20s"),
    query: z.unknown().refine(value => readQuery(value), "Unsupported read query"),
    sort: z.array(z.record(z.unknown())).length(2),
    search_after: z.array(z.union([z.string().max(1024), z.number().finite()])).length(2).optional()
  }).strict() }).strict()
]);
export type RelayOperation = z.infer<typeof relayOperationSchema>;
export const relaySourceSchema = z.object({
  kibanaBaseUrl: z.string().url().max(2048).refine(value => {
    const url = new URL(value);
    return ["https:", "http:"].includes(url.protocol) && !url.username && !url.password && !url.search && !url.hash;
  }), spaceId: z.string().max(128), policy: relayPolicySchema, reputationConfigured: z.boolean().optional(), reputationRevision: z.string().uuid().optional()
}).strict();
export type RelaySource = z.infer<typeof relaySourceSchema>;
export const RELAY_MAX_BYTES = 8 * 1024 * 1024;
export function relayFieldCapsPath(indexPattern: string, fields: string[]): string {
  const query = new URLSearchParams({ fields: fields.join(","), include_unmapped: "true" });
  return `/${encodeURIComponent(indexPattern)}/_field_caps?${query}`;
}
export function relayIndexAllowed(index: string, pattern: string): boolean {
  if (typeof index !== "string" || index.startsWith(".") && !index.startsWith(".ds-")) return false;
  const name = index.startsWith(".ds-") ? index.slice(4).replace(/-\d{4}\.\d{2}\.\d{2}-\d+$/, "") : index;
  return pattern.split(",").some(part => new RegExp(`^${part.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replaceAll("*", ".*")}$`).test(name));
}
export function validateRelayOperation(value: unknown, policy: RelayPolicy): RelayOperation {
  const operation = relayOperationSchema.parse(value);
  if ("indexPattern" in operation && operation.indexPattern !== policy.indexPattern) throw new Error("Relay index scope changed; reconnect with the saved policy.");
  if (operation.kind === "evidence" && !relayIndexAllowed(operation.index, policy.indexPattern)) throw new Error("Evidence index is outside the authorized log scope.");
  if (operation.kind === "live") {
    const duration = Date.parse(operation.to) - Date.parse(operation.from);
    if (duration <= 0 || duration > 15 * 60000) throw new Error("Live queries require a fixed window of at most 15 minutes.");
    if (operation.stage === "context" ? !operation.sources?.length : operation.sources !== undefined) throw new Error("Only live context queries accept candidate source IPs.");
  }
  if (operation.kind === "search") {
    const sort = operation.body.sort;
    if (JSON.stringify(sort) !== JSON.stringify([{ [policy.timestampField]: { order: "asc", unmapped_type: "date" } }, { _shard_doc: "asc" }])) throw new Error("Unsupported relay sort.");
    const filters = (operation.body.query as { bool?: { filter?: unknown[] } })?.bool?.filter;
    if (!filters?.some(value => {
      if (!object(value) || !object(value.range)) return false;
      const range = value.range[policy.timestampField];
      return object(range) && typeof range.gte === "string" && typeof range.lte === "string"
        && Number.isFinite(Date.parse(range.gte)) && Number.isFinite(Date.parse(range.lte)) && Date.parse(range.gte) <= Date.parse(range.lte);
    })) throw new Error("Relay searches require a fixed time window.");
  }
  return operation;
}
export const relaySourceFields = (policy: RelayPolicy) => [policy.timestampField, policy.infrastructureField,
  "event.*", "source.*", "destination.*", "client.*", "server.*", "host.*", "observer.*", "agent.*", "user.*",
  "dns.*", "url.*", "file.*", "process.*", "network.*", "rule.*", "threat.*", "related.*", "kibana.alert.*", "message", "log.*"];

// The extension constructs these fixed templates itself; callers cannot supply aggregation DSL.
export function relayLiveSearch(value: unknown, policy: RelayPolicy): Record<string, unknown> {
  const operation = validateRelayOperation(value, policy);
  if (operation.kind !== "live") throw new Error("Expected a live operation.");
  const terms = (name: string, size: number) => ({ terms: { field: name, size, shard_size: size * 3, show_term_doc_count_error: true } });
  const proof = (size: number) => ({ top_hits: { size, sort: [{ [policy.timestampField]: { order: "desc", unmapped_type: "date" } }], _source: relaySourceFields(policy) } });
  const blocked = { bool: { should: [{ terms: { "event.action": ["deny", "denied", "drop", "dropped", "block", "blocked", "reject", "rejected", "connection_denied", "connection-denied", "connection_blocked", "connection-blocked", "firewall_denied", "prevented", "quarantined"] } },
    { term: { "event.type": "denied" } }], minimum_should_match: 1 } };
  const filter: unknown[] = [{ range: { [policy.timestampField]: { gte: operation.from, lte: operation.to } } }];
  if (operation.query) filter.push({ query_string: { query: operation.query, lenient: false, allow_leading_wildcard: false } });
  let aggs: Record<string, unknown>;
  if (operation.stage === "scans") {
    filter.push({ term: { "event.category": "network" } }, blocked);
    // Remove internal/resolver chatter before selecting the busiest source buckets.
    const nonPublic = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
      "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3",
      "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "2001:db8::/32"];
    filter.push({ bool: { must_not: [...nonPublic.map(cidr => ({ term: { "source.ip": cidr } })),
      { terms: { "source.ip": ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
        "208.67.222.222", "208.67.220.220", "94.140.14.14", "94.140.15.15", "2606:4700:4700::1111", "2606:4700:4700::1001",
        "2001:4860:4860::8888", "2001:4860:4860::8844", "2620:fe::fe", "2620:fe::9"] } },
      { term: { "source.port": 53 } }, { term: { "destination.port": 53 } }, { term: { "network.protocol": "dns" } }] } });
    aggs = { sources: { ...terms("source.ip", 32), aggs: {
      ports: terms("destination.port", 128), targets: terms("destination.ip", 128),
      proof: proof(5)
    } } };
  } else if (operation.stage === "context") {
    filter.push({ terms: { "source.ip": operation.sources } }, { term: { "event.category": "network" } },
      { bool: { should: [{ terms: { "event.action": ["accept", "accepted", "allow", "allowed", "connection-started", "connection-finished"] } },
        { term: { "event.outcome": "success" } }], minimum_should_match: 1, must_not: [blocked, { term: { "event.outcome": "failure" } }] } });
    aggs = { sources: { ...terms("source.ip", 32), aggs: { proof: proof(3) } } };
  } else {
    const authentication = { term: { "event.category": "authentication" } };
    const signals = { bool: { should: [{ term: { "event.kind": "alert" } }, { exists: { field: "threat.indicator.type" } }], minimum_should_match: 1 } };
    filter.push({ bool: { should: [authentication, signals], minimum_should_match: 1 } });
    aggs = {
      authentication: { filter: authentication, aggs: {
        users: { ...terms("user.name", 20), aggs: { proof: proof(20) } }
      } },
      signals: { filter: signals, aggs: { proof: proof(100) } }
    };
  }
  return { size: 0, track_total_hits: true, timeout: "15s", query: { bool: { filter } }, aggs };
}
