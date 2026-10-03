import { z } from "zod";

const field = z.string().regex(/^[a-zA-Z0-9.@-][a-zA-Z0-9_.@-]{0,127}$/);
const pitId = z.string().min(1).max(16384);
export const relayPolicySchema = z.object({
  indexPattern: z.string().min(1).max(512).refine(value => value.split(",").every(part => /^[a-zA-Z0-9_][a-zA-Z0-9_.*-]*$/.test(part))),
  timestampField: field,
  infrastructureField: field
}).strict();
export type RelayPolicy = z.infer<typeof relayPolicySchema>;

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
  z.object({ kind: z.literal("openPit"), indexPattern: relayPolicySchema.shape.indexPattern }).strict(),
  z.object({ kind: z.literal("closePit"), id: pitId }).strict(),
  z.object({ kind: z.literal("fieldCaps"), indexPattern: relayPolicySchema.shape.indexPattern, fields: z.array(field).min(1).max(100) }).strict(),
  z.object({ kind: z.literal("evidence"), index: z.string().max(255).regex(/^(?:[a-zA-Z0-9_]|\.ds-)[a-zA-Z0-9_.-]+$/), id: z.string().min(1).max(2048) }).strict(),
  z.object({ kind: z.literal("search"), body: z.object({
    pit: z.object({ id: pitId, keep_alive: z.literal("10m") }).strict(),
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
  }), spaceId: z.string().max(128), policy: relayPolicySchema
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
  "dns.*", "url.*", "file.*", "process.*", "network.*", "rule.*", "threat.*", "related.*", "message", "log.*"];
