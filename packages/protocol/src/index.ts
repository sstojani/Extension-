import { z } from "zod";

export const BRIDGE_VERSION = 1 as const;

export const bridgeActions = [
  "bridge.ping",
  "kibana.status",
  "dataViews.list",
  "dataViews.get",
  "fleet.summary",
  "fleet.list",
  "fleet.get",
  "fleet.incomingData",
  "ioc.search",
  "ioc.bulkSearch",
  "threatIntel.dailyHunt",
  "threatRadar.analyze",
  "threatRadar.agent.configure",
  "threatRadar.agent.run",
  "config.get",
  "config.save",
  "logs.search",
  "logs.lastSeen",
  "logs.volume",
  "infrastructure.list",
  "infrastructure.get",
  "infrastructure.health",
  "watchlist.list",
  "watchlist.add",
  "watchlist.remove",
  "watchlist.check"
] as const;

export type BridgeAction = (typeof bridgeActions)[number];

export const errorCodes = [
  "BRIDGE_NOT_INSTALLED",
  "INVALID_REQUEST",
  "INVALID_ORIGIN",
  "INVALID_IOC",
  "INVALID_AGENT_ID",
  "INVALID_TIME_RANGE",
  "KIBANA_UNREACHABLE",
  "KIBANA_AUTH_REQUIRED",
  "KIBANA_FORBIDDEN",
  "KIBANA_NOT_FOUND",
  "FLEET_UNAVAILABLE",
  "FLEET_FORBIDDEN",
  "SEARCH_FAILED",
  "SEARCH_TIMEOUT",
  "DATA_VIEW_NOT_FOUND",
  "RATE_LIMITED",
  "RESULT_TOO_LARGE",
  "INTERNAL_ERROR"
] as const;

export type BridgeErrorCode = (typeof errorCodes)[number];

export interface BridgeRequest<T = unknown> {
  version: 1;
  requestId: string;
  action: BridgeAction;
  params: T;
}

export interface BridgeSuccess<T = unknown> {
  version: 1;
  requestId: string;
  success: true;
  data: T;
  durationMs?: number;
}

export interface BridgeFailure {
  version: 1;
  requestId: string;
  success: false;
  error: {
    code: BridgeErrorCode;
    message: string;
    details?: unknown;
  };
  durationMs?: number;
}

export type BridgeResponse<T = unknown> = BridgeSuccess<T> | BridgeFailure;

export interface BridgeConfig {
  kibanaBaseUrl: string;
  spaceId?: string;
  selectedDataViewId?: string;
  indexPattern?: string;
  timestampField: string;
  infrastructureField?: string;
  fieldMapping: IOCFieldMapping;
  monitoringIntervalMinutes: number;
}

export interface IOCFieldMapping {
  ip: string[];
  domain: string[];
  url: string[];
  md5: string[];
  sha1: string[];
  sha256: string[];
}

export interface FleetSummary {
  online: number;
  offline: number;
  error: number;
  inactive: number;
  updating: number;
  unenrolled: number;
  active: number;
  all: number;
  other: number;
}

export interface SanitizedAgentComponent {
  id?: string;
  type?: string;
  status?: string;
  message?: string;
  units?: SanitizedAgentComponent[];
}

export interface SanitizedFleetAgent {
  id: string;
  status: string;
  active: boolean;
  hostname?: string;
  hostIps?: string[];
  agentVersion?: string;
  lastCheckin?: string;
  enrolledAt?: string;
  policyId?: string;
  policyRevision?: number;
  components?: SanitizedAgentComponent[];
  metrics?: {
    cpu?: number;
    memory?: number;
  };
}

export interface KibanaStatus {
  version?: string;
  name?: string;
  overall?: string;
  elasticsearch?: string;
  savedObjects?: string;
}

export interface DataViewSummary {
  id: string;
  name?: string;
  title: string;
  timeFieldName?: string;
}

const nonEmptyString = z.string().min(1).max(2048);

export const bridgeRequestSchema = z.object({
  version: z.literal(BRIDGE_VERSION),
  requestId: z.string().uuid().or(z.string().min(8).max(128)),
  action: z.enum(bridgeActions),
  params: z.unknown().default({})
});

export const fleetSummaryParamsSchema = z
  .object({
    policyId: z.string().max(256).optional(),
    policyIds: z.array(z.string().max(256)).max(100).optional(),
    kuery: z.string().max(2000).optional()
  })
  .strict();

export const fleetListParamsSchema = z
  .object({
    page: z.number().int().min(1).max(10000).default(1),
    perPage: z.number().int().min(1).max(1000).default(100),
    kuery: z.string().max(2000).optional(),
    showInactive: z.boolean().default(true),
    withMetrics: z.boolean().default(true),
    getStatusSummary: z.boolean().default(false)
  })
  .strict();

export const fleetGetParamsSchema = z
  .object({
    agentId: z.string().regex(/^[a-zA-Z0-9:_-]{3,256}$/),
    withMetrics: z.boolean().default(true)
  })
  .strict();

export const dataViewGetParamsSchema = z
  .object({
    viewId: z.string().min(1).max(512)
  })
  .strict();

export const iocSearchParamsSchema = z
  .object({
    value: nonEmptyString,
    indexPattern: z.string().min(1).max(512),
    timestampField: z.string().min(1).max(256).default("@timestamp"),
    from: z.string().min(1).max(128).default("now-24h"),
    to: z.string().min(1).max(128).default("now"),
    size: z.number().int().min(0).max(100).default(25),
    fieldMapping: z
      .object({
        ip: z.array(z.string()).max(20).default(["source.ip", "destination.ip", "client.ip", "server.ip", "host.ip"]),
        domain: z.array(z.string()).max(20).default(["url.domain", "dns.question.name", "destination.domain"]),
        url: z.array(z.string()).max(20).default(["url.full", "url.original"]),
        md5: z.array(z.string()).max(20).default(["file.hash.md5"]),
        sha1: z.array(z.string()).max(20).default(["file.hash.sha1"]),
        sha256: z.array(z.string()).max(20).default(["file.hash.sha256"])
      })
      .default({})
  })
  .strict();

export const dailyIocHuntParamsSchema = z
  .object({
    indexPattern: z.string().min(1).max(512),
    timestampField: z.string().min(1).max(256).default("@timestamp"),
    from: z.string().min(1).max(128).default("now-30d"),
    to: z.string().min(1).max(128).default("now"),
    size: z.number().int().min(0).max(25).default(5),
    maxIocs: z.number().int().min(1).max(5000).default(1000)
  })
  .strict();

export const threatRadarAnalyzeParamsSchema = z
  .object({
    indexPattern: z.string().min(1).max(512),
    timestampField: z.string().min(1).max(256).default("@timestamp"),
    from: z.string().min(1).max(128).default("now-15m"),
    to: z.string().min(1).max(128).default("now"),
    size: z.number().int().min(1).max(50).default(15)
  })
  .strict();

export const threatRadarAgentConfigSchema = z
  .object({
    enabled: z.boolean().default(true),
    intervalMinutes: z.number().int().min(5).max(60).default(15),
    indexPattern: z.string().min(1).max(512).default("logs-*"),
    timestampField: z.string().min(1).max(256).default("@timestamp"),
    candidateExclusions: z.array(z.string().trim().min(1).max(256)).max(200).default([])
  })
  .strict();

export function ok<T>(requestId: string, data: T, durationMs?: number): BridgeSuccess<T> {
  return withOptional({ version: BRIDGE_VERSION, requestId, success: true, data }, "durationMs", durationMs);
}

export function fail(
  requestId: string,
  code: BridgeErrorCode,
  message: string,
  durationMs?: number,
  details?: unknown
): BridgeFailure {
  const error = withOptional({ code, message }, "details", details);
  return withOptional({ version: BRIDGE_VERSION, requestId, success: false, error }, "durationMs", durationMs);
}

export function parseBridgeRequest(value: unknown): BridgeRequest {
  return bridgeRequestSchema.parse(value) as BridgeRequest;
}

export function isAllowedOrigin(senderUrl: string | undefined, allowedOrigins: readonly string[]): boolean {
  if (!senderUrl) return false;
  try {
    const url = new URL(senderUrl);
    return allowedOrigins.some((allowedOrigin) => {
      const allowedUrl = new URL(allowedOrigin);
      return url.protocol === allowedUrl.protocol && url.hostname === allowedUrl.hostname;
    });
  } catch {
    return false;
  }
}

export function kibanaApiPath(path: string, spaceId?: string): string {
  const cleanPath = path.replace(/^\/+/, "");
  if (!spaceId || spaceId === "default") {
    return `/api/${cleanPath.replace(/^api\//, "")}`;
  }
  return `/s/${encodeURIComponent(spaceId)}/api/${cleanPath.replace(/^api\//, "")}`;
}

export function sanitizeFleetSummary(raw: unknown): FleetSummary {
  const results = typeof raw === "object" && raw !== null && "results" in raw ? (raw as { results: unknown }).results : raw;
  const source = typeof results === "object" && results !== null ? (results as Record<string, unknown>) : {};
  return {
    online: readNumber(source.online),
    offline: readNumber(source.offline),
    error: readNumber(source.error),
    inactive: readNumber(source.inactive),
    updating: readNumber(source.updating),
    unenrolled: readNumber(source.unenrolled),
    active: readNumber(source.active),
    all: readNumber(source.all),
    other: readNumber(source.other)
  };
}

export function sanitizeFleetAgent(raw: unknown): SanitizedFleetAgent {
  const agent = typeof raw === "object" && raw !== null && "item" in raw ? (raw as { item: unknown }).item : raw;
  const record = typeof agent === "object" && agent !== null ? (agent as Record<string, unknown>) : {};
  const localMetadata = readRecord(record.local_metadata);
  const host = readRecord(localMetadata.host);
  const elastic = readRecord(localMetadata.elastic);
  const agentInfo = readRecord(elastic.agent);
  const metrics = readRecord(record.metrics);

  const sanitized: SanitizedFleetAgent = {
    id: readString(record.id) ?? readString(record.agent_id) ?? "unknown",
    status: readString(record.status) ?? "unknown",
    active: readBoolean(record.active) ?? false,
  };

  const metricsOut: { cpu?: number; memory?: number } = {};
  setOptional(metricsOut, "cpu", readNumberOrUndefined(metrics.cpu));
  setOptional(metricsOut, "memory", readNumberOrUndefined(metrics.memory));

  setOptional(sanitized, "hostname", readString(host.hostname) ?? readString(record.hostname));
  setOptional(sanitized, "hostIps", readStringArray(host.ip));
  setOptional(sanitized, "agentVersion", readString(agentInfo.version) ?? readString(record.agent_version));
  setOptional(sanitized, "lastCheckin", readString(record.last_checkin));
  setOptional(sanitized, "enrolledAt", readString(record.enrolled_at));
  setOptional(sanitized, "policyId", readString(record.policy_id));
  setOptional(sanitized, "policyRevision", readNumberOrUndefined(record.policy_revision));
  setOptional(sanitized, "components", sanitizeComponents(record.components));
  if (Object.keys(metricsOut).length > 0) setOptional(sanitized, "metrics", metricsOut);
  return sanitized;
}

export function mapKibanaStatus(raw: unknown): KibanaStatus {
  const record = typeof raw === "object" && raw !== null ? (raw as Record<string, unknown>) : {};
  const version = readRecord(record.version);
  const status = readRecord(record.status);
  const overall = readRecord(status.overall);
  const core = readRecord(status.core);
  const elasticsearch = readRecord(core.elasticsearch);
  const savedObjects = readRecord(core.savedObjects);
  const mapped: KibanaStatus = {};
  setOptional(mapped, "version", readString(version.number));
  setOptional(mapped, "name", readString(record.name));
  setOptional(mapped, "overall", readString(overall.level));
  setOptional(mapped, "elasticsearch", readString(elasticsearch.level));
  setOptional(mapped, "savedObjects", readString(savedObjects.level));
  return mapped;
}

export function buildQuery(params: Record<string, string | number | boolean | string[] | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined) continue;
    if (Array.isArray(value)) {
      for (const item of value) search.append(key, item);
    } else {
      search.set(key, String(value));
    }
  }
  const query = search.toString();
  return query ? `?${query}` : "";
}

function sanitizeComponents(value: unknown): SanitizedAgentComponent[] | undefined {
  if (!Array.isArray(value)) return undefined;
  return value.slice(0, 100).map((component) => {
    const record = typeof component === "object" && component !== null ? (component as Record<string, unknown>) : {};
    const sanitized: SanitizedAgentComponent = {};
    setOptional(sanitized, "id", readString(record.id));
    setOptional(sanitized, "type", readString(record.type));
    setOptional(sanitized, "status", readString(record.status));
    setOptional(sanitized, "message", readString(record.message));
    setOptional(sanitized, "units", sanitizeComponents(record.units));
    return sanitized;
  });
}

function readRecord(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null ? (value as Record<string, unknown>) : {};
}

function readString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function readBoolean(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

function readStringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  return value.filter((item): item is string => typeof item === "string").slice(0, 32);
}

function readNumber(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

function readNumberOrUndefined(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function setOptional<T extends object, K extends keyof T>(target: T, key: K, value: T[K] | undefined): void {
  if (value !== undefined) target[key] = value;
}

function withOptional<T extends object, K extends string, V>(
  target: T,
  key: K,
  value: V | undefined
): T & Partial<Record<K, V>> {
  if (value === undefined) return target;
  return { ...target, [key]: value } as T & Partial<Record<K, V>>;
}
