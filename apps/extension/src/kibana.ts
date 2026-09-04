import {
  buildQuery,
  dataViewGetParamsSchema,
  fleetGetParamsSchema,
  fleetListParamsSchema,
  fleetSummaryParamsSchema,
  iocSearchParamsSchema,
  kibanaApiPath,
  mapKibanaStatus,
  sanitizeFleetAgent,
  sanitizeFleetSummary,
  threatRadarAgentConfigSchema,
  threatRadarAnalyzeParamsSchema,
  type BridgeErrorCode,
  type DataViewSummary,
  type KibanaStatus,
  type SanitizedFleetAgent
} from "@soc-watch/protocol";
import { classifyIOC } from "@soc-watch/ioc";
import { DEFAULT_KIBANA_BASE_URL, DEFAULT_SPACE_ID } from "./config";
import { buildIOCSearchBody } from "./search";
import { isExcludedCandidate } from "./candidate-exclusions";

export class BridgeOperationError extends Error {
  constructor(
    readonly code: BridgeErrorCode,
    message: string,
    readonly details?: unknown
  ) {
    super(message);
  }
}

export interface KibanaRuntimeConfig {
  kibanaBaseUrl: string;
  spaceId: string;
}

export interface GtiIpReputation {
  verdict?: string;
  severity?: string;
  threatScore: number;
  malicious: number;
  suspicious: number;
  reputation: number;
  country?: string;
  asn: number;
  asOwner?: string;
}

type ThreatRadarRole = "source" | "destination";
type ThreatRadarSeverity = "critical" | "high" | "medium" | "low";

export interface ThreatRadarFinding {
  ip: string;
  sourceIp: string;
  destinationIp: string;
  gtiIp: string;
  role: ThreatRadarRole;
  score: number;
  severity: ThreatRadarSeverity;
  events: number;
  relatedHosts: number;
  infrastructureCount: number;
  destinationPorts: number;
  dangerousPorts: number[];
  topPorts: number[];
  actions: Array<{ key: string; count: number }>;
  datasets: Array<{ key: string; count: number }>;
  latest: ReturnType<typeof readLatestHit>;
  reasons: string[];
}

export async function readRuntimeConfig(): Promise<KibanaRuntimeConfig> {
  const stored = await chrome.storage.local.get(["kibanaBaseUrl", "spaceId"]);
  return {
    kibanaBaseUrl: typeof stored.kibanaBaseUrl === "string" ? stored.kibanaBaseUrl : DEFAULT_KIBANA_BASE_URL,
    spaceId: typeof stored.spaceId === "string" ? stored.spaceId : DEFAULT_SPACE_ID
  };
}

export async function getKibanaStatus(): Promise<KibanaStatus> {
  const config = await readRuntimeConfig();
  const raw = await kibanaFetchJson(config, kibanaApiPath("status", config.spaceId));
  return mapKibanaStatus(raw);
}

export async function getFleetSummary(params: unknown) {
  const parsed = fleetSummaryParamsSchema.parse(params);
  const config = await readRuntimeConfig();
  const raw = await kibanaFetchJson(config, kibanaApiPath(`fleet/agent_status${buildQuery(parsed)}`, config.spaceId));
  return sanitizeFleetSummary(raw);
}

export async function listFleetAgents(params: unknown): Promise<{ items: SanitizedFleetAgent[]; total?: number; page: number; perPage: number }> {
  const parsed = fleetListParamsSchema.parse(params);
  const config = await readRuntimeConfig();
  const raw = await kibanaFetchJson(config, kibanaApiPath(`fleet/agents${buildQuery(parsed)}`, config.spaceId));
  const record = asRecord(raw);
  const items = Array.isArray(record.items) ? record.items.map(sanitizeFleetAgent) : [];
  return {
    items,
    total: typeof record.total === "number" ? record.total : undefined,
    page: parsed.page,
    perPage: parsed.perPage
  };
}

export async function listAllFleetAgents(limit = 5000): Promise<SanitizedFleetAgent[]> {
  const perPage = 1000;
  const items: SanitizedFleetAgent[] = [];

  for (let page = 1; page <= Math.ceil(limit / perPage); page += 1) {
    const response = await listFleetAgents({
      page,
      perPage,
      showInactive: true,
      withMetrics: true,
      getStatusSummary: false
    });
    items.push(...response.items);

    if (response.total !== undefined && items.length >= response.total) break;
    if (response.items.length < perPage) break;
  }

  return items.slice(0, limit);
}

export async function getFleetAgent(params: unknown): Promise<SanitizedFleetAgent> {
  const parsed = fleetGetParamsSchema.parse(params);
  const config = await readRuntimeConfig();
  const query = buildQuery({ withMetrics: parsed.withMetrics });
  const path = kibanaApiPath(`fleet/agents/${encodeURIComponent(parsed.agentId)}${query}`, config.spaceId);
  return sanitizeFleetAgent(await kibanaFetchJson(config, path));
}

export async function getFleetIncomingData(params: unknown) {
  const schema = fleetGetParamsSchema.pick({ agentId: true });
  const parsed = schema.parse(params);
  const config = await readRuntimeConfig();
  return kibanaFetchJson(config, kibanaApiPath(`fleet/agent_status/data${buildQuery({ agentsIds: parsed.agentId })}`, config.spaceId));
}

export async function listDataViews(): Promise<DataViewSummary[]> {
  const config = await readRuntimeConfig();
  const raw = await kibanaFetchJson(config, kibanaApiPath("data_views", config.spaceId));
  const record = asRecord(raw);
  const views = Array.isArray(record.data_view) ? record.data_view : Array.isArray(record.data_views) ? record.data_views : [];
  return views.map((view) => {
    const item = asRecord(view);
    return {
      id: String(item.id ?? ""),
      name: typeof item.name === "string" ? item.name : undefined,
      title: String(item.title ?? ""),
      timeFieldName: typeof item.timeFieldName === "string" ? item.timeFieldName : undefined
    };
  }).filter((view) => view.id && view.title);
}

export async function getDataView(params: unknown) {
  const parsed = dataViewGetParamsSchema.parse(params);
  const config = await readRuntimeConfig();
  return kibanaFetchJson(config, kibanaApiPath(`data_views/data_view/${encodeURIComponent(parsed.viewId)}`, config.spaceId));
}

export async function searchIOC(params: unknown) {
  const parsed = iocSearchParamsSchema.parse(params);
  const classified = classifyIOC(parsed.value);
  if (classified.type === "unknown") {
    throw new BridgeOperationError("INVALID_IOC", "The indicator could not be classified.");
  }

  const config = await readRuntimeConfig();
  const body = buildIOCSearchBody({ ...parsed, ioc: classified });
  const esPath = `${parsed.indexPattern}/_search`;
  const proxyPath = kibanaApiPath(
    `console/proxy${buildQuery({ path: esPath, method: "POST" })}`,
    config.spaceId
  );
  const raw = await kibanaFetchJson(config, proxyPath, {
    method: "POST",
    body: JSON.stringify(body)
  });
  return {
    ioc: classified,
    raw
  };
}

export async function analyzeThreatRadar(params: unknown) {
  const parsed = threatRadarAnalyzeParamsSchema.parse(params);
  const config = await readRuntimeConfig();
  const body = buildThreatRadarBody(parsed);
  const esPath = `${parsed.indexPattern}/_search`;
  const proxyPath = kibanaApiPath(
    `console/proxy${buildQuery({ path: esPath, method: "POST" })}`,
    config.spaceId
  );
  const raw = await kibanaFetchJson(config, proxyPath, {
    method: "POST",
    body: JSON.stringify(body)
  });
  const stored = await chrome.storage.local.get(["googleThreatIntelApiKey", "threatRadarAgentConfig"]);
  const gtiApiKey = typeof stored.googleThreatIntelApiKey === "string" ? stored.googleThreatIntelApiKey.trim() : "";
  const agentConfig = threatRadarAgentConfigSchema.parse(stored.threatRadarAgentConfig ?? {});
  const externalSources = rankThreatRadarFindings([
    ...summarizeThreatRadarEntities(raw, "source_entities", "source"),
    ...summarizeThreatRadarEntities(raw, "client_entities", "source")
  ].filter((finding) => !isExcludedCandidate({
    ip: finding.ip,
    sourceIp: finding.sourceIp,
    destinationIp: finding.destinationIp,
    values: [...finding.actions.map((action) => action.key), ...finding.datasets.map((dataset) => dataset.key)],
    text: `${finding.latest?.message ?? ""} ${finding.reasons.join(" ")}`
  }, agentConfig.candidateExclusions)), parsed.size);
  const suspiciousDestinations = rankThreatRadarFindings([
    ...summarizeThreatRadarEntities(raw, "destination_entities", "destination"),
    ...summarizeThreatRadarEntities(raw, "server_entities", "destination")
  ].filter((finding) => !isExcludedCandidate({
    ip: finding.ip,
    sourceIp: finding.sourceIp,
    destinationIp: finding.destinationIp,
    values: [...finding.actions.map((action) => action.key), ...finding.datasets.map((dataset) => dataset.key)],
    text: `${finding.latest?.message ?? ""} ${finding.reasons.join(" ")}`
  }, agentConfig.candidateExclusions)), parsed.size);
  const suspects = [...externalSources, ...suspiciousDestinations]
    .sort((left, right) => right.score - left.score || right.events - left.events);
  const enriched = await enrichThreatRadarSuspects(suspects, gtiApiKey);
  return {
    from: parsed.from,
    to: parsed.to,
    analyzedAt: new Date().toISOString(),
    suspects: enriched,
    externalSources: enriched.filter((item) => item.role === "source"),
    suspiciousDestinations: enriched.filter((item) => item.role === "destination"),
    gtiEnabled: Boolean(gtiApiKey),
    summary: {
      suspects: enriched.length,
      critical: enriched.filter((item) => item.severity === "critical").length,
      high: enriched.filter((item) => item.severity === "high").length,
      medium: enriched.filter((item) => item.severity === "medium").length
    }
  };
}

export function buildThreatRadarBody(params: { timestampField: string; from: string; to: string; size: number }) {
  const entityLimit = Math.max(200, params.size * 12);
  return {
    size: 0,
    query: {
      bool: {
        filter: [
          {
            range: {
              [params.timestampField]: {
                gte: params.from,
                lte: params.to
              }
            }
          },
          {
            bool: {
              should: [
                { exists: { field: "source.ip" } },
                { exists: { field: "destination.ip" } },
                { exists: { field: "client.ip" } },
                { exists: { field: "server.ip" } }
              ],
              minimum_should_match: 1
            }
          }
        ]
      }
    },
    aggs: {
      source_entities: buildThreatEntityAggregation("source.ip", "destination.ip", params.timestampField, entityLimit),
      destination_entities: buildThreatEntityAggregation("destination.ip", "source.ip", params.timestampField, entityLimit),
      client_entities: buildThreatEntityAggregation("client.ip", "server.ip", params.timestampField, entityLimit),
      server_entities: buildThreatEntityAggregation("server.ip", "client.ip", params.timestampField, entityLimit)
    }
  };
}

function buildThreatEntityAggregation(entityField: string, peerField: string, timestampField: string, size: number) {
  return {
    terms: {
      field: entityField,
      size,
      shard_size: size * 2,
      order: { _count: "desc" }
    },
    aggs: {
      peer_ips: { cardinality: { field: peerField } },
      infrastructure: { cardinality: { field: "data_stream.namespace" } },
      destination_ports: { cardinality: { field: "destination.port" } },
      ports: { terms: { field: "destination.port", size: 12 } },
      actions: { terms: { field: "event.action", size: 12 } },
      outcomes: { terms: { field: "event.outcome", size: 6 } },
      categories: { terms: { field: "event.category", size: 6 } },
      datasets: { terms: { field: "event.dataset", size: 5 } },
      latest: {
        top_hits: {
          size: 1,
          sort: [{ [timestampField]: { order: "desc" } }],
          _source: {
            includes: [
              timestampField,
              "source.ip",
              "destination.ip",
              "client.ip",
              "server.ip",
              "destination.port",
              "event.action",
              "event.outcome",
              "event.category",
              "event.dataset",
              "host.name",
              "message"
            ]
          }
        }
      }
    }
  };
}

function summarizeThreatRadarEntities(raw: unknown, aggregationName: string, role: ThreatRadarRole): ThreatRadarFinding[] {
  const aggregations = asRecord(asRecord(raw).aggregations);
  const group = asRecord(aggregations[aggregationName]);
  const buckets = Array.isArray(group.buckets) ? group.buckets : [];
  return buckets
    .map((bucket) => summarizeThreatEntityBucket(asRecord(bucket), role))
    .filter((item) => item.ip !== "--")
    .filter((item) => item.score > 0);
}

function rankThreatRadarFindings(findings: ThreatRadarFinding[], size: number): ThreatRadarFinding[] {
  const byIp = new Map<string, ThreatRadarFinding>();
  for (const finding of findings) {
    const existing = byIp.get(finding.ip);
    if (!existing || finding.score > existing.score || (finding.score === existing.score && finding.events > existing.events)) {
      byIp.set(finding.ip, finding);
    }
  }
  return [...byIp.values()]
    .sort((left, right) => right.score - left.score || right.events - left.events)
    .slice(0, size);
}

function summarizeThreatEntityBucket(bucket: Record<string, unknown>, role: ThreatRadarRole): ThreatRadarFinding {
  const ip = typeof bucket.key === "string" ? bucket.key : String(bucket.key ?? "--");
  const latestHit = readLatestHit(bucket);
  const sourceIp = role === "source" ? ip : latestHit.sourceIp ?? latestHit.clientIp ?? "--";
  const destinationIp = role === "destination" ? ip : latestHit.destinationIp ?? latestHit.serverIp ?? "--";
  const gtiIp = isPublicIp(ip) ? ip : "--";
  const events = readNumber(bucket.doc_count);
  const relatedHosts = readNumber(asRecord(bucket.peer_ips).value);
  const infrastructureCount = readNumber(asRecord(bucket.infrastructure).value);
  const destinationPorts = readNumber(asRecord(bucket.destination_ports).value);
  const ports = readBuckets(asRecord(bucket.ports).buckets).map((item) => Number(item.key)).filter((value) => Number.isFinite(value));
  const actions = readBuckets(asRecord(bucket.actions).buckets);
  const outcomes = readBuckets(asRecord(bucket.outcomes).buckets);
  const categories = readBuckets(asRecord(bucket.categories).buckets);
  const datasets = readBuckets(asRecord(bucket.datasets).buckets);
  const dangerousPorts = ports.filter((port) => [22, 23, 3389, 445, 1433, 1521, 3306, 5432, 5900, 6379, 9200].includes(port));
  const failedActions = [...actions, ...outcomes].filter((action) => /fail|denied|blocked|drop|reject|invalid|error|nak|timeout/i.test(action.key));
  const reasons: string[] = [];
  let score = 0;

  if (events >= 1000) {
    score += 35;
    reasons.push("High log volume");
  } else if (events >= 400) {
    score += 30;
    reasons.push("High log volume");
  } else if (events >= 250) {
    score += 24;
    reasons.push("Elevated log volume");
  } else if (events >= 100) {
    score += 12;
    reasons.push("Noticeable log volume");
  }

  if (destinationPorts >= 20) {
    score += 35;
    reasons.push(role === "source" ? "Possible port scan" : "Many services targeted");
  } else if (destinationPorts >= 8) {
    score += 22;
    reasons.push("Multiple destination ports");
  }

  if (relatedHosts >= 10) {
    score += 30;
    reasons.push(role === "source" ? "Horizontal scanning across infrastructure" : "Many sources targeted this destination");
  } else if (relatedHosts >= 4) {
    score += 16;
    reasons.push(role === "source" ? "Multiple destination hosts" : "Multiple source IPs");
  }

  if (dangerousPorts.length > 0) {
    score += Math.min(24, dangerousPorts.length * 8);
    reasons.push(`Dangerous ports ${dangerousPorts.slice(0, 5).join(", ")}`);
  }

  if (failedActions.length > 0) {
    score += Math.min(28, failedActions.reduce((sum, action) => sum + action.count, 0) >= 50 ? 28 : 14);
    reasons.push("Failed/blocked activity");
  }

  if (categories.some((category) => /authentication|network|dhcp/i.test(category.key))) {
    reasons.push(`Event category: ${categories.find((category) => /authentication|network|dhcp/i.test(category.key))?.key}`);
  }

  return {
    ip,
    sourceIp,
    destinationIp,
    gtiIp,
    role,
    score,
    severity: score >= 80 ? "critical" : score >= 55 ? "high" : score >= 25 ? "medium" : "low",
    events,
    relatedHosts,
    infrastructureCount,
    destinationPorts,
    dangerousPorts,
    topPorts: ports.slice(0, 6),
    actions: [...actions, ...outcomes].slice(0, 5),
    datasets: datasets.slice(0, 3),
    latest: latestHit,
    reasons: reasons.length ? reasons : ["Baseline activity"]
  };
}

async function enrichThreatRadarSuspects(suspects: ThreatRadarFinding[], apiKey: string): Promise<Array<ThreatRadarFinding & { gti?: GtiIpReputation }>> {
  if (!apiKey) return suspects;
  const enriched: Array<ThreatRadarFinding & { gti?: GtiIpReputation }> = [];
  for (const [index, suspect] of suspects.entries()) {
    if (index >= 20 || !isPublicIp(suspect.gtiIp)) {
      enriched.push(suspect);
      continue;
    }
    const gti = await fetchGtiIpReputation(suspect.gtiIp, apiKey);
    if (!gti) {
      enriched.push(suspect);
      continue;
    }
    const boost = Math.min(90, Math.round((gti.threatScore ?? 0) * 0.7) + (gti.malicious ?? 0) * 4 + (gti.suspicious ?? 0) * 2);
    const score = suspect.score + boost;
    enriched.push({
      ...suspect,
      score,
      severity: score >= 100 ? "critical" : score >= 70 ? "high" : score >= 35 ? "medium" : "low",
      gti,
      reasons: boost > 0 ? [...suspect.reasons, "GTI/VT reputation risk"] : suspect.reasons
    });
  }
  return enriched;
}

async function fetchGtiIpReputation(ip: string, apiKey: string): Promise<GtiIpReputation | undefined> {
  try {
    const response = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ip)}`, {
      headers: {
        "x-apikey": apiKey,
        "x-tool": "SOC-WatchBridge"
      }
    });
    if (!response.ok) return undefined;
    const body = asRecord(await response.json());
    const data = asRecord(body.data);
    const attributes = asRecord(data.attributes);
    const stats = asRecord(attributes.last_analysis_stats);
    const assessment = asRecord(attributes.gti_assessment);
    const verdict = asRecord(assessment.verdict);
    const severity = asRecord(assessment.severity);
    const threatScore = asRecord(assessment.threat_score);
    return {
      verdict: typeof verdict.value === "string" ? verdict.value : undefined,
      severity: typeof severity.value === "string" ? severity.value : undefined,
      threatScore: readNumber(threatScore.value),
      malicious: readNumber(stats.malicious),
      suspicious: readNumber(stats.suspicious),
      reputation: readNumber(attributes.reputation),
      country: typeof attributes.country === "string" ? attributes.country : undefined,
      asn: readNumber(attributes.asn),
      asOwner: typeof attributes.as_owner === "string" ? attributes.as_owner : undefined
    };
  } catch {
    return undefined;
  }
}

function isPublicIp(value: string): boolean {
  const parts = value.split(".").map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  const [first, second] = parts;
  if (first === 10 || first === 127 || first === 0) return false;
  if (first === 172 && second >= 16 && second <= 31) return false;
  if (first === 192 && second === 168) return false;
  if (first === 169 && second === 254) return false;
  if (first >= 224) return false;
  return true;
}

function readBuckets(value: unknown): Array<{ key: string; count: number }> {
  if (!Array.isArray(value)) return [];
  return value.map((item) => {
    const record = asRecord(item);
    return { key: String(record.key ?? "--"), count: readNumber(record.doc_count) };
  });
}

function readLatestHit(bucket: Record<string, unknown>) {
  const values = Array.isArray(asRecord(asRecord(bucket.latest).hits).hits) ? (asRecord(asRecord(bucket.latest).hits).hits as unknown[]) : [];
  const first = asRecord(values[0]);
  const source = asRecord(first._source);
  const sourceInfo = asRecord(source.source);
  const client = asRecord(source.client);
  const server = asRecord(source.server);
  const event = asRecord(source.event);
  const destination = asRecord(source.destination);
  const host = asRecord(source.host);
  return {
    timestamp: typeof source["@timestamp"] === "string" ? source["@timestamp"] : undefined,
    sourceIp: typeof sourceInfo.ip === "string" ? sourceInfo.ip : undefined,
    destinationIp: typeof destination.ip === "string" ? destination.ip : undefined,
    clientIp: typeof client.ip === "string" ? client.ip : undefined,
    serverIp: typeof server.ip === "string" ? server.ip : undefined,
    destinationPort: typeof destination.port === "number" ? destination.port : undefined,
    action: typeof event.action === "string" ? event.action : undefined,
    host: typeof host.name === "string" ? host.name : undefined,
    message: typeof source.message === "string" ? source.message.slice(0, 180) : undefined
  };
}

function readNumber(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

async function kibanaFetchJson(config: KibanaRuntimeConfig, path: string, init: RequestInit = {}): Promise<unknown> {
  const url = new URL(path, config.kibanaBaseUrl);
  let response: Response;
  try {
    response = await fetch(url, {
      ...init,
      method: init.method ?? "GET",
      credentials: "include",
      headers: {
        "content-type": "application/json",
        "kbn-xsrf": "soc-watch",
        ...init.headers
      }
    });
  } catch (error) {
    return kibanaTabFetchJson(config, path, init, error);
  }

  const contentType = response.headers.get("content-type") ?? "";
  if (response.status === 401 || response.redirected || contentType.includes("text/html")) {
    throw new BridgeOperationError("KIBANA_AUTH_REQUIRED", "Kibana authentication is required.");
  }
  if (response.status === 403) throw new BridgeOperationError("KIBANA_FORBIDDEN", "The current Kibana user is not permitted to perform this read operation.");
  if (response.status === 404) throw new BridgeOperationError("KIBANA_NOT_FOUND", "The Kibana endpoint or resource was not found.");
  if (response.status === 429) throw new BridgeOperationError("RATE_LIMITED", "Kibana rate limited this request.");
  if (!response.ok) throw new BridgeOperationError("KIBANA_UNREACHABLE", `Kibana returned HTTP ${response.status}.`);

  try {
    return await response.json();
  } catch {
    throw new BridgeOperationError("KIBANA_UNREACHABLE", "Kibana responded, but the response was not valid JSON.");
  }
}

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null ? (value as Record<string, unknown>) : {};
}

async function kibanaTabFetchJson(
  config: KibanaRuntimeConfig,
  path: string,
  init: RequestInit,
  originalError: unknown
): Promise<unknown> {
  const kibanaOrigin = new URL(config.kibanaBaseUrl).origin;
  const tabs = await chrome.tabs.query({});
  const kibanaTab = tabs.find((tab) => {
    if (!tab.id || !tab.url) return false;
    try {
      return new URL(tab.url).origin === kibanaOrigin;
    } catch {
      return false;
    }
  });

  if (!kibanaTab?.id) {
    throw new BridgeOperationError(
      "KIBANA_UNREACHABLE",
      "The extension could not reach Kibana from the background worker and no open Kibana tab was found. Open Kibana, log in, then retry Connect.",
      {
        url: kibanaOrigin,
        cause: originalError instanceof Error ? originalError.message : String(originalError)
      }
    );
  }

  let result: chrome.scripting.InjectionResult<{
    ok: boolean;
    status: number;
    redirected: boolean;
    contentType: string;
    json: unknown;
    textPrefix: string;
  }>[] = [];

  try {
    result = await chrome.scripting.executeScript({
      target: { tabId: kibanaTab.id },
      func: async (apiPath: string, method: string, body: string | null) => {
        const response = await fetch(apiPath, {
          method,
          credentials: "include",
          headers: {
            "content-type": "application/json",
            "kbn-xsrf": "soc-watch"
          },
          body: body ?? undefined
        });
        const contentType = response.headers.get("content-type") ?? "";
        const text = await response.text();
        let json: unknown = null;
        try {
          json = text ? JSON.parse(text) : null;
        } catch {
          json = null;
        }
        return {
          ok: response.ok,
          status: response.status,
          redirected: response.redirected,
          contentType,
          json,
          textPrefix: text.slice(0, 120)
        };
      },
      args: [path, init.method ?? "GET", typeof init.body === "string" ? init.body : null]
    });
  } catch (error) {
    throw new BridgeOperationError(
      "KIBANA_UNREACHABLE",
      "Chrome could not run the Kibana tab bridge. Keep one logged-in Kibana tab open, then retry Connect.",
      {
        tabId: kibanaTab.id,
        tabUrl: kibanaTab.url,
        cause: error instanceof Error ? error.message : String(error)
      }
    );
  }

  const value = result[0]?.result;

  if (!value) {
    throw new BridgeOperationError("KIBANA_UNREACHABLE", "The open Kibana tab did not return a bridge fetch result.");
  }
  if (value.status === 401 || value.redirected || value.contentType.includes("text/html")) {
    throw new BridgeOperationError("KIBANA_AUTH_REQUIRED", "Kibana authentication is required.");
  }
  if (value.status === 403) throw new BridgeOperationError("KIBANA_FORBIDDEN", "The current Kibana user is not permitted to perform this read operation.");
  if (value.status === 404) throw new BridgeOperationError("KIBANA_NOT_FOUND", "The Kibana endpoint or resource was not found.");
  if (value.status === 429) throw new BridgeOperationError("RATE_LIMITED", "Kibana rate limited this request.");
  if (!value.ok) throw new BridgeOperationError("KIBANA_UNREACHABLE", `Kibana tab returned HTTP ${value.status}.`);
  if (value.json === null) {
    throw new BridgeOperationError("KIBANA_UNREACHABLE", "Kibana tab responded, but the response was not valid JSON.", {
      textPrefix: value.textPrefix
    });
  }
  return value.json;
}
