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
import { buildIOCBulkSearchBody, buildIOCSearchBody } from "./search";
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
  harmless?: number;
  undetected?: number;
  totalEngines?: number;
  reputation: number;
  country?: string;
  asn: number;
  asOwner?: string;
}

export type GtiLookupStatus =
  | "scored"
  | "not_configured"
  | "pending"
  | "not_found"
  | "rate_limited"
  | "unauthorized"
  | "unavailable";

export interface GtiEnrichmentState {
  gti?: GtiIpReputation;
  gtiStatus?: GtiLookupStatus;
  gtiMessage?: string;
  gtiCached?: boolean;
}

type ThreatRadarRole = "source" | "destination";
type ThreatRadarSeverity = "critical" | "high" | "medium" | "low";
type ThreatRadarDirection = "inbound" | "outbound" | "internal" | "external" | "unknown";

export interface ThreatRadarIndicator extends GtiEnrichmentState {
  value: string;
  type: "domain" | "hash";
  score: number;
  severity: ThreatRadarSeverity;
  events: number;
  infrastructureCount: number;
  deniedEvents: number;
  suspiciousKeywordHits: number;
  matchedKeywords: string[];
  signalCounts: Record<string, number>;
  actions: Array<{ key: string; count: number }>;
  datasets: Array<{ key: string; count: number }>;
  latest: ReturnType<typeof readLatestHit>;
  reasons: string[];
}

export interface ThreatRadarFinding extends GtiEnrichmentState {
  ip: string;
  sourceIp: string;
  destinationIp: string;
  gtiIp: string;
  role: ThreatRadarRole;
  direction: ThreatRadarDirection;
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
  deniedEvents: number;
  successfulEvents: number;
  outboundEvents: number;
  suspiciousKeywordHits: number;
  matchedKeywords: string[];
  signalCounts: Record<string, number>;
  latest: ReturnType<typeof readLatestHit>;
  reasons: string[];
}

export interface GtiCoverageSummary {
  status: "healthy" | "partial" | "unavailable" | "not_configured";
  requested: number;
  scored: number;
  cached: number;
  pending: number;
  rateLimited: number;
  failed: number;
}

type ThreatRadarSearchBody = {
  size: number;
  track_total_hits: boolean;
  timeout: string;
  query: Record<string, unknown>;
  aggs: Record<string, unknown>;
};

type ThreatRadarSearchStage = {
  key: string;
  label: string;
  body: ThreatRadarSearchBody;
  entity?: {
    aggregationName: "source_entities" | "destination_entities";
    field: "source.ip" | "destination.ip";
    candidateLimit: number;
  };
};

type ThreatRadarSearchResult = {
  raw: unknown;
  strategy: "single" | "staged";
  completedStages: string[];
  skippedStages: string[];
};

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

export async function searchIOCBatch(params: {
  iocs: Array<ReturnType<typeof classifyIOC>>;
  indexPattern: string;
  timestampField: string;
  from: string;
  to: string;
  size: number;
}): Promise<unknown> {
  const config = await readRuntimeConfig();
  const body = buildIOCBulkSearchBody(params);
  const esPath = `${params.indexPattern}/_search`;
  const proxyPath = kibanaApiPath(
    `console/proxy${buildQuery({ path: esPath, method: "POST" })}`,
    config.spaceId
  );
  return kibanaFetchJson(config, proxyPath, {
    method: "POST",
    body: JSON.stringify(body)
  });
}

export async function analyzeThreatRadar(params: unknown) {
  const parsed = threatRadarAnalyzeParamsSchema.parse(params);
  const config = await readRuntimeConfig();
  const searchResult = parsed.from === "now/d"
    ? await runStagedThreatRadarSearch(config, parsed)
    : {
        raw: await runThreatRadarSearch(config, parsed.indexPattern, buildThreatRadarBody(parsed)),
        strategy: "single" as const,
        completedStages: ["all evidence"],
        skippedStages: []
      };
  const raw = searchResult.raw;
  const stored = await chrome.storage.local.get(["googleThreatIntelApiKey", "threatRadarAgentConfig"]);
  const gtiApiKey = typeof stored.googleThreatIntelApiKey === "string" ? stored.googleThreatIntelApiKey.trim() : "";
  const agentConfig = threatRadarAgentConfigSchema.parse(stored.threatRadarAgentConfig ?? {});
  const enrichmentPoolSize = Math.min(40, Math.max(parsed.size * 2, 30));
  const externalSources = rankThreatRadarFindings([
    ...summarizeThreatRadarEntities(raw, "source_entities", "source"),
    ...summarizeThreatRadarEntities(raw, "client_entities", "source")
  ].filter(isActionableThreatFinding).filter((finding) => !isExcludedCandidate({
    ip: finding.ip,
    sourceIp: finding.sourceIp,
    destinationIp: finding.destinationIp,
    values: [...finding.actions.map((action) => action.key), ...finding.datasets.map((dataset) => dataset.key)],
    text: `${finding.latest?.message ?? ""} ${finding.reasons.join(" ")}`
  }, agentConfig.candidateExclusions)), enrichmentPoolSize);
  const suspiciousDestinations = rankThreatRadarFindings([
    ...summarizeThreatRadarEntities(raw, "destination_entities", "destination"),
    ...summarizeThreatRadarEntities(raw, "server_entities", "destination")
  ].filter(isActionableThreatFinding).filter((finding) => !isExcludedCandidate({
    ip: finding.ip,
    sourceIp: finding.sourceIp,
    destinationIp: finding.destinationIp,
    values: [...finding.actions.map((action) => action.key), ...finding.datasets.map((dataset) => dataset.key)],
    text: `${finding.latest?.message ?? ""} ${finding.reasons.join(" ")}`
  }, agentConfig.candidateExclusions)), enrichmentPoolSize);
  const suspects = [...externalSources, ...suspiciousDestinations]
    .sort((left, right) => right.score - left.score || right.events - left.events)
    .slice(0, enrichmentPoolSize);
  const assessed = rankThreatRadarFindings(
    (await enrichThreatRadarSuspects(suspects, gtiApiKey)).map(removeUnsupportedThreatLabels),
    enrichmentPoolSize
  );
  const enriched = rankThreatRadarFindings(assessed.filter(isConfirmedSuspiciousFinding), parsed.size);
  const reviewCandidates = rankThreatRadarFindings(
    assessed
      .filter((finding) => !isConfirmedSuspiciousFinding(finding))
      .filter(isInvestigationCandidate),
    parsed.size
  );
  const indicatorCandidates = rankThreatRadarIndicators([
    ...summarizeThreatRadarIndicators(raw, "dns_domain_entities", "domain"),
    ...summarizeThreatRadarIndicators(raw, "url_domain_entities", "domain"),
    ...summarizeThreatRadarIndicators(raw, "destination_domain_entities", "domain"),
    ...summarizeThreatRadarIndicators(raw, "sha256_entities", "hash"),
    ...summarizeThreatRadarIndicators(raw, "sha1_entities", "hash"),
    ...summarizeThreatRadarIndicators(raw, "md5_entities", "hash")
  ].filter((indicator) => !isExcludedCandidate({
    type: indicator.type === "hash" ? "sha256" : "domain",
    normalized: indicator.value,
    values: [...indicator.actions.map((action) => action.key), ...indicator.datasets.map((dataset) => dataset.key)],
    text: `${indicator.latest?.message ?? ""} ${indicator.reasons.join(" ")}`
  }, agentConfig.candidateExclusions)), parsed.size);
  const assessedIndicators = (await enrichThreatRadarIndicators(indicatorCandidates, gtiApiKey))
    .map(removeUnsupportedIndicatorLabels);
  const suspiciousIndicators = rankThreatRadarIndicators(
    assessedIndicators.filter(isConfirmedSuspiciousIndicator),
    parsed.size
  );
  const suspiciousOutbound = enriched
    .filter((item) => item.role === "source" && item.direction === "outbound")
    .sort((left, right) => right.score - left.score || right.outboundEvents - left.outboundEvents);
  const deniedActivity = enriched
    .filter((item) => item.role === "source" && item.direction === "inbound" && isPublicIp(item.ip) && item.deniedEvents > 0)
    .sort((left, right) => right.deniedEvents - left.deniedEvents || right.score - left.score);
  const reputation = summarizeGtiCoverage([...assessed, ...assessedIndicators], Boolean(gtiApiKey));
  return {
    from: parsed.from,
    to: parsed.to,
    analyzedAt: new Date().toISOString(),
    eventsAnalyzed: readSearchTotal(raw),
    suspects: enriched,
    externalSources: enriched.filter((item) => item.role === "source" && item.direction === "inbound" && isPublicIp(item.ip)),
    suspiciousDestinations: enriched.filter((item) => item.role === "destination" && isPublicIp(item.ip)),
    suspiciousOutbound,
    deniedActivity,
    reviewCandidates,
    suspiciousIndicators,
    signals: summarizeDetectionSignals(enriched, suspiciousIndicators),
    gtiEnabled: Boolean(gtiApiKey),
    analysis: {
      strategy: searchResult.strategy,
      partial: searchResult.skippedStages.length > 0,
      completedStages: searchResult.completedStages,
      skippedStages: searchResult.skippedStages,
      candidatesEvaluated: suspects.length,
      candidatesForReview: reviewCandidates.length,
      reputation,
      candidateMethods: ["threat signals", "denied activity", "risky authentication", "risky ports", "traffic volume"]
    },
    summary: {
      suspects: enriched.length,
      critical: enriched.filter((item) => item.severity === "critical").length,
      high: enriched.filter((item) => item.severity === "high").length,
      medium: enriched.filter((item) => item.severity === "medium").length
    }
  };
}

async function runThreatRadarSearch(config: KibanaRuntimeConfig, indexPattern: string, body: ThreatRadarSearchBody): Promise<unknown> {
  const esPath = `${indexPattern}/_search`;
  const proxyPath = kibanaApiPath(
    `console/proxy${buildQuery({ path: esPath, method: "POST" })}`,
    config.spaceId
  );
  return kibanaFetchJson(config, proxyPath, {
    method: "POST",
    body: JSON.stringify(body)
  });
}

async function runStagedThreatRadarSearch(
  config: KibanaRuntimeConfig,
  params: { indexPattern: string; timestampField: string; from: string; to: string; size: number }
): Promise<ThreatRadarSearchResult> {
  const stages = buildThreatRadarStageBodies(params);
  const merged: Record<string, unknown> = { aggregations: {} };
  const completedStages: string[] = [];
  const skippedStages: string[] = [];
  let lastError: unknown;
  let lastCoreError: unknown;

  for (const stage of stages) {
    try {
      let raw: unknown;
      let partialTimeout = false;

      if (stage.entity) {
        const candidatesRaw = await runThreatRadarSearch(config, params.indexPattern, stage.body);
        const candidates = readThreatRadarStageCandidates(
          candidatesRaw,
          stage.entity.aggregationName,
          stage.entity.candidateLimit,
          readThreatRadarSignalCandidates(merged, stage.entity.aggregationName)
        );
        partialTimeout = asRecord(candidatesRaw).timed_out === true;
        mergeThreatRadarSearchMetadata(merged, candidatesRaw, stage.entity.aggregationName);

        if (candidates.length === 0 && partialTimeout) {
          throw new BridgeOperationError("KIBANA_UNREACHABLE", `Kibana timed out before it could identify ${stage.label} candidates.`);
        }

        raw = candidates.length > 0
          ? await runThreatRadarSearch(
              config,
              params.indexPattern,
              buildThreatRadarEntityDetailBody(params, stage.entity.aggregationName, stage.entity.field, candidates)
            )
          : candidatesRaw;
      } else {
        raw = await runThreatRadarSearch(config, params.indexPattern, stage.body);
      }

      mergeThreatRadarRawResponse(merged, raw);
      completedStages.push(stage.label);
      if (partialTimeout || asRecord(raw).timed_out === true) skippedStages.push(`${stage.label} (partial timeout)`);
    } catch (error) {
      if (isFatalThreatRadarError(error)) throw error;
      lastError = error;
      if (stage.entity) lastCoreError = error;
      skippedStages.push(stage.label);
    }
  }

  const completedCoreStage = stages.some((stage) => stage.entity && completedStages.includes(stage.label));
  if (!completedCoreStage) {
    if (lastCoreError instanceof Error) throw lastCoreError;
    throw new BridgeOperationError("KIBANA_UNREACHABLE", "Kibana could not complete either IP activity stage of the Today analysis.");
  }

  if (completedStages.length === 0) {
    if (lastError instanceof Error) throw lastError;
    throw new BridgeOperationError("KIBANA_UNREACHABLE", "Kibana could not complete any stage of the Today analysis.");
  }

  return { raw: merged, strategy: "staged", completedStages, skippedStages };
}

function readThreatRadarStageCandidates(raw: unknown, aggregationName: string, limit: number, signalCandidates: string[] = []): string[] {
  const aggregation = asRecord(asRecord(asRecord(raw).aggregations)[aggregationName]);
  const candidates = new Set(signalCandidates.slice(0, limit));
  const addBuckets = (value: unknown) => {
    const buckets = Array.isArray(value) ? value : [];
    for (const bucket of buckets) {
      const key = asRecord(bucket).key;
      if (typeof key === "string" && key.length > 0) candidates.add(key);
      if (candidates.size >= limit) return;
    }
  };

  for (const lane of ["denied", "risky_auth_success", "risky_ports"]) {
    addBuckets(asRecord(asRecord(aggregation[lane]).entities).buckets);
    if (candidates.size >= limit) return [...candidates];
  }
  addBuckets(asRecord(aggregation.volume).buckets);
  return [...candidates].slice(0, limit);
}

function readThreatRadarSignalCandidates(raw: unknown, aggregationName: string): string[] {
  const signalBuckets = asRecord(asRecord(asRecord(asRecord(raw).aggregations).security_signals).buckets);
  const candidates = new Set<string>();
  for (const signalBucket of Object.values(signalBuckets)) {
    const buckets = asRecord(asRecord(signalBucket)[aggregationName]).buckets;
    if (!Array.isArray(buckets)) continue;
    for (const bucket of buckets) {
      const key = asRecord(bucket).key;
      if (typeof key === "string" && key.length > 0) candidates.add(key);
    }
  }
  return [...candidates];
}

function mergeThreatRadarSearchMetadata(target: Record<string, unknown>, source: unknown, aggregationName: string): void {
  const sourceRecord = asRecord(source);
  const aggregation = asRecord(asRecord(sourceRecord.aggregations)[aggregationName]);
  const buckets = Array.isArray(asRecord(aggregation.volume).buckets) ? asRecord(aggregation.volume).buckets as unknown[] : [];
  const candidateEventTotal = buckets.reduce((total, bucket) => total + readNumber(asRecord(bucket).doc_count), 0);
  const sourceTotal = Math.max(readSearchTotal(source), candidateEventTotal);
  const targetTotal = readSearchTotal(target);
  if (sourceTotal > targetTotal) {
    target.hits = { total: { value: sourceTotal, relation: "eq" }, hits: [] };
  }
  target.took = readNumber(target.took) + readNumber(sourceRecord.took);
}

function isFatalThreatRadarError(error: unknown): boolean {
  return error instanceof BridgeOperationError
    && ["KIBANA_AUTH_REQUIRED", "KIBANA_FORBIDDEN", "KIBANA_NOT_FOUND"].includes(error.code);
}

function mergeThreatRadarRawResponse(target: Record<string, unknown>, source: unknown): void {
  const sourceRecord = asRecord(source);
  const targetAggregations = asRecord(target.aggregations);
  Object.assign(targetAggregations, asRecord(sourceRecord.aggregations));
  target.aggregations = targetAggregations;

  const sourceTotal = readSearchTotal(source);
  const targetTotal = readSearchTotal(target);
  if (sourceTotal > targetTotal) {
    target.hits = { total: { value: sourceTotal, relation: "eq" }, hits: [] };
  }
  target.took = readNumber(target.took) + readNumber(sourceRecord.took);
  target.timed_out = target.timed_out === true || sourceRecord.timed_out === true;
}

export function buildThreatRadarBody(params: { timestampField: string; from: string; to: string; size: number }) {
  const wideWindow = params.from === "now/d";
  const entityLimit = wideWindow
    ? Math.max(32, Math.min(50, params.size * 2))
    : Math.max(80, params.size * 2);
  const indicatorLimit = wideWindow
    ? Math.max(20, Math.min(30, params.size))
    : Math.max(40, params.size);
  return {
    size: 0,
    track_total_hits: true,
    timeout: wideWindow ? "25s" : "15s",
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
                { exists: { field: "server.ip" } },
                { exists: { field: "dns.question.name" } },
                { exists: { field: "url.domain" } },
                { exists: { field: "destination.domain" } },
                { exists: { field: "file.hash.sha256" } },
                { exists: { field: "file.hash.sha1" } },
                { exists: { field: "file.hash.md5" } }
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
      ...(wideWindow ? {} : {
        client_entities: buildThreatEntityAggregation("client.ip", "server.ip", params.timestampField, entityLimit),
        server_entities: buildThreatEntityAggregation("server.ip", "client.ip", params.timestampField, entityLimit)
      }),
      dns_domain_entities: buildThreatIndicatorAggregation("dns.question.name", params.timestampField, indicatorLimit),
      url_domain_entities: buildThreatIndicatorAggregation("url.domain", params.timestampField, indicatorLimit),
      destination_domain_entities: buildThreatIndicatorAggregation("destination.domain", params.timestampField, indicatorLimit),
      sha256_entities: buildThreatIndicatorAggregation("file.hash.sha256", params.timestampField, indicatorLimit),
      sha1_entities: buildThreatIndicatorAggregation("file.hash.sha1", params.timestampField, indicatorLimit),
      md5_entities: buildThreatIndicatorAggregation("file.hash.md5", params.timestampField, indicatorLimit),
      security_signals: buildSecuritySignalAggregation(entityLimit, indicatorLimit)
    }
  };
}

export function buildThreatRadarStageBodies(params: { timestampField: string; from: string; to: string; size: number }): ThreatRadarSearchStage[] {
  const fullBody = buildThreatRadarBody(params);
  const aggregations = asRecord(fullBody.aggs);
  const allEvidenceFields = [
    "source.ip",
    "destination.ip",
    "client.ip",
    "server.ip",
    "dns.question.name",
    "url.domain",
    "destination.domain",
    "file.hash.sha256",
    "file.hash.sha1",
    "file.hash.md5"
  ];
  const indicatorFields = allEvidenceFields.slice(4);

  const buildStage = (
    key: string,
    label: string,
    aggregationNames: string[],
    evidenceFields: string[],
    trackTotalHits = false,
    signalOnly = false,
    evidenceFilterOverride?: Record<string, unknown>
  ): ThreatRadarSearchStage => {
    const selectedAggregations = Object.fromEntries(
      aggregationNames
        .filter((name) => aggregations[name] !== undefined)
        .map((name) => [name, aggregations[name]])
    );
    const evidenceFilter = evidenceFilterOverride ?? (signalOnly
      ? { bool: { should: Object.values(buildThreatSignalFilters()), minimum_should_match: 1 } }
      : { bool: { should: evidenceFields.map((field) => ({ exists: { field } })), minimum_should_match: 1 } });
    return {
      key,
      label,
      body: {
        ...fullBody,
        track_total_hits: trackTotalHits,
        timeout: "20s",
        query: {
          bool: {
            filter: [
              { range: { [params.timestampField]: { gte: params.from, lte: params.to } } },
              evidenceFilter
            ]
          }
        },
        aggs: selectedAggregations
      }
    };
  };

  const sourceCandidateFilter = {
    bool: {
      filter: [{ exists: { field: "source.ip" } }],
      should: [buildPublicIpFilter("source.ip"), buildPublicIpFilter("destination.ip")],
      minimum_should_match: 1
    }
  };
  const destinationCandidateFilter = {
    bool: {
      filter: [{ exists: { field: "destination.ip" } }],
      should: [buildPublicIpFilter("destination.ip"), buildPublicIpFilter("source.ip")],
      minimum_should_match: 1
    }
  };

  const sourceStage = buildStage("sources", "source IP activity", ["source_entities"], ["source.ip"], true, false, sourceCandidateFilter);
  const candidateLaneSize = Math.min(80, Math.max(40, params.size * 3));
  const candidateLimit = Math.min(200, Math.max(100, params.size * 8));
  sourceStage.body.aggs = {
    source_entities: buildThreatEntityCandidateAggregation("source.ip", candidateLaneSize)
  };
  sourceStage.entity = { aggregationName: "source_entities", field: "source.ip", candidateLimit };

  const destinationStage = buildStage("destinations", "destination IP activity", ["destination_entities"], ["destination.ip"], false, false, destinationCandidateFilter);
  destinationStage.body.aggs = {
    destination_entities: buildThreatEntityCandidateAggregation("destination.ip", candidateLaneSize)
  };
  destinationStage.entity = { aggregationName: "destination_entities", field: "destination.ip", candidateLimit };

  return [
    buildStage("signals", "security signal evidence", ["security_signals"], allEvidenceFields, false, true),
    sourceStage,
    destinationStage,
    buildStage("indicators", "domain and hash indicators", [
      "dns_domain_entities",
      "url_domain_entities",
      "destination_domain_entities",
      "sha256_entities",
      "sha1_entities",
      "md5_entities"
    ], indicatorFields)
  ];
}

function buildThreatEntityCandidateAggregation(field: string, size: number) {
  const terms = () => ({
    terms: {
      field,
      size,
      shard_size: size * 3,
      order: { _count: "desc" }
    }
  });
  return {
    filter: { match_all: {} },
    aggs: {
      denied: {
        filter: buildDeniedActivityFilter(),
        aggs: { entities: terms() }
      },
      risky_auth_success: {
        filter: {
          bool: {
            filter: [
              { terms: { "destination.port": RISKY_DESTINATION_PORTS } },
              buildSuccessfulAuthenticationFilter()
            ]
          }
        },
        aggs: { entities: terms() }
      },
      risky_ports: {
        filter: { terms: { "destination.port": RISKY_DESTINATION_PORTS } },
        aggs: { entities: terms() }
      },
      volume: terms()
    }
  };
}

export function buildThreatRadarEntityDetailBody(
  params: { timestampField: string; from: string; to: string; size: number },
  aggregationName: "source_entities" | "destination_entities",
  entityField: "source.ip" | "destination.ip",
  candidates: string[]
): ThreatRadarSearchBody {
  const fullBody = buildThreatRadarBody(params);
  const aggregation = asRecord(asRecord(fullBody.aggs)[aggregationName]);
  const aggregationTerms = asRecord(aggregation.terms);
  const detailedAggregation = {
    ...aggregation,
    terms: {
      ...aggregationTerms,
      size: candidates.length,
      shard_size: Math.max(candidates.length, candidates.length * 2)
    }
  };
  return {
    ...fullBody,
    track_total_hits: false,
    timeout: "20s",
    query: {
      bool: {
        filter: [
          { range: { [params.timestampField]: { gte: params.from, lte: params.to } } },
          { terms: { [entityField]: candidates } }
        ]
      }
    },
    aggs: { [aggregationName]: detailedAggregation }
  };
}

const RISKY_DESTINATION_PORTS = [
  21, 22, 23, 25, 53, 69, 110, 135, 137, 138, 139, 143, 161, 389, 445,
  1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 8080, 8443, 9200, 11211, 27017
];

function buildDeniedActivityFilter() {
  return {
    bool: {
      should: [
        { terms: { "event.outcome": ["failure", "failed", "denied"] } },
        {
          terms: {
            "event.action": [
              "deny", "denied", "drop", "dropped", "reject", "rejected", "block", "blocked",
              "failure", "failed", "authentication_failed", "login_failed", "connection_failed"
            ]
          }
        }
      ],
      minimum_should_match: 1
    }
  };
}

function buildSuccessfulAuthenticationFilter() {
  return {
    bool: {
      should: [
        {
          bool: {
            filter: [
              { term: { "event.category": "authentication" } },
              { term: { "event.outcome": "success" } }
            ]
          }
        },
        {
          terms: {
            "event.action": [
              "authentication_success", "login_success", "logged-in", "user_login", "ssh_login",
              "accepted_password", "session_opened"
            ]
          }
        }
      ],
      minimum_should_match: 1
    }
  };
}

function buildThreatEntityAggregation(entityField: string, peerField: string, timestampField: string, size: number) {
  return {
    terms: {
      field: entityField,
      size,
      shard_size: size * 2,
      order: { _count: "desc" },
      collect_mode: "breadth_first"
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
      denied_events: { filter: buildDeniedActivityFilter() },
      authentication_successes: { filter: buildSuccessfulAuthenticationFilter() },
      threat_signals: {
        filters: {
          filters: Object.fromEntries(Object.entries(buildThreatSignalFilters()).filter(([key]) => key !== "denied"))
        }
      },
      outbound_events: {
        filter: buildPublicIpFilter(peerField),
        aggs: { peer_values: { terms: { field: peerField, size: 5 } } }
      },
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
              "event.reason",
              "rule.name",
              "rule.description",
              "threat.indicator.description",
              "dns.question.name",
              "url.domain",
              "destination.domain",
              "file.hash.sha256",
              "file.hash.sha1",
              "file.hash.md5",
              "process.command_line",
              "host.name",
              "message"
            ]
          }
        }
      }
    }
  };
}

function buildThreatIndicatorAggregation(field: string, timestampField: string, size: number) {
  return {
    terms: {
      field,
      size,
      shard_size: size * 2,
      order: { _count: "desc" }
    },
    aggs: {
      infrastructure: { cardinality: { field: "data_stream.namespace" } },
      actions: { terms: { field: "event.action", size: 8 } },
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
              "event.reason",
              "rule.name",
              "rule.description",
              "threat.indicator.description",
              "dns.question.name",
              "url.domain",
              "destination.domain",
              "file.hash.sha256",
              "file.hash.sha1",
              "file.hash.md5",
              "process.command_line",
              "host.name",
              "message"
            ]
          }
        }
      }
    }
  };
}

const DETECTION_SIGNAL_FIELDS = [
  "rule.name^4",
  "rule.description^3",
  "threat.indicator.description^4",
  "event.reason^2",
  "message"
];

function buildTextSignalFilter(query: string, fields = DETECTION_SIGNAL_FIELDS) {
  return {
    simple_query_string: {
      query,
      fields,
      default_operator: "or"
    }
  };
}

function buildThreatSignalFilters() {
  return {
    denied: buildTextSignalFilter("fail* | denied | blocked | drop* | reject* | timeout | refused", ["event.action^4", "event.outcome^4", "event.reason^2", "message"]),
    brute_force: buildTextSignalFilter('"brute force" | bruteforce | "password spray" | "credential stuffing" | "repeated login" | "authentication attack"'),
    malware: buildTextSignalFilter('"malware detected" | "malware blocked" | "malicious file" | "malicious payload" | "virus detected" | trojan | ransomware | backdoor | botnet | cryptominer | rootkit | spyware'),
    command_control: buildTextSignalFilter('"command and control" | "command-and-control" | "c2 traffic" | "c2 communication" | "c2 server" | "dns tunnel" | "dns tunneling" | "malware beacon" | botnet'),
    exfiltration: buildTextSignalFilter('exfiltration | exfiltrate* | "covert channel" | "data theft" | "unusual upload"'),
    scanning: buildTextSignalFilter('"port scan" | "network scan" | reconnaissance | enumeration | probing'),
    exploit: buildTextSignalFilter('"exploit attempt" | "exploit detected" | shellcode | webshell | "remote code execution" | "sql injection" | "command injection"'),
    phishing: buildTextSignalFilter('"phishing detected" | "phishing domain" | "credential theft" | "credential harvesting"')
  };
}

function buildSecuritySignalAggregation(entitySize: number, indicatorSize: number) {
  return {
    filters: {
      filters: buildThreatSignalFilters()
    },
    aggs: {
      source_entities: { terms: { field: "source.ip", size: entitySize } },
      destination_entities: { terms: { field: "destination.ip", size: entitySize } },
      client_entities: { terms: { field: "client.ip", size: entitySize } },
      server_entities: { terms: { field: "server.ip", size: entitySize } },
      dns_domain_entities: { terms: { field: "dns.question.name", size: indicatorSize } },
      url_domain_entities: { terms: { field: "url.domain", size: indicatorSize } },
      destination_domain_entities: { terms: { field: "destination.domain", size: indicatorSize } },
      sha256_entities: { terms: { field: "file.hash.sha256", size: indicatorSize } },
      sha1_entities: { terms: { field: "file.hash.sha1", size: indicatorSize } },
      md5_entities: { terms: { field: "file.hash.md5", size: indicatorSize } }
    }
  };
}

function buildPublicIpFilter(field: string) {
  const privateRanges = [
    ["0.0.0.0", "0.255.255.255"],
    ["10.0.0.0", "10.255.255.255"],
    ["100.64.0.0", "100.127.255.255"],
    ["127.0.0.0", "127.255.255.255"],
    ["169.254.0.0", "169.254.255.255"],
    ["172.16.0.0", "172.31.255.255"],
    ["192.168.0.0", "192.168.255.255"],
    ["224.0.0.0", "255.255.255.255"],
    ["::", "::1"],
    ["fc00::", "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"],
    ["fe80::", "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff"],
    ["ff00::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]
  ];
  return {
    bool: {
      filter: [{ exists: { field } }],
      must_not: privateRanges.map(([gte, lte]) => ({ range: { [field]: { gte, lte } } }))
    }
  };
}

function summarizeThreatRadarEntities(raw: unknown, aggregationName: string, role: ThreatRadarRole): ThreatRadarFinding[] {
  const aggregations = asRecord(asRecord(raw).aggregations);
  const group = asRecord(aggregations[aggregationName]);
  const buckets = Array.isArray(group.buckets) ? group.buckets : [];
  return buckets
    .map((bucket) => {
      const record = asRecord(bucket);
      return summarizeThreatEntityBucket(record, role, readThreatSignalCounts(raw, aggregationName, String(record.key ?? "--")));
    })
    .filter((item) => item.ip !== "--")
    .filter((item) => item.score > 0);
}

function isActionableThreatFinding(finding: ThreatRadarFinding): boolean {
  const hasBehavioralSignal = finding.deniedEvents >= 10
    || finding.suspiciousKeywordHits > 0
    || finding.destinationPorts >= 8
    || finding.relatedHosts >= 4
    || finding.dangerousPorts.length > 0;
  if (isPublicIp(finding.ip)) return hasBehavioralSignal || finding.events >= 50;
  if (finding.direction === "internal") return false;
  return finding.direction === "outbound" && isPublicIp(finding.gtiIp) && hasBehavioralSignal;
}

export function isConfirmedSuspiciousFinding(finding: ThreatRadarFinding & { gti?: GtiIpReputation }): boolean {
  const reputationRisk = hasAdverseGtiReputation(finding.gti);
  const supportedCommandControl = finding.matchedKeywords.includes("command_control")
    && (reputationRisk || hasStrongCommandControlBehavior(finding));
  const strongThreatLanguage = finding.matchedKeywords.some((keyword) => [
    "brute_force",
    "malware",
    "exfiltration",
    "exploit",
    "phishing"
  ].includes(keyword)) || supportedCommandControl;
  const scanBehavior = finding.role === "source" && finding.destinationPorts >= 8 && finding.relatedHosts >= 4;
  const riskyPublicServiceAttack = finding.role === "source"
    && isPublicIp(finding.ip)
    && finding.dangerousPorts.length > 0
    && finding.events >= 400
    && finding.relatedHosts >= 4;
  const behaviorEvidence = finding.deniedEvents >= 20
    || finding.dangerousPorts.length > 0
    || finding.destinationPorts >= 8
    || finding.relatedHosts >= 4;
  const corroboratedThreatLanguage = strongThreatLanguage && (reputationRisk || behaviorEvidence);
  const deniedAttackBehavior = finding.role === "source" && ((finding.deniedEvents >= 100
    && (isPublicIp(finding.ip) || finding.dangerousPorts.length > 0 || finding.destinationPorts >= 4 || strongThreatLanguage))
    || (finding.deniedEvents >= 20
      && (finding.dangerousPorts.length > 0 || scanBehavior || corroboratedThreatLanguage)));

  if (finding.direction === "outbound") {
    return (reputationRisk && finding.outboundEvents >= 5)
      || (corroboratedThreatLanguage && finding.outboundEvents >= 5)
      || (supportedCommandControl && finding.outboundEvents > 0);
  }
  if (finding.direction === "internal" || !isPublicIp(finding.ip)) return false;
  return reputationRisk || corroboratedThreatLanguage || scanBehavior || riskyPublicServiceAttack || deniedAttackBehavior;
}

export function isInvestigationCandidate(finding: ThreatRadarFinding & { gti?: GtiIpReputation }): boolean {
  if (finding.direction === "internal") return false;

  const reputationRisk = hasAdverseGtiReputation(finding.gti);
  const evidence = [
    finding.deniedEvents >= 10,
    finding.dangerousPorts.length > 0 && finding.events >= 20,
    finding.destinationPorts >= 4,
    finding.relatedHosts >= 2,
    finding.matchedKeywords.length > 0,
    finding.successfulEvents > 0 && finding.dangerousPorts.length > 0
  ].filter(Boolean).length;
  const strongBehavior = finding.deniedEvents >= 50
    || finding.destinationPorts >= 8
    || finding.relatedHosts >= 4
    || (finding.matchedKeywords.length > 0 && evidence >= 2);

  if (finding.direction === "outbound") {
    return isPrivateIp(finding.ip)
      && isPublicIp(finding.gtiIp)
      && finding.outboundEvents >= 5
      && (reputationRisk || strongBehavior || evidence >= 2);
  }

  return isPublicIp(finding.ip)
    && finding.score >= 20
    && (strongBehavior || evidence >= 2);
}

function hasAdverseGtiReputation(gti?: GtiIpReputation): boolean {
  return gti ? classifyGtiReputation(gti) !== "Clean" : false;
}

function hasStrongCommandControlBehavior(finding: ThreatRadarFinding): boolean {
  return (finding.signalCounts.command_control ?? 0) >= 3
    && finding.outboundEvents >= 20
    && (finding.deniedEvents >= 20 || finding.destinationPorts >= 4 || finding.dangerousPorts.length > 0);
}

function removeUnsupportedThreatLabels(finding: ThreatRadarFinding & { gti?: GtiIpReputation }): ThreatRadarFinding & { gti?: GtiIpReputation } {
  const matchedKeywords = finding.matchedKeywords.filter((keyword) => isSupportedFindingSignal(finding, keyword));
  if (matchedKeywords.length === finding.matchedKeywords.length) return finding;
  const removedKeywords = finding.matchedKeywords.filter((keyword) => !matchedKeywords.includes(keyword));
  const removedScore = removedKeywords.reduce((sum, keyword) => sum + signalScore(keyword, finding.signalCounts[keyword] ?? 0), 0);
  const score = Math.max(0, finding.score - removedScore);
  const reasons = finding.reasons.filter((reason) => !reason.startsWith("Signals:"));
  if (matchedKeywords.length > 0) reasons.push(`Signals: ${matchedKeywords.map(formatSignalLabel).join(", ")}`);
  return {
    ...finding,
    score,
    severity: severityForScore(score),
    matchedKeywords,
    suspiciousKeywordHits: matchedKeywords.reduce((sum, keyword) => sum + (finding.signalCounts[keyword] ?? 0), 0),
    reasons: reasons.length > 0 ? reasons : ["Behavioral evidence"]
  };
}

function isSupportedFindingSignal(finding: ThreatRadarFinding & { gti?: GtiIpReputation }, signal: string): boolean {
  const count = finding.signalCounts[signal] ?? 0;
  const reputation = finding.gti ? classifyGtiReputation(finding.gti) : "Unknown";
  const publicSubject = isPublicIp(finding.ip);

  if (signal === "command_control") {
    return publicSubject
      ? reputation === "Malicious" || (reputation !== "Clean" && count >= 3 && finding.deniedEvents >= 20)
      : finding.direction === "outbound" && (reputation === "Malicious" || hasStrongCommandControlBehavior(finding));
  }
  if (signal === "exfiltration") {
    return finding.direction === "outbound"
      && count >= 3
      && finding.outboundEvents >= 50
      && (reputation !== "Clean" || finding.destinationPorts >= 4);
  }
  if (!publicSubject) return false;
  if (signal === "malware") return reputation === "Malicious"
    || (reputation !== "Clean" && count >= 3 && finding.deniedEvents >= 20);
  if (signal === "brute_force") return count >= 3
    && finding.deniedEvents >= 20
    && (finding.dangerousPorts.length > 0 || finding.relatedHosts >= 2 || finding.successfulEvents > 0);
  if (signal === "scanning") return count > 0 && (finding.destinationPorts >= 8 || finding.relatedHosts >= 4);
  if (signal === "exploit") return count >= 2 && (reputation !== "Clean" || finding.deniedEvents >= 20 || finding.successfulEvents > 0);
  if (signal === "phishing") return count >= 2 && reputation !== "Clean";
  return false;
}

const THREAT_SIGNAL_WEIGHTS: Record<string, number> = {
  brute_force: 28,
  malware: 35,
  command_control: 32,
  exfiltration: 32,
  scanning: 22,
  exploit: 30,
  phishing: 28
};

function signalScore(signal: string, count: number): number {
  return Math.min(THREAT_SIGNAL_WEIGHTS[signal] ?? 16, Math.max(8, count));
}

function severityForScore(score: number): ThreatRadarSeverity {
  return score >= 80 ? "critical" : score >= 55 ? "high" : score >= 25 ? "medium" : "low";
}

function rankThreatRadarFindings<T extends ThreatRadarFinding>(findings: T[], size: number): T[] {
  const byIp = new Map<string, T>();
  for (const finding of findings) {
    const existing = byIp.get(finding.ip);
    if (!existing || finding.score > existing.score || (finding.score === existing.score && finding.events > existing.events)) {
      byIp.set(finding.ip, finding);
    }
  }
  return [...byIp.values()]
    .sort((left, right) => {
      const leftGti = (left as T & { gti?: GtiIpReputation }).gti;
      const rightGti = (right as T & { gti?: GtiIpReputation }).gti;
      return getGtiCategoryRank(rightGti) - getGtiCategoryRank(leftGti)
        || right.score - left.score
        || right.events - left.events;
    })
    .slice(0, size);
}

function summarizeThreatEntityBucket(bucket: Record<string, unknown>, role: ThreatRadarRole, signalCounts: Record<string, number>): ThreatRadarFinding {
  const ip = typeof bucket.key === "string" ? bucket.key : String(bucket.key ?? "--");
  const latestHit = readLatestHit(bucket);
  const outboundPeers = readBuckets(asRecord(asRecord(bucket.outbound_events).peer_values).buckets);
  const sourceIp = role === "source" ? ip : latestHit.sourceIp ?? latestHit.clientIp ?? "--";
  const destinationIp = role === "destination"
    ? ip
    : isPrivateIp(ip) && outboundPeers[0]?.key ? outboundPeers[0].key : latestHit.destinationIp ?? latestHit.serverIp ?? "--";
  const gtiIp = isPublicIp(ip) ? ip : role === "source" && isPublicIp(destinationIp) ? destinationIp : "--";
  const events = readNumber(bucket.doc_count);
  const relatedHosts = readNumber(asRecord(bucket.peer_ips).value);
  const infrastructureCount = readNumber(asRecord(bucket.infrastructure).value);
  const destinationPorts = readNumber(asRecord(bucket.destination_ports).value);
  const ports = readBuckets(asRecord(bucket.ports).buckets).map((item) => Number(item.key)).filter((value) => Number.isFinite(value));
  const actions = readBuckets(asRecord(bucket.actions).buckets);
  const outcomes = readBuckets(asRecord(bucket.outcomes).buckets);
  const categories = readBuckets(asRecord(bucket.categories).buckets);
  const datasets = readBuckets(asRecord(bucket.datasets).buckets);
  const dangerousPorts = ports.filter((port) => RISKY_DESTINATION_PORTS.includes(port));
  const localSignalCounts = readLocalThreatSignalCounts(bucket);
  const combinedSignalCounts = Object.fromEntries(
    [...new Set([...Object.keys(signalCounts), ...Object.keys(localSignalCounts)])]
      .map((key) => [key, Math.max(signalCounts[key] ?? 0, localSignalCounts[key] ?? 0)])
  );
  const deniedEvents = Math.max(readNumber(asRecord(bucket.denied_events).doc_count), signalCounts.denied ?? 0);
  const successfulEvents = readNumber(asRecord(bucket.authentication_successes).doc_count);
  const outboundEvents = readNumber(asRecord(bucket.outbound_events).doc_count);
  const matchedKeywords = Object.entries(combinedSignalCounts).filter(([key, count]) => key !== "denied" && count > 0).map(([key]) => key);
  const suspiciousKeywordHits = matchedKeywords.reduce((sum, key) => sum + (combinedSignalCounts[key] ?? 0), 0);
  const direction: ThreatRadarDirection = role === "source"
    ? isPrivateIp(ip) && outboundEvents > 0 ? "outbound" : isPublicIp(ip) ? "inbound" : "internal"
    : isPrivateIp(ip) && outboundEvents > 0 ? "inbound" : isPublicIp(ip) ? "external" : "unknown";
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

  if (deniedEvents > 0) {
    score += deniedEvents >= 100 ? 28 : deniedEvents >= 20 ? 20 : 8;
    reasons.push(`${deniedEvents} failed or denied events`);
  }

  if (direction === "outbound" && outboundEvents > 0) {
    score += outboundEvents >= 250 ? 12 : outboundEvents >= 50 ? 7 : 3;
    reasons.push(`${outboundEvents} outbound events`);
  }

  for (const keyword of matchedKeywords) {
    score += signalScore(keyword, combinedSignalCounts[keyword] ?? 0);
  }
  if (matchedKeywords.length > 0) {
    reasons.push(`Signals: ${matchedKeywords.map(formatSignalLabel).join(", ")}`);
  }

  if (role === "source"
    && isPublicIp(ip)
    && isOffHours(latestHit.timestamp)
    && dangerousPorts.length > 0
    && (events >= 400 || relatedHosts >= 4)) {
    score += 18;
    reasons.push("Risky service activity outside business hours");
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
    direction,
    score,
    severity: severityForScore(score),
    events,
    relatedHosts,
    infrastructureCount,
    destinationPorts,
    dangerousPorts,
    topPorts: ports.slice(0, 6),
    actions: [...actions, ...outcomes].slice(0, 5),
    datasets: datasets.slice(0, 3),
    deniedEvents,
    successfulEvents,
    outboundEvents,
    suspiciousKeywordHits,
    matchedKeywords,
    signalCounts: combinedSignalCounts,
    latest: latestHit,
    reasons: reasons.length ? reasons : ["Baseline activity"]
  };
}

function readLocalThreatSignalCounts(bucket: Record<string, unknown>): Record<string, number> {
  const signalBuckets = asRecord(asRecord(bucket.threat_signals).buckets);
  return Object.fromEntries(
    Object.entries(signalBuckets).map(([key, value]) => [key, readNumber(asRecord(value).doc_count)])
  );
}

function summarizeThreatRadarIndicators(raw: unknown, aggregationName: string, type: "domain" | "hash"): ThreatRadarIndicator[] {
  const aggregations = asRecord(asRecord(raw).aggregations);
  const group = asRecord(aggregations[aggregationName]);
  const buckets = Array.isArray(group.buckets) ? group.buckets : [];
  return buckets
    .map((bucket) => {
      const record = asRecord(bucket);
      return summarizeThreatIndicatorBucket(record, type, readThreatSignalCounts(raw, aggregationName, String(record.key ?? "--")));
    })
    .filter((item) => item.value !== "--")
    .filter((item) => item.suspiciousKeywordHits > 0
      || item.deniedEvents >= 20
      || (item.type === "domain" && item.reasons.includes("Unusual domain shape") && item.events >= 10));
}

function summarizeThreatIndicatorBucket(bucket: Record<string, unknown>, type: "domain" | "hash", signalCounts: Record<string, number>): ThreatRadarIndicator {
  const value = String(bucket.key ?? "--");
  const events = readNumber(bucket.doc_count);
  const infrastructureCount = readNumber(asRecord(bucket.infrastructure).value);
  const deniedEvents = signalCounts.denied ?? 0;
  const matchedKeywords = Object.entries(signalCounts).filter(([key, count]) => key !== "denied" && count > 0).map(([key]) => key);
  const suspiciousKeywordHits = matchedKeywords.reduce((sum, key) => sum + (signalCounts[key] ?? 0), 0);
  const actions = readBuckets(asRecord(bucket.actions).buckets);
  const datasets = readBuckets(asRecord(bucket.datasets).buckets);
  const reasons: string[] = [];
  let score = 0;

  if (events >= 1000) {
    score += 28;
    reasons.push("High log volume");
  } else if (events >= 250) {
    score += 20;
    reasons.push("Elevated log volume");
  } else if (events >= 50) {
    score += 10;
    reasons.push("Repeated activity");
  }
  if (deniedEvents > 0) {
    score += deniedEvents >= 50 ? 18 : 8;
    reasons.push(`${deniedEvents} failed or denied events`);
  }
  if (matchedKeywords.length > 0) {
    for (const keyword of matchedKeywords) {
      score += signalScore(keyword, signalCounts[keyword] ?? 0);
    }
    reasons.push(`Signals: ${matchedKeywords.map(formatSignalLabel).join(", ")}`);
  }
  if (type === "domain" && looksAlgorithmicDomain(value)) {
    score += 12;
    reasons.push("Unusual domain shape");
  }

  return {
    value,
    type,
    score,
    severity: severityForScore(score),
    events,
    infrastructureCount,
    deniedEvents,
    suspiciousKeywordHits,
    matchedKeywords,
    signalCounts,
    actions: actions.slice(0, 5),
    datasets: datasets.slice(0, 3),
    latest: readLatestHit(bucket),
    reasons: reasons.length ? reasons : ["Observed indicator"]
  };
}

function rankThreatRadarIndicators(indicators: ThreatRadarIndicator[], size: number): ThreatRadarIndicator[] {
  const byIndicator = new Map<string, ThreatRadarIndicator>();
  for (const indicator of indicators) {
    const key = `${indicator.type}:${indicator.value.toLowerCase()}`;
    const existing = byIndicator.get(key);
    if (!existing || indicator.score > existing.score || (indicator.score === existing.score && indicator.events > existing.events)) {
      byIndicator.set(key, indicator);
    }
  }
  return [...byIndicator.values()]
    .sort((left, right) => getGtiCategoryRank(right.gti) - getGtiCategoryRank(left.gti)
      || right.score - left.score
      || right.events - left.events)
    .slice(0, size);
}

function summarizeDetectionSignals(findings: ThreatRadarFinding[], indicators: ThreatRadarIndicator[]) {
  const combinedKeywords = [...findings.flatMap((item) => item.matchedKeywords), ...indicators.flatMap((item) => item.matchedKeywords)];
  const keywordCounts = combinedKeywords.reduce<Record<string, number>>((counts, key) => {
    counts[key] = (counts[key] ?? 0) + 1;
    return counts;
  }, {});
  return [
    { key: "denied", label: "Denied activity", count: findings.filter((item) => item.role === "source" && item.direction === "inbound" && isPublicIp(item.ip) && item.deniedEvents > 0).length },
    { key: "outbound", label: "Suspicious outbound", count: findings.filter((item) => item.direction === "outbound").length },
    { key: "dangerous_ports", label: "Risky ports", count: findings.filter((item) => item.role === "source" && item.direction === "inbound" && isPublicIp(item.ip) && item.dangerousPorts.length > 0).length },
    ...Object.entries(keywordCounts).map(([key, count]) => ({
      key,
      label: key === "command_control" ? "Command control evidence" : formatSignalLabel(key),
      count
    })),
    { key: "indicators", label: "Domain and hash indicators", count: indicators.length }
  ].filter((item) => item.count > 0);
}

function readThreatSignalCounts(raw: unknown, aggregationName: string, value: string): Record<string, number> {
  const aggregations = asRecord(asRecord(raw).aggregations);
  const signalBuckets = asRecord(asRecord(aggregations.security_signals).buckets);
  const counts: Record<string, number> = {};
  for (const [signal, signalBucket] of Object.entries(signalBuckets)) {
    const entityBuckets = asRecord(asRecord(signalBucket)[aggregationName]).buckets;
    if (!Array.isArray(entityBuckets)) continue;
    const match = entityBuckets.find((item) => String(asRecord(item).key ?? "--") === value);
    counts[signal] = match ? readNumber(asRecord(match).doc_count) : 0;
  }
  return counts;
}

function formatSignalLabel(value: string): string {
  return value.split("_").map((part) => part ? `${part.charAt(0).toUpperCase()}${part.slice(1)}` : part).join(" ");
}

function looksAlgorithmicDomain(value: string): boolean {
  const hostname = value.toLowerCase().replace(/\.$/, "");
  const label = hostname.split(".")[0] ?? "";
  const digits = (label.match(/\d/g) ?? []).length;
  const hyphens = (label.match(/-/g) ?? []).length;
  return hostname.startsWith("xn--") || hostname.length > 55 || label.length > 28 || digits >= 7 || hyphens >= 5;
}

export async function enrichThreatRadarSuspects(suspects: ThreatRadarFinding[], apiKey: string): Promise<ThreatRadarFinding[]> {
  const publicIps = [...new Set(suspects.map((suspect) => suspect.gtiIp).filter(isPublicIp))];
  const reputations = await fetchGtiReputations(publicIps.map((value) => ({ value, type: "ip" as const })), apiKey);
  return suspects.map((suspect) => {
    if (suspect.gti) return suspect;
    const lookup = reputations.get(gtiCacheKey(suspect.gtiIp, "ip"));
    if (!lookup) return suspect;
    if (!lookup.gti) return { ...suspect, ...lookup };
    const gti = lookup.gti;
    const boost = calculateGtiBoost(gti);
    const score = suspect.score + boost;
    const origin = gti.country
      ? `Origin ${gti.country}${gti.asn ? ` | AS${gti.asn}` : ""}`
      : gti.asn ? `Origin AS${gti.asn}` : undefined;
    const reasons = boost > 0 ? [...suspect.reasons, `${formatGtiCategory(gti)} GTI/VT reputation`] : [...suspect.reasons];
    if (origin) reasons.push(origin);
    return {
      ...suspect,
      score,
      severity: severityForScore(score),
      ...lookup,
      reasons
    };
  });
}

async function enrichThreatRadarIndicators(indicators: ThreatRadarIndicator[], apiKey: string): Promise<ThreatRadarIndicator[]> {
  const uniqueIndicators = [...new Map(indicators.map((indicator) => [
    `${indicator.type}:${indicator.value.toLowerCase()}`,
    indicator
  ])).values()];
  const reputations = await fetchGtiReputations(uniqueIndicators.map((indicator) => ({
    value: indicator.value,
    type: indicator.type
  })), apiKey);
  return indicators.map((indicator) => {
    if (indicator.gti) return indicator;
    const lookup = reputations.get(gtiCacheKey(indicator.value, indicator.type));
    if (!lookup) return indicator;
    if (!lookup.gti) return { ...indicator, ...lookup };
    const gti = lookup.gti;
    const boost = calculateGtiBoost(gti);
    const score = indicator.score + boost;
    return {
      ...indicator,
      score,
      severity: severityForScore(score),
      ...lookup,
      reasons: boost > 0 ? [...indicator.reasons, `${formatGtiCategory(gti)} GTI/VT reputation`] : indicator.reasons
    };
  });
}

function summarizeGtiCoverage(items: GtiEnrichmentState[], configured: boolean): GtiCoverageSummary {
  const relevant = items.filter((item) => item.gti || item.gtiStatus);
  const scored = relevant.filter((item) => Boolean(item.gti)).length;
  const rateLimited = relevant.filter((item) => item.gtiStatus === "rate_limited").length;
  const pending = relevant.filter((item) => item.gtiStatus === "pending").length;
  const failed = relevant.filter((item) => ["not_found", "unauthorized", "unavailable"].includes(item.gtiStatus ?? "")).length;
  const status = !configured
    ? "not_configured"
    : relevant.some((item) => item.gtiStatus === "unauthorized" || item.gtiStatus === "unavailable") && scored === 0
      ? "unavailable"
      : scored === relevant.length
        ? "healthy"
        : "partial";
  return {
    status,
    requested: relevant.length,
    scored,
    cached: relevant.filter((item) => item.gtiCached).length,
    pending,
    rateLimited,
    failed
  };
}

function removeUnsupportedIndicatorLabels(indicator: ThreatRadarIndicator): ThreatRadarIndicator {
  const matchedKeywords = indicator.matchedKeywords.filter((keyword) => isSupportedIndicatorSignal(indicator, keyword));
  if (matchedKeywords.length === indicator.matchedKeywords.length) return indicator;
  const removedKeywords = indicator.matchedKeywords.filter((keyword) => !matchedKeywords.includes(keyword));
  const removedScore = removedKeywords.reduce((sum, keyword) => sum + signalScore(keyword, indicator.signalCounts[keyword] ?? 0), 0);
  const score = Math.max(0, indicator.score - removedScore);
  const reasons = indicator.reasons.filter((reason) => !reason.startsWith("Signals:"));
  if (matchedKeywords.length > 0) reasons.push(`Signals: ${matchedKeywords.map(formatSignalLabel).join(", ")}`);
  return {
    ...indicator,
    score,
    severity: severityForScore(score),
    matchedKeywords,
    suspiciousKeywordHits: matchedKeywords.reduce((sum, keyword) => sum + (indicator.signalCounts[keyword] ?? 0), 0),
    reasons: reasons.length > 0 ? reasons : ["Behavioral evidence"]
  };
}

function isSupportedIndicatorSignal(indicator: ThreatRadarIndicator, signal: string): boolean {
  const count = indicator.signalCounts[signal] ?? 0;
  const reputation = indicator.gti ? classifyGtiReputation(indicator.gti) : "Unknown";

  if (signal === "malware") return reputation === "Malicious" || (indicator.type === "hash" && count > 0) || count >= 3;
  if (signal === "command_control") return reputation === "Malicious" || count >= 3;
  if (signal === "phishing") return reputation !== "Clean" && count >= 2;
  if (signal === "exploit") return count >= 2 && reputation !== "Clean";
  return count >= 3 && (indicator.deniedEvents >= 10 || indicator.events >= 20);
}

function isConfirmedSuspiciousIndicator(indicator: ThreatRadarIndicator): boolean {
  if (hasAdverseGtiReputation(indicator.gti)) return true;
  if (indicator.matchedKeywords.length > 0) return true;
  return indicator.type === "domain"
    && indicator.deniedEvents >= 10
    && indicator.reasons.includes("Unusual domain shape");
}

export function calculateGtiBoost(gti?: GtiIpReputation): number {
  if (!gti) return 0;
  const category = classifyGtiReputation(gti);
  if (category === "Clean") return 0;
  return Math.min(140,
    Math.round(gti.threatScore * 0.8)
      + Math.min(48, gti.malicious * 8)
      + Math.min(24, gti.suspicious * 4)
      + (category === "Malicious" ? 30 : 0));
}

function formatGtiCategory(gti: GtiIpReputation): "Malicious" | "Suspicious" {
  return classifyGtiReputation(gti) === "Malicious" ? "Malicious" : "Suspicious";
}

export function classifyGtiReputation(gti: GtiIpReputation): "Malicious" | "Suspicious" | "Clean" {
  const verdict = gti.verdict ?? "";
  const severity = gti.severity ?? "";
  if (/malicious/i.test(verdict) || gti.malicious >= 3 || /critical|high/i.test(severity) || gti.threatScore >= 70) return "Malicious";
  const explicitlyBenign = /benign|undetected|harmless/i.test(verdict)
    && gti.malicious < 3
    && gti.threatScore < 20
    && gti.reputation >= 0;
  if (explicitlyBenign) return "Clean";
  if (/suspicious/i.test(verdict)
    || gti.malicious > 0
    || gti.suspicious > 0
    || /medium/i.test(severity)
    || gti.threatScore >= 20
    || gti.reputation < 0) return "Suspicious";
  return "Clean";
}

function getGtiCategoryRank(gti?: GtiIpReputation): number {
  if (!gti) return 1;
  const category = classifyGtiReputation(gti);
  if (category === "Malicious") return 3;
  if (category === "Suspicious") return 2;
  return 0;
}

type GtiLookupTarget = { value: string; type: "ip" | "domain" | "hash" };
type GtiLookupResult = GtiEnrichmentState & { gtiStatus: GtiLookupStatus };
type GtiCacheEntry = GtiLookupResult & { checkedAt: string };

const GTI_CACHE_KEY = "gtiReputationCacheV1";
const GTI_CACHE_LIMIT = 2000;
const GTI_SCORE_TTL_MS = 24 * 60 * 60 * 1000;
const GTI_NOT_FOUND_TTL_MS = 60 * 60 * 1000;
const GTI_FAILURE_TTL_MS = 5 * 60 * 1000;
let gtiRateLimitedUntil = 0;

export function resetGtiLookupState(): void {
  gtiRateLimitedUntil = 0;
}

async function fetchGtiReputations(targets: GtiLookupTarget[], apiKey: string): Promise<Map<string, GtiLookupResult>> {
  const results = new Map<string, GtiLookupResult>();
  const uniqueTargets = [...new Map(targets.map((target) => [gtiCacheKey(target.value, target.type), target])).values()];
  if (!apiKey) {
    for (const target of uniqueTargets) {
      results.set(gtiCacheKey(target.value, target.type), {
        gtiStatus: "not_configured",
        gtiMessage: "Add a Google Threat Intelligence or VirusTotal API key in Settings."
      });
    }
    return results;
  }

  const stored = await chrome.storage.local.get(GTI_CACHE_KEY);
  const cache = readGtiCache(stored[GTI_CACHE_KEY]);
  let cacheChanged = false;
  for (const target of uniqueTargets) {
    const key = gtiCacheKey(target.value, target.type);
    const cached = cache[key];
    if (cached && isFreshGtiCacheEntry(cached)) {
      const { checkedAt: _checkedAt, ...cachedResult } = cached;
      results.set(key, { ...cachedResult, gtiCached: true });
      continue;
    }
    if (Date.now() < gtiRateLimitedUntil) {
      results.set(key, {
        gtiStatus: "pending",
        gtiMessage: "Queued for the next GTI quota window."
      });
      continue;
    }

    const lookup = await fetchGtiReputation(target.value, target.type, apiKey);
    results.set(key, lookup);
    if (lookup.gtiStatus === "rate_limited") {
      gtiRateLimitedUntil = Math.max(gtiRateLimitedUntil, Date.now() + GTI_FAILURE_TTL_MS);
      continue;
    }
    cache[key] = { ...lookup, checkedAt: new Date().toISOString() };
    cacheChanged = true;
  }

  if (cacheChanged) {
    const trimmed = Object.fromEntries(Object.entries(cache)
      .sort(([, left], [, right]) => Date.parse(right.checkedAt) - Date.parse(left.checkedAt))
      .slice(0, GTI_CACHE_LIMIT));
    await chrome.storage.local.set({ [GTI_CACHE_KEY]: trimmed });
  }
  return results;
}

async function fetchGtiReputation(value: string, type: "ip" | "domain" | "hash", apiKey: string): Promise<GtiLookupResult> {
  try {
    const collection = type === "ip" ? "ip_addresses" : type === "domain" ? "domains" : "files";
    const url = `https://www.virustotal.com/api/v3/${collection}/${encodeURIComponent(value)}`;
    let response = await fetchGtiUrl(url, apiKey);
    if ([503, 504].includes(response.status)) {
      await wait(350);
      response = await fetchGtiUrl(url, apiKey);
    }
    if (response.ok) {
      return {
        gti: parseGtiReputationResponse(await response.json()),
        gtiStatus: "scored",
        gtiMessage: "Reputation retrieved from GTI/VT."
      };
    }
    const message = await readGtiErrorMessage(response);
    if (response.status === 401 || response.status === 403) {
      return { gtiStatus: "unauthorized", gtiMessage: message || "The configured GTI/VT API key was rejected." };
    }
    if (response.status === 404) {
      return { gtiStatus: "not_found", gtiMessage: message || "GTI/VT has no report for this indicator." };
    }
    if (response.status === 429) {
      const retryAfter = readRetryAfter(response.headers.get("retry-after"));
      gtiRateLimitedUntil = Date.now() + retryAfter;
      return { gtiStatus: "rate_limited", gtiMessage: message || "GTI/VT request quota reached; retry is automatic." };
    }
    return { gtiStatus: "unavailable", gtiMessage: message || `GTI/VT returned HTTP ${response.status}.` };
  } catch (error) {
    return {
      gtiStatus: "unavailable",
      gtiMessage: error instanceof Error ? error.message : "GTI/VT could not be reached."
    };
  }
}

function fetchGtiUrl(url: string, apiKey: string): Promise<Response> {
  return fetch(url, {
    headers: {
      "x-apikey": apiKey,
      "x-tool": "SOC-WatchBridge"
    }
  });
}

function gtiCacheKey(value: string, type: GtiLookupTarget["type"]): string {
  return `${type}:${value.trim().toLowerCase()}`;
}

function readGtiCache(value: unknown): Record<string, GtiCacheEntry> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return value as Record<string, GtiCacheEntry>;
}

function isFreshGtiCacheEntry(entry: GtiCacheEntry): boolean {
  const checkedAt = Date.parse(entry.checkedAt);
  if (!Number.isFinite(checkedAt)) return false;
  const ttl = entry.gti
    ? GTI_SCORE_TTL_MS
    : entry.gtiStatus === "not_found"
      ? GTI_NOT_FOUND_TTL_MS
      : GTI_FAILURE_TTL_MS;
  return Date.now() - checkedAt < ttl;
}

function readRetryAfter(value: string | null): number {
  if (!value) return GTI_FAILURE_TTL_MS;
  const seconds = Number(value);
  if (Number.isFinite(seconds) && seconds >= 0) return Math.max(60_000, Math.min(seconds * 1000, GTI_FAILURE_TTL_MS));
  const date = Date.parse(value);
  return Number.isFinite(date) ? Math.max(60_000, Math.min(date - Date.now(), GTI_FAILURE_TTL_MS)) : GTI_FAILURE_TTL_MS;
}

async function readGtiErrorMessage(response: Response): Promise<string> {
  try {
    const body = asRecord(await response.json());
    const error = asRecord(body.error);
    return typeof error.message === "string" ? error.message : "";
  } catch {
    return "";
  }
}

function wait(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

export function parseGtiReputationResponse(raw: unknown): GtiIpReputation {
  const body = asRecord(raw);
  const data = asRecord(body.data);
  const attributes = asRecord(data.attributes);
  const stats = asRecord(attributes.last_analysis_stats);
  const results = asRecord(attributes.last_analysis_results);
  const assessment = asRecord(attributes.gti_assessment);
  const malicious = Math.max(readNumberLike(stats.malicious), countAnalysisResults(results, "malicious"));
  const suspicious = Math.max(readNumberLike(stats.suspicious), countAnalysisResults(results, "suspicious"));
  const harmless = Math.max(readNumberLike(stats.harmless), countAnalysisResults(results, "harmless"));
  const undetected = Math.max(readNumberLike(stats.undetected), countAnalysisResults(results, "undetected"));
  const verdict = readWrappedString(assessment.verdict) ?? readWrappedString(attributes.threat_verdict);
  const severity = readWrappedString(assessment.severity)
    ?? readWrappedString(asRecord(attributes.threat_severity).threat_severity_level);
  const threatScore = readWrappedNumber(assessment.threat_score)
    || readWrappedNumber(attributes.threat_score);
  return {
    verdict,
    severity,
    threatScore,
    malicious,
    suspicious,
    harmless,
    undetected,
    totalEngines: malicious + suspicious + harmless + undetected
      + readNumberLike(stats.timeout)
      + readNumberLike(stats.failure)
      + readNumberLike(stats["confirmed-timeout"])
      + readNumberLike(stats["type-unsupported"]),
    reputation: readNumberLike(attributes.reputation),
    country: typeof attributes.country === "string" ? attributes.country : undefined,
    asn: readNumberLike(attributes.asn),
    asOwner: typeof attributes.as_owner === "string" ? attributes.as_owner : undefined
  };
}

function readWrappedString(value: unknown): string | undefined {
  if (typeof value === "string") return value;
  const wrapped = asRecord(value).value;
  return typeof wrapped === "string" ? wrapped : undefined;
}

function readWrappedNumber(value: unknown): number {
  const direct = readNumberLike(value);
  return direct || readNumberLike(asRecord(value).value);
}

function readNumberLike(value: unknown): number {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim()) {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return 0;
}

function countAnalysisResults(results: Record<string, unknown>, category: string): number {
  return Object.values(results).filter((result) => asRecord(result).category === category).length;
}

function isPublicIp(value: string): boolean {
  if (value.includes(":")) {
    const normalized = value.toLowerCase();
    if (!/^[0-9a-f:]+$/.test(normalized) || (normalized.match(/:/g) ?? []).length < 2) return false;
    return normalized !== "::"
      && normalized !== "::1"
      && !normalized.startsWith("fc")
      && !normalized.startsWith("fd")
      && !/^fe[89ab]/.test(normalized)
      && !normalized.startsWith("ff");
  }
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

function isPrivateIp(value: string): boolean {
  if (value.includes(":")) {
    const normalized = value.toLowerCase();
    if (!/^[0-9a-f:]+$/.test(normalized) || (normalized.match(/:/g) ?? []).length < 2) return false;
    return normalized.startsWith("fc") || normalized.startsWith("fd");
  }
  const parts = value.split(".").map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  const [first, second] = parts;
  return first === 10
    || (first === 172 && second >= 16 && second <= 31)
    || (first === 192 && second === 168);
}

function isOffHours(timestamp?: string): boolean {
  if (!timestamp) return false;
  const date = new Date(timestamp);
  if (!Number.isFinite(date.getTime())) return false;
  const hour = date.getHours();
  return hour < 6 || hour >= 22;
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

function readSearchTotal(raw: unknown): number {
  const total = asRecord(asRecord(raw).hits).total;
  if (typeof total === "number") return readNumber(total);
  return readNumber(asRecord(total).value);
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
