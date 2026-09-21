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
import { isExcludedCandidate, type CandidateException } from "./candidate-exclusions";
import { buildDetectionCoverage, DETECTION_PACK_VERSION } from "./detection-packs";
import {
  assessIdentityObservations,
  classifyIdentityValue,
  normalizeReputationDomain,
  normalizeReputationHash,
  type IdentityAnomaly,
  type IdentityBaseline,
  type IdentityObservation
} from "./identity-analysis";
import { getKnownInfrastructure, isRoutineKnownInfrastructureTraffic, KNOWN_PUBLIC_DNS_IPS } from "./known-infrastructure";

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
  verdict?: string | undefined;
  severity?: string | undefined;
  threatScore: number;
  malicious: number;
  suspicious: number;
  harmless?: number | undefined;
  undetected?: number | undefined;
  totalEngines?: number | undefined;
  reputation: number;
  country?: string | undefined;
  asn: number;
  asOwner?: string | undefined;
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

export type ThreatRadarIdentityAnomaly = IdentityAnomaly;

export interface ThreatRadarFinding extends GtiEnrichmentState {
  ip: string;
  sourceIp: string;
  destinationIp: string;
  gtiIp: string;
  role: ThreatRadarRole;
  direction: ThreatRadarDirection;
  evidenceScope: "entity" | "source_destination";
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
  outboundBytes: number;
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
  notFound: number;
  unauthorized: number;
  unavailable: number;
  failed: number;
  failureReasons: Array<{ message: string; count: number }>;
}

export interface ThreatRadarDataHealth {
  status: "healthy" | "partial" | "unavailable";
  indexPattern: string;
  from: string;
  to: string;
  events: number;
  exactEventCount: boolean;
  fields: Array<{ key: string; label: string; coverage: number; events: number }>;
  completedStages: string[];
  skippedStages: string[];
  tookMs?: number;
  message?: string;
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
    ...(typeof record.total === "number" ? { total: record.total } : {}),
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
      ...(typeof item.name === "string" ? { name: item.name } : {}),
      title: String(item.title ?? ""),
      ...(typeof item.timeFieldName === "string" ? { timeFieldName: item.timeFieldName } : {})
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
  const dataHealth = await readThreatRadarDataHealth(config, parsed, searchResult);
  const stored = await chrome.storage.local.get(["googleThreatIntelApiKey", "threatRadarAgentConfig"]);
  const gtiApiKey = typeof stored.googleThreatIntelApiKey === "string" ? stored.googleThreatIntelApiKey.trim() : "";
  const agentConfig = threatRadarAgentConfigSchema.parse(stored.threatRadarAgentConfig ?? {});
  const enrichmentPoolSize = Math.min(100, Math.max(parsed.size * 4, 60));
  const indicatorPoolSize = Math.min(120, Math.max(parsed.size * 4, 80));
  const externalSources = rankThreatRadarFindings([
    ...summarizeThreatRadarEntities(raw, "source_entities", "source"),
    ...summarizeThreatRadarEntities(raw, "client_entities", "source")
  ].filter(isActionableThreatFinding).filter((finding) => !isExcludedCandidate({
    ip: finding.ip,
    sourceIp: finding.sourceIp,
    destinationIp: finding.destinationIp,
    values: [...finding.actions.map((action) => action.key), ...finding.datasets.map((dataset) => dataset.key)],
    text: `${finding.latest?.message ?? ""} ${finding.reasons.join(" ")}`,
    fields: {
      "source.ip": finding.sourceIp,
      "destination.ip": finding.destinationIp,
      "host.name": finding.latest?.host,
      "event.action": finding.actions.map((action) => action.key),
      "data_stream.dataset": finding.datasets.map((dataset) => dataset.key)
    }
  }, agentConfig.candidateExclusions, agentConfig.candidateExceptions)), enrichmentPoolSize);
  const suspiciousDestinations = rankThreatRadarFindings([
    ...summarizeThreatRadarEntities(raw, "destination_entities", "destination"),
    ...summarizeThreatRadarEntities(raw, "server_entities", "destination")
  ].filter(isActionableThreatFinding).filter((finding) => !isExcludedCandidate({
    ip: finding.ip,
    sourceIp: finding.sourceIp,
    destinationIp: finding.destinationIp,
    values: [...finding.actions.map((action) => action.key), ...finding.datasets.map((dataset) => dataset.key)],
    text: `${finding.latest?.message ?? ""} ${finding.reasons.join(" ")}`,
    fields: {
      "source.ip": finding.sourceIp,
      "destination.ip": finding.destinationIp,
      "host.name": finding.latest?.host,
      "event.action": finding.actions.map((action) => action.key),
      "data_stream.dataset": finding.datasets.map((dataset) => dataset.key)
    }
  }, agentConfig.candidateExclusions, agentConfig.candidateExceptions)), enrichmentPoolSize);
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
  const domainIndicators = [
    ...summarizeThreatRadarIndicators(raw, "dns_domain_entities", "domain"),
    ...summarizeThreatRadarIndicators(raw, "url_domain_entities", "domain"),
    ...summarizeThreatRadarIndicators(raw, "destination_domain_entities", "domain")
  ];
  const assessedIdentities = await analyzeThreatRadarIdentities(raw, indicatorPoolSize, agentConfig.candidateExclusions, agentConfig.candidateExceptions);
  const identityAnomalies = assessedIdentities.filter((item) => item.promoted).slice(0, parsed.size);
  const reputationDomainIndicators = domainIndicators.flatMap((indicator) => {
    const value = normalizeReputationDomain(indicator.value);
    return value ? [{ ...indicator, value }] : [];
  });
  const hashIndicators = [
    ...summarizeThreatRadarIndicators(raw, "sha256_entities", "hash"),
    ...summarizeThreatRadarIndicators(raw, "sha1_entities", "hash"),
    ...summarizeThreatRadarIndicators(raw, "md5_entities", "hash")
  ].flatMap((indicator) => {
    const value = normalizeReputationHash(indicator.value);
    return value ? [{ ...indicator, value }] : [];
  });
  const indicatorCandidates = rankThreatRadarIndicators([
    ...reputationDomainIndicators,
    ...hashIndicators
  ].filter((indicator) => !isExcludedCandidate({
    type: indicator.type === "hash" ? "sha256" : "domain",
    normalized: indicator.value,
    values: [...indicator.actions.map((action) => action.key), ...indicator.datasets.map((dataset) => dataset.key)],
    text: `${indicator.latest?.message ?? ""} ${indicator.reasons.join(" ")}`,
    fields: {
      "event.action": indicator.actions.map((action) => action.key),
      "data_stream.dataset": indicator.datasets.map((dataset) => dataset.key),
      "host.name": indicator.latest?.host
    }
  }, agentConfig.candidateExclusions, agentConfig.candidateExceptions)), indicatorPoolSize);
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
  const signals = summarizeDetectionSignals(enriched, suspiciousIndicators, identityAnomalies);
  const detectionCoverage = buildDetectionCoverage(
    signals,
    suspiciousIndicators.length,
    identityAnomalies.length,
    suspiciousOutbound.length,
    deniedActivity.length,
    enriched.filter((item) => item.dangerousPorts.length > 0).length
  );
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
    identityAnomalies,
    signals,
    gtiEnabled: Boolean(gtiApiKey),
    analysis: {
      strategy: searchResult.strategy,
      partial: searchResult.skippedStages.length > 0,
      completedStages: searchResult.completedStages,
      skippedStages: searchResult.skippedStages,
      candidatesEvaluated: suspects.length + assessedIndicators.length + assessedIdentities.length,
      ipCandidatesEvaluated: suspects.length,
      indicatorCandidatesEvaluated: assessedIndicators.length,
      identityCandidatesEvaluated: assessedIdentities.length,
      candidatesForReview: reviewCandidates.length + assessedIdentities.filter((item) => !item.promoted).length,
      reputation,
      dataHealth,
      detectionPackVersion: DETECTION_PACK_VERSION,
      detectionCoverage,
      candidateMethods: [
        "exact source-destination correlation",
        "threat-signal lanes",
        "denied activity",
        "risky authentication",
        "identity baselines",
        "known-infrastructure context",
        "risky ports",
        "traffic volume"
      ]
    },
    summary: {
      suspects: enriched.length + identityAnomalies.filter((item) => item.promoted).length,
      critical: enriched.filter((item) => item.severity === "critical").length + identityAnomalies.filter((item) => item.promoted && item.severity === "critical").length,
      high: enriched.filter((item) => item.severity === "high").length + identityAnomalies.filter((item) => item.promoted && item.severity === "high").length,
      medium: enriched.filter((item) => item.severity === "medium").length + identityAnomalies.filter((item) => item.promoted && item.severity === "medium").length
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

async function readThreatRadarDataHealth(
  config: KibanaRuntimeConfig,
  params: { indexPattern: string; timestampField: string; from: string; to: string },
  searchResult: ThreatRadarSearchResult
): Promise<ThreatRadarDataHealth> {
  try {
    const raw = await runThreatRadarSearch(config, params.indexPattern, buildThreatRadarDataHealthBody(params));
    const total = readSearchTotal(raw);
    const buckets = asRecord(asRecord(asRecord(raw).aggregations).field_coverage).buckets;
    const coverageBuckets = asRecord(buckets);
    const fields = buildDataHealthFieldDefinitions(params.timestampField).map((definition) => {
      const events = readNumber(asRecord(coverageBuckets[definition.key]).doc_count);
      return {
        key: definition.key,
        label: definition.label,
        events,
        coverage: total > 0 ? Math.round((events / total) * 1000) / 10 : 0
      };
    });
    const timedOut = asRecord(raw).timed_out === true;
    const partial = timedOut || searchResult.skippedStages.length > 0;
    return {
      status: partial ? "partial" : "healthy",
      indexPattern: params.indexPattern,
      from: params.from,
      to: params.to,
      events: total,
      exactEventCount: asRecord(asRecord(asRecord(raw).hits).total).relation !== "gte",
      fields,
      completedStages: searchResult.completedStages,
      skippedStages: searchResult.skippedStages,
      tookMs: readNumber(asRecord(raw).took),
      ...(timedOut ? { message: "Elasticsearch timed out while measuring field coverage." } : {})
    };
  } catch (error) {
    return {
      status: "unavailable",
      indexPattern: params.indexPattern,
      from: params.from,
      to: params.to,
      events: 0,
      exactEventCount: false,
      fields: [],
      completedStages: searchResult.completedStages,
      skippedStages: searchResult.skippedStages,
      message: error instanceof Error ? error.message : "Data-health query failed."
    };
  }
}

function buildThreatRadarDataHealthBody(params: { timestampField: string; from: string; to: string }): ThreatRadarSearchBody {
  return {
    size: 0,
    track_total_hits: true,
    timeout: params.from === "now/d" ? "20s" : "10s",
    query: {
      bool: {
        filter: [{ range: { [params.timestampField]: { gte: params.from, lte: params.to } } }]
      }
    },
    aggs: {
      field_coverage: {
        filters: {
          filters: Object.fromEntries(buildDataHealthFieldDefinitions(params.timestampField).map((definition) => [definition.key, definition.filter]))
        }
      }
    }
  };
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
  const candidateEventTotal = buckets.reduce<number>((total, bucket) => total + readNumber(asRecord(bucket).doc_count), 0);
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
    ? Math.max(80, Math.min(160, params.size * 4))
    : Math.max(100, Math.min(200, params.size * 4));
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
                { exists: { field: "file.hash.md5" } },
                ...THREAT_IDENTITY_FIELDS.map(({ field }) => ({ exists: { field } }))
              ],
              minimum_should_match: 1
            }
          }
        ]
      }
    },
    aggs: {
      source_entities: buildThreatEntityAggregation("source.ip", "destination.ip", params.timestampField, entityLimit, true),
      destination_entities: buildThreatEntityAggregation("destination.ip", "source.ip", params.timestampField, entityLimit),
      ...(wideWindow ? {} : {
        client_entities: buildThreatEntityAggregation("client.ip", "server.ip", params.timestampField, entityLimit, true),
        server_entities: buildThreatEntityAggregation("server.ip", "client.ip", params.timestampField, entityLimit)
      }),
      dns_domain_entities: buildThreatIndicatorAggregation("dns.question.name", params.timestampField, indicatorLimit),
      url_domain_entities: buildThreatIndicatorAggregation("url.domain", params.timestampField, indicatorLimit),
      destination_domain_entities: buildThreatIndicatorAggregation("destination.domain", params.timestampField, indicatorLimit),
      sha256_entities: buildThreatIndicatorAggregation("file.hash.sha256", params.timestampField, indicatorLimit),
      sha1_entities: buildThreatIndicatorAggregation("file.hash.sha1", params.timestampField, indicatorLimit),
      md5_entities: buildThreatIndicatorAggregation("file.hash.md5", params.timestampField, indicatorLimit),
      ...Object.fromEntries(THREAT_IDENTITY_FIELDS.map(({ aggregation, field }) => [
        aggregation,
        buildThreatIdentityAggregation(field, params.timestampField, indicatorLimit)
      ])),
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
    "file.hash.md5",
    ...THREAT_IDENTITY_FIELDS.map(({ field }) => field)
  ];
  const indicatorFields = ["dns.question.name", "url.domain", "destination.domain", "file.hash.sha256", "file.hash.sha1", "file.hash.md5"];
  const identityFields = THREAT_IDENTITY_FIELDS.map(({ field }) => field);

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
      should: [buildPublicIpFilter("source.ip"), buildPublicIpFilter("destination.ip", KNOWN_PUBLIC_DNS_IPS)],
      minimum_should_match: 1
    }
  };
  const destinationCandidateFilter = {
    bool: {
      filter: [{ exists: { field: "destination.ip" } }],
      should: [buildPublicIpFilter("destination.ip", KNOWN_PUBLIC_DNS_IPS), buildPublicIpFilter("source.ip")],
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
    ], indicatorFields),
    buildStage(
      "identities",
      "identity and authentication activity",
      THREAT_IDENTITY_FIELDS.map(({ aggregation }) => aggregation),
      identityFields
    )
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

const THREAT_IDENTITY_FIELDS = [
  { aggregation: "user_id_identities", field: "user.id" },
  { aggregation: "user_name_identities", field: "user.name" },
  { aggregation: "user_email_identities", field: "user.email" },
  { aggregation: "source_user_id_identities", field: "source.user.id" },
  { aggregation: "source_user_name_identities", field: "source.user.name" },
  { aggregation: "source_user_email_identities", field: "source.user.email" },
  { aggregation: "destination_user_id_identities", field: "destination.user.id" },
  { aggregation: "destination_user_name_identities", field: "destination.user.name" },
  { aggregation: "destination_user_email_identities", field: "destination.user.email" },
  { aggregation: "client_user_id_identities", field: "client.user.id" },
  { aggregation: "client_user_name_identities", field: "client.user.name" },
  { aggregation: "server_user_id_identities", field: "server.user.id" },
  { aggregation: "server_user_name_identities", field: "server.user.name" },
] as const;

function buildDataHealthFieldDefinitions(timestampField: string): Array<{ key: string; label: string; filter: Record<string, unknown> }> {
  const anyField = (fields: string[]) => ({
    bool: {
      should: fields.map((field) => ({ exists: { field } })),
      minimum_should_match: 1
    }
  });
  return [
    { key: "timestamp", label: "Timestamp", filter: { exists: { field: timestampField } } },
    { key: "source_ip", label: "Source IP", filter: { exists: { field: "source.ip" } } },
    { key: "destination_ip", label: "Destination IP", filter: { exists: { field: "destination.ip" } } },
    { key: "event_action", label: "Event action", filter: { exists: { field: "event.action" } } },
    { key: "namespace", label: "Infrastructure namespace", filter: { exists: { field: "data_stream.namespace" } } },
    { key: "identity", label: "Identity", filter: anyField(THREAT_IDENTITY_FIELDS.map(({ field }) => field)) },
    { key: "domain", label: "Domain", filter: anyField(["dns.question.name", "url.domain", "destination.domain"]) },
    { key: "hash", label: "File hash", filter: anyField(["file.hash.sha256", "file.hash.sha1", "file.hash.md5"]) }
  ];
}

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
        buildAuthenticationActionFilter([
          "authentication_success", "login_success", "logged-in", "user_login", "ssh_login",
          "accepted_password", "session_opened"
        ])
      ],
      minimum_should_match: 1
    }
  };
}

function buildFailedAuthenticationFilter() {
  return {
    bool: {
      should: [
        {
          bool: {
            filter: [
              { term: { "event.category": "authentication" } },
              { term: { "event.outcome": "failure" } }
            ]
          }
        },
        buildAuthenticationActionFilter([
          "authentication_failed", "login_failed", "failed_login", "logon-failed", "invalid_login",
          "invalid_user", "user_login_failed", "ssh_login_failed", "failed_password"
        ])
      ],
      minimum_should_match: 1
    }
  };
}

function buildAuthenticationActionFilter(actions: string[]) {
  return {
    bool: {
      filter: [
        { terms: { "event.action": actions } },
        {
          bool: {
            should: [
              { term: { "event.category": "authentication" } },
              { wildcard: { "event.dataset": "*auth*" } },
              { wildcard: { "event.dataset": "*login*" } },
              { wildcard: { "event.dataset": "*sshd*" } },
              { wildcard: { "event.dataset": "*security*" } },
              { wildcard: { "event.dataset": "*winlog*" } }
            ],
            minimum_should_match: 1
          }
        }
      ]
    }
  };
}

function buildAuthenticationActivityFilter() {
  return {
    bool: {
      should: [
        { term: { "event.category": "authentication" } },
        buildFailedAuthenticationFilter(),
        buildSuccessfulAuthenticationFilter()
      ],
      minimum_should_match: 1
    }
  };
}

function buildThreatEntityAggregation(entityField: string, peerField: string, timestampField: string, size: number, excludeKnownResolvers = false) {
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
      ...buildThreatEvidenceAggregations(timestampField),
      outbound_events: {
        filter: buildPublicIpFilter(peerField, excludeKnownResolvers ? KNOWN_PUBLIC_DNS_IPS : []),
        aggs: {
          peer_values: {
            terms: { field: peerField, size: 5, order: { _count: "desc" } },
            aggs: buildThreatEvidenceAggregations(timestampField)
          }
        }
      }
    }
  };
}

function buildThreatEvidenceAggregations(timestampField: string) {
  return {
    infrastructure: { cardinality: { field: "data_stream.namespace" } },
    destination_ports: { cardinality: { field: "destination.port" } },
    ports: { terms: { field: "destination.port", size: 12 } },
    actions: { terms: { field: "event.action", size: 12 } },
    outcomes: { terms: { field: "event.outcome", size: 6 } },
    categories: { terms: { field: "event.category", size: 6 } },
    datasets: { terms: { field: "event.dataset", size: 5 } },
    denied_events: { filter: buildDeniedActivityFilter() },
    authentication_successes: { filter: buildSuccessfulAuthenticationFilter() },
    source_bytes: { sum: { field: "source.bytes" } },
    network_bytes: { sum: { field: "network.bytes" } },
    threat_signals: {
      filters: {
        filters: Object.fromEntries(Object.entries(buildThreatSignalFilters()).filter(([key]) => key !== "denied"))
      }
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
            "source.bytes",
            "network.bytes",
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
      infrastructures: { terms: { field: "data_stream.namespace", size: 12 } },
      source_ip_count: { cardinality: { field: "source.ip" } },
      source_ips: { terms: { field: "source.ip", size: 12 } },
      destination_ip_count: { cardinality: { field: "destination.ip" } },
      destination_ips: { terms: { field: "destination.ip", size: 8 } },
      ports: { terms: { field: "destination.port", size: 8 } },
      actions: { terms: { field: "event.action", size: 8 } },
      outcomes: { terms: { field: "event.outcome", size: 6 } },
      datasets: { terms: { field: "event.dataset", size: 5 } },
      authentication_events: { filter: buildAuthenticationActivityFilter() },
      failed_authentication: { filter: buildFailedAuthenticationFilter() },
      successful_authentication: { filter: buildSuccessfulAuthenticationFilter() },
      first_seen: { min: { field: timestampField } },
      last_seen: { max: { field: timestampField } },
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

function buildThreatIdentityAggregation(field: string, timestampField: string, size: number) {
  return {
    terms: {
      field,
      size,
      shard_size: size * 2,
      order: { _count: "desc" }
    },
    aggs: {
      authentication_events: { filter: buildAuthenticationActivityFilter() },
      failed_authentication: { filter: buildFailedAuthenticationFilter() },
      successful_authentication: { filter: buildSuccessfulAuthenticationFilter() },
      infrastructure: { cardinality: { field: "data_stream.namespace" } },
      infrastructures: { terms: { field: "data_stream.namespace", size: 12 } },
      source_ip_count: { cardinality: { field: "source.ip" } },
      source_ips: { terms: { field: "source.ip", size: 12 } },
      destination_ip_count: { cardinality: { field: "destination.ip" } },
      destination_ips: { terms: { field: "destination.ip", size: 8 } },
      ports: { terms: { field: "destination.port", size: 8 } },
      actions: { terms: { field: "event.action", size: 12 } },
      outcomes: { terms: { field: "event.outcome", size: 6 } },
      datasets: { terms: { field: "event.dataset", size: 6 } },
      first_seen: { min: { field: timestampField } },
      last_seen: { max: { field: timestampField } },
      latest: {
        top_hits: {
          size: 1,
          sort: [{ [timestampField]: { order: "desc" } }],
          _source: {
            includes: [
              timestampField,
              "source.ip",
              "destination.ip",
              "destination.port",
              "event.action",
              "event.outcome",
              "event.category",
              "event.dataset",
              "host.name",
              "user.id",
              "user.domain",
              "user.name",
              "user.email",
              "source.user.id",
              "source.user.domain",
              "source.user.name",
              "source.user.email",
              "destination.user.id",
              "destination.user.domain",
              "destination.user.name",
              "destination.user.email",
              "client.user.id",
              "client.user.domain",
              "client.user.name",
              "server.user.id",
              "server.user.domain",
              "server.user.name",
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

function buildPublicIpFilter(field: string, excludedIps: readonly string[] = []) {
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
      must_not: [
        ...privateRanges.map(([gte, lte]) => ({ range: { [field]: { gte, lte } } })),
        ...(excludedIps.length > 0 ? [{ terms: { [field]: excludedIps } }] : [])
      ]
    }
  };
}

export function summarizeThreatRadarEntities(raw: unknown, aggregationName: string, role: ThreatRadarRole): ThreatRadarFinding[] {
  const aggregations = asRecord(asRecord(raw).aggregations);
  const group = asRecord(aggregations[aggregationName]);
  const buckets = Array.isArray(group.buckets) ? group.buckets : [];
  return buckets
    .flatMap((bucket) => {
      const record = asRecord(bucket);
      const ip = String(record.key ?? "--");
      if (role === "source" && isPrivateIp(ip)) {
        const outboundPeers = asRecord(asRecord(record.outbound_events).peer_values).buckets;
        if (Array.isArray(outboundPeers) && outboundPeers.length > 0) {
          return outboundPeers.map((peer) => {
            const peerBucket = asRecord(peer);
            const peerIp = String(peerBucket.key ?? "--");
            return summarizeThreatEntityBucket({
              ...peerBucket,
              key: ip,
              peer_ips: { value: 1 },
              outbound_events: {
                doc_count: readNumber(peerBucket.doc_count),
                peer_values: { buckets: [{ key: peerIp, doc_count: readNumber(peerBucket.doc_count) }] }
              }
            }, role, {}, "source_destination");
          });
        }
      }
      return [summarizeThreatEntityBucket(
        record,
        role,
        readThreatSignalCounts(raw, aggregationName, ip),
        "entity"
      )];
    })
    .filter((item) => item.ip !== "--")
    .filter((item) => item.score > 0);
}

function isActionableThreatFinding(finding: ThreatRadarFinding): boolean {
  if (isRoutineKnownDestination(finding) && finding.matchedKeywords.length === 0) return false;
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
  const reputation = finding.gti ? classifyGtiReputation(finding.gti) : "Unknown";
  const maliciousReputation = reputation === "Malicious";
  const reputationRisk = reputation !== "Clean" && reputation !== "Unknown";
  const supportedThreatLanguage = finding.matchedKeywords.some((keyword) =>
    isSupportedFindingSignal(finding, keyword)
  );
  const knownPublicEntity = finding.direction !== "outbound" && Boolean(getKnownInfrastructure(finding.ip));
  const scanBehavior = finding.role === "source"
    && finding.direction === "inbound"
    && finding.destinationPorts >= 8
    && finding.relatedHosts >= 4
    && (finding.deniedEvents >= 20 || reputationRisk);
  const riskyPublicServiceAttack = finding.role === "source"
    && isPublicIp(finding.ip)
    && !knownPublicEntity
    && finding.dangerousPorts.length > 0
    && finding.events >= 400
    && finding.relatedHosts >= 4;
  const behaviorEvidence = finding.deniedEvents >= 20
    || finding.dangerousPorts.length > 0
    || finding.destinationPorts >= 8
    || finding.relatedHosts >= 4;
  const corroboratedThreatLanguage = supportedThreatLanguage && (reputationRisk || behaviorEvidence);
  const deniedAttackBehavior = finding.role === "source" && ((finding.deniedEvents >= 100
    && (isPublicIp(finding.ip) || finding.dangerousPorts.length > 0 || finding.destinationPorts >= 4 || supportedThreatLanguage))
    || (finding.deniedEvents >= 20
      && (finding.dangerousPorts.length > 0 || scanBehavior || corroboratedThreatLanguage)));

  if (finding.direction === "outbound") {
    if (finding.evidenceScope !== "source_destination") return false;
    if (isRoutineKnownDestination(finding) && !reputationRisk) return false;
    return (reputationRisk && finding.outboundEvents >= 5)
      || (supportedThreatLanguage && finding.outboundEvents >= 5);
  }
  if (finding.direction === "internal" || !isPublicIp(finding.ip)) return false;
  if (knownPublicEntity && !reputationRisk && !supportedThreatLanguage) return false;
  return maliciousReputation
    || (reputationRisk && behaviorEvidence)
    || corroboratedThreatLanguage
    || scanBehavior
    || riskyPublicServiceAttack
    || deniedAttackBehavior;
}

export function isInvestigationCandidate(finding: ThreatRadarFinding & { gti?: GtiIpReputation }): boolean {
  if (finding.direction === "internal") return false;

  const reputationRisk = hasAdverseGtiReputation(finding.gti);
  const knownPublicEntity = finding.direction !== "outbound" && Boolean(getKnownInfrastructure(finding.ip));
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
    if (isRoutineKnownDestination(finding) && !reputationRisk) return false;
    return isPrivateIp(finding.ip)
      && isPublicIp(finding.gtiIp)
      && finding.evidenceScope === "source_destination"
      && finding.outboundEvents >= 5
      && (reputationRisk || finding.matchedKeywords.length > 0 || (strongBehavior && finding.deniedEvents >= 20));
  }

  if (knownPublicEntity && !reputationRisk && finding.matchedKeywords.length === 0) return false;

  return isPublicIp(finding.ip)
    && finding.score >= 20
    && (strongBehavior || evidence >= 2);
}

function hasAdverseGtiReputation(gti?: GtiIpReputation): boolean {
  return gti ? classifyGtiReputation(gti) !== "Clean" : false;
}

function hasStrongCommandControlBehavior(finding: ThreatRadarFinding): boolean {
  return (finding.signalCounts.command_control ?? 0) >= 3
    && finding.evidenceScope === "source_destination"
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
  const exactOutbound = finding.direction === "outbound"
    && finding.evidenceScope === "source_destination"
    && isPrivateIp(finding.sourceIp)
    && isPublicIp(finding.destinationIp);
  const expectedKnownDestination = exactOutbound && Boolean(getKnownInfrastructure(finding.destinationIp));

  if (expectedKnownDestination && reputation !== "Malicious" && reputation !== "Suspicious") return false;

  if (signal === "command_control") {
    return exactOutbound
      && count >= 1
      && (reputation === "Malicious" || hasStrongCommandControlBehavior(finding));
  }
  if (signal === "exfiltration") {
    const materialTransfer = finding.outboundBytes >= 25 * 1024 * 1024;
    return exactOutbound
      && count >= 2
      && finding.outboundEvents >= 10
      && (reputation === "Malicious" || reputation === "Suspicious" || materialTransfer);
  }
  if (signal === "malware" && exactOutbound) return reputation === "Malicious" && count > 0;
  if (!publicSubject) return false;
  if (signal === "malware") return reputation === "Malicious"
    || (reputation !== "Clean" && count >= 3 && finding.deniedEvents >= 20);
  if (signal === "brute_force") return count >= 3
    && finding.direction === "inbound"
    && finding.deniedEvents >= 20
    && (finding.dangerousPorts.length > 0 || finding.relatedHosts >= 2 || finding.successfulEvents > 0);
  if (signal === "scanning") return finding.direction === "inbound"
    && count > 0
    && (finding.destinationPorts >= 8 || finding.relatedHosts >= 4)
    && (finding.deniedEvents >= 20 || reputation !== "Clean");
  if (signal === "exploit") return finding.direction === "inbound"
    && count >= 2
    && (reputation !== "Clean" || finding.deniedEvents >= 20 || finding.successfulEvents > 0);
  if (signal === "phishing") return count >= 2 && reputation !== "Clean";
  return false;
}

function isRoutineKnownDestination(finding: ThreatRadarFinding): boolean {
  return finding.direction === "outbound"
    && finding.evidenceScope === "source_destination"
    && isRoutineKnownInfrastructureTraffic({
      destinationIp: finding.destinationIp,
      ports: finding.topPorts,
      actions: finding.actions,
      datasets: finding.datasets
    });
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
    const key = finding.direction === "outbound" && finding.evidenceScope === "source_destination"
      ? `${finding.role}:${finding.sourceIp}->${finding.destinationIp}`
      : `${finding.role}:${finding.ip}`;
    const existing = byIp.get(key);
    if (!existing || finding.score > existing.score || (finding.score === existing.score && finding.events > existing.events)) {
      byIp.set(key, finding);
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

function summarizeThreatEntityBucket(
  bucket: Record<string, unknown>,
  role: ThreatRadarRole,
  signalCounts: Record<string, number>,
  evidenceScope: ThreatRadarFinding["evidenceScope"]
): ThreatRadarFinding {
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
  const outboundBytes = Math.max(
    readNumber(asRecord(bucket.source_bytes).value),
    readNumber(asRecord(bucket.network_bytes).value)
  );
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
    evidenceScope,
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
    outboundBytes,
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

const THREAT_RADAR_IDENTITY_BASELINE_KEY = "threatRadarIdentityBaselineV1";

async function analyzeThreatRadarIdentities(
  raw: unknown,
  size: number,
  exclusions: string[],
  exceptions: CandidateException[]
): Promise<ThreatRadarIdentityAnomaly[]> {
  const observations: IdentityObservation[] = [];
  for (const { aggregation, field } of THREAT_IDENTITY_FIELDS) {
    observations.push(...summarizeIdentityAggregation(raw, aggregation, field, true));
  }
  for (const [aggregation, field] of [
    ["dns_domain_entities", "dns.question.name"],
    ["url_domain_entities", "url.domain"],
    ["destination_domain_entities", "destination.domain"]
  ] as const) {
    observations.push(...summarizeIdentityAggregation(raw, aggregation, field, false));
  }

  const merged = mergeIdentityObservations(observations).filter((observation) => !isExcludedCandidate({
    type: "identity",
    normalized: observation.identity,
    sourceIp: observation.sourceIp,
    destinationIp: observation.destinationIp,
    values: [observation.identity, ...observation.actions.map((action) => action.key), ...observation.datasets.map((dataset) => dataset.key)],
    text: observation.rawIdentity,
    fields: {
      [observation.sourceField]: observation.identity,
      "source.ip": observation.sourceIp,
      "destination.ip": observation.destinationIp,
      "data_stream.dataset": observation.datasets.map((dataset) => dataset.key)
    }
  }, exclusions, exceptions));
  const stored = await chrome.storage.local.get(THREAT_RADAR_IDENTITY_BASELINE_KEY);
  const baseline = readIdentityBaseline(stored[THREAT_RADAR_IDENTITY_BASELINE_KEY]);
  const observedAt = new Date().toISOString();
  const assessed = assessIdentityObservations(merged, baseline, observedAt);
  await chrome.storage.local.set({ [THREAT_RADAR_IDENTITY_BASELINE_KEY]: assessed.baseline });
  return assessed.findings.slice(0, size);
}

function summarizeIdentityAggregation(
  raw: unknown,
  aggregationName: string,
  sourceField: string,
  allowAccount: boolean
): IdentityObservation[] {
  const aggregations = asRecord(asRecord(raw).aggregations);
  const buckets = asRecord(aggregations[aggregationName]).buckets;
  if (!Array.isArray(buckets)) return [];
  return buckets.flatMap((item) => {
    const bucket = asRecord(item);
    const rawIdentity = String(bucket.key ?? "");
    const classified = classifyIdentityValue(rawIdentity, allowAccount);
    if (!classified) return [];
    const latest = readLatestHit(bucket);
    const actions = readBuckets(asRecord(bucket.actions).buckets);
    const outcomes = readBuckets(asRecord(bucket.outcomes).buckets);
    const sourceIps = readBuckets(asRecord(bucket.source_ips).buckets).map((entry) => entry.key).filter((entry) => entry !== "--");
    const destinationIps = readBuckets(asRecord(bucket.destination_ips).buckets).map((entry) => entry.key).filter((entry) => entry !== "--");
    const infrastructures = readBuckets(asRecord(bucket.infrastructures).buckets).map((entry) => entry.key).filter((entry) => entry !== "--");
    const ports = readBuckets(asRecord(bucket.ports).buckets).map((entry) => Number(entry.key)).filter(Number.isFinite);
    const datasets = readBuckets(asRecord(bucket.datasets).buckets);
    const failedEvents = readNumber(asRecord(bucket.failed_authentication).doc_count);
    const successfulEvents = readNumber(asRecord(bucket.successful_authentication).doc_count);
    const authenticationEvents = Math.max(
      readNumber(asRecord(bucket.authentication_events).doc_count),
      failedEvents + successfulEvents
    );
    const firstSeen = readAggregationTimestamp(bucket.first_seen) ?? latest.timestamp;
    const lastSeen = readAggregationTimestamp(bucket.last_seen) ?? latest.timestamp;
    return [{
      identity: classified.value,
      rawIdentity,
      identityType: classified.type,
      sourceField,
      encodedValue: classified.encodedValue,
      sourceIp: sourceIps[0] ?? latest.sourceIp ?? latest.clientIp ?? "--",
      destinationIp: destinationIps[0] ?? latest.destinationIp ?? latest.serverIp ?? "--",
      service: datasets[0]?.key ?? (ports[0] ? `port ${ports[0]}` : "--"),
      events: readNumber(bucket.doc_count),
      authenticationEvents,
      failedEvents,
      successfulEvents,
      infrastructureCount: Math.max(readNumber(asRecord(bucket.infrastructure).value), infrastructures.length),
      infrastructures,
      sourceIpCount: Math.max(readNumber(asRecord(bucket.source_ip_count).value), sourceIps.length),
      sourceIps,
      destinationPorts: ports.slice(0, 8),
      actions: [...actions, ...outcomes].slice(0, 8),
      datasets: datasets.slice(0, 6),
      ...(firstSeen ? { firstSeen } : {}),
      ...(lastSeen ? { lastSeen } : {})
    }];
  });
}

function mergeIdentityObservations(observations: IdentityObservation[]): IdentityObservation[] {
  const merged = new Map<string, IdentityObservation>();
  for (const observation of observations) {
    const key = observation.identity.toLowerCase();
    const prior = merged.get(key);
    if (!prior) {
      merged.set(key, observation);
      continue;
    }
    const sourceIps = [...new Set([...prior.sourceIps, ...observation.sourceIps])].slice(0, 12);
    const infrastructures = [...new Set([...prior.infrastructures, ...observation.infrastructures])].slice(0, 12);
    const destinationPorts = [...new Set([...prior.destinationPorts, ...observation.destinationPorts])].slice(0, 8);
    const firstSeen = earliestTimestamp(prior.firstSeen, observation.firstSeen);
    const lastSeen = latestTimestamp(prior.lastSeen, observation.lastSeen);
    merged.set(key, {
      ...prior,
      rawIdentity: prior.encodedValue ? prior.rawIdentity : observation.rawIdentity,
      identityType: prior.identityType === "service_account" || observation.identityType === "service_account" ? "service_account" : prior.identityType,
      sourceField: prior.sourceField.includes("domain") ? prior.sourceField : observation.sourceField,
      encodedValue: prior.encodedValue || observation.encodedValue,
      sourceIp: prior.sourceIp !== "--" ? prior.sourceIp : observation.sourceIp,
      destinationIp: prior.destinationIp !== "--" ? prior.destinationIp : observation.destinationIp,
      service: prior.service !== "--" ? prior.service : observation.service,
      events: Math.max(prior.events, observation.events),
      authenticationEvents: Math.max(prior.authenticationEvents, observation.authenticationEvents),
      failedEvents: Math.max(prior.failedEvents, observation.failedEvents),
      successfulEvents: Math.max(prior.successfulEvents, observation.successfulEvents),
      infrastructureCount: Math.max(prior.infrastructureCount, observation.infrastructureCount, infrastructures.length),
      infrastructures,
      sourceIpCount: Math.max(prior.sourceIpCount, observation.sourceIpCount, sourceIps.length),
      sourceIps,
      destinationPorts,
      actions: mergeCountBuckets(prior.actions, observation.actions, 8),
      datasets: mergeCountBuckets(prior.datasets, observation.datasets, 6),
      ...(firstSeen ? { firstSeen } : {}),
      ...(lastSeen ? { lastSeen } : {})
    });
  }
  return [...merged.values()];
}

function readIdentityBaseline(value: unknown): IdentityBaseline {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return value as IdentityBaseline;
}

function mergeCountBuckets(
  left: Array<{ key: string; count: number }>,
  right: Array<{ key: string; count: number }>,
  limit: number
): Array<{ key: string; count: number }> {
  const counts = new Map<string, number>();
  for (const item of [...left, ...right]) counts.set(item.key, Math.max(counts.get(item.key) ?? 0, item.count));
  return [...counts.entries()].map(([key, count]) => ({ key, count })).sort((a, b) => b.count - a.count).slice(0, limit);
}

function readAggregationTimestamp(value: unknown): string | undefined {
  const record = asRecord(value);
  if (typeof record.value_as_string === "string") return record.value_as_string;
  if (typeof record.value === "number" && Number.isFinite(record.value)) return new Date(record.value).toISOString();
  return undefined;
}

function earliestTimestamp(left?: string, right?: string): string | undefined {
  if (!left) return right;
  if (!right) return left;
  return Date.parse(left) <= Date.parse(right) ? left : right;
}

function latestTimestamp(left?: string, right?: string): string | undefined {
  if (!left) return right;
  if (!right) return left;
  return Date.parse(left) >= Date.parse(right) ? left : right;
}

export function summarizeThreatRadarIndicators(raw: unknown, aggregationName: string, type: "domain" | "hash"): ThreatRadarIndicator[] {
  const aggregations = asRecord(asRecord(raw).aggregations);
  const group = asRecord(aggregations[aggregationName]);
  const bucketsByValue = new Map<string, Record<string, unknown>>();
  const addBuckets = (value: unknown) => {
    if (!Array.isArray(value)) return;
    for (const bucket of value) {
      const record = asRecord(bucket);
      const key = String(record.key ?? "--");
      if (key !== "--" && !bucketsByValue.has(key)) bucketsByValue.set(key, record);
    }
  };
  addBuckets(group.buckets);
  const signalBuckets = asRecord(asRecord(aggregations.security_signals).buckets);
  for (const signalBucket of Object.values(signalBuckets)) {
    addBuckets(asRecord(asRecord(signalBucket)[aggregationName]).buckets);
  }
  return [...bucketsByValue.values()]
    .map((bucket) => {
      return summarizeThreatIndicatorBucket(bucket, type, readThreatSignalCounts(raw, aggregationName, String(bucket.key ?? "--")));
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

function summarizeDetectionSignals(
  findings: ThreatRadarFinding[],
  indicators: ThreatRadarIndicator[],
  identityAnomalies: ThreatRadarIdentityAnomaly[]
) {
  const combinedKeywords = [...findings.flatMap((item) => item.matchedKeywords), ...indicators.flatMap((item) => item.matchedKeywords)];
  const keywordCounts = combinedKeywords.reduce<Record<string, number>>((counts, key) => {
    counts[key] = (counts[key] ?? 0) + 1;
    return counts;
  }, {});
  return [
    { key: "denied", label: "Denied activity", count: findings.filter((item) => item.role === "source" && item.direction === "inbound" && isPublicIp(item.ip) && item.deniedEvents > 0).length },
    { key: "outbound", label: "Suspicious outbound", count: findings.filter((item) => item.direction === "outbound").length },
    { key: "dangerous_ports", label: "Risky ports", count: findings.filter((item) => item.role === "source" && item.direction === "inbound" && isPublicIp(item.ip) && item.dangerousPorts.length > 0).length },
    { key: "identity_auth", label: "Authentication attack evidence", count: identityAnomalies.filter((item) => item.promoted).length },
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
  const notFound = relevant.filter((item) => item.gtiStatus === "not_found").length;
  const unauthorized = relevant.filter((item) => item.gtiStatus === "unauthorized").length;
  const unavailable = relevant.filter((item) => item.gtiStatus === "unavailable").length;
  const failed = notFound + unauthorized + unavailable;
  const status = !configured
    ? "not_configured"
    : (unauthorized > 0 || unavailable > 0) && scored === 0
      ? "unavailable"
      : pending > 0 || rateLimited > 0 || unauthorized > 0 || unavailable > 0
        ? "partial"
        : "healthy";
  return {
    status,
    requested: relevant.length,
    scored,
    cached: relevant.filter((item) => item.gtiCached).length,
    pending,
    rateLimited,
    notFound,
    unauthorized,
    unavailable,
    failed,
    failureReasons: summarizeGtiFailureReasons(relevant)
  };
}

function summarizeGtiFailureReasons(items: GtiEnrichmentState[]): Array<{ message: string; count: number }> {
  const counts = new Map<string, number>();
  for (const item of items) {
    if (item.gtiStatus !== "unavailable" || !item.gtiMessage) continue;
    counts.set(item.gtiMessage, (counts.get(item.gtiMessage) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([message, count]) => ({ message, count }))
    .sort((left, right) => right.count - left.count)
    .slice(0, 3);
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

  if (reputation === "Clean") return false;
  if (reputation === "Malicious") return count > 0;
  if (reputation === "Suspicious") return count > 0;
  if (signal === "malware" && indicator.type === "hash") return count > 0;
  if (["malware", "command_control", "phishing", "exploit"].includes(signal)) {
    return count >= 3 && indicator.deniedEvents >= 10;
  }
  return count >= 5 && indicator.deniedEvents >= 20 && indicator.events >= 20;
}

export function isConfirmedSuspiciousIndicator(indicator: ThreatRadarIndicator): boolean {
  if (hasAdverseGtiReputation(indicator.gti)) return true;
  if (indicator.matchedKeywords.length > 0) return true;
  return false;
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
const GTI_FAILURE_TTL_MS = 60 * 1000;
const GTI_REQUEST_TIMEOUT_MS = 8 * 1000;
const GTI_MAX_ATTEMPTS = 3;
const GTI_TRANSIENT_HTTP_STATUSES = new Set([408, 425, 500, 502, 503, 504]);
let gtiRateLimitedUntil = 0;

export function resetGtiLookupState(): void {
  gtiRateLimitedUntil = 0;
}

async function fetchGtiReputations(targets: GtiLookupTarget[], apiKey: string): Promise<Map<string, GtiLookupResult>> {
  const results = new Map<string, GtiLookupResult>();
  const uniqueTargets = [...new Map(targets.flatMap((target) => {
    const value = target.type === "domain"
      ? normalizeReputationDomain(target.value)
      : target.type === "hash"
        ? normalizeReputationHash(target.value)
        : target.value.trim().toLowerCase();
    if (!value || (target.type === "ip" && !isPublicIp(value))) return [];
    const normalizedTarget = { ...target, value };
    return [[gtiCacheKey(value, target.type), normalizedTarget] as const];
  })).values()];
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
  const collection = type === "ip" ? "ip_addresses" : type === "domain" ? "domains" : "files";
  const url = `https://www.virustotal.com/api/v3/${collection}/${encodeURIComponent(value)}`;
  let lastFailure = "GTI/VT could not be reached.";
  let attemptsUsed = 0;

  for (let attempt = 1; attempt <= GTI_MAX_ATTEMPTS; attempt += 1) {
    attemptsUsed = attempt;
    try {
      const response = await fetchGtiUrl(url, apiKey);
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
      lastFailure = message || `GTI/VT returned HTTP ${response.status}.`;
      if (!GTI_TRANSIENT_HTTP_STATUSES.has(response.status) || attempt === GTI_MAX_ATTEMPTS) break;
      await wait(readTransientRetryDelay(response.headers.get("retry-after"), attempt));
    } catch (error) {
      lastFailure = error instanceof DOMException && error.name === "AbortError"
        ? `GTI/VT request timed out after ${GTI_REQUEST_TIMEOUT_MS / 1000} seconds.`
        : error instanceof Error ? error.message : "GTI/VT could not be reached.";
      if (attempt === GTI_MAX_ATTEMPTS) break;
      await wait(transientRetryDelay(attempt));
    }
  }

  return {
    gtiStatus: "unavailable",
    gtiMessage: `${lastFailure} Failed after ${attemptsUsed} ${attemptsUsed === 1 ? "attempt" : "attempts"}.`
  };
}

async function fetchGtiUrl(url: string, apiKey: string): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), GTI_REQUEST_TIMEOUT_MS);
  try {
    return await fetch(url, {
      headers: {
        "x-apikey": apiKey,
        "x-tool": "SOC-WatchBridge"
      },
      signal: controller.signal
    });
  } finally {
    clearTimeout(timeout);
  }
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

function transientRetryDelay(attempt: number): number {
  return Math.min(3_000, 500 * (2 ** (attempt - 1)));
}

function readTransientRetryDelay(value: string | null, attempt: number): number {
  if (!value) return transientRetryDelay(attempt);
  const seconds = Number(value);
  if (Number.isFinite(seconds) && seconds >= 0) return Math.max(250, Math.min(seconds * 1000, 3_000));
  const date = Date.parse(value);
  return Number.isFinite(date) ? Math.max(250, Math.min(date - Date.now(), 3_000)) : transientRetryDelay(attempt);
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
  const [first = 0, second = 0] = parts;
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
  const [first = 0, second = 0] = parts;
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
          ...(body === null ? {} : { body })
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
