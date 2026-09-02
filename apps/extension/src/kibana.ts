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
  type BridgeErrorCode,
  type DataViewSummary,
  type KibanaStatus,
  type SanitizedFleetAgent
} from "@soc-watch/protocol";
import { classifyIOC } from "@soc-watch/ioc";
import { DEFAULT_KIBANA_BASE_URL, DEFAULT_SPACE_ID } from "./config";
import { buildIOCSearchBody } from "./search";

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
    throw new BridgeOperationError(
      "KIBANA_UNREACHABLE",
      "The extension could not reach Kibana. Open Kibana in Chrome first, accept any certificate warning, log in, then retry Connect.",
      {
        url: url.origin,
        cause: error instanceof Error ? error.message : String(error)
      }
    );
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
