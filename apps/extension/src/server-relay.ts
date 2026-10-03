import { z } from "zod";
import {
  buildQuery, kibanaApiPath, relayPolicySchema, relayIndexAllowed, relaySourceFields,
  validateRelayOperation, relayFieldCapsPath, relayPitIdSchema, RELAY_MAX_PIT_ID_BYTES, RELAY_MAX_BYTES, type RelaySource
} from "@soc-watch/protocol";
import { BridgeOperationError, kibanaFetchJson, readRuntimeConfig } from "./kibana";

const leaseParams = z.object({ relayId: z.string().uuid() });
const executeParams = leaseParams.extend({ jobId: z.string().uuid(), operation: z.unknown() }).strict();
const defaults = {
  config: readRuntimeConfig,
  request: kibanaFetchJson,
  tabs: async (): Promise<Array<{ url?: string | undefined }>> => chrome.tabs.query({}),
  clock: Date.now
};

function validateTimestamp(raw: unknown, source: RelaySource) {
  const { indexPattern, timestampField } = source.policy;
  const result = raw as { indices?: unknown[]; fields?: Record<string, Record<string, { searchable?: boolean }>>; _shards?: { failed?: number } } | null;
  if (!result || typeof result.fields !== "object" || !result.fields || Array.isArray(result.fields)) {
    throw new BridgeOperationError("KIBANA_UNREACHABLE", "Kibana returned an unexpected field-capabilities response; no log-read access was confirmed.");
  }
  if (result._shards?.failed) throw new BridgeOperationError("KIBANA_UNREACHABLE", "Kibana's log-field check was incomplete. No log-read access was confirmed.");
  if (Array.isArray(result.indices) && !result.indices.length) {
    throw new BridgeOperationError("INVALID_REQUEST", `No accessible indexes match "${indexPattern}". Choose the index pattern from your Kibana Discover data view in Agent Settings.`);
  }
  const types = Object.entries(result.fields[timestampField] || {}).filter(([type]) => type !== "unmapped");
  if (!types.length) {
    throw new BridgeOperationError("INVALID_REQUEST", `Timestamp field "${timestampField}" is not mapped in "${indexPattern}". Select your Kibana Discover data view's time field in Agent Settings.`);
  }
  if (types.some(([type]) => !["date", "date_nanos"].includes(type))) {
    throw new BridgeOperationError("INVALID_REQUEST", `Timestamp field "${timestampField}" in "${indexPattern}" has incompatible types (${types.map(([type]) => type).join(", ")}). Use a date/date_nanos time field or narrow the index pattern in Agent Settings.`);
  }
  if (types.some(([, capability]) => capability?.searchable !== true)) {
    throw new BridgeOperationError("INVALID_REQUEST", `Timestamp field "${timestampField}" is not searchable across "${indexPattern}". Check the field mappings or narrow the index pattern in Agent Settings. This is not proof of a login failure.`);
  }
}

function snapshotId(raw: unknown): string {
  const response = raw as { id?: unknown; _shards?: { failed?: number } } | null;
  if (typeof response?.id !== "string" || !response.id) {
    throw new BridgeOperationError("KIBANA_UNREACHABLE", "The Elasticsearch snapshot response did not contain a valid ID. This is an unexpected response, not proof of missing read permissions.");
  }
  if (!relayPitIdSchema.safeParse(response.id).success) {
    const idBytes = new TextEncoder().encode(response.id).length;
    throw new BridgeOperationError("RESULT_TOO_LARGE",
      `Elasticsearch returned a ${idBytes}-byte snapshot ID; the bridge supports up to ${RELAY_MAX_PIT_ID_BYTES} bytes. This is a size limit, not an authentication failure. Choose a narrower log index pattern in Agent Settings.`,
      { idBytes, maxIdBytes: RELAY_MAX_PIT_ID_BYTES });
  }
  return response.id;
}

function validateSnapshot(raw: unknown): void {
  if ((raw as { _shards?: { failed?: number } } | null)?._shards?.failed) {
    throw new BridgeOperationError("KIBANA_UNREACHABLE", "Elasticsearch could not open a complete log snapshot because some shards failed. No complete log-read access was confirmed.");
  }
}

export class ServerBrowserRelay {
  private lease: { id: string; owner: string; source: RelaySource; expires: number; pits: Set<string> } | undefined;
  private completed = new Map<string, { operation: string; response: Promise<unknown> }>();
  constructor(private deps = defaults) {}

  private async checkBrowser(source: RelaySource) {
    const current = await this.deps.config();
    if (current.kibanaBaseUrl.replace(/\/$/, "") !== source.kibanaBaseUrl || (current.spaceId || "default") !== source.spaceId) throw new Error("Kibana configuration changed. Reconnect the browser relay.");
    const tabs = await this.deps.tabs();
    if (!tabs.some(tab => { try { return !!tab.url && new URL(tab.url).origin === new URL(source.kibanaBaseUrl).origin; } catch { return false; } })) {
      throw new BridgeOperationError("KIBANA_AUTH_REQUIRED", "Keep a signed-in Kibana tab open on this work computer.");
    }
  }
  private async read(source: RelaySource, path: string, method: string, body?: unknown, timeoutMs = 22000) {
    const proxy = kibanaApiPath(`console/proxy${buildQuery({ path, method })}`, source.spaceId);
    const result = await this.deps.request(source, proxy, { method: "POST", ...(body ? { body: JSON.stringify(body) } : {}) }, { timeoutMs, maxBytes: RELAY_MAX_BYTES - 4096 });
    if (new TextEncoder().encode(JSON.stringify(result)).length > RELAY_MAX_BYTES - 4096) {
      throw new BridgeOperationError("RESULT_TOO_LARGE", "Relay response exceeds the 8 MiB limit. Reduce the page size or narrow the log index pattern.");
    }
    return result;
  }
  private require(id: string, owner: string) {
    const lease = this.lease;
    if (!lease || lease.id !== id || lease.expires < this.deps.clock()) throw new BridgeOperationError("KIBANA_UNREACHABLE", "Browser relay authorization expired. Reconnect it from the Server Agent page.");
    if (lease.owner !== owner) throw new BridgeOperationError("INVALID_ORIGIN", "Browser relay belongs to another console tab.");
    return lease;
  }
  async handle(action: string, params: unknown, owner: string) {
    if (!owner) throw new Error("Browser relay requires an authorized console tab.");
    if (action === "agent.relay.connect") {
      if (this.lease && this.lease.expires > this.deps.clock() && this.lease.owner !== owner) throw new Error("Another console tab is using this extension relay.");
      const policy = relayPolicySchema.parse(params);
      const config = await this.deps.config();
      const source: RelaySource = { kibanaBaseUrl: config.kibanaBaseUrl.replace(/\/$/, ""), spaceId: config.spaceId || "default", policy };
      await this.checkBrowser(source);
      const result = await this.read(source, relayFieldCapsPath(policy.indexPattern, [policy.timestampField]), "POST", undefined, 7000);
      validateTimestamp(result, source);
      // Metadata availability alone does not prove that this user can read log events.
      const proof = await this.read(source, `/${encodeURIComponent(policy.indexPattern)}/_pit?keep_alive=1m`, "POST", undefined, 7000);
      const id = snapshotId(proof);
      try { validateSnapshot(proof); }
      catch (error) { await this.read(source, "/_pit", "DELETE", { id }, 3000).catch(() => {}); throw error; }
      await this.read(source, "/_pit", "DELETE", { id }, 3000);
      this.lease = { id: crypto.randomUUID(), owner, source, expires: this.deps.clock() + 90000, pits: new Set() };
      this.completed.clear();
      return { relayId: this.lease.id, source };
    }
    const { relayId } = leaseParams.parse(params), lease = this.require(relayId, owner);
    if (action === "agent.relay.disconnect") { this.lease = undefined; this.completed.clear(); return { disconnected: true }; }
    await this.checkBrowser(lease.source);
    if (action === "agent.relay.heartbeat") {
      const result = await this.read(lease.source, relayFieldCapsPath(lease.source.policy.indexPattern, [lease.source.policy.timestampField]), "POST");
      validateTimestamp(result, lease.source);
      lease.expires = this.deps.clock() + 90000;
      return { ready: true };
    }
    const parsed = executeParams.parse(params);
    const operation = validateRelayOperation(parsed.operation, lease.source.policy);
    const encoded = JSON.stringify(operation), existing = this.completed.get(parsed.jobId);
    if (existing) { if (existing.operation !== encoded) throw new Error("Conflicting relay job ID."); return existing.response; }
    if (this.completed.size >= 4) this.completed.delete(this.completed.keys().next().value!);
    const response = (async () => {
      let result: unknown;
      if (operation.kind === "openPit") {
        if (lease.pits.size >= 8) throw new Error("Too many open relay search snapshots.");
        result = await this.read(lease.source, `/${encodeURIComponent(operation.indexPattern)}/_pit?keep_alive=10m`, "POST");
        const id = snapshotId(result);
        try { validateSnapshot(result); }
        catch (error) { await this.read(lease.source, "/_pit", "DELETE", { id }).catch(() => {}); throw error; }
        lease.pits.add(id);
      } else if (operation.kind === "closePit") {
        if (!lease.pits.has(operation.id)) throw new Error("Search snapshot is not owned by this relay.");
        try { result = await this.read(lease.source, "/_pit", "DELETE", { id: operation.id }); }
        finally { lease.pits.delete(operation.id); }
      } else if (operation.kind === "search") {
        if (!lease.pits.has(operation.body.pit.id)) throw new Error("Search snapshot is not owned by this relay.");
        result = await this.read(lease.source, "/_search", "POST", { ...operation.body, _source: relaySourceFields(lease.source.policy) });
        const raw = result as { pit_id?: unknown; hits?: { hits?: { _index: string }[] } };
        if (raw?.hits?.hits?.some(hit => !relayIndexAllowed(hit._index, lease.source.policy.indexPattern))) throw new Error("Kibana returned an index outside the authorized log scope.");
        if (raw && Object.hasOwn(raw, "pit_id")) {
          const id = snapshotId({ id: raw.pit_id });
          if (id !== operation.body.pit.id) { lease.pits.delete(operation.body.pit.id); lease.pits.add(id); }
        }
      } else if (operation.kind === "fieldCaps") {
        result = await this.read(lease.source, relayFieldCapsPath(operation.indexPattern, operation.fields), "POST");
      } else {
        result = await this.read(lease.source, `/${encodeURIComponent(operation.index)}/_doc/${encodeURIComponent(operation.id)}${buildQuery({ _source_includes: relaySourceFields(lease.source.policy).join(",") })}`, "GET");
      }
      return result;
    })();
    this.completed.set(parsed.jobId, { operation: encoded, response });
    return response;
  }
}
