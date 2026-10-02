import { z } from "zod";
import {
  buildQuery, kibanaApiPath, relayPolicySchema, relayIndexAllowed, relaySourceFields,
  validateRelayOperation, RELAY_MAX_BYTES, type RelaySource
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
    return this.deps.request(source, proxy, { method: "POST", ...(body ? { body: JSON.stringify(body) } : {}) }, { timeoutMs, maxBytes: RELAY_MAX_BYTES - 4096 });
  }
  private require(id: string, owner: string) {
    const lease = this.lease;
    if (!lease || lease.id !== id || lease.owner !== owner || lease.expires < this.deps.clock()) throw new Error("Browser relay authorization expired. Reconnect it from the Server Agent page.");
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
      const result = await this.read(source, `/${encodeURIComponent(policy.indexPattern)}/_field_caps`, "POST", { fields: [policy.timestampField], include_unmapped: true }, 7000) as { fields?: Record<string, unknown> };
      if (!result?.fields || !Object.values(result.fields[policy.timestampField] || {}).some(type => (type as { searchable?: boolean }).searchable === true)) throw new Error("The signed-in Kibana user cannot search the configured log timestamp field. Check the index and timestamp settings.");
      // Metadata availability alone does not prove that this user can read log events.
      const proof = await this.read(source, `/${encodeURIComponent(policy.indexPattern)}/_pit?keep_alive=1m`, "POST", undefined, 7000) as { id?: unknown };
      if (typeof proof?.id !== "string" || !proof.id || proof.id.length > 16384) throw new Error("Kibana did not confirm log-read permissions.");
      await this.read(source, "/_pit", "DELETE", { id: proof.id }, 3000);
      this.lease = { id: crypto.randomUUID(), owner, source, expires: this.deps.clock() + 90000, pits: new Set() };
      this.completed.clear();
      return { relayId: this.lease.id, source };
    }
    const { relayId } = leaseParams.parse(params), lease = this.require(relayId, owner);
    if (action === "agent.relay.disconnect") { this.lease = undefined; this.completed.clear(); return { disconnected: true }; }
    await this.checkBrowser(lease.source);
    if (action === "agent.relay.heartbeat") {
      await this.read(lease.source, `/${encodeURIComponent(lease.source.policy.indexPattern)}/_field_caps`, "POST", { fields: [lease.source.policy.timestampField], include_unmapped: true });
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
        const id = (result as { id?: string })?.id;
        if (typeof id !== "string" || !id || id.length > 16384) throw new Error("Kibana did not return a search snapshot ID.");
        lease.pits.add(id);
      } else if (operation.kind === "closePit") {
        if (!lease.pits.has(operation.id)) throw new Error("Search snapshot is not owned by this relay.");
        try { result = await this.read(lease.source, "/_pit", "DELETE", { id: operation.id }); }
        finally { lease.pits.delete(operation.id); }
      } else if (operation.kind === "search") {
        if (!lease.pits.has(operation.body.pit.id)) throw new Error("Search snapshot is not owned by this relay.");
        result = await this.read(lease.source, "/_search", "POST", { ...operation.body, _source: relaySourceFields(lease.source.policy) });
        const raw = result as { pit_id?: string; hits?: { hits?: { _index: string }[] } };
        if (raw?.hits?.hits?.some(hit => !relayIndexAllowed(hit._index, lease.source.policy.indexPattern))) throw new Error("Kibana returned an index outside the authorized log scope.");
        if (raw.pit_id && raw.pit_id !== operation.body.pit.id) { lease.pits.delete(operation.body.pit.id); lease.pits.add(raw.pit_id); }
      } else if (operation.kind === "fieldCaps") {
        result = await this.read(lease.source, `/${encodeURIComponent(operation.indexPattern)}/_field_caps`, "POST", { fields: operation.fields, include_unmapped: true });
      } else {
        result = await this.read(lease.source, `/${encodeURIComponent(operation.index)}/_doc/${encodeURIComponent(operation.id)}${buildQuery({ _source_includes: relaySourceFields(lease.source.policy).join(",") })}`, "GET");
      }
      if (new TextEncoder().encode(JSON.stringify(result)).length > RELAY_MAX_BYTES - 4096) throw new Error("Relay evidence exceeds the size limit. Reduce the page size.");
      return result;
    })();
    this.completed.set(parsed.jobId, { operation: encoded, response });
    return response;
  }
}
