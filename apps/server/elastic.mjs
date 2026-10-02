import { INDICATOR_FIELDS } from "./intelligence.mjs";
import { BrowserRelay } from "./relay.mjs";

export class ElasticClient {
  constructor(runtime, fetcher = fetch) { this.runtime = runtime; this.fetch = fetcher; this.relay = runtime.dataSource === "browser_relay" ? new BrowserRelay() : null; }
  ready() { return this.relay ? this.relay.status().ready : Boolean(this.runtime.elasticUrl && this.runtime.elasticApiKey); }
  sourceIdentity() { return this.relay ? JSON.stringify(this.relay.status().source) : this.runtime.elasticUrl; }
  async request(path, body, method = "POST") {
    if (this.relay) {
      let operation;
      if (path === "/_search" && method === "POST") operation = { kind: "search", body };
      else if (path === "/_pit" && method === "DELETE") operation = { kind: "closePit", id: body.id };
      else {
        const parts = path.split("/");
        const index = decodeURIComponent(parts[1] || "");
        if (parts.length === 3 && parts[2] === "_pit?keep_alive=10m" && method === "POST") operation = { kind: "openPit", indexPattern: index };
        else if (parts.length === 3 && parts[2] === "_field_caps" && method === "POST") operation = { kind: "fieldCaps", indexPattern: index, fields: body.fields };
        else if (parts.length === 4 && parts[2] === "_doc" && method === "GET") operation = { kind: "evidence", index, id: decodeURIComponent(parts[3]) };
        else throw new Error("Unsupported browser relay operation.");
      }
      return this.relay.execute(operation, this.signal);
    }
    if (!this.runtime.elasticUrl || !this.runtime.elasticApiKey) throw new Error("Server Elasticsearch URL and read-only API key are not configured.");
    const response = await this.fetch(`${this.runtime.elasticUrl}${path}`, {
      method, headers: { authorization: `ApiKey ${this.runtime.elasticApiKey}`, "content-type": "application/json" },
      ...(body ? { body: JSON.stringify(body) } : {}), signal: this.signal ? AbortSignal.any([this.signal, AbortSignal.timeout(30000)]) : AbortSignal.timeout(30000), redirect: "error"
    });
    if (!response.ok) throw new Error(response.status === 401 || response.status === 403
      ? `Elasticsearch authentication/permissions failed (HTTP ${response.status}).`
      : `Elasticsearch returned HTTP ${response.status}.`);
    return response.json();
  }
  async probe(config) {
    const fields = [config.timestampField, "source.ip", "destination.ip", "event.category", "event.outcome", "user.name", "dns.question.name", "file.hash.sha256", "source.bytes", "process.entity_id"];
    const caps = await this.request(`/${encodeURIComponent(config.indexPattern)}/_field_caps`, { fields, include_unmapped: true });
    return Object.fromEntries(fields.map(field => [field, Object.values(caps.fields?.[field] || {}).some(type => type.searchable === true)]));
  }
  async page(config, from, to, cursor = null, extraQuery = null) {
    if (this.relay) config = { ...config, pageSize: Math.min(config.pageSize, 500) };
    const pit = cursor?.pit || (await this.request(`/${encodeURIComponent(config.indexPattern)}/_pit?keep_alive=10m`, null)).id;
    if (typeof pit !== "string" || !pit) throw new Error("Elasticsearch did not return a valid point-in-time ID.");
    const filter = [{ range: { [config.timestampField]: { gte: from, lte: to } } }];
    if (config.query) filter.push({ query_string: { query: config.query, lenient: false, allow_leading_wildcard: false } });
    if (extraQuery) filter.push(extraQuery);
    try {
      const body = await this.request("/_search", {
        pit: { id: pit, keep_alive: "10m" }, size: config.pageSize, track_total_hits: true, timeout: "20s",
        query: { bool: { filter } }, sort: [{ [config.timestampField]: { order: "asc", unmapped_type: "date" } }, { _shard_doc: "asc" }],
        ...(cursor?.after ? { search_after: cursor.after } : {})
      });
      if (body.timed_out || body._shards?.failed > 0) throw new Error("Elasticsearch page was incomplete; checkpoint was not advanced.");
      const hits = body.hits?.hits, total = body.hits?.total;
      if (!Array.isArray(hits) || !Number.isSafeInteger(total?.value) || total.value < 0 || total.relation !== "eq"
        || hits.length > config.pageSize || hits.some(hit => !hit || !Array.isArray(hit.sort) || hit.sort.length !== 2
          || typeof hit._id !== "string" || typeof hit._index !== "string")) {
        throw new Error("Elasticsearch returned malformed or inexact search results; checkpoint was not advanced.");
      }
      return { hits, total: total.value, cursor: { pit: body.pit_id || pit, after: hits.at(-1)?.sort || cursor?.after }, complete: hits.length < config.pageSize };
    } catch (error) {
      if (!cursor) await this.closePit(pit);
      throw error;
    }
  }
  async closePit(id) { try { await this.request("/_pit", { id }, "DELETE"); } catch { /* Expired PITs are already released by Elasticsearch. */ } }
  async watched(config, rule, from, to) {
    const fields = INDICATOR_FIELDS[rule.indicatorType];
    const should = fields.map(field => ({ term: { [field]: rule.indicatorType === "ip" ? rule.indicatorValue : { value: rule.indicatorValue, case_insensitive: true } } }));
    if (rule.indicatorType === "domain" && rule.includeSubdomains) {
      for (const field of fields) should.push({ wildcard: { [field]: { value: `*.${rule.indicatorValue}`, case_insensitive: true } } });
    }
    const query = { bool: { should, minimum_should_match: 1 } };
    const filter = [];
    if (rule.scope?.host) filter.push({ term: { "host.name": rule.scope.host } });
    if (rule.scope?.infrastructure) filter.push({ term: { [config.infrastructureField]: rule.scope.infrastructure } });
    if (rule.requireSuccess) filter.push({ term: { "event.outcome": "success" } });
    const page = await this.page({ ...config, query: "", pageSize: Math.min(config.pageSize, 500) }, from, to, null, { bool: { filter: [query, ...filter] } });
    await this.closePit(page.cursor.pit);
    return page;
  }
  async evidence(index, id) { return this.request(`/${encodeURIComponent(index)}/_doc/${encodeURIComponent(id)}`, null, "GET"); }
}
