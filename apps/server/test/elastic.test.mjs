import { test } from "node:test";
import assert from "node:assert/strict";
import { ElasticClient } from "../elastic.mjs";
const config = { indexPattern: "logs-*", timestampField: "@timestamp", pageSize: 500, query: "" };
test("PIT pagination uses returned tie-break cursor and rejects partial searches", async () => {
  const calls = [];
  const c = new ElasticClient({ elasticUrl: "https://elastic.test", elasticApiKey: "test" }, async (url,init) => {
    calls.push({ url, body: init.body && JSON.parse(init.body) });
    return Response.json(url.includes("_pit?") ? { id: "pit" } : { pit_id: "updated", hits: { total: { value: 2, relation: "eq" }, hits: [{ _index: "logs-security", _id: "1", sort: [123,45] }] }, _shards: { failed: 0 } });
  });
  const p = await c.page(config, "from", "to");
  assert.deepEqual(p.cursor, { pit: "updated", after: [123,45] });
  await c.page(config, "from", "to", p.cursor);
  assert.deepEqual(calls.at(-1).body.search_after, [123,45]);
  c.fetch = async () => Response.json({ timed_out: true });
  await assert.rejects(() => c.page(config, "from", "to", p.cursor), /incomplete/);
});
test("explicit watched IOC query has no dashboard keyword or promotion gate", async () => {
  let body;
  const c = new ElasticClient({ elasticUrl: "https://elastic.test", elasticApiKey: "test" }, async (url,init) => {
    if (url.endsWith("/_search")) body = JSON.parse(init.body);
    return Response.json(url.includes("_pit?") ? { id: "pit" } : { hits: { total: { value: 0, relation: "eq" }, hits: [] } });
  });
  await c.watched({ ...config, query: "malware" }, { indicatorType: "domain", indicatorValue: "evil.com", includeSubdomains: true, scope: {}, requireSuccess: false }, "from", "to");
  assert.equal(JSON.stringify(body).includes("malware"), false);
  assert.ok(JSON.stringify(body).includes("*.evil.com"));
});
