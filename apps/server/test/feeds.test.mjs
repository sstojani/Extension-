import { test } from "node:test";
import assert from "node:assert/strict";
import { rankFeedIndicators, campaignBatch, feedMatchQuery } from "../feeds.mjs";
test("feed snapshot priority does not invent independent confidence and batches never repeat", () => {
  const data = Array.from({ length: 1100 }, (_,i) => ({ value: `x${i}.evil.com`, type: "domain", provider: "A", context: "phishing" }));
  data.push({ value: "c2.evil.com", type: "domain", provider: "A", context: "botnet C2" });
  data.push({ value: "c2.evil.com", type: "domain", provider: "B", context: "botnet C2" });
  const iocs = rankFeedIndicators(data, "2026-10-02T00:00:00.000Z");
  assert.equal(iocs[0].value, "c2.evil.com"); assert.equal(iocs[0].priority, 90);
  const a = campaignBatch({ iocs, offset: 0 }), b = campaignBatch({ iocs, offset: 500 });
  assert.equal(a.length, 500); assert.equal(b.length, 500); assert.equal(a.some(i => b.some(j => i.key === j.key)), false);
  assert.throws(() => campaignBatch({ iocs, offset: 0 }, 501));
  assert.equal(JSON.stringify(feedMatchQuery(a)).includes("terms"), true);
});
