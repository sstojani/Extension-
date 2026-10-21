import { describe, expect, it } from "vitest";
import { buildIOCBulkSearchBody, buildIOCSearchBody } from "../src/search";
import { classifyIOC } from "@soc-watch/ioc";
import { DEFAULT_IOC_FIELD_MAPPING, dailyIocHuntParamsSchema } from "@soc-watch/protocol";

describe("search adapter query generation", () => {
  it.each([
    ["203.0.113.8", "ip", "dns.resolved_ip"],
    ["bad.example.test", "domain", "source.domain"],
    ["a".repeat(32), "md5", "process.hash.md5"],
    ["b".repeat(40), "sha1", "process.hash.sha1"],
    ["c".repeat(64), "sha256", "process.hash.sha256"]
  ])("searches exact IOC fields with the selected time field: %s", (value, type, extraField) => {
    const ioc = classifyIOC(value);
    const body = buildIOCBulkSearchBody({ iocs: [ioc], timestampField: "event.created", from: "now/d", to: "now", size: 5 });
    expect(body.query.bool.filter[0]).toEqual({ range: { "event.created": { gte: "now/d", lte: "now" } } });
    const filter = body.aggs.ioc_matches.filters.filters.ioc_0;
    const fields = DEFAULT_IOC_FIELD_MAPPING[type as keyof typeof DEFAULT_IOC_FIELD_MAPPING];
    expect(filter?.bool.should).toEqual(fields.map((field) => ({ term: { [field]: ioc.normalized } })));
    expect(filter?.bool.should).toContainEqual({ term: { [extraField]: ioc.normalized } });
    expect(body.query.bool.filter[1]).toMatchObject({ bool: { should: expect.arrayContaining([{ terms: { [extraField]: [ioc.normalized] } }]) } });
    expect(JSON.stringify(body)).not.toContain("wildcard");
    expect(JSON.stringify(body)).not.toContain("match_all");
  });

  it("validates explicit hunt groups and campaign identity", () => {
    for (const group of ["ip", "domain", "hash", "url"]) expect(dailyIocHuntParamsSchema.parse({ indexPattern: "logs-*", indicatorGroup: group }).indicatorGroup).toBe(group);
    expect(dailyIocHuntParamsSchema.safeParse({ indexPattern: "logs-*", indicatorGroup: "anything" }).success).toBe(false);
    expect(dailyIocHuntParamsSchema.safeParse({ indexPattern: "logs-*", campaignId: "wrong" }).success).toBe(false);
  });
  it("builds bounded read-only IOC search DSL", () => {
    const body = buildIOCSearchBody({
      ioc: { original: "62[.]238[.]44[.]99", normalized: "62.238.44.99", type: "ip" },
      fieldMapping: { ip: ["source.ip"], domain: [], url: [], md5: [], sha1: [], sha256: [] },
      timestampField: "@timestamp",
      from: "now-24h",
      to: "now",
      size: 25
    });

    expect(body.query.bool.filter[1]).toEqual({
      bool: {
        should: [{ term: { "source.ip": "62.238.44.99" } }],
        minimum_should_match: 1
      }
    });
    expect(JSON.stringify(body)).not.toContain("DELETE");
  });

  it("builds one bounded aggregation query for a distinct IOC batch", () => {
    const body = buildIOCBulkSearchBody({
      iocs: [
        { original: "1.2.3.4", normalized: "1.2.3.4", type: "ip" },
        { original: "bad.example", normalized: "bad.example", type: "domain" }
      ],
      timestampField: "@timestamp",
      from: "now-24h",
      to: "now",
      size: 5
    });
    const filters = body.aggs.ioc_matches.filters.filters as Record<string, unknown>;
    expect(body.size).toBe(0);
    expect(body.timeout).toBe("45s");
    expect(Object.keys(filters)).toEqual(["ioc_0", "ioc_1"]);
    expect(body.aggs.ioc_matches.aggs.latest.top_hits.size).toBe(5);
  });
});
