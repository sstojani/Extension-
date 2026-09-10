import { describe, expect, it } from "vitest";
import { buildIOCBulkSearchBody, buildIOCSearchBody } from "../src/search";

describe("search adapter query generation", () => {
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
