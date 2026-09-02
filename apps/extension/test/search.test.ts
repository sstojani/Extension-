import { describe, expect, it } from "vitest";
import { buildIOCSearchBody } from "../src/search";

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
});
