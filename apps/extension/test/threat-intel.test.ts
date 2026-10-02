import { describe, expect, it } from "vitest";
import { prioritizeThreatIntel, type RawIntelIOC } from "../src/threat-intel";

const NOW = Date.parse("2026-09-29T12:00:00Z");

describe("threat-intel prioritization", () => {
  it("deduplicates indicators and rewards independent-feed corroboration", () => {
    const records: RawIntelIOC[] = [
      { value: "203.0.113.44", source: "ThreatView IP", threatType: "threat_feed" },
      { value: "203.0.113.44", source: "ThreatFox", threatType: "botnet_c2", confidence: 90, firstSeen: "2026-09-29T08:00:00Z" },
      { value: "203.0.113.44", source: "Feodo Tracker", threatType: "botnet_c2", firstSeen: "2026-09-29T07:00:00Z" }
    ];

    const [ioc] = prioritizeThreatIntel(records, NOW);
    expect(ioc?.sources).toHaveLength(3);
    expect(ioc?.riskLevel).toBe("critical");
    expect(ioc?.riskReasons.join(" ")).toContain("Corroborated by 3 feeds");
  });

  it("keeps the strongest threat description when feeds disagree", () => {
    const [ioc] = prioritizeThreatIntel([
      { value: "203.0.113.44", source: "Generic Feed", threatType: "threat_feed" },
      { value: "203.0.113.44", source: "Feodo Tracker", threatType: "botnet_c2", malware: "Dridex" }
    ], NOW);

    expect(ioc?.threatType).toBe("botnet_c2");
    expect(ioc?.malware).toBe("Dridex");
    expect(ioc?.riskReasons).toContain("Command-and-control or botnet context");
  });

  it("ranks fresh command-and-control intelligence above a generic feed entry", () => {
    const ranked = prioritizeThreatIntel([
      { value: "198.51.100.9", source: "ThreatView IP", threatType: "threat_feed" },
      { value: "203.0.113.8", source: "Feodo Tracker", threatType: "botnet_c2", firstSeen: "2026-09-29T10:00:00Z" }
    ], NOW);

    expect(ranked.map((ioc) => ioc.normalized)).toEqual(["203.0.113.8", "198.51.100.9"]);
    expect(ranked[0]?.riskReasons).toContain("Command-and-control or botnet context");
  });

  it("drops values that are not valid IOC types", () => {
    expect(prioritizeThreatIntel([{ value: "not an indicator", source: "test" }], NOW)).toEqual([]);
  });
});
