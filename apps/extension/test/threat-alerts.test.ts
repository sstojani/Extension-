import { describe, expect, it } from "vitest";
import { buildThreatAlertCandidates, normalizeAlertIndicator, type ThreatAlertRule } from "../src/threat-alerts";

const rule: ThreatAlertRule = {
  id: "rule-1",
  name: "Watch scanner",
  indicatorType: "ip",
  indicatorValue: "203.0.113.10",
  minScore: 55,
  enabled: true,
  createdAt: "2026-09-09T00:00:00.000Z"
};

describe("Threat Radar alerts", () => {
  it("refangs indicator values", () => {
    expect(normalizeAlertIndicator("Example[.]COM.")).toBe("example.com");
  });

  it("creates a watched IOC candidate only after the score threshold", () => {
    const finding = {
      ip: "203.0.113.10",
      role: "source" as const,
      direction: "inbound" as const,
      score: 70,
      sourceIp: "203.0.113.10",
      destinationIp: "10.0.0.5",
      events: 900,
      dangerousPorts: [22],
      actions: [{ key: "denied", count: 850 }],
      deniedEvents: 850,
      outboundEvents: 0,
      matchedKeywords: [],
      reasons: ["Repeated denied activity"]
    };
    expect(buildThreatAlertCandidates({ suspects: [finding] }, [rule])).toHaveLength(1);
    expect(buildThreatAlertCandidates({ suspects: [{ ...finding, score: 40 }] }, [rule])).toHaveLength(0);
  });

  it("does not auto-alert on reputation alone without corroborated behavior", () => {
    const finding = {
      ip: "198.51.100.8",
      role: "source" as const,
      direction: "inbound" as const,
      score: 90,
      sourceIp: "198.51.100.8",
      destinationIp: "10.0.0.5",
      events: 20,
      dangerousPorts: [443],
      actions: [{ key: "accept", count: 20 }],
      deniedEvents: 0,
      outboundEvents: 0,
      matchedKeywords: [],
      reasons: ["Adverse reputation"],
      gti: { verdict: "malicious", threatScore: 90, malicious: 10, suspicious: 0 }
    };
    expect(buildThreatAlertCandidates({ suspects: [finding] }, [])).toHaveLength(0);
  });
});
