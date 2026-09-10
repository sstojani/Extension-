import { describe, expect, it } from "vitest";
import { buildThreatRadarBody, buildThreatRadarEntityDetailBody, buildThreatRadarStageBodies, calculateGtiBoost, classifyGtiReputation, isConfirmedSuspiciousFinding, isInvestigationCandidate, parseGtiReputationResponse, type GtiIpReputation, type ThreatRadarFinding } from "../src/kibana";

type EnrichedFinding = ThreatRadarFinding & { gti?: GtiIpReputation };

function finding(overrides: Partial<EnrichedFinding> = {}): EnrichedFinding {
  return {
    ip: "10.1.76.2",
    sourceIp: "10.1.76.2",
    destinationIp: "192.168.1.250",
    gtiIp: "--",
    role: "source",
    direction: "internal",
    score: 90,
    severity: "critical",
    events: 900,
    relatedHosts: 1,
    infrastructureCount: 1,
    destinationPorts: 1,
    dangerousPorts: [],
    topPorts: [67],
    actions: [{ key: "connection failed", count: 700 }],
    datasets: [{ key: "dhcp", count: 900 }],
    deniedEvents: 700,
    successfulEvents: 0,
    outboundEvents: 0,
    suspiciousKeywordHits: 0,
    matchedKeywords: [],
    signalCounts: {},
    latest: {
      timestamp: undefined,
      sourceIp: undefined,
      destinationIp: undefined,
      clientIp: undefined,
      serverIp: undefined,
      destinationPort: undefined,
      action: undefined,
      host: undefined,
      message: undefined
    },
    reasons: ["High log volume"],
    ...overrides
  };
}

describe("Threat Radar query generation", () => {
  it("aggregates network identities and suspicious indicators without retrieving raw events", () => {
    const body = buildThreatRadarBody({
      timestampField: "@timestamp",
      from: "now-15m",
      to: "now",
      size: 50
    });

    expect(body.size).toBe(0);
    expect(body.track_total_hits).toBe(true);
    expect(body.aggs).toMatchObject({
      source_entities: { terms: { field: "source.ip" } },
      destination_entities: { terms: { field: "destination.ip" } },
      client_entities: { terms: { field: "client.ip" } },
      server_entities: { terms: { field: "server.ip" } },
      dns_domain_entities: { terms: { field: "dns.question.name" } },
      url_domain_entities: { terms: { field: "url.domain" } },
      destination_domain_entities: { terms: { field: "destination.domain" } },
      sha256_entities: { terms: { field: "file.hash.sha256" } },
      sha1_entities: { terms: { field: "file.hash.sha1" } },
      md5_entities: { terms: { field: "file.hash.md5" } }
    });
    const serialized = JSON.stringify(body);
    expect(serialized).toContain("event.outcome");
    expect(serialized).toContain("outbound_events");
    expect(serialized).toContain("security_signals");
    expect(serialized).toContain('"denied"');
    expect(serialized).toContain("brute_force");
    expect(serialized).toContain("command_control");
    expect(serialized).not.toContain("DELETE");

    const wideBody = buildThreatRadarBody({
      timestampField: "@timestamp",
      from: "now/d",
      to: "now",
      size: 20
    });
    expect(wideBody.timeout).toBe("25s");
    expect(wideBody.aggs).not.toHaveProperty("client_entities");
    expect(wideBody.aggs).not.toHaveProperty("server_entities");
  });

  it("splits a full-day analysis into bounded Kibana stages", () => {
    const stages = buildThreatRadarStageBodies({
      timestampField: "@timestamp",
      from: "now/d",
      to: "now",
      size: 20
    });

    expect(stages.map((stage) => stage.key)).toEqual(["signals", "sources", "destinations", "indicators"]);
    expect(Object.keys(stages[0]?.body.aggs ?? {})).toEqual(["security_signals"]);
    expect(Object.keys(stages[1]?.body.aggs ?? {})).toEqual(["source_entities"]);
    expect(Object.keys(stages[2]?.body.aggs ?? {})).toEqual(["destination_entities"]);
    expect(Object.keys(stages[3]?.body.aggs ?? {})).toHaveLength(6);
    expect(stages[1]?.body.aggs.source_entities).toHaveProperty("aggs.denied");
    expect(stages[1]?.body.aggs.source_entities).toHaveProperty("aggs.risky_auth_success");
    expect(stages[1]?.body.aggs.source_entities).toHaveProperty("aggs.risky_ports");
    expect(stages[1]?.body.aggs.source_entities).toHaveProperty("aggs.volume");
    expect(stages[2]?.body.aggs.destination_entities).toHaveProperty("aggs.denied");
    expect(stages.every((stage) => stage.body.timeout === "20s")).toBe(true);
    expect(stages[1]?.body.track_total_hits).toBe(true);
    expect(stages.filter((stage) => stage.key !== "sources").every((stage) => stage.body.track_total_hits === false)).toBe(true);

    const detail = buildThreatRadarEntityDetailBody(
      { timestampField: "@timestamp", from: "now/d", to: "now", size: 20 },
      "source_entities",
      "source.ip",
      ["8.8.8.8", "1.1.1.1"]
    );
    expect(detail.query).toMatchObject({ bool: { filter: [{ range: expect.anything() }, { terms: { "source.ip": ["8.8.8.8", "1.1.1.1"] } }] } });
    expect(detail.aggs.source_entities).toHaveProperty("aggs.latest.top_hits");
    expect(detail.aggs.source_entities).toHaveProperty("aggs.denied_events.filter");
    expect(detail.aggs.source_entities).toHaveProperty("aggs.authentication_successes.filter");
    expect(detail.aggs.source_entities).toHaveProperty("aggs.threat_signals.filters");
    expect(detail.aggs.source_entities).toHaveProperty("terms.size", 2);
  });

  it("does not promote ordinary private internal failures by volume alone", () => {
    expect(isConfirmedSuspiciousFinding(finding())).toBe(false);
  });

  it("promotes a high-volume denied attack from a public source", () => {
    expect(isConfirmedSuspiciousFinding(finding({
      ip: "8.34.210.39",
      sourceIp: "8.34.210.39",
      direction: "inbound",
      deniedEvents: 450
    }))).toBe(true);
  });

  it("requires behavioral or reputation evidence alongside a threat keyword", () => {
    expect(isConfirmedSuspiciousFinding(finding({
      direction: "external",
      deniedEvents: 0,
      matchedKeywords: ["exploit"],
      suspiciousKeywordHits: 1,
      signalCounts: { exploit: 1 }
    }))).toBe(false);
  });

  it("does not label clean outbound resolver traffic as command and control", () => {
    expect(isConfirmedSuspiciousFinding(finding({
      destinationIp: "1.1.1.1",
      gtiIp: "1.1.1.1",
      direction: "outbound",
      outboundEvents: 3271,
      deniedEvents: 443,
      destinationPorts: 6,
      relatedHosts: 2,
      matchedKeywords: ["command_control"],
      suspiciousKeywordHits: 1,
      signalCounts: { command_control: 1 },
      gti: {
        threatScore: 0,
        malicious: 0,
        suspicious: 0,
        reputation: 0,
        asn: 13335
      }
    }))).toBe(false);
  });

  it("keeps strong command-control behavior visible when reputation is not known yet", () => {
    expect(isConfirmedSuspiciousFinding(finding({
      destinationIp: "185.220.101.24",
      gtiIp: "185.220.101.24",
      direction: "outbound",
      outboundEvents: 80,
      deniedEvents: 30,
      destinationPorts: 5,
      matchedKeywords: ["command_control"],
      suspiciousKeywordHits: 4,
      signalCounts: { command_control: 4 }
    }))).toBe(true);
  });

  it("never promotes private internal traffic as malware or scanning", () => {
    expect(isConfirmedSuspiciousFinding(finding({
      matchedKeywords: ["malware", "scanning"],
      suspiciousKeywordHits: 100,
      signalCounts: { malware: 50, scanning: 50 },
      dangerousPorts: [445],
      destinationPorts: 25,
      relatedHosts: 12
    }))).toBe(false);
  });

  it("does not place routine private internal traffic in the investigation queue", () => {
    expect(isInvestigationCandidate(finding({
      events: 5000,
      deniedEvents: 1200,
      destinationPorts: 30,
      relatedHosts: 20,
      dangerousPorts: [445]
    }))).toBe(false);
  });

  it("keeps a multi-evidence public source available for analyst investigation", () => {
    expect(isInvestigationCandidate(finding({
      ip: "203.0.113.45",
      sourceIp: "203.0.113.45",
      direction: "inbound",
      score: 42,
      events: 70,
      deniedEvents: 14,
      destinationPorts: 5,
      relatedHosts: 2,
      dangerousPorts: [22]
    }))).toBe(true);
  });

  it("requires corroboration before queueing an unknown outbound destination", () => {
    expect(isInvestigationCandidate(finding({
      destinationIp: "203.0.113.80",
      gtiIp: "203.0.113.80",
      direction: "outbound",
      outboundEvents: 8,
      deniedEvents: 0,
      destinationPorts: 1,
      relatedHosts: 1,
      dangerousPorts: []
    }))).toBe(false);
  });

  it("promotes a public source attacking SSH across many infrastructures", () => {
    expect(isConfirmedSuspiciousFinding(finding({
      ip: "45.148.10.24",
      sourceIp: "45.148.10.24",
      destinationIp: "10.20.30.40",
      gtiIp: "45.148.10.24",
      direction: "inbound",
      events: 1800,
      relatedHosts: 10,
      infrastructureCount: 10,
      destinationPorts: 1,
      dangerousPorts: [22],
      topPorts: [22],
      deniedEvents: 0
    }))).toBe(true);
  });

  it("gives confirmed malicious reputation a larger rank boost than suspicious or clean reputation", () => {
    const base = { reputation: 0, asn: 0 };
    expect(calculateGtiBoost({ ...base, threatScore: 90, malicious: 3, suspicious: 0, verdict: "VERDICT_MALICIOUS" }))
      .toBeGreaterThan(calculateGtiBoost({ ...base, threatScore: 35, malicious: 0, suspicious: 2 }));
    expect(calculateGtiBoost({ ...base, threatScore: 35, malicious: 0, suspicious: 2 }))
      .toBeGreaterThan(calculateGtiBoost({ ...base, threatScore: 0, malicious: 0, suspicious: 0 }));
  });

  it("classifies a GTI-suspicious IP with many malicious vendor detections as malicious", () => {
    const gti = parseGtiReputationResponse({
      data: {
        attributes: {
          gti_assessment: {
            verdict: { value: "VERDICT_SUSPICIOUS" },
            severity: { value: "SEVERITY_MEDIUM" },
            threat_score: { value: 25 }
          },
          last_analysis_stats: {
            malicious: 14,
            suspicious: 0,
            harmless: 20,
            undetected: 55
          },
          reputation: -12,
          asn: 135377
        }
      }
    });

    expect(gti).toMatchObject({
      verdict: "VERDICT_SUSPICIOUS",
      severity: "SEVERITY_MEDIUM",
      threatScore: 25,
      malicious: 14,
      totalEngines: 89,
      reputation: -12
    });
    expect(classifyGtiReputation(gti)).toBe("Malicious");
  });

  it("keeps an explicitly benign GTI verdict clean despite isolated vendor noise", () => {
    expect(classifyGtiReputation({
      verdict: "VERDICT_BENIGN",
      severity: "SEVERITY_NONE",
      threatScore: 0,
      malicious: 2,
      suspicious: 0,
      reputation: 0,
      asn: 15169
    })).toBe("Clean");
  });
});
