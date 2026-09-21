import { describe, expect, it } from "vitest";
import { buildThreatRadarBody, buildThreatRadarEntityDetailBody, buildThreatRadarStageBodies, calculateGtiBoost, classifyGtiReputation, isConfirmedSuspiciousFinding, isConfirmedSuspiciousIndicator, isInvestigationCandidate, parseGtiReputationResponse, summarizeThreatRadarEntities, summarizeThreatRadarIndicators, type GtiIpReputation, type ThreatRadarFinding, type ThreatRadarIndicator } from "../src/kibana";

type EnrichedFinding = ThreatRadarFinding & { gti?: GtiIpReputation };

function finding(overrides: Partial<EnrichedFinding> = {}): EnrichedFinding {
  return {
    ip: "10.1.76.2",
    sourceIp: "10.1.76.2",
    destinationIp: "192.168.1.250",
    gtiIp: "--",
    role: "source",
    direction: "internal",
    evidenceScope: "entity",
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
    outboundBytes: 0,
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

function indicator(overrides: Partial<ThreatRadarIndicator> = {}): ThreatRadarIndicator {
  return {
    value: "example.test",
    type: "domain",
    score: 40,
    severity: "medium",
    events: 50,
    infrastructureCount: 1,
    deniedEvents: 20,
    suspiciousKeywordHits: 3,
    matchedKeywords: ["malware"],
    signalCounts: { malware: 3 },
    actions: [],
    datasets: [],
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
    reasons: ["Signals: Malware"],
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
    expect(serialized).toContain('"1.1.1.1"');
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

    expect(stages.map((stage) => stage.key)).toEqual(["signals", "sources", "destinations", "indicators", "identities"]);
    expect(Object.keys(stages[0]?.body.aggs ?? {})).toEqual(["security_signals"]);
    expect(Object.keys(stages[1]?.body.aggs ?? {})).toEqual(["source_entities"]);
    expect(Object.keys(stages[2]?.body.aggs ?? {})).toEqual(["destination_entities"]);
    expect(Object.keys(stages[3]?.body.aggs ?? {})).toHaveLength(6);
    expect(Object.keys(stages[4]?.body.aggs ?? {})).toHaveLength(13);
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
    expect(detail.aggs.source_entities).toHaveProperty("aggs.outbound_events.aggs.peer_values.aggs.source_bytes");
    expect(detail.aggs.source_entities).toHaveProperty("aggs.outbound_events.aggs.peer_values.aggs.network_bytes");
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
      evidenceScope: "source_destination",
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
      evidenceScope: "source_destination",
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
      evidenceScope: "source_destination",
      outboundEvents: 8,
      deniedEvents: 0,
      destinationPorts: 1,
      relatedHosts: 1,
      dangerousPorts: []
    }))).toBe(false);
  });

  it("keeps private outbound evidence isolated to each exact destination", () => {
    const results = summarizeThreatRadarEntities({
      aggregations: {
        source_entities: {
          buckets: [{
            key: "192.168.1.20",
            doc_count: 1000,
            outbound_events: {
              peer_values: {
                buckets: [
                  {
                    key: "1.1.1.1",
                    doc_count: 900,
                    infrastructure: { value: 2 },
                    destination_ports: { value: 1 },
                    ports: { buckets: [{ key: 53, doc_count: 900 }] },
                    actions: { buckets: [{ key: "dns_query", doc_count: 900 }] },
                    outcomes: { buckets: [{ key: "success", doc_count: 900 }] },
                    categories: { buckets: [{ key: "network", doc_count: 900 }] },
                    datasets: { buckets: [{ key: "dns", doc_count: 900 }] },
                    denied_events: { doc_count: 0 },
                    authentication_successes: { doc_count: 0 },
                    source_bytes: { value: 12000 },
                    network_bytes: { value: 18000 },
                    threat_signals: { buckets: { exfiltration: { doc_count: 0 } } },
                    latest: { hits: { hits: [] } }
                  },
                  {
                    key: "203.0.113.90",
                    doc_count: 40,
                    infrastructure: { value: 1 },
                    destination_ports: { value: 1 },
                    ports: { buckets: [{ key: 4444, doc_count: 40 }] },
                    actions: { buckets: [{ key: "connection_failed", doc_count: 35 }] },
                    outcomes: { buckets: [{ key: "failure", doc_count: 35 }] },
                    categories: { buckets: [{ key: "network", doc_count: 40 }] },
                    datasets: { buckets: [{ key: "firewall", doc_count: 40 }] },
                    denied_events: { doc_count: 35 },
                    authentication_successes: { doc_count: 0 },
                    source_bytes: { value: 5000 },
                    network_bytes: { value: 8000 },
                    threat_signals: { buckets: { command_control: { doc_count: 4 } } },
                    latest: { hits: { hits: [] } }
                  }
                ]
              }
            }
          }]
        }
      }
    }, "source_entities", "source");

    expect(results).toHaveLength(2);
    expect(results[0]).toMatchObject({
      sourceIp: "192.168.1.20",
      destinationIp: "1.1.1.1",
      evidenceScope: "source_destination",
      events: 900,
      topPorts: [53],
      deniedEvents: 0,
      outboundBytes: 18000,
      matchedKeywords: []
    });
    expect(results[1]).toMatchObject({
      sourceIp: "192.168.1.20",
      destinationIp: "203.0.113.90",
      evidenceScope: "source_destination",
      events: 40,
      topPorts: [4444],
      deniedEvents: 35,
      matchedKeywords: ["command_control"]
    });
  });

  it("keeps rare domains selected by a threat-signal lane even when absent from the volume lane", () => {
    const indicators = summarizeThreatRadarIndicators({
      aggregations: {
        dns_domain_entities: { buckets: [] },
        security_signals: {
          buckets: {
            malware: {
              dns_domain_entities: { buckets: [{ key: "rare-signal.example", doc_count: 2 }] }
            }
          }
        }
      }
    }, "dns_domain_entities", "domain");

    expect(indicators).toHaveLength(1);
    expect(indicators[0]).toMatchObject({
      value: "rare-signal.example",
      events: 2,
      matchedKeywords: ["malware"]
    });
  });

  it("does not promote clean high-volume outbound traffic as exfiltration without supported evidence", () => {
    expect(isConfirmedSuspiciousFinding(finding({
      destinationIp: "1.1.1.1",
      gtiIp: "1.1.1.1",
      direction: "outbound",
      evidenceScope: "source_destination",
      events: 22000,
      outboundEvents: 22000,
      outboundBytes: 50 * 1024 * 1024,
      matchedKeywords: [],
      suspiciousKeywordHits: 0,
      signalCounts: {},
      gti: {
        verdict: "VERDICT_BENIGN",
        threatScore: 0,
        malicious: 0,
        suspicious: 0,
        reputation: 0,
        asn: 13335
      }
    }))).toBe(false);
  });

  it("does not turn a clean public resolver into an exfiltration endpoint on nonstandard port fan-out", () => {
    expect(isConfirmedSuspiciousFinding(finding({
      destinationIp: "8.8.8.8",
      gtiIp: "8.8.8.8",
      direction: "outbound",
      evidenceScope: "source_destination",
      events: 19065,
      outboundEvents: 19065,
      outboundBytes: 200 * 1024 * 1024,
      topPorts: [443, 53, 161, 1900, 5985, 80],
      destinationPorts: 6,
      matchedKeywords: ["exfiltration"],
      suspiciousKeywordHits: 4,
      signalCounts: { exfiltration: 4 },
      gti: {
        verdict: "VERDICT_BENIGN",
        threatScore: 0,
        malicious: 0,
        suspicious: 0,
        reputation: 0,
        asn: 15169
      }
    }))).toBe(false);
  });

  it("does not queue a clean public resolver merely because normal replies fan out", () => {
    expect(isInvestigationCandidate(finding({
      ip: "8.8.8.8",
      sourceIp: "8.8.8.8",
      gtiIp: "8.8.8.8",
      direction: "inbound",
      events: 12000,
      relatedHosts: 40,
      destinationPorts: 80,
      deniedEvents: 0,
      matchedKeywords: [],
      signalCounts: {},
      gti: {
        verdict: "VERDICT_BENIGN",
        threatScore: 0,
        malicious: 0,
        suspicious: 0,
        reputation: 0,
        asn: 15169
      }
    }))).toBe(false);
  });

  it("promotes exact outbound exfiltration only when corroborated by transfer and explicit signals", () => {
    expect(isConfirmedSuspiciousFinding(finding({
      destinationIp: "203.0.113.91",
      gtiIp: "203.0.113.91",
      direction: "outbound",
      evidenceScope: "source_destination",
      events: 80,
      outboundEvents: 80,
      outboundBytes: 50 * 1024 * 1024,
      matchedKeywords: ["exfiltration"],
      suspiciousKeywordHits: 3,
      signalCounts: { exfiltration: 3 }
    }))).toBe(true);
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

  it("does not confirm a clean domain merely because log text carried a threat label", () => {
    expect(isConfirmedSuspiciousIndicator(indicator({
      matchedKeywords: [],
      suspiciousKeywordHits: 0,
      gti: {
        verdict: "VERDICT_BENIGN",
        threatScore: 0,
        malicious: 0,
        suspicious: 0,
        reputation: 0,
        asn: 0
      }
    }))).toBe(false);
  });

  it("ranks an adversely scored domain as a confirmed IOC even when it is new to text rules", () => {
    expect(isConfirmedSuspiciousIndicator(indicator({
      matchedKeywords: [],
      suspiciousKeywordHits: 0,
      gti: {
        verdict: "VERDICT_SUSPICIOUS",
        threatScore: 35,
        malicious: 1,
        suspicious: 2,
        reputation: -5,
        asn: 64500
      }
    }))).toBe(true);
  });
});
