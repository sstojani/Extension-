import { describe, expect, it } from "vitest";
import {
  assessIdentityObservations,
  classifyIdentityValue,
  normalizeReputationDomain,
  normalizeReputationHash,
  type IdentityBaseline,
  type IdentityObservation
} from "../src/identity-analysis";

function observation(overrides: Partial<IdentityObservation> = {}): IdentityObservation {
  return {
    identity: "analyst@apdurres",
    rawIdentity: "analyst@apdurres",
    identityType: "email",
    sourceField: "user.email",
    encodedValue: false,
    sourceIp: "10.1.1.20",
    destinationIp: "10.1.1.5",
    service: "system.auth",
    events: 12,
    authenticationEvents: 12,
    failedEvents: 0,
    successfulEvents: 12,
    infrastructureCount: 1,
    infrastructures: ["durres"],
    sourceIpCount: 1,
    sourceIps: ["10.1.1.20"],
    destinationPorts: [443],
    actions: [{ key: "login_success", count: 12 }],
    datasets: [{ key: "system.auth", count: 12 }],
    firstSeen: "2026-09-11T08:00:00.000Z",
    lastSeen: "2026-09-11T08:10:00.000Z",
    ...overrides
  };
}

describe("identity analysis", () => {
  it("reclassifies a serialized account instead of treating it as a reputation domain", () => {
    expect(classifyIdentityValue("b'logrhythm@apdurres'")).toEqual({
      value: "logrhythm@apdurres",
      type: "service_account",
      encodedValue: true
    });
    expect(normalizeReputationDomain("b'logrhythm@apdurres'")).toBeUndefined();
    expect(normalizeReputationHash("not-a-hash")).toBeUndefined();
  });

  it("does not submit serialized or internal DNS names for public reputation", () => {
    expect(normalizeReputationDomain("b'brn3c2af4803012.ascunion.local'")).toBeUndefined();
    expect(normalizeReputationDomain("\"b'brn3c2af4803012.ascunion.local'\"")).toBeUndefined();
    expect(normalizeReputationDomain("printer.office.lan")).toBeUndefined();
    expect(normalizeReputationDomain("4.3.2.1.in-addr.arpa")).toBeUndefined();
    expect(normalizeReputationDomain("Threat.Public-Domain.COM.")).toBe("threat.public-domain.com");
  });

  it("promotes repeated failures with independent source spread evidence", () => {
    const result = assessIdentityObservations([observation({
      events: 81,
      failedEvents: 80,
      successfulEvents: 1,
      sourceIpCount: 5,
      sourceIps: ["203.0.113.4", "203.0.113.5", "203.0.113.6", "203.0.113.7", "203.0.113.8"],
      actions: [{ key: "failed_password", count: 80 }, { key: "login_success", count: 1 }]
    })], {}, "2026-09-11T08:10:00.000Z");

    expect(result.findings[0]).toMatchObject({ promoted: true, severity: "critical" });
    expect(result.findings[0]?.reasons).toContain("Failures and successes occurred in the same window; ordering is not verified");
  });

  it("does not promote an ordinary account from generic failure volume alone", () => {
    const result = assessIdentityObservations([observation({
      events: 180,
      failedEvents: 150,
      successfulEvents: 30,
      sourceIpCount: 6,
      sourceIps: ["10.1.1.20", "10.1.1.21", "10.1.1.22", "10.1.1.23", "10.1.1.24", "10.1.1.25"],
      actions: [{ key: "authentication", count: 180 }]
    })], {}, "2026-09-11T08:10:00.000Z");

    expect(result.findings[0]).toMatchObject({ promoted: false });
  });

  it("learns low-risk context and later detects a new source and unusual hour", () => {
    let baseline: IdentityBaseline = {};
    for (let day = 8; day <= 10; day += 1) {
      const dayOfMonth = String(day).padStart(2, "0");
      const learned = assessIdentityObservations([observation({
        firstSeen: `2026-09-${dayOfMonth}T08:00:00.000Z`,
        lastSeen: `2026-09-${dayOfMonth}T08:10:00.000Z`
      })], baseline, `2026-09-${dayOfMonth}T08:10:00.000Z`);
      baseline = learned.baseline;
    }
    const anomaly = assessIdentityObservations([observation({
      sourceIp: "198.51.100.9",
      sourceIps: ["198.51.100.9"],
      lastSeen: "2026-09-11T02:15:00.000Z"
    })], baseline, "2026-09-11T02:15:00.000Z").findings[0];

    expect(anomaly?.reasons).toContain("New source IP for this identity: 198.51.100.9");
    expect(anomaly?.reasons).toContain("Activity outside this identity's learned hours");
  });
});
