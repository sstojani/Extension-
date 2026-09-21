import { describe, expect, it } from "vitest";
import { isExcludedCandidate, type CandidateException } from "../src/candidate-exclusions";

describe("candidate exclusions", () => {
  const rules = [
    "ip:10.20.0.0/16",
    "keyword:dhcp lease renewal",
    "domain:trusted.example",
    "hash:0123456789abcdef"
  ];

  it("matches internal IPs by CIDR without matching adjacent ranges", () => {
    expect(isExcludedCandidate({ ip: "10.20.44.8" }, rules)).toBe(true);
    expect(isExcludedCandidate({ ip: "10.21.44.8" }, rules)).toBe(false);
  });

  it("matches known-normal activity by keyword", () => {
    expect(isExcludedCandidate({ ip: "192.168.1.10", text: "DHCP lease renewal completed" }, rules)).toBe(true);
    expect(isExcludedCandidate({ ip: "192.168.1.10", text: "Authentication failed" }, rules)).toBe(false);
  });

  it("matches IOC domains and hashes only in their matching indicator class", () => {
    expect(isExcludedCandidate({ type: "domain", normalized: "api.trusted.example" }, rules)).toBe(true);
    expect(isExcludedCandidate({ type: "sha256", normalized: "0123456789abcdef" }, rules)).toBe(true);
    expect(isExcludedCandidate({ type: "domain", normalized: "untrusted.example" }, rules)).toBe(false);
  });

  it("applies structured exceptions only to their configured ECS field", () => {
    const exceptions: CandidateException[] = [{
      id: "exception-1",
      scope: "identity",
      value: "svc-backup",
      field: "user.name",
      enabled: true,
      createdAt: "2026-09-11T08:00:00.000Z"
    }];
    expect(isExcludedCandidate({ type: "identity", values: ["other-user"], fields: { "user.name": "svc-backup" } }, [], exceptions)).toBe(true);
    expect(isExcludedCandidate({ type: "identity", values: ["svc-backup"], fields: { "user.name": "other-user" } }, [], exceptions)).toBe(false);
  });

  it("ignores disabled and expired structured exceptions", () => {
    const base: CandidateException = {
      id: "exception-2",
      scope: "ip",
      value: "198.51.100.0/24",
      enabled: true,
      createdAt: "2026-09-11T08:00:00.000Z"
    };
    expect(isExcludedCandidate({ ip: "198.51.100.20" }, [], [{ ...base, enabled: false }])).toBe(false);
    expect(isExcludedCandidate({ ip: "198.51.100.20" }, [], [{ ...base, expiresAt: "2026-09-11T08:30:00.000Z" }], Date.parse("2026-09-11T09:00:00.000Z"))).toBe(false);
    expect(isExcludedCandidate({ ip: "198.51.100.20" }, [], [{ ...base, expiresAt: "2026-09-11T09:30:00.000Z" }], Date.parse("2026-09-11T09:00:00.000Z"))).toBe(true);
  });
});
