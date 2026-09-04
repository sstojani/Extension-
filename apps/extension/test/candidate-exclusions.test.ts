import { describe, expect, it } from "vitest";
import { isExcludedCandidate } from "../src/candidate-exclusions";

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
});
