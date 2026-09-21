import { describe, expect, it } from "vitest";
import { getKnownInfrastructure, isRoutineKnownInfrastructureTraffic } from "../src/known-infrastructure";

describe("known infrastructure context", () => {
  it("recognizes major public DNS services", () => {
    expect(getKnownInfrastructure("1.1.1.1")).toMatchObject({ kind: "public_dns", provider: "Cloudflare Public DNS" });
    expect(getKnownInfrastructure("8.8.8.8")).toMatchObject({ kind: "public_dns", provider: "Google Public DNS" });
  });

  it("treats resolver traffic as routine only when its exact context fits DNS use", () => {
    expect(isRoutineKnownInfrastructureTraffic({
      destinationIp: "1.1.1.1",
      ports: [53, 443],
      actions: [{ key: "connection-started" }, { key: "accept" }],
      datasets: [{ key: "network_traffic.dns" }]
    })).toBe(true);
  });

  it("does not suppress non-resolver ports or explicit security telemetry", () => {
    expect(isRoutineKnownInfrastructureTraffic({
      destinationIp: "8.8.8.8",
      ports: [53, 22],
      actions: [{ key: "accept" }],
      datasets: [{ key: "firewall" }]
    })).toBe(false);
    expect(isRoutineKnownInfrastructureTraffic({
      destinationIp: "8.8.8.8",
      ports: [443],
      actions: [{ key: "malware-detected" }],
      datasets: [{ key: "endpoint.alerts" }]
    })).toBe(false);
  });
});
