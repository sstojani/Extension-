import { describe, expect, it } from "vitest";
import { deriveConnectionHealth } from "../src/connection-health";

describe("connection health", () => {
  it("reports connected only after Kibana and Fleet checks succeed", () => {
    expect(deriveConnectionHealth({
      kibanaAvailable: true,
      fleetAvailable: true,
      agentsAvailable: true
    })).toMatchObject({
      state: "connected",
      kibana: "authenticated",
      fleet: "available",
      agents: "available"
    });
  });

  it("reports authentication failures as disconnected", () => {
    expect(deriveConnectionHealth({
      kibanaAvailable: false,
      fleetAvailable: false,
      agentsAvailable: false,
      kibanaError: { code: "KIBANA_AUTH_REQUIRED", message: "Kibana authentication is required." }
    })).toMatchObject({
      state: "disconnected",
      kibana: "authentication_required",
      fleet: "not_checked",
      agents: "not_checked"
    });
  });

  it("reports a verified Kibana session with failed Fleet checks as degraded", () => {
    expect(deriveConnectionHealth({
      kibanaAvailable: true,
      fleetAvailable: false,
      agentsAvailable: false
    })).toMatchObject({
      state: "degraded",
      kibana: "authenticated",
      fleet: "unavailable",
      agents: "unavailable"
    });
  });

  it("never converts an unreachable Kibana result into connected", () => {
    expect(deriveConnectionHealth({
      kibanaAvailable: false,
      fleetAvailable: true,
      agentsAvailable: true,
      kibanaError: { code: "KIBANA_UNREACHABLE", message: "No authenticated Kibana tab was found." }
    })).toMatchObject({
      state: "disconnected",
      kibana: "unreachable"
    });
  });
});
