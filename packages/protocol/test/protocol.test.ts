import { describe, expect, it } from "vitest";
import {
  DEFAULT_THREAT_RADAR_CARD_RULES,
  DEFAULT_THREAT_RADAR_RISKY_PORTS,
  DEFAULT_THREAT_RADAR_SIGNAL_RULES,
  threatRadarAgentConfigSchema,
  isAllowedOrigin,
  kibanaApiPath,
  parseBridgeRequest,
  sanitizeFleetAgent,
  sanitizeFleetSummary,
  dailyIocHuntParamsSchema
} from "../src/index";

describe("protocol validation", () => {
  it("accepts explicit versioned bridge requests", () => {
    expect(
      parseBridgeRequest({
        version: 1,
        requestId: "12345678",
        action: "bridge.ping",
        params: {}
      }).action
    ).toBe("bridge.ping");
  });

  it("rejects arbitrary proxy actions", () => {
    expect(() =>
      parseBridgeRequest({
        version: 1,
        requestId: "12345678",
        action: "fetch.anything",
        params: { url: "https://example.test" }
      })
    ).toThrow();
  });

  it("defaults IOC hunts to 500 indicators and accepts a batch offset", () => {
    expect(dailyIocHuntParamsSchema.parse({ indexPattern: "logs-*" })).toMatchObject({
      maxIocs: 500,
      batchOffset: 0
    });
    expect(dailyIocHuntParamsSchema.parse({ indexPattern: "logs-*", maxIocs: 500, batchOffset: 500 }).batchOffset).toBe(500);
  });

  it("accepts the persisted-finding clear action", () => {
    expect(parseBridgeRequest({
      version: 1,
      requestId: "12345678",
      action: "threatRadar.agent.clear",
      params: {}
    }).action).toBe("threatRadar.agent.clear");
  });

  it("adds the complete detection policy to older agent configurations", () => {
    const config = threatRadarAgentConfigSchema.parse({
      enabled: true,
      intervalMinutes: 15,
      indexPattern: "logs-*",
      timestampField: "@timestamp",
      candidateExclusions: [],
      candidateExceptions: []
    });

    expect(config.historyRetentionHours).toBe(24);
    expect(config.riskyPorts).toEqual(DEFAULT_THREAT_RADAR_RISKY_PORTS);
    expect(config.signalRules).toEqual(DEFAULT_THREAT_RADAR_SIGNAL_RULES);
    expect(config.cardRules).toEqual(DEFAULT_THREAT_RADAR_CARD_RULES);
  });
});

describe("origin validation", () => {
  it("requires exact approved origins", () => {
    expect(isAllowedOrigin("https://socwatch.internal/app", ["https://socwatch.internal"])).toBe(true);
    expect(isAllowedOrigin("https://socwatch.internal:8443/app", ["https://socwatch.internal"])).toBe(false);
    expect(isAllowedOrigin("https://evil.example/app", ["https://socwatch.internal"])).toBe(false);
  });
});

describe("kibana routes", () => {
  it("supports default and named spaces", () => {
    expect(kibanaApiPath("status")).toBe("/api/status");
    expect(kibanaApiPath("/api/status", "blue team")).toBe("/s/blue%20team/api/status");
  });
});

describe("fleet sanitization", () => {
  it("maps summary counts without hardcoding snapshots", () => {
    expect(sanitizeFleetSummary({ results: { online: 29, offline: 4, access_api_key: "secret" } })).toEqual({
      online: 29,
      offline: 4,
      error: 0,
      inactive: 0,
      updating: 0,
      unenrolled: 0,
      active: 0,
      all: 0,
      other: 0
    });
  });

  it("strips raw Fleet secrets by allowlist", () => {
    const agent = sanitizeFleetAgent({
      item: {
        id: "agent-1",
        status: "online",
        active: true,
        access_api_key: "secret",
        access_api_key_id: "secret-id",
        local_metadata: {
          host: { hostname: "SERVER01", ip: ["10.0.0.5"] },
          elastic: { agent: { version: "8.17.4" } }
        }
      }
    });
    expect(JSON.stringify(agent)).not.toContain("secret");
    expect(agent.hostname).toBe("SERVER01");
  });
});
