import { describe, expect, it } from "vitest";
import {
  isAllowedOrigin,
  kibanaApiPath,
  parseBridgeRequest,
  sanitizeFleetAgent,
  sanitizeFleetSummary
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
});

describe("origin validation", () => {
  it("requires exact approved origins", () => {
    expect(isAllowedOrigin("https://socwatch.internal/app", ["https://socwatch.internal"])).toBe(true);
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
