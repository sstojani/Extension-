import { describe, expect, it } from "vitest";
import { evaluateSourceHealth, rollupHealth } from "../src/index";

describe("health evaluation", () => {
  it("separates agent online status from log freshness", () => {
    expect(evaluateSourceHealth({ id: "firewall", expected: true, agentOnline: true })).toBe("critical");
  });

  it("rolls up worst active state", () => {
    expect(rollupHealth(["healthy", "critical", "warning"])).toBe("critical");
  });
});
