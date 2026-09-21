import { describe, expect, it } from "vitest";
import { mergeFindingHistory, type HistoricalFinding } from "../src/threat-radar-history";

const base: HistoricalFinding = {
  ip: "203.0.113.10",
  role: "source",
  direction: "inbound",
  sourceIp: "203.0.113.10",
  destinationIp: "10.0.0.4",
  events: 100,
  score: 80
};

describe("Threat Radar finding history", () => {
  it("tracks event growth and preserves findings absent from the latest scan", () => {
    const first = mergeFindingHistory([base], [], "2026-09-08T10:00:00.000Z");
    const second = mergeFindingHistory([{ ...base, events: 145 }], first, "2026-09-08T10:05:00.000Z");
    const retained = mergeFindingHistory([], second, "2026-09-08T10:10:00.000Z");

    expect(second[0]).toMatchObject({ firstSeen: "2026-09-08T10:00:00.000Z", observations: 2, previousEvents: 100, eventDelta: 45, active: true });
    expect(retained[0]).toMatchObject({ events: 145, observations: 2, active: false });
  });

  it("expires findings outside the retention period", () => {
    const previous = [{ ...base, firstSeen: "2026-09-07T09:00:00.000Z", lastSeen: "2026-09-07T09:00:00.000Z", active: false }];
    expect(mergeFindingHistory([], previous, "2026-09-08T10:00:00.000Z")).toEqual([]);
  });

  it("keeps retained enrichment when the next observation has no new reputation result", () => {
    const previous: Array<HistoricalFinding & { gti?: { threatScore: number; malicious: number } }> = [{
      ...base,
      gti: { threatScore: 82, malicious: 7 },
      firstSeen: "2026-09-08T10:00:00.000Z",
      lastSeen: "2026-09-08T10:00:00.000Z"
    }];
    const next = mergeFindingHistory([{ ...base, events: 120 }], previous, "2026-09-08T10:05:00.000Z");

    expect(next[0]).toMatchObject({
      events: 120,
      gti: { threatScore: 82, malicious: 7 },
      observations: 1,
      active: true
    });
  });
});
