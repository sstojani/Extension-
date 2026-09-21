import { describe, expect, it } from "vitest";
import { normalizeCaseRecord } from "../src/case-store";

describe("case storage normalization", () => {
  it("rejects records without a stable id and title", () => {
    expect(normalizeCaseRecord({ id: "case-1" })).toBeUndefined();
    expect(normalizeCaseRecord({ title: "Investigation" })).toBeUndefined();
  });

  it("deduplicates references and preserves bounded evidence and notes", () => {
    const record = normalizeCaseRecord({
      id: "case-1",
      title: "  Suspicious SSH route  ",
      status: "invalid",
      severity: "critical",
      createdAt: "2026-09-11T08:00:00.000Z",
      alertIds: ["alert-1", "alert-1"],
      fingerprints: ["route-1", "route-1"],
      tags: ["ssh", "ssh"],
      evidence: [{ label: "Route", value: "198.51.100.20 to 10.0.0.5" }, { bad: true }],
      notes: [{ id: "note-1", body: "Investigating", author: "Analyst" }, { id: 2, body: "ignored" }]
    });
    expect(record).toMatchObject({ title: "Suspicious SSH route", status: "open", severity: "critical" });
    expect(record?.alertIds).toEqual(["alert-1"]);
    expect(record?.evidence).toEqual([{ label: "Route", value: "198.51.100.20 to 10.0.0.5" }]);
    expect(record?.notes).toHaveLength(1);
  });
});
