import { describe, expect, it } from "vitest";
import { feedbackTargetKey, isThreatFeedbackActive, suppressesAutomaticAlert, type ThreatFeedbackRecord } from "../src/threat-feedback";

function feedback(disposition: ThreatFeedbackRecord["disposition"], expiresAt?: string): ThreatFeedbackRecord {
  return {
    id: "feedback-1",
    targetKind: "alert",
    targetFingerprint: "route|198.51.100.20",
    disposition,
    createdAt: "2026-09-11T08:00:00.000Z",
    ...(expiresAt ? { expiresAt } : {})
  };
}

describe("threat feedback", () => {
  it("suppresses only active expected or benign dispositions", () => {
    expect(suppressesAutomaticAlert(feedback("benign"))).toBe(true);
    expect(suppressesAutomaticAlert(feedback("expected_scanner"))).toBe(true);
    expect(suppressesAutomaticAlert(feedback("expected_service"))).toBe(true);
    expect(suppressesAutomaticAlert(feedback("confirmed_malicious"))).toBe(false);
    expect(suppressesAutomaticAlert(feedback("needs_review"))).toBe(false);
  });

  it("stops suppressing when feedback expires", () => {
    const record = feedback("benign", "2026-09-11T08:30:00.000Z");
    expect(isThreatFeedbackActive(record, Date.parse("2026-09-11T08:00:00.000Z"))).toBe(true);
    expect(suppressesAutomaticAlert(record, Date.parse("2026-09-11T09:00:00.000Z"))).toBe(false);
  });

  it("normalizes the audit key", () => {
    expect(feedbackTargetKey("alert", " Route|EXAMPLE.COM ")).toBe("alert|route|example.com");
  });
});
