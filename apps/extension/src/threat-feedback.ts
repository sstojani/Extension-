export type ThreatFeedbackDisposition = "confirmed_malicious" | "benign" | "expected_scanner" | "expected_service" | "needs_review";
export type ThreatFeedbackTarget = "alert" | "finding" | "indicator" | "identity";

export type ThreatFeedbackRecord = {
  id: string;
  targetKind: ThreatFeedbackTarget;
  targetFingerprint: string;
  disposition: ThreatFeedbackDisposition;
  reason?: string;
  analyst?: string;
  createdAt: string;
  expiresAt?: string;
};

export function isThreatFeedbackActive(record: ThreatFeedbackRecord, now = Date.now()): boolean {
  if (!record.expiresAt) return true;
  const expiry = Date.parse(record.expiresAt);
  return !Number.isFinite(expiry) || expiry > now;
}

export function suppressesAutomaticAlert(record: ThreatFeedbackRecord, now = Date.now()): boolean {
  return isThreatFeedbackActive(record, now)
    && (record.disposition === "benign" || record.disposition === "expected_scanner" || record.disposition === "expected_service");
}

export function feedbackTargetKey(targetKind: ThreatFeedbackTarget, targetFingerprint: string): string {
  return `${targetKind}|${targetFingerprint.trim().toLowerCase()}`;
}
