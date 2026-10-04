const pick = (value, keys) => Object.fromEntries(keys.filter(key => value?.[key] !== undefined).map(key => [key, value[key]]));

export const FINDING_OVERVIEW_LIMIT = 2000;
const FINDING_OVERVIEW_BYTES = 2 * 1024 * 1024;

export function findingSummary(finding) {
  return {
    ...pick(finding, ["id", "fingerprint", "title", "category", "indicator", "indicatorType", "severity", "priority", "behaviorScore", "confidence", "firstSeen", "lastSeen", "count", "status", "assignedTo", "updatedAt"]),
    reputation: finding.reputation ? pick(finding.reputation, ["verdict", "score", "status", "source", "gtiVerdict", "checkedAt"]) : null
  };
}

export function findingOverview(findings, retained) {
  const summaries = [];
  let bytes = 2;
  for (const finding of findings) {
    const summary = findingSummary(finding), size = Buffer.byteLength(JSON.stringify(summary)) + 1;
    if (bytes + size > FINDING_OVERVIEW_BYTES) continue;
    summaries.push(summary); bytes += size;
  }
  return { findings: summaries, findingWindow: { limit: FINDING_OVERVIEW_LIMIT, returned: summaries.length, retained,
    limited: retained > FINDING_OVERVIEW_LIMIT || summaries.length < findings.length } };
}

export function runSummary(run) {
  return pick(run, ["id", "startedAt", "finishedAt", "mode", "status", "eventsRead", "totalMatched", "invalidEvents", "coverage", "from", "to", "error"]);
}

export function investigationSummary(investigation) {
  return pick(investigation, ["id", "status", "completedAt", "error"]);
}

export function alertSummary(alert) {
  // Notification context stays available; bulk proof references are loaded with the finding.
  return pick(alert, ["id", "title", "message", "indicator", "findingId", "createdAt", "timestamp", "priority", "reasons", "activity"]);
}
