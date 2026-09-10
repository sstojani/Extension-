export const THREAT_RADAR_HISTORY_RETENTION_MS = 24 * 60 * 60 * 1000;

export type HistoricalFinding = {
  ip: string;
  role: "source" | "destination";
  direction: string;
  sourceIp: string;
  destinationIp: string;
  events: number;
  score: number;
  firstSeen?: string;
  lastSeen?: string;
  observations?: number;
  previousEvents?: number;
  eventDelta?: number;
  active?: boolean;
};

export function mergeFindingHistory<T extends HistoricalFinding>(
  current: T[],
  previous: T[],
  observedAt: string,
  retentionMs = THREAT_RADAR_HISTORY_RETENTION_MS
): T[] {
  const observedTime = Date.parse(observedAt);
  const cutoff = Number.isFinite(observedTime) ? observedTime - retentionMs : Date.now() - retentionMs;
  const previousByKey = new Map(previous.map((finding) => [findingHistoryKey(finding), finding]));
  const currentKeys = new Set<string>();

  const active = current.map((finding) => {
    const key = findingHistoryKey(finding);
    currentKeys.add(key);
    const prior = previousByKey.get(key);
    return {
      ...prior,
      ...finding,
      firstSeen: prior?.firstSeen ?? prior?.lastSeen ?? observedAt,
      lastSeen: observedAt,
      observations: (prior?.observations ?? 0) + 1,
      previousEvents: prior?.events,
      eventDelta: prior ? finding.events - prior.events : undefined,
      active: true
    } as T;
  });

  const retained = previous
    .filter((finding) => !currentKeys.has(findingHistoryKey(finding)))
    .filter((finding) => {
      const lastSeen = Date.parse(finding.lastSeen ?? "");
      return Number.isFinite(lastSeen) && lastSeen >= cutoff;
    })
    .map((finding) => ({ ...finding, active: false, eventDelta: undefined }) as T);

  return [...active, ...retained]
    .sort((left, right) => Number(right.active) - Number(left.active) || right.score - left.score || right.events - left.events);
}

function findingHistoryKey(finding: HistoricalFinding): string {
  return `${finding.role}|${finding.direction}|${finding.ip || finding.sourceIp || finding.destinationIp}`;
}
