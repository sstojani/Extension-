export type ThreatCaseStatus = "open" | "acknowledged" | "in_progress" | "resolved" | "closed";
export type ThreatCaseSeverity = "critical" | "high" | "medium" | "low";

export type ThreatCaseEvidence = {
  label: string;
  value: string;
};

export type ThreatCaseNote = {
  id: string;
  body: string;
  author?: string;
  createdAt: string;
};

export type ThreatCaseRecord = {
  id: string;
  title: string;
  status: ThreatCaseStatus;
  severity: ThreatCaseSeverity;
  createdAt: string;
  updatedAt: string;
  assignee?: string;
  summary: string;
  alertIds: string[];
  fingerprints: string[];
  tags: string[];
  evidence: ThreatCaseEvidence[];
  notes: ThreatCaseNote[];
  resolution?: string;
};

export function normalizeCaseStatus(value: unknown): ThreatCaseStatus {
  return value === "acknowledged" || value === "in_progress" || value === "resolved" || value === "closed" ? value : "open";
}

export function normalizeCaseSeverity(value: unknown): ThreatCaseSeverity {
  return value === "critical" || value === "high" || value === "medium" ? value : "low";
}

export function normalizeCaseRecord(value: unknown): ThreatCaseRecord | undefined {
  if (typeof value !== "object" || value === null) return undefined;
  const record = value as Record<string, unknown>;
  if (typeof record.id !== "string" || typeof record.title !== "string" || !record.title.trim()) return undefined;
  const createdAt = typeof record.createdAt === "string" ? record.createdAt : new Date().toISOString();
  const updatedAt = typeof record.updatedAt === "string" ? record.updatedAt : createdAt;
  const evidence = Array.isArray(record.evidence)
    ? record.evidence.flatMap((item) => {
      if (typeof item !== "object" || item === null) return [];
      const entry = item as Record<string, unknown>;
      return typeof entry.label === "string" && typeof entry.value === "string"
        ? [{ label: entry.label.slice(0, 120), value: entry.value.slice(0, 2000) }]
        : [];
    }).slice(0, 100)
    : [];
  const notes = Array.isArray(record.notes)
    ? record.notes.flatMap((item) => {
      if (typeof item !== "object" || item === null) return [];
      const entry = item as Record<string, unknown>;
      return typeof entry.id === "string" && typeof entry.body === "string"
        ? [{
          id: entry.id,
          body: entry.body.slice(0, 4000),
          ...(typeof entry.author === "string" && entry.author.trim() ? { author: entry.author.slice(0, 120) } : {}),
          createdAt: typeof entry.createdAt === "string" ? entry.createdAt : updatedAt
        }]
        : [];
    }).slice(0, 200)
    : [];
  return {
    id: record.id,
    title: record.title.trim().slice(0, 200),
    status: normalizeCaseStatus(record.status),
    severity: normalizeCaseSeverity(record.severity),
    createdAt,
    updatedAt,
    ...(typeof record.assignee === "string" && record.assignee.trim() ? { assignee: record.assignee.trim().slice(0, 120) } : {}),
    summary: typeof record.summary === "string" ? record.summary.slice(0, 4000) : "",
    alertIds: normalizeStringArray(record.alertIds, 200),
    fingerprints: normalizeStringArray(record.fingerprints, 200),
    tags: normalizeStringArray(record.tags, 50),
    evidence,
    notes,
    ...(typeof record.resolution === "string" && record.resolution.trim() ? { resolution: record.resolution.slice(0, 4000) } : {})
  };
}

function normalizeStringArray(value: unknown, max: number): string[] {
  return Array.isArray(value)
    ? [...new Set(value.filter((item): item is string => typeof item === "string" && Boolean(item.trim())).map((item) => item.trim().slice(0, 512)))].slice(0, max)
    : [];
}
