export type HealthState = "healthy" | "warning" | "critical" | "unknown" | "maintenance";

export interface SourceState {
  id: string;
  expected: boolean;
  lastSeen?: string;
  agentOnline?: boolean;
  maintenance?: boolean;
}

export function evaluateSourceHealth(source: SourceState, now = new Date(), staleMinutes = 30): HealthState {
  if (source.maintenance) return "maintenance";
  if (!source.expected) return "unknown";
  if (source.agentOnline === false) return "critical";
  if (!source.lastSeen) return "critical";

  const lastSeen = new Date(source.lastSeen);
  if (Number.isNaN(lastSeen.getTime())) return "unknown";
  const ageMinutes = (now.getTime() - lastSeen.getTime()) / 60000;
  if (ageMinutes > staleMinutes) return "critical";
  if (ageMinutes > staleMinutes / 2) return "warning";
  return "healthy";
}

export function rollupHealth(states: HealthState[]): HealthState {
  if (states.includes("critical")) return "critical";
  if (states.includes("warning")) return "warning";
  if (states.length > 0 && states.every((state) => state === "maintenance")) return "maintenance";
  if (states.includes("unknown")) return "unknown";
  return "healthy";
}
