export type ConnectionState = "connected" | "degraded" | "disconnected";
export type KibanaConnectionState = "authenticated" | "authentication_required" | "forbidden" | "unreachable";

export type ConnectionServiceError = {
  code: string;
  message: string;
  details?: unknown;
};

export type ConnectionHealth = {
  state: ConnectionState;
  kibana: KibanaConnectionState;
  fleet: "available" | "unavailable" | "not_checked";
  agents: "available" | "unavailable" | "not_checked";
  message: string;
};

export function deriveConnectionHealth(input: {
  kibanaAvailable: boolean;
  fleetAvailable: boolean;
  agentsAvailable: boolean;
  kibanaError?: ConnectionServiceError;
}): ConnectionHealth {
  if (!input.kibanaAvailable) {
    const kibana = classifyKibanaError(input.kibanaError);
    return {
      state: "disconnected",
      kibana,
      fleet: "not_checked",
      agents: "not_checked",
      message: connectionFailureMessage(kibana, input.kibanaError?.message)
    };
  }

  if (!input.fleetAvailable || !input.agentsAvailable) {
    return {
      state: "degraded",
      kibana: "authenticated",
      fleet: input.fleetAvailable ? "available" : "unavailable",
      agents: input.agentsAvailable ? "available" : "unavailable",
      message: "Kibana is authenticated, but one or more Fleet checks failed."
    };
  }

  return {
    state: "connected",
    kibana: "authenticated",
    fleet: "available",
    agents: "available",
    message: "Kibana authentication and Fleet access were verified."
  };
}

function classifyKibanaError(error?: ConnectionServiceError): KibanaConnectionState {
  if (error?.code === "KIBANA_AUTH_REQUIRED") return "authentication_required";
  if (error?.code === "KIBANA_FORBIDDEN") return "forbidden";
  return "unreachable";
}

function connectionFailureMessage(state: KibanaConnectionState, fallback?: string): string {
  if (state === "authentication_required") return "Kibana is reachable, but the Chrome session is not authenticated.";
  if (state === "forbidden") return "Kibana is reachable, but the current user is not permitted to read the required APIs.";
  return fallback || "Kibana could not be reached or verified.";
}
