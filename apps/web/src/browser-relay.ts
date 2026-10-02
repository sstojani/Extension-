import { relaySourceSchema, relayOperationSchema, type BridgeAction, type BridgeResponse, type RelayPolicy } from "@soc-watch/protocol";

export type RelayProgress = { state: "connecting" | "connected" | "disconnected"; message: string };
type Api = <T>(path: string, options: { method: string; body: unknown; signal?: AbortSignal }) => Promise<T>;
type Bridge = (action: BridgeAction, params: unknown) => Promise<BridgeResponse<unknown>>;

function sleep(ms: number, signal: AbortSignal) {
  return new Promise<void>(resolve => {
    const finish = () => { clearTimeout(timer); signal.removeEventListener("abort", finish); resolve(); };
    const timer = setTimeout(finish, ms);
    signal.addEventListener("abort", finish, { once: true }); if (signal.aborted) finish();
  });
}

export async function runBrowserRelay({ api, bridge, policy, signal, onProgress, pollMs = 1000, retryMs = 10000 }: {
  api: Api; bridge: Bridge; policy: RelayPolicy; signal: AbortSignal;
  onProgress: (value: RelayProgress) => void; pollMs?: number; retryMs?: number;
}) {
  const clientId = crypto.randomUUID();
  const call = async (action: BridgeAction, params: unknown) => {
    const response = await bridge(action, params);
    if (!response.success) throw new Error(response.error.message);
    if (signal.aborted) throw new DOMException("Relay cancelled", "AbortError");
    return response.data;
  };
  const post = <T>(route: string, body: unknown) => api<T>(route, { method: "POST", body, signal });
  while (!signal.aborted) {
    let relayId: string | undefined;
    try {
      onProgress({ state: "connecting", message: "Verifying the extension and signed-in Kibana session..." });
      const connection = await call("agent.relay.connect", policy) as { relayId: string; source: unknown };
      if (typeof connection?.relayId !== "string") throw new Error("Invalid extension relay response. Install the matching Bridge package.");
      relayId = connection.relayId;
      const source = relaySourceSchema.parse(connection.source);
      await post("/relay/connect", { clientId, source });
      let lastProof = Date.now();
      onProgress({ state: "connected", message: `${source.kibanaBaseUrl} / ${source.spaceId}` });
      while (!signal.aborted) {
        if (Date.now() - lastProof >= 20000) {
          await call("agent.relay.heartbeat", { relayId }); lastProof = Date.now();
        }
        const { job } = await post<{ job: null | { id: string; operation: unknown } }>("/relay/poll", { clientId });
        if (!job) { await sleep(pollMs, signal); continue; }
        const operation = relayOperationSchema.parse(job.operation);
        const result = await bridge("agent.relay.execute", { relayId, jobId: job.id, operation });
        if (signal.aborted) break;
        await post("/relay/result", { clientId, id: job.id, success: result.success,
          ...(result.success ? { data: result.data } : { error: result.error.message }) });
        if (!result.success) throw new Error(result.error.message);
      }
    } catch (error) {
      if (!signal.aborted) onProgress({ state: "disconnected", message: error instanceof Error ? error.message : "Browser relay failed." });
    } finally {
      // Cleanup must still run after the polling AbortController is cancelled.
      await api("/relay/disconnect", { method: "POST", body: { clientId } }).catch(() => {});
      if (relayId) await bridge("agent.relay.disconnect", { relayId }).catch(() => {});
    }
    if (!signal.aborted) await sleep(retryMs, signal);
  }
}
