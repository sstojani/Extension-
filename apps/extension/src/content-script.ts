var socWatchBridgeWindow = window as unknown as { __socWatchBridgeRelayActive?: boolean };

if (isAllowedSocWatchOrigin(window.location) && !socWatchBridgeWindow.__socWatchBridgeRelayActive) {
  socWatchBridgeWindow.__socWatchBridgeRelayActive = true;
  let port: chrome.runtime.Port | null = null;
  let reconnectTimer: number | undefined;
  const queuedMessages: unknown[] = [];

  announce({
    type: "soc-watch.relay-ready",
    extensionId: chrome.runtime.id
  });

  const readyInterval = window.setInterval(() => {
    announce({
      type: "soc-watch.relay-ready",
      extensionId: chrome.runtime.id
    });
  }, 500);

  window.setTimeout(() => {
    window.clearInterval(readyInterval);
  }, 5000);

  connectPort();

  window.addEventListener("message", (event) => {
    if (event.source !== window || event.origin !== window.location.origin) return;
    const data = typeof event.data === "object" && event.data !== null ? (event.data as Record<string, unknown>) : {};
    if (data.source !== "soc-watch-web") return;
    if (isHello(data.message)) {
      announce({
        type: "soc-watch.relay-ready",
        extensionId: chrome.runtime.id
      });
      sendToBridge({ type: "soc-watch.requestSnapshot" });
      return;
    }
    sendToBridge(data.message);
  });

  window.addEventListener("pageshow", () => {
    connectPort();
    sendToBridge({ type: "soc-watch.requestSnapshot" });
  });

  window.addEventListener("pagehide", () => {
    disconnectPort();
  });

  function connectPort(): void {
    if (port) return;
    try {
      port = chrome.runtime.connect({ name: "soc-watch-page-relay" });
    } catch (error) {
      scheduleReconnect(error instanceof Error ? error.message : "SOC Watch Bridge connection failed.");
      return;
    }

    port.onMessage.addListener((message: unknown) => {
      announce(message);
    });

    port.onDisconnect.addListener(() => {
      const reason = chrome.runtime.lastError?.message ?? "SOC Watch Bridge disconnected.";
      port = null;
      announce({
        type: "soc-watch.disconnected",
        reason
      });
      scheduleReconnect(reason);
    });

    flushQueue();
  }

  function sendToBridge(message: unknown): void {
    if (!port) {
      queuedMessages.push(message);
      connectPort();
      return;
    }

    try {
      port.postMessage(message);
    } catch (error) {
      queuedMessages.push(message);
      const reason = error instanceof Error ? error.message : "SOC Watch Bridge disconnected.";
      port = null;
      announce({
        type: "soc-watch.disconnected",
        reason
      });
      scheduleReconnect(reason);
    }
  }

  function flushQueue(): void {
    while (port && queuedMessages.length > 0) {
      const message = queuedMessages.shift();
      if (message !== undefined) sendToBridge(message);
    }
  }

  function scheduleReconnect(reason: string): void {
    if (reconnectTimer !== undefined) return;
    reconnectTimer = window.setTimeout(() => {
      reconnectTimer = undefined;
      announce({
        type: "soc-watch.reconnecting",
        reason
      });
      connectPort();
    }, 1000);
  }

  function disconnectPort(): void {
    if (!port) return;
    const openPort = port;
    port = null;
    try {
      openPort.disconnect();
    } catch {
      // Chrome may already have disposed of the port during page lifecycle changes.
    }
  }
}

function announce(message: unknown): void {
  window.postMessage(
    {
      source: "soc-watch-content",
      message
    },
    window.location.origin
  );
}

function isHello(message: unknown): boolean {
  if (typeof message !== "object" || message === null) return false;
  return (message as Record<string, unknown>).type === "soc-watch.hello";
}

function isAllowedSocWatchOrigin(location: Location): boolean {
  if (location.origin === "https://socwatch.internal") return true;
  if (location.protocol !== "http:") return false;
  return location.hostname === "localhost" || location.hostname === "127.0.0.1";
}
