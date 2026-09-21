const popup = document.getElementById("popup");
const button = document.getElementById("connect");
const subtitle = document.getElementById("subtitle");
const version = document.getElementById("version");
const permission = document.getElementById("permission");
const bridge = document.getElementById("bridge");
const kibana = document.getElementById("kibana");
const fleet = document.getElementById("fleet");
const details = document.getElementById("details");
const hint = document.getElementById("hint");
const openKibana = document.getElementById("openKibana");
const kibanaUrl = document.getElementById("kibanaUrl");
let connectionCheckInFlight = false;

version.textContent = `Version ${chrome.runtime.getManifest().version}`;
void initializePopup();

button.addEventListener("click", () => {
  void checkConnection({ allowPermissionRequest: true, save: true, showChecking: true });
});

openKibana.addEventListener("click", () => {
  chrome.tabs.create({ url: normalizedKibanaUrl() });
});

async function initializePopup() {
  await loadConfig();
  await showLastCheckTime();
  await checkConnection({ allowPermissionRequest: false, save: false, showChecking: true });
  window.setInterval(() => {
    void checkConnection({ allowPermissionRequest: false, save: false, showChecking: false });
  }, 10000);
}

async function checkConnection({ allowPermissionRequest, save, showChecking }) {
  if (connectionCheckInFlight) return;
  connectionCheckInFlight = true;
  if (showChecking) {
    setState("checking", "Verifying Kibana session");
    button.disabled = true;
    button.textContent = "Checking connection";
    permission.textContent = "Checking";
    bridge.textContent = "Checking";
    kibana.textContent = "Checking";
    fleet.textContent = "Checking";
    hint.textContent = "Checking the extension, Kibana authentication, and Fleet access now.";
  }

  try {
    const baseUrl = normalizedKibanaUrl();
    if (save) await saveConfig(baseUrl);
    const hasPermission = await ensureKibanaPermission(baseUrl, allowPermissionRequest);
    if (!hasPermission) {
      permission.textContent = "Not allowed";
      throw new Error(`SITE_ACCESS_REQUIRED: Allow Chrome site access for ${new URL(baseUrl).origin}, then retry.`);
    }
    permission.textContent = "Allowed";

    const ping = await send("bridge.ping", {});
    if (!ping.success) throw bridgeError(ping);
    bridge.textContent = "Extension ready";

    const status = await send("kibana.status", {});
    if (!status.success) {
      kibana.textContent = status.error?.code === "KIBANA_AUTH_REQUIRED" ? "Authentication required" : "Unavailable";
      throw bridgeError(status);
    }
    kibana.textContent = status.data?.overall ?? "Available";

    const summary = await send("fleet.summary", {});
    if (!summary.success) {
      fleet.textContent = "Unavailable";
      throw bridgeError(summary);
    }
    const online = summary.data?.online ?? 0;
    const offline = summary.data?.offline ?? 0;
    fleet.textContent = `${online} online / ${offline} offline`;

    const updatedAt = new Date().toISOString();
    setState("connected", "Kibana authenticated");
    button.textContent = "Kibana connected";
    details.textContent = `Verified ${new Date(updatedAt).toLocaleTimeString()}`;
    hint.textContent = "The extension verified Kibana authentication and Fleet access. This status refreshes automatically.";
    await chrome.storage.local.set({
      lastConnection: {
        state: "connected",
        updatedAt,
        bridge: { state: "connected", version: chrome.runtime.getManifest().version },
        connection: {
          state: "connected",
          kibana: "authenticated",
          fleet: "available",
          agents: "available",
          message: "Kibana authentication and Fleet access were verified."
        },
        kibana: status.data,
        fleet: summary.data
      }
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unable to connect.";
    const updatedAt = new Date().toISOString();
    setState("error", "Kibana disconnected");
    button.textContent = "Retry connection";
    bridge.textContent = bridge.textContent === "Checking" ? "Failed" : bridge.textContent;
    permission.textContent = permission.textContent === "Checking" ? "Failed" : permission.textContent;
    kibana.textContent = kibana.textContent === "Checking" ? "Unavailable" : kibana.textContent;
    fleet.textContent = fleet.textContent === "Checking" ? "Not checked" : fleet.textContent;
    hint.textContent = message;
    details.textContent = `Failed ${new Date(updatedAt).toLocaleTimeString()}`;
    await chrome.storage.local.set({
      lastConnection: {
        state: "disconnected",
        updatedAt,
        bridge: { state: bridge.textContent === "Extension ready" ? "connected" : "unavailable", version: chrome.runtime.getManifest().version },
        connection: {
          state: "disconnected",
          kibana: message.includes("KIBANA_AUTH_REQUIRED") ? "authentication_required" : "unreachable",
          fleet: "not_checked",
          agents: "not_checked",
          message
        },
        kibana: { overall: "unavailable" },
        fleet: null,
        serviceErrors: [{ code: message.split(":", 1)[0] || "KIBANA_UNREACHABLE", message }]
      }
    });
  } finally {
    button.disabled = false;
    connectionCheckInFlight = false;
  }
}

async function showLastCheckTime() {
  const stored = await chrome.storage.local.get(["lastConnection"]);
  const last = stored.lastConnection;
  if (!last || typeof last !== "object") return;
  details.textContent = last.updatedAt ? `Last check ${new Date(last.updatedAt).toLocaleTimeString()}` : "No verified check";
}

async function ensureKibanaPermission(baseUrl, allowRequest) {
  const originPattern = `${new URL(baseUrl).protocol}//${new URL(baseUrl).hostname}/*`;
  const permissionRequest = { origins: [originPattern] };
  const alreadyAllowed = await chrome.permissions.contains(permissionRequest);
  if (alreadyAllowed) return true;
  if (!allowRequest) return false;
  return chrome.permissions.request(permissionRequest);
}

async function loadConfig() {
  const stored = await chrome.storage.local.get(["kibanaBaseUrl"]);
  if (typeof stored.kibanaBaseUrl === "string") {
    kibanaUrl.value = stored.kibanaBaseUrl;
  }
}

function saveConfig(baseUrl) {
  return chrome.runtime.sendMessage({
    type: "soc-watch.saveConfig",
    requestId: crypto.randomUUID(),
    kibanaBaseUrl: baseUrl
  });
}

function normalizedKibanaUrl() {
  const value = kibanaUrl.value.trim() || "https://10.10.254.202:8888";
  const url = new URL(value);
  if (url.hostname !== "10.10.254.202") {
    throw new Error("Only the configured Kibana host 10.10.254.202 is allowed.");
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error("Kibana URL must start with http:// or https://.");
  }
  return url.origin;
}

function send(action, params) {
  const request = {
    version: 1,
    requestId: crypto.randomUUID(),
    action,
    params
  };

  return new Promise((resolve) => {
    chrome.runtime.sendMessage(request, (response) => {
      const lastError = chrome.runtime.lastError;
      if (lastError || !response) {
        resolve({
          version: 1,
          requestId: request.requestId,
          success: false,
          error: {
            code: "BRIDGE_NOT_INSTALLED",
            message: lastError?.message ?? "SOC Watch Bridge did not respond."
          }
        });
        return;
      }
      resolve(response);
    });
  });
}

function setState(state, text) {
  popup.className = `popup ${state}`;
  subtitle.textContent = text;
}

function bridgeError(response) {
  const code = response.error?.code ?? "UNKNOWN";
  const message = response.error?.message ?? "Unable to connect.";
  const cause = response.error?.details?.cause;
  return new Error(cause ? `${code}: ${message} (${cause})` : `${code}: ${message}`);
}
