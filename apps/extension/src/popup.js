const popup = document.getElementById("popup");
const button = document.getElementById("connect");
const subtitle = document.getElementById("subtitle");
const permission = document.getElementById("permission");
const bridge = document.getElementById("bridge");
const kibana = document.getElementById("kibana");
const fleet = document.getElementById("fleet");
const details = document.getElementById("details");
const hint = document.getElementById("hint");
const openKibana = document.getElementById("openKibana");
const kibanaUrl = document.getElementById("kibanaUrl");

void loadConfig();
void restoreLastConnection();

button.addEventListener("click", () => {
  void connect();
});

openKibana.addEventListener("click", () => {
  chrome.tabs.create({ url: normalizedKibanaUrl() });
});

async function connect() {
  setState("checking", "Checking bridge");
  button.disabled = true;
  button.textContent = "Connecting";
  permission.textContent = "Checking";
  bridge.textContent = "Checking";
  kibana.textContent = "Checking";
  fleet.textContent = "Checking";
  details.textContent = "None";
  hint.textContent = "Requesting site access, then checking Kibana and Fleet.";

  try {
    const baseUrl = normalizedKibanaUrl();
    await saveConfig(baseUrl);
    const hasPermission = await ensureKibanaPermission(baseUrl);
    if (!hasPermission) {
      permission.textContent = "Denied";
      throw new Error(`KIBANA_UNREACHABLE: Chrome site access for ${new URL(baseUrl).origin} is required.`);
    }
    permission.textContent = "Allowed";

    const ping = await send("bridge.ping", {});
    if (!ping.success) throw bridgeError(ping);
    bridge.textContent = "Connected";

    const status = await send("kibana.status", {});
    if (!status.success) throw bridgeError(status);
    kibana.textContent = status.data?.overall ?? "Available";

    const summary = await send("fleet.summary", {});
    if (!summary.success) throw bridgeError(summary);
    const online = summary.data?.online ?? 0;
    const offline = summary.data?.offline ?? 0;
    fleet.textContent = `${online} online / ${offline} offline`;

    setState("connected", "Connected");
    button.textContent = "Connected";
    hint.textContent = "SOC Watch Bridge can reach Kibana/Fleet with your current Chrome session.";
    await chrome.storage.local.set({
      lastConnection: {
        state: "connected",
        updatedAt: new Date().toISOString(),
        kibana: status.data,
        fleet: summary.data
      }
    });
  } catch (error) {
    setState("error", "Connection failed");
    button.textContent = "Retry Connect";
    bridge.textContent = bridge.textContent === "Checking" ? "Failed" : bridge.textContent;
    permission.textContent = permission.textContent === "Checking" ? "Failed" : permission.textContent;
    kibana.textContent = kibana.textContent === "Checking" ? "Failed" : kibana.textContent;
    fleet.textContent = fleet.textContent === "Checking" ? "Failed" : fleet.textContent;
    hint.textContent = error instanceof Error ? error.message : "Unable to connect.";
    details.textContent = hint.textContent;
  } finally {
    button.disabled = false;
  }
}

async function restoreLastConnection() {
  const stored = await chrome.storage.local.get(["lastConnection"]);
  const last = stored.lastConnection;
  if (!last || typeof last !== "object") return;
  if (last.state === "connected") {
    setState("connected", "Connected");
    button.textContent = "Connected";
    permission.textContent = "Allowed";
    bridge.textContent = "Connected";
    kibana.textContent = last.kibana?.overall ?? "available";
    const online = last.fleet?.online ?? 0;
    const offline = last.fleet?.offline ?? 0;
    fleet.textContent = `${online} online / ${offline} offline`;
    details.textContent = last.updatedAt ? `Updated ${new Date(last.updatedAt).toLocaleTimeString()}` : "None";
    hint.textContent = "SOC Watch Bridge can reach Kibana/Fleet with your current Chrome session.";
  }
}

async function ensureKibanaPermission(baseUrl) {
  const originPattern = `${new URL(baseUrl).protocol}//${new URL(baseUrl).hostname}/*`;
  const permissionRequest = { origins: [originPattern] };
  const alreadyAllowed = await chrome.permissions.contains(permissionRequest);
  if (alreadyAllowed) return true;
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
