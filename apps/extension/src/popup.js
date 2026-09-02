const popup = document.getElementById("popup");
const button = document.getElementById("connect");
const subtitle = document.getElementById("subtitle");
const bridge = document.getElementById("bridge");
const kibana = document.getElementById("kibana");
const fleet = document.getElementById("fleet");
const hint = document.getElementById("hint");

button.addEventListener("click", () => {
  void connect();
});

async function connect() {
  setState("checking", "Checking bridge");
  button.disabled = true;
  button.textContent = "Connecting";
  bridge.textContent = "Checking";
  kibana.textContent = "Checking";
  fleet.textContent = "Checking";
  hint.textContent = "Checking the extension, Kibana status, and Fleet access.";

  try {
    const ping = await send("bridge.ping", {});
    if (!ping.success) throw new Error(ping.error.message);
    bridge.textContent = "Connected";

    const status = await send("kibana.status", {});
    if (!status.success) throw new Error(status.error.message);
    kibana.textContent = status.data?.overall ?? "Available";

    const summary = await send("fleet.summary", {});
    if (!summary.success) throw new Error(summary.error.message);
    const online = summary.data?.online ?? 0;
    const offline = summary.data?.offline ?? 0;
    fleet.textContent = `${online} online / ${offline} offline`;

    setState("connected", "Connected");
    button.textContent = "Connected";
    hint.textContent = "SOC Watch Bridge can reach Kibana/Fleet with your current Chrome session.";
  } catch (error) {
    setState("error", "Connection failed");
    button.textContent = "Retry Connect";
    bridge.textContent = bridge.textContent === "Checking" ? "Failed" : bridge.textContent;
    kibana.textContent = kibana.textContent === "Checking" ? "Failed" : kibana.textContent;
    fleet.textContent = fleet.textContent === "Checking" ? "Failed" : fleet.textContent;
    hint.textContent = error instanceof Error ? error.message : "Unable to connect.";
  } finally {
    button.disabled = false;
  }
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
