import { readFile } from "node:fs/promises";
import { createContext, runInContext } from "node:vm";

const distRoot = new URL("../dist/", import.meta.url);
const contentScript = await readFile(new URL("content-script.js", distRoot), "utf8");
const serviceWorker = await readFile(new URL("service-worker.js", distRoot), "utf8");
const manifest = JSON.parse(await readFile(new URL("manifest.json", distRoot), "utf8"));
const tailscaleOrigins = ["https://laptop-1.tail029be8.ts.net", "https://laptop-1.tail029be8.ts.net:8443"];

if (/^\s*import(?:\s|\()/m.test(contentScript)) {
  throw new Error("content-script.js contains an ES-module import; Chrome manifest content scripts must be standalone.");
}

const contentMatches = manifest.content_scripts?.flatMap((entry) => entry.matches ?? []) ?? [];
for (const origin of tailscaleOrigins) {
  const pattern = `${origin}/*`;
  const exactOrigin = new RegExp(`["']${origin.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}["']`);
  if (!exactOrigin.test(contentScript) || !exactOrigin.test(serviceWorker)) {
    throw new Error(`The built relay or service worker does not recognize ${origin}.`);
  }
  if (!manifest.host_permissions?.includes(pattern) || !contentMatches.includes(pattern)) {
    throw new Error(`The extension manifest does not inject the relay on ${origin}.`);
  }
  if (!manifest.externally_connectable?.matches?.includes(pattern)) {
    throw new Error(`The extension manifest does not permit external messages from ${origin}.`);
  }
}

const announcements = [];
let connections = 0;
const page = {
  location: { origin: tailscaleOrigins[0] },
  postMessage(message) { announcements.push(message); },
  addEventListener() {},
  setInterval() { return 1; },
  setTimeout() { return 1; },
  clearInterval() {}
};
const chrome = {
  runtime: {
    id: "abcdefghijklmnopabcdefghijklmnop",
    getManifest() { return manifest; },
    connect() {
      connections += 1;
      return {
        onMessage: { addListener() {} },
        onDisconnect: { addListener() {} },
        postMessage() {}
      };
    }
  }
};
const context = createContext({ window: page, chrome });
runInContext(contentScript, context);
runInContext(contentScript, context);
if (connections !== 1 || announcements.filter(({ message }) => message?.type === "soc-watch.relay-ready").length !== 1) {
  throw new Error("Repeated content-script injection must reuse the existing relay without redeclaration or duplicate connections.");
}

console.log("Verified standalone, repeat-safe content script and both Tailscale deployment origins.");
