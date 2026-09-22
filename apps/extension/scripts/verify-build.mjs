import { readFile } from "node:fs/promises";

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

console.log("Verified standalone content script and both Tailscale deployment origins.");
