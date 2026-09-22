import { readFile } from "node:fs/promises";

const distRoot = new URL("../dist/", import.meta.url);
const contentScript = await readFile(new URL("content-script.js", distRoot), "utf8");
const manifest = JSON.parse(await readFile(new URL("manifest.json", distRoot), "utf8"));
const tailscaleOrigin = "https://laptop-1.tail029be8.ts.net:8443";
const tailscalePattern = `${tailscaleOrigin}/*`;

if (/^\s*import(?:\s|\()/m.test(contentScript)) {
  throw new Error("content-script.js contains an ES-module import; Chrome manifest content scripts must be standalone.");
}

if (!contentScript.includes(tailscaleOrigin)) {
  throw new Error("content-script.js does not contain the approved Tailscale origin.");
}

const contentMatches = manifest.content_scripts?.flatMap((entry) => entry.matches ?? []) ?? [];
if (!contentMatches.includes(tailscalePattern)) {
  throw new Error("The extension manifest does not inject the relay on the approved Tailscale origin.");
}

if (!manifest.externally_connectable?.matches?.includes(tailscalePattern)) {
  throw new Error("The extension manifest does not permit external messages from the approved Tailscale origin.");
}

console.log("Verified standalone content script and Tailscale origin permissions.");
