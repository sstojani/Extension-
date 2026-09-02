import { copyFile, mkdir } from "node:fs/promises";

await mkdir(new URL("../dist/", import.meta.url), { recursive: true });
await copyFile(new URL("../manifest.json", import.meta.url), new URL("../dist/manifest.json", import.meta.url));
await copyFile(new URL("../src/popup.html", import.meta.url), new URL("../dist/popup.html", import.meta.url));
await copyFile(new URL("../src/popup.css", import.meta.url), new URL("../dist/popup.css", import.meta.url));
await copyFile(new URL("../src/popup.js", import.meta.url), new URL("../dist/popup.js", import.meta.url));
