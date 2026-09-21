import { spawn } from "node:child_process";
import { copyFile, mkdir } from "node:fs/promises";
import { watch } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const extensionRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const distRoot = resolve(extensionRoot, "dist");
const staticFiles = ["manifest.json", "src/popup.html", "src/popup.css", "src/popup.js", "src/icon-128.svg", "src/icon-128-off.svg", "public/icon-128.png"];

async function copyStaticFiles() {
  await mkdir(distRoot, { recursive: true });
  await Promise.all(staticFiles.map((relativePath) => copyFile(
    resolve(extensionRoot, relativePath),
    resolve(distRoot, relativePath.replace(/^(?:src|public)[\\/]/, ""))
  )));
}

await copyStaticFiles();

const viteCommand = process.platform === "win32" ? "vite.cmd" : "vite";
const vite = spawn(viteCommand, ["build", "--watch", "--configLoader", "runner"], {
  cwd: extensionRoot,
  stdio: "inherit",
  shell: process.platform === "win32"
});

let copyTimer;
for (const relativePath of staticFiles) {
  watch(resolve(extensionRoot, relativePath), () => {
    clearTimeout(copyTimer);
    copyTimer = setTimeout(() => void copyStaticFiles(), 80);
  });
}

function stop() {
  vite.kill();
  process.exit(vite.exitCode ?? 0);
}

process.on("SIGINT", stop);
process.on("SIGTERM", stop);
vite.on("exit", (code) => process.exit(code ?? 0));
