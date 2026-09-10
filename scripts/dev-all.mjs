import { spawn } from "node:child_process";

const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
const spawnOptions = { stdio: "inherit", shell: process.platform === "win32" };
const children = [
  spawn(npmCommand, ["run", "dev", "-w", "apps/web", "--", "--port", "5173"], spawnOptions),
  spawn(npmCommand, ["run", "dev:watch", "-w", "apps/extension"], spawnOptions)
];

function stop() {
  for (const child of children) child.kill();
  process.exit(0);
}

process.on("SIGINT", stop);
process.on("SIGTERM", stop);
for (const child of children) child.on("exit", (code) => {
  if (code && code !== 0) process.exit(code);
});
