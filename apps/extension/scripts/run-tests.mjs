import path from "node:path";
import { fileURLToPath } from "node:url";
import { startVitest } from "vitest/node";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const filters = process.argv.slice(2).filter((argument) => argument !== "--run");

// Loading the Vite config through esbuild fails on some Windows paths that contain "+".
const context = await startVitest(
  "test",
  filters,
  { run: true, root, config: false },
  { root, configFile: false }
);

if (!context) process.exitCode = 1;
