import path from "node:path";
import { fileURLToPath } from "node:url";
import { startVitest } from "vitest/node";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const filters = process.argv.slice(2).filter((argument) => argument !== "--run" && argument !== "--passWithNoTests");

// Keep test startup independent of esbuild config loading on Windows paths containing "+".
const context = await startVitest(
  "test",
  filters,
  { run: true, passWithNoTests: true, root, config: false },
  { root, configFile: false }
);

if (!context) process.exitCode = 1;
