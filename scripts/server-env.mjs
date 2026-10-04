import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import * as util from "node:util";

export function loadServerEnvironment(root, env = process.env) {
  const explicit = env.SOC_WATCH_ENV_FILE;
  const path = explicit ? resolve(explicit) : resolve(root, ".env");
  if (!existsSync(path)) {
    if (explicit) throw new Error("The configured SOC_WATCH_ENV_FILE does not exist.");
    return;
  }
  if (!util.parseEnv) throw new Error("Loading a server .env file requires Node.js 24 or later.");
  let parsed;
  try { parsed = util.parseEnv(readFileSync(path, "utf8")); }
  catch { throw new Error("The server environment file could not be read. Check its permissions and syntax."); }
  for (const [name, value] of Object.entries(parsed)) if (env[name] === undefined) env[name] = value;
}
