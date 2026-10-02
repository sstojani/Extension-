import { createReadStream, existsSync, statSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { extname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const webRoot = resolve(projectRoot, "apps", "web", "dist");
const indexPath = resolve(webRoot, "index.html");
const host = process.env.SOC_WATCH_HOST ?? "127.0.0.1";
const port = parsePort(process.env.SOC_WATCH_PORT ?? "8080");
let worker, store, handleAgent;
if (process.env.SOC_WATCH_SERVER_AGENT === "true") {
  if (Number(process.versions.node.split(".")[0]) < 24) throw new Error("The persistent server agent needs Node.js 24 LTS or later. Static web hosting remains available without SOC_WATCH_SERVER_AGENT=true.");
  const [{ Store }, { ElasticClient }, { runtimeConfig }, { AgentWorker }, { createAgentApi }] = await Promise.all([
    import("../apps/server/store.mjs"), import("../apps/server/elastic.mjs"), import("../apps/server/config.mjs"),
    import("../apps/server/worker.mjs"), import("../apps/server/api.mjs")
  ]);
  const runtime = runtimeConfig();
  store = new Store(resolve(runtime.dataDir, "soc-watch.sqlite"));
  worker = new AgentWorker(store, new ElasticClient(runtime), runtime);
  const version = JSON.parse(readFileSync(resolve(projectRoot, "package.json"), "utf8")).version;
  handleAgent = createAgentApi(worker, runtime, version);
}

if (!existsSync(indexPath)) {
  console.error(`Web build not found at ${indexPath}. Run npm run build first.`);
  process.exit(1);
}

const mimeTypes = new Map([
  [".css", "text/css; charset=utf-8"],
  [".html", "text/html; charset=utf-8"],
  [".ico", "image/x-icon"],
  [".js", "text/javascript; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".map", "application/json; charset=utf-8"],
  [".png", "image/png"],
  [".svg", "image/svg+xml"],
  [".txt", "text/plain; charset=utf-8"],
  [".webp", "image/webp"],
  [".woff", "font/woff"],
  [".woff2", "font/woff2"],
  [".zip", "application/zip"]
]);

const server = createServer(async (request, response) => {
  if (handleAgent) {
    try { if (await handleAgent(request, response)) return; }
    catch { response.writeHead(500, { "Content-Type": "application/json" }); response.end(JSON.stringify({ error: "Server agent request failed" })); return; }
  }
  if (request.url?.startsWith("/api/")) {
    response.writeHead(404, { "Content-Type": "application/json", "Cache-Control": "no-store" });
    response.end(JSON.stringify({ available: false, error: "Server agent is not enabled on this host." })); return;
  }
  if (request.method !== "GET" && request.method !== "HEAD") {
    response.writeHead(405, { Allow: "GET, HEAD" });
    response.end("Method Not Allowed");
    return;
  }

  const requestedPath = safePathname(request.url);
  if (requestedPath === null) {
    response.writeHead(400);
    response.end("Bad Request");
    return;
  }

  const candidate = resolve(webRoot, `.${requestedPath}`);
  const insideWebRoot = candidate === webRoot || candidate.startsWith(`${webRoot}${sep}`);
  if (!insideWebRoot) {
    response.writeHead(403);
    response.end("Forbidden");
    return;
  }

  const candidateIsFile = isFile(candidate);
  if (!candidateIsFile && extname(requestedPath)) {
    response.writeHead(404);
    response.end("Not Found");
    return;
  }

  const filePath = candidateIsFile ? candidate : indexPath;
  const extension = extname(filePath).toLowerCase();
  const isEntryPoint = filePath === indexPath;

  response.writeHead(200, {
    "Cache-Control": isEntryPoint ? "no-cache" : "public, max-age=31536000, immutable",
    "Content-Type": mimeTypes.get(extension) ?? "application/octet-stream",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY"
  });

  if (request.method === "HEAD") {
    response.end();
    return;
  }

  const stream = createReadStream(filePath);
  stream.on("error", () => response.destroy());
  stream.pipe(response);
});

server.listen(port, host, () => {
  console.log(`SOC Watch web is listening on http://${host}:${port}`);
  worker?.start();
});
server.on("error", error => {
  console.error(error.code === "EADDRINUSE" ? `Port ${port} on ${host} is already in use. Set SOC_WATCH_PORT to an available port; do not stop unrelated services.` : error.message);
  store?.close(); process.exitCode = 1;
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, async () => {
    await worker?.stop(); store?.close();
    server.close((error) => process.exit(error ? 1 : 0));
  });
}

function safePathname(rawUrl) {
  try {
    return decodeURIComponent(new URL(rawUrl ?? "/", "http://localhost").pathname);
  } catch {
    return null;
  }
}

function isFile(path) {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

function parsePort(value) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) {
    throw new Error(`Invalid SOC_WATCH_PORT: ${value}`);
  }
  return parsed;
}
