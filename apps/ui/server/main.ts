import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { createApi } from "./api.js";

// devsec-ui: serves the UI for the repository in the current folder, live-updating from .devsec/.
const usage = `usage: devsec-ui [-C <dir>] [--port <n>] [--open]

Serves a live view of <dir>/.devsec (default: current folder) at http://127.0.0.1:<port>.
Updates as scans run (devsec scan, MCP devsec_scan) without reloading.`;

const { values } = parseArgs({
  options: {
    C: { type: "string", short: "C" },
    port: { type: "string", short: "p", default: "4321" },
    open: { type: "boolean", short: "o" },
    help: { type: "boolean", short: "h" },
  },
});
if (values.help) {
  console.log(usage);
  process.exit(0);
}

const cwd = values.C ?? process.cwd();
const client = fileURLToPath(new URL("./client/", import.meta.url));
const types: Record<string, string> = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml" };
const api = createApi(cwd);

const server = createServer((req, res) => {
  void api(req, res, async () => {
    const path = normalize(new URL(req.url ?? "/", "http://localhost").pathname).replace(/^(\.\.[/\\])+/, "");
    const file = join(client, path === "/" ? "index.html" : path);
    const body = await readFile(file).catch(() => readFile(join(client, "index.html")));
    res.setHeader("content-type", types[extname(file)] ?? "text/html");
    res.end(body);
  });
});

/** Try the requested port, then the next few. */
const listen = (s: Server, port: number, tries = 10): Promise<number> =>
  new Promise((resolve, reject) => {
    s.once("error", (e: NodeJS.ErrnoException) =>
      e.code === "EADDRINUSE" && tries > 1 ? resolve(listen(s, port + 1, tries - 1)) : reject(e),
    );
    s.listen(port, "127.0.0.1", () => resolve(port));
  });

const port = await listen(server, Number(values.port));
const url = `http://127.0.0.1:${port}`;
process.stderr.write(`devsec-ui: ${url}  (repo: ${cwd})\n`);
if (values.open) {
  const opener = process.platform === "darwin" ? "open" : process.platform === "win32" ? "explorer" : "xdg-open";
  spawn(opener, [url], { stdio: "ignore", detached: true }).unref();
}
