import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { createApi } from "./api.js";

// The UI server: serves the UI for a repository, live-updating from its .devsec/.
// Started by `devsec ui` (detached) or `devsec ui --serve` (foreground).
const usage = `usage: devsec ui --serve [-C <dir>] [--port <n>] [--open]

Serves a live view of <dir>/.devsec (default: current folder) at http://127.0.0.1:<port>.
Updates as scans run (devsec scan, MCP devsec_scan) without reloading.`;

/** Try the requested port, then the next few. */
const listen = (s: Server, port: number, tries = 10): Promise<number> =>
  new Promise((resolve, reject) => {
    s.once("error", (e: NodeJS.ErrnoException) =>
      e.code === "EADDRINUSE" && tries > 1 ? resolve(listen(s, port + 1, tries - 1)) : reject(e),
    );
    s.listen(port, "127.0.0.1", () => resolve(port));
  });

/** Serve the UI until the process exits. Prints `devsec-ui: <url>` on stderr when ready (the launcher waits for it). */
export const serveUi = async (argv: readonly string[]): Promise<void> => {
  const { values } = parseArgs({
    args: [...argv],
    options: {
      C: { type: "string", short: "C" },
      port: { type: "string", short: "p", default: "4321" },
      open: { type: "boolean", short: "o" },
      help: { type: "boolean", short: "h" },
    },
  });
  if (values.help) {
    console.log(usage);
    return;
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

  const port = await listen(server, Number(values.port));
  const url = `http://127.0.0.1:${port}`;
  process.stderr.write(`devsec-ui: ${url}  (repo: ${cwd})\n`);
  if (values.open) {
    const opener = process.platform === "darwin" ? "open" : process.platform === "win32" ? "explorer" : "xdg-open";
    spawn(opener, [url], { stdio: "ignore", detached: true }).unref();
  }
};
