import type { IncomingMessage, ServerResponse } from "node:http";
import { describeError, finding, isRunId, listRuns, readRun, repoRootOf, workspaceLayout, type DevsecError, type Result } from "@devsec/core";
import { nodeDeps, watchTree } from "@devsec/node";
import type { StreamMessage } from "./protocol.js";

// Runtime shell: HTTP routes over core functions bound to Node deps. No domain logic here.


const deps = nodeDeps();

const send = (res: ServerResponse, r: Result<unknown, DevsecError>) => {
  res.statusCode = r.ok ? 200 : 404;
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify(r.ok ? r.value : { error: describeError(r.error) }));
};

/** Watches `.devsec/runs` and fans changes out to every connected browser (server-sent events). */
const createStream = (cwd: string) => {
  const clients = new Set<ServerResponse>();
  const changed = new Set<string>();
  let timer: NodeJS.Timeout | undefined;
  let watching = false;

  const message = async (): Promise<string> => {
    const runs = await listRuns(deps)({ cwd });
    const msg: StreamMessage = { runs: runs.ok ? runs.value : [], changed: [...changed] };
    changed.clear();
    return `data: ${JSON.stringify(msg)}\n\n`;
  };

  const broadcast = async () => {
    timer = undefined;
    const data = await message();
    for (const c of clients) c.write(data);
  };

  const watch = async () => {
    if (watching) return;
    watching = true;
    const root = await repoRootOf(deps)(cwd);
    if (!root.ok) return;
    watchTree(workspaceLayout(root.value).runs, (path) => {
      const runId = path.split(/[\\/]/)[0];
      if (runId) changed.add(runId);
      timer ??= setTimeout(() => void broadcast(), 100);
    });
  };

  return async (req: IncomingMessage, res: ServerResponse) => {
    res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache", connection: "keep-alive" });
    clients.add(res);
    req.on("close", () => clients.delete(res));
    res.write(await message());
    await watch();
  };
};

/**
 * DNS-rebinding guard: a page on evil.example whose DNS later points at 127.0.0.1 sends
 * `Host: evil.example`. Only loopback host names are served.
 */
const loopbackHosts = new Set(["127.0.0.1", "localhost", "[::1]"]);
export const isLoopbackHost = (host: string | undefined): boolean => {
  if (!host) return false;
  const name = host.startsWith("[") ? host.slice(0, host.indexOf("]") + 1) : host.split(":")[0];
  return loopbackHosts.has((name ?? "").toLowerCase());
};

/** Returns a connect-style handler for every request: rejects non-loopback hosts, serves /api, else `next`. */
export const createApi = (cwd: string) => {
  const stream = createStream(cwd);
  return async (req: IncomingMessage, res: ServerResponse, next: () => void): Promise<void> => {
    if (!isLoopbackHost(req.headers.host)) {
      res.statusCode = 403;
      res.end("forbidden host");
      return;
    }
    const url = new URL(req.url ?? "/", "http://localhost");
    const parts = url.pathname.split("/").filter(Boolean);
    if (parts[0] !== "api") return next();
    const [, resource, runId, sub, id] = parts;

    if (resource === "stream") return stream(req, res);
    if (resource === "repo") {
      const root = await repoRootOf(deps)(cwd);
      return send(res, root.ok ? { ok: true, value: { root: root.value } } : root);
    }
    if (resource !== "runs" || runId === undefined || !isRunId(runId)) {
      return send(res, { ok: false, error: { type: "io", detail: "not found" } });
    }
    if (sub === undefined) return send(res, await readRun(deps)({ cwd, runId }));
    if (sub === "findings" && id) return send(res, await finding(deps)({ cwd, runId, id }));
    return send(res, { ok: false, error: { type: "io", detail: "not found" } });
  };
};
