#!/usr/bin/env bash
# Pack the devsec package, install the tarball into an empty folder like a user would,
# and exercise the CLI, the MCP server and the UI from the installed copy.
# Needs a prior `pnpm build` and the scanners (`devsec setup` or on PATH).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd -P)"
work="$(mktemp -d)"
work="$(cd "$work" && pwd -P)"
trap 'devsec_bin ui --stop -C "$work/repo" >/dev/null 2>&1 || true; rm -rf "$work"' EXIT

step() { printf '\n== %s\n' "$*"; }

step "pack"
(cd "$root/apps/devsec" && pnpm pack --pack-destination "$work" >/dev/null)
tarball="$(ls "$work"/devsec-*.tgz)"
tar -tzf "$tarball" | sed 's/^/  /'

step "install into an empty project"
mkdir "$work/app" && cd "$work/app"
npm init -y >/dev/null
npm install --no-audit --no-fund --silent "$tarball"
devsec_bin() { "$work/app/node_modules/.bin/devsec" "$@"; }
echo "  version: $(devsec_bin --version)"

step "doctor"
devsec_bin doctor >/dev/null && echo "  ok"

step "scan the example repo (expect exit 1: policy fails)"
"$root/scripts/make-example.sh" "$work/repo" >/dev/null
set +e
devsec_bin scan -C "$work/repo" --quiet >"$work/scan.json"
code=$?
set -e
[ "$code" -eq 1 ] || { echo "  expected exit 1, got $code"; exit 1; }
node -e 'const r=require(process.argv[1]); console.log("  " + r.summary)' "$work/scan.json"

step "mcp: initialize and list tools"
node --input-type=module - "$work/app/node_modules/.bin/devsec" <<'JS'
import { spawn } from "node:child_process";
const child = spawn(process.argv[2], ["mcp"], { stdio: ["pipe", "pipe", "inherit"] });
const send = (m) => child.stdin.write(JSON.stringify({ jsonrpc: "2.0", ...m }) + "\n");
let buf = "";
const timer = setTimeout(() => { console.error("  mcp: no answer"); process.exit(1); }, 15000);
child.stdout.on("data", (d) => {
  buf += d;
  for (const line of buf.split("\n").slice(0, -1)) {
    const m = JSON.parse(line);
    if (m.id === 1) {
      send({ method: "notifications/initialized" });
      send({ id: 2, method: "tools/list" });
    }
    if (m.id === 2) {
      const names = m.result.tools.map((t) => t.name).sort();
      console.log("  tools: " + names.join(", "));
      if (!names.includes("devsec_scan")) process.exit(1);
      clearTimeout(timer);
      child.kill();
    }
  }
  buf = buf.slice(buf.lastIndexOf("\n") + 1);
});
send({ id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "smoke", version: "0" } } });
JS

step "ui: start detached, fetch, stop"
url="$(devsec_bin ui -C "$work/repo" --no-open | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(JSON.parse(s).url))')"
curl -sf "$url/" | grep -q '<div id="root">' && echo "  page served at $url"
curl -sf "$url/api/repo" >/dev/null && echo "  api ok"
devsec_bin ui -C "$work/repo" --stop >/dev/null && echo "  stopped"

printf '\nsmoke test passed\n'
