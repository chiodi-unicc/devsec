import { runCli } from "../../cli/src/cli.js";
import { startMcp } from "../../mcp/src/server.js";
import { serveUi } from "../../ui/server/serve.js";

// The devsec executable: one entry for the three apps. Each app is unchanged; this only
// picks which one to start. `ui --serve` is also how `devsec ui` starts the UI in the background.

declare const __DEVSEC_VERSION__: string;
const version = __DEVSEC_VERSION__;

const argv = process.argv.slice(2);
const [command, ...rest] = argv;

if (command === "mcp") {
  await startMcp({ version });
} else if (command === "ui" && rest.includes("--serve")) {
  await serveUi(rest.filter((a) => a !== "--serve"));
} else {
  process.exitCode = await runCli(argv, { version });
}
