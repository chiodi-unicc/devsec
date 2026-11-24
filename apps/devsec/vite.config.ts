import { readFileSync } from "node:fs";
import { defineConfig } from "vite";

const { version } = JSON.parse(readFileSync(new URL("./package.json", import.meta.url), "utf8")) as { version: string };

// One ESM file (dist/devsec.js). Our workspace code (core, node, cli, mcp, ui server) is inlined;
// third-party packages stay external and are installed as normal npm dependencies, so
// `npm audit` and SBOMs of projects using devsec see exactly what it runs.
export default defineConfig({
  define: { __DEVSEC_VERSION__: JSON.stringify(version) },
  build: {
    ssr: "src/main.ts",
    outDir: "dist",
    emptyOutDir: true,
    target: "node24",
    sourcemap: false,
    rollupOptions: { output: { entryFileNames: "devsec.js", banner: "#!/usr/bin/env node" } },
  },
  ssr: { noExternal: [/^@devsec\//] },
});
