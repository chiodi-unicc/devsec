import { defineConfig } from "vite";

// Server → one self-contained ESM file (dist/cli.js) with @devsec/core and @devsec/node inlined,
// so `npx` needs no runtime dependencies. Node built-ins stay external.
export default defineConfig({
  build: {
    ssr: "server/main.ts",
    outDir: "dist",
    emptyOutDir: false,
    target: "node22",
    sourcemap: false,
    rollupOptions: { output: { entryFileNames: "cli.js", banner: "#!/usr/bin/env node" } },
  },
  ssr: { noExternal: true },
});
