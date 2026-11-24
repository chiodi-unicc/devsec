import { defineConfig } from "vite";
import solid from "vite-plugin-solid";
import { createApi } from "./server/api.js";

// Client build → dist/client. In dev, the same API handler the CLI server uses runs as middleware.
export default defineConfig({
  plugins: [
    solid(),
    {
      name: "devsec-api",
      configureServer(server) {
        const api = createApi(process.env["DEVSEC_REPO"] ?? process.cwd());
        server.middlewares.use((req, res, next) => void api(req, res, next));
      },
    },
  ],
  build: { outDir: "dist/client", emptyOutDir: true },
});
