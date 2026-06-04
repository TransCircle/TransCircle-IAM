import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { "@": path.resolve(root, "./src") },
  },
  server: {
    port: 5173,
    proxy: {
      // Dev convenience: proxy API + OAuth to the backend.
      "/api": { target: "http://localhost:8080", changeOrigin: true },
      "/oauth2": { target: "http://localhost:8080", changeOrigin: true },
      "/.well-known": { target: "http://localhost:8080", changeOrigin: true },
    },
  },
});
