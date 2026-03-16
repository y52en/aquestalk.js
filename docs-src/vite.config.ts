import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "aquestalk.js": path.resolve(__dirname, "../src/index.ts"),
      v86: path.resolve(__dirname, "node_modules/v86"),
    },
  },
  build: {
    outDir: "../docs",
  },
  base: "./",
  server: {
    fs: {
      allow: [
        "../",
        "../../ax/pkg/"
      ],
    },
  },
});
