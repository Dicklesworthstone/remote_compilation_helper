import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// GitHub Pages serves project sites from /<repo>/, so the base path must match
// or every asset 404s. Override with RCH_DASH_BASE for a user/organisation page
// (base "/") or a custom domain.
const base = process.env.RCH_DASH_BASE ?? "/remote_compilation_helper/";

export default defineConfig({
  base,
  plugins: [react()],
  build: {
    outDir: "dist",
    sourcemap: false,
    target: "es2022",
  },
});
