import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// GitHub Pages serves project sites from /<repo>/, so the base path must match
// or every asset 404s. Override with RCH_DASH_BASE for a user/organisation page
// (base "/") or a custom domain.
const base = process.env.RCH_DASH_BASE ?? "/remote_compilation_helper/";

export default defineConfig({
  base,
  plugins: [react()],
  // `npm run serve:dist` (vite preview) must land on the port tests/e2e.mjs
  // drives against.
  preview: {
    port: 4174,
    strictPort: true,
  },
  build: {
    outDir: "dist",
    sourcemap: false,
    target: "es2022",
  },
});
