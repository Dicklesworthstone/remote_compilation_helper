/* Perf harness (profiling-only, no code changes): baseline S1/S2/S3.
 * S1: browser navigate -> .kpis visible (decrypt+first render), N runs, p50/p95.
 * S2: `node tools/fleet-llm.mjs` wall time, N runs (p50/p95) + one --cpu-prof run.
 * S3: dist asset bytes.
 * Usage: node tests/perf.mjs [outDir] [--browser-only|--node-only]
 * Env: RCH_DASH_BASE must match the base the served dist was built with.
 */
import { chromium } from "playwright";
import { readFileSync, mkdirSync, writeFileSync, statSync, readdirSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const outDir = process.argv[2] ?? `tests/artifacts/perf/run-${Date.now()}`;
const mode = process.argv[3] ?? "";
mkdirSync(outDir, { recursive: true });

const env = Object.fromEntries(
  readFileSync(`${root}/.env`, "utf8").split("\n").filter((l) => l.includes("="))
    .map((l) => [l.slice(0, l.indexOf("=")).trim(), l.slice(l.indexOf("=") + 1).trim().replace(/^['"]|['"]$/g, "")]),
);
const PASS = env.RCH_DASH_PASSPHRASE;
const PORT = process.env.RCH_DASH_E2E_PORT ?? "4174";
const BASE = process.env.RCH_DASH_BASE ?? "/remote_compilation_helper/";
const URL = `http://127.0.0.1:${PORT}${BASE}`;

const pct = (arr, p) => {
  const s = [...arr].sort((a, b) => a - b);
  const i = Math.min(s.length - 1, Math.ceil((p / 100) * s.length) - 1);
  return Math.round(s[i]);
};

const result = { scenario_fingerprint: { host: "macbook m4 pro (arm64, darwin 25.2.0)", node: process.version, run_id: new Date().toISOString() } };

// ---------- S1: browser load -> kpis ----------
if (mode !== "--node-only") {
  const browser = await chromium.launch();
  const runs = [];
  for (let i = 0; i < 12; i++) {
    const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const page = await ctx.newPage();
    const t0 = Date.now();
    await page.goto(URL, { waitUntil: "load" });
    await page.waitForSelector(".gate-card");
    const tGate = Date.now() - t0;
    await page.fill("#pp", PASS);
    const t1 = Date.now();
    await page.click("button.btn");
    await page.waitForSelector(".kpis", { timeout: 60000 });
    const tUnlock = Date.now() - t1; // deriveKey(600k PBKDF2) + decrypt + first render
    runs.push({ gate_ms: tGate, unlock_to_kpis_ms: tUnlock });
    await ctx.close();
  }
  await browser.close();
  const u = runs.map((r) => r.unlock_to_kpis_ms);
  const g = runs.map((r) => r.gate_ms);
  result.S1_browser = {
    runs,
    gate_ms: { p50: pct(g, 50), p95: pct(g, 95) },
    unlock_to_kpis_ms: { p50: pct(u, 50), p95: pct(u, 95), note: "includes 600k PBKDF2 deriveKey (webcrypto, security parameter)" },
  };
}

// ---------- S2: node llm pipeline ----------
if (mode !== "--browser-only") {
  const runs = [];
  for (let i = 0; i < 12; i++) {
    const t0 = process.hrtime.bigint();
    execFileSync("node", ["tools/fleet-llm.mjs", "--format", "json"], { cwd: root, stdio: "ignore", env: { ...process.env, ...env } });
    runs.push(Number(process.hrtime.bigint() - t0) / 1e6);
  }
  result.S2_node_llm_ms = { runs: runs.map(Math.round), p50: pct(runs, 50), p95: pct(runs, 95) };
  // One profiled run for attribution.
  try {
    execFileSync("node", ["--cpu-prof", "--cpu-prof-dir", outDir, "tools/fleet-llm.mjs", "--format", "json"],
      { cwd: root, stdio: "ignore", env: { ...process.env, ...env } });
  } catch (e) {
    result.S2_cpuprof_error = String(e.message);
  }
}

// ---------- S3: bundle bytes ----------
const assets = readdirSync(join(root, "dist/assets"));
result.S3_dist_bytes = Object.fromEntries(assets.map((a) => [a, statSync(join(root, "dist/assets", a)).size]));

writeFileSync(join(outDir, "baseline.json"), JSON.stringify(result, null, 2));
console.log(JSON.stringify(result, null, 2));
