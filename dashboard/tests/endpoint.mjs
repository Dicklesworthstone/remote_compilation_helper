/**
 * Smoke test for the /api/fleet LLM endpoint against the real bundled handler.
 *
 * Usage:
 *   npm run build:api
 *   RCH_DASH_PASSPHRASE='...' node tests/endpoint.mjs
 */

import http from "node:http";
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";

const BUNDLE = resolve(process.env.API_BUNDLE ?? ".vercel-fn/index.mjs");
const { default: handler } = await import(pathToFileURL(BUNDLE).href);

const srv = http.createServer((req, res) => handler(req, res));
await new Promise((r) => srv.listen(4180, r));

const PW = process.env.RCH_DASH_PASSPHRASE;
if (!PW) {
  console.error("RCH_DASH_PASSPHRASE not set");
  process.exit(2);
}

const call = async (path, headers = {}) => {
  const r = await fetch(`http://127.0.0.1:4180${path}`, { headers });
  return { status: r.status, ct: r.headers.get("content-type") ?? "", body: await r.text() };
};

let fails = 0;
const chk = (name, ok, note = "") => {
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${name}${note ? " — " + note : ""}`);
  if (!ok) fails++;
};

let r = await call("/api/fleet");
chk("401 without a key", r.status === 401, r.body.trim());

r = await call("/api/fleet", { authorization: "Bearer totally-wrong-passphrase" });
chk("401 on wrong passphrase", r.status === 401, r.body.trim());
// Kept for the KDF-cache guards at the bottom: this sample is taken BEFORE any
// successful request, i.e. against a guaranteed-empty derivation cache.
const wrongOnEmptyCache = { status: r.status, ct: r.ct, body: r.body };

r = await call("/api/fleet", { authorization: `Bearer ${PW}` });
chk("200 with bearer key", r.status === 200, `${r.body.length}B`);
chk("defaults to TOON", r.body.startsWith("schema: rch.fleet.llm.v1"), r.body.split("\n")[0]);
chk("uses tabular arrays", /problems\[\d+\]\{/.test(r.body) && /workers\[\d+\]\{/.test(r.body));
const toonLen = r.body.length;

r = await call("/api/fleet?format=json", { "x-fleet-key": PW });
chk("json via X-Fleet-Key header", r.status === 200 && r.ct.includes("application/json"));
const parsed = JSON.parse(r.body);
chk("json parses with schema", parsed.schema === "rch.fleet.llm.v1", `${parsed.summary.workers} workers`);
chk("problems ranked critical-first",
  parsed.problems.length === 0 || parsed.problems[0].severity === "critical",
  `${parsed.problems.length} problems`);
chk("TOON is smaller than JSON", toonLen < r.body.length,
  `${toonLen}B vs ${r.body.length}B (${(100 - (toonLen / r.body.length) * 100).toFixed(0)}% smaller)`);

r = await call(`/api/fleet?view=full&key=${encodeURIComponent(PW)}`);
chk("view=full via ?key", r.status === 200 && r.body.includes("worker_detail"), `${r.body.length}B`);

r = await call("/api/fleet?format=xml", { authorization: `Bearer ${PW}` });
chk("400 on bad format", r.status === 400, r.body.trim());

r = await call("/api/fleet?view=nonsense", { authorization: `Bearer ${PW}` });
chk("400 on bad view", r.status === 400, r.body.trim());

// ── KDF-cache guards ───────────────────────────────────────────────────────
// This endpoint stores no secret: 600k-iteration PBKDF2 is BOTH the auth check
// and the brute-force cost. Caching derivations that already decrypted is only
// sound while a WRONG passphrase keeps paying full price. These guards fail if
// that ever stops being true. The handler runs in this process, so process CPU
// time measures it directly — and unlike wall-clock it survives a loaded host.
const cpuMs = async (fn) => {
  const c0 = process.cpuUsage();
  const out = await fn();
  const c = process.cpuUsage(c0);
  return { ms: (c.user + c.system) / 1000, out };
};
// min-of-N: under contention the minimum is the least-contaminated estimate of
// the work actually done.
const minCpu = async (n, fn) => {
  let best = Infinity, last;
  for (let i = 0; i < n; i++) { const s = await cpuMs(fn); best = Math.min(best, s.ms); last = s.out; }
  return { ms: best, out: last };
};

// Many successful requests have run above, so the correct passphrase is cached.
const warm = await minCpu(3, () => call("/api/fleet", { authorization: `Bearer ${PW}` }));
const wrong = await minCpu(3, () => call("/api/fleet", { authorization: "Bearer another-wrong-passphrase" }));
// A one-character-off passphrase: the case that would break if the cache were
// ever keyed on anything that a near-miss could partially match.
const nearMiss = PW.slice(0, -1) + (PW.slice(-1) === "x" ? "y" : "x");
const near = await minCpu(3, () => call("/api/fleet", { authorization: `Bearer ${nearMiss}` }));

chk("warm correct passphrase skips re-derivation", warm.ms * 5 < wrong.ms,
  `warm ${warm.ms.toFixed(1)}ms cpu vs ${wrong.ms.toFixed(1)}ms uncached`);
chk("wrong passphrase still pays the full derivation", wrong.ms > warm.ms * 5,
  `${(wrong.ms / warm.ms).toFixed(1)}x the warm cost`);
chk("near-miss passphrase pays the full derivation", near.ms > warm.ms * 5,
  `${(near.ms / warm.ms).toFixed(1)}x the warm cost`);
chk("wrong-passphrase response unchanged by a populated cache",
  wrong.out.status === wrongOnEmptyCache.status && wrong.out.ct === wrongOnEmptyCache.ct
  && wrong.out.body === wrongOnEmptyCache.body,
  `${wrong.out.status} ${JSON.stringify(wrong.out.body)}`);

srv.close();
console.log(fails === 0 ? "\nALL ENDPOINT CHECKS PASSED" : `\n${fails} CHECK(S) FAILED`);
process.exit(fails ? 1 : 0);
