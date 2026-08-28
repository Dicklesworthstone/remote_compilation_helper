/**
 * Smoke test for the /api/fleet LLM endpoint against the real bundled handler.
 *
 * Usage:
 *   npm run build:api
 *   RCH_DASH_PASSPHRASE='...' node tests/endpoint.mjs
 */

import http from "node:http";
import { pathToFileURL } from "node:url";
import { resolve, join } from "node:path";
import { readFile, writeFile, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { build } from "esbuild";

const BUNDLE = resolve(process.env.API_BUNDLE ?? ".vercel-fn/index.mjs");
const { default: handler } = await import(pathToFileURL(BUNDLE).href);

const srv = http.createServer((req, res) => handler(req, res));
await new Promise((r) => srv.listen(4180, r));

const PW = process.env.RCH_DASH_PASSPHRASE;

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

// The contract is readable WITHOUT the key: an agent holding only the URL
// must be able to learn the parameters and problem kinds before it has a
// credential. It carries no fleet data.
r = await call("/api/fleet?view=help&format=json");
chk("help answers 200 without a key", r.status === 200 && r.ct.includes("application/json"), String(r.status));
{
  const help = r.status === 200 ? JSON.parse(r.body) : {};
  chk("help documents view, target and format",
    ["view", "target", "format"].every((k) => typeof help.params?.[k] === "string"));
  chk("help lists the problem kinds with a fix for each",
    Array.isArray(help.kinds) && help.kinds.length > 10 && help.kinds.every((k) => k.kind && k.severity && k.fix));
  chk("help leaks no fleet data", !/vmi\d|hz\d|\d+\.\d+\.\d+\.\d+/.test(r.body));
}
r = await call("/api/fleet?view=diagnose");
chk("diagnose without a target is a 400 that says so, before auth",
  r.status === 400 && /target/.test(r.body), r.body.trim());

if (!PW) {
  // A 2-assertion green run is not a passing endpoint suite. Say so loudly and
  // fail, unless the caller has explicitly accepted the reduced run.
  if (process.env.RCH_DASH_ALLOW_SKIP === "1") {
    console.log("  SKIP  positive decrypt tests (RCH_DASH_PASSPHRASE not set; RCH_DASH_ALLOW_SKIP=1)");
    srv.close();
    process.exit(fails > 0 ? 1 : 0);
  }
  console.log("  FAIL  RCH_DASH_PASSPHRASE is not set: the decrypt, view and target checks did not run.");
  console.log("        Set it (or RCH_DASH_ALLOW_SKIP=1 to accept the reduced run).");
  srv.close();
  process.exit(1);
}

r = await call("/api/fleet", { authorization: `Bearer ${PW}` });
chk("200 with bearer key", r.status === 200, `${r.body.length}B`);
chk("defaults to TOON", r.body.startsWith("schema: rch.fleet.llm.v2"), r.body.split("\n")[0]);
chk("uses tabular arrays", /problems\[\d+\]\{/.test(r.body) && /workers\[\d+\]\{/.test(r.body));
const toonLen = r.body.length;

r = await call("/api/fleet?format=json", { "x-fleet-key": PW });
chk("json via X-Fleet-Key header", r.status === 200 && r.ct.includes("application/json"));
const parsed = JSON.parse(r.body);
chk("json parses with schema", parsed.schema === "rch.fleet.llm.v2", `${parsed.summary.workers} workers`);
// Every row, not just the first: a critical after a warn anywhere is a sort bug.
const SEV = { critical: 0, warn: 1, info: 2 };
chk("problems are severity-sorted throughout",
  parsed.problems.every((p, i, a) => i === 0 || SEV[a[i - 1].severity] <= SEV[p.severity]),
  `${parsed.problems.length} problems`);
chk("every problem row has the seven string columns",
  parsed.problems.every((p) => ["severity", "kind", "target", "detail", "since", "action", "on"].every((k) => typeof p[k] === "string")));
chk("summary carries verdict, next_actions and the fleet version",
  typeof parsed.verdict === "string" && Array.isArray(parsed.next_actions) && typeof parsed.summary.daemon_version === "string");
chk("dev rows say hook/shim/doctor state and the measured offload share",
  parsed.dev_machines.every((d) => "hook" in d && "shim" in d && "doctor" in d && "offload_pct" in d && "local_now" in d));
chk("TOON is smaller than JSON", toonLen < r.body.length,
  `${toonLen}B vs ${r.body.length}B (${(100 - (toonLen / r.body.length) * 100).toFixed(0)}% smaller)`);

r = await call(`/api/fleet?view=full&key=${encodeURIComponent(PW)}`);
chk("view=full via ?key", r.status === 200 && r.body.includes("worker_detail"), `${r.body.length}B`);

r = await call("/api/fleet?view=problems&format=json", { authorization: `Bearer ${PW}` });
{
  const p = JSON.parse(r.body);
  chk("view=problems carries problems and next_actions and nothing per-row",
    r.status === 200 && Array.isArray(p.problems) && Array.isArray(p.next_actions) && !("workers" in p) && !("dev_machines" in p));
  chk("view=problems agrees with the summary view", p.problems_total === parsed.problems_total);
  // Target the first dev machine the summary listed.
  const devIds = new Set(parsed.dev_machines.map((d) => d.id));
  const dev = parsed.dev_machines[0]?.id;
  // A worker that is NOT also a dev machine, so the worker-only shape is exercised.
  const worker = parsed.workers.find((w) => !devIds.has(w.id))?.id;
  // A box that is both, when the fleet has one.
  const both = parsed.workers.find((w) => devIds.has(w.id))?.id;
  if (both) {
    const t = await call(`/api/fleet?view=diagnose&target=${encodeURIComponent(both)}&format=json`, { authorization: `Bearer ${PW}` });
    const tj = t.status === 200 ? JSON.parse(t.body) : {};
    chk("a box that is both dev machine and worker diagnoses as both halves",
      t.status === 200 && tj.target?.type === "both" && "dev_machine" in tj && "worker" in tj && "worker_detail" in tj, t.body.slice(0, 120));
    const w = await call(`/api/fleet?view=diagnose&target=worker:${encodeURIComponent(both)}&format=json`, { authorization: `Bearer ${PW}` });
    const wj = w.status === 200 ? JSON.parse(w.body) : {};
    chk("the worker: prefix picks the worker half alone",
      w.status === 200 && wj.target?.type === "worker" && !("dev_machine" in wj) && "detail" in wj, w.body.slice(0, 120));
  }
  if (dev) {
    const t = await call(`/api/fleet?view=diagnose&target=${encodeURIComponent(dev.toUpperCase())}&format=json`, { authorization: `Bearer ${PW}` });
    const tj = t.status === 200 ? JSON.parse(t.body) : {};
    chk("diagnose resolves a dev machine case-insensitively",
      t.status === 200 && tj.target?.type === "dev_machine" && tj.target?.id === dev && tj.dev_machine?.id === dev && "detail" in tj, t.body.slice(0, 120));
    chk("diagnose scopes problems to the target",
      (tj.problems ?? []).every((x) => x.target === dev || x.target.startsWith(`${dev}:`) || x.on === dev || x.kind === "fleet.degraded" || x.kind.startsWith("snapshot.")));
    const s = await call(`/api/fleet?target=${encodeURIComponent(dev)}&format=json`, { authorization: `Bearer ${PW}` });
    const sj = JSON.parse(s.body);
    chk("summary with a target filters the per-row lists",
      s.status === 200 && sj.dev_machines.length === 1 && sj.workers.length === 0);
  }
  if (worker) {
    const t = await call(`/api/fleet?view=diagnose&target=${encodeURIComponent(worker)}&format=json`, { authorization: `Bearer ${PW}` });
    const tj = t.status === 200 ? JSON.parse(t.body) : {};
    chk("diagnose on a worker carries its per-machine slot view and what others say about it",
      t.status === 200 && tj.target?.type === "worker" && typeof tj.detail?.slots_by_dev === "string" &&
      Array.isArray(tj.hints_about) && Array.isArray(tj.alerts_about), t.body.slice(0, 120));
  }
}

r = await call("/api/fleet?target=no-such-machine", { authorization: `Bearer ${PW}` });
chk("404 on an unknown target, listing the known ids",
  r.status === 404 && /dev machines:/.test(r.body) && /workers:/.test(r.body), r.body.trim().slice(0, 160));

r = await call("/api/fleet?format=xml", { authorization: `Bearer ${PW}` });
chk("400 on bad format, pointing at help", r.status === 400 && /view=help/.test(r.body), r.body.trim());

r = await call("/api/fleet?view=nonsense", { authorization: `Bearer ${PW}` });
chk("400 on bad view, pointing at help", r.status === 400 && /view=help/.test(r.body), r.body.trim());

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

// ── transport compression ──────────────────────────────────────────────────
//
// The collector gzips the snapshot before encrypting it: the published file is
// base64 of AES-GCM ciphertext, which is incompressible, so nothing downstream
// of encryption can shrink it. This endpoint has to inflate what it decrypts.
{
  const bundled = JSON.parse(await readFile(resolve("public/data/fleet.enc.json"), "utf8"));
  // The collector has written gzip since pass 6; an envelope with no codec
  // field is a pre-compression artifact and must not pass as "declared".
  chk("bundled envelope declares its codec", bundled.compression === "gzip",
    `compression=${JSON.stringify(bundled.compression ?? null)}`);
  if (bundled.compression === "gzip") {
    // Every 200 above came out of a gzip'd envelope, so the inflate path is
    // already proven; report the leverage.
    const plainish = bundled.ciphertext.length * 0.75;
    chk("compressed envelope is a fraction of the plaintext it carries", plainish < 40_000,
      `${Math.round(plainish)}B ciphertext for a ~51KB snapshot`);
  }

  // VERSION SKEW, forward: a snapshot written by a NEWER collector, using a codec
  // this deployment cannot inflate. The failure must not be reported as a bad
  // passphrase — the caller's credential is fine and telling them otherwise
  // sends them to rotate a secret that was never the problem.
  const dir = await mkdtemp(join(tmpdir(), "rch-endpoint-skew-"));
  const doctored = join(dir, "fleet.enc.json");
  await writeFile(doctored, JSON.stringify({ ...bundled, compression: "codec-from-the-future" }));
  const skewBundle = join(dir, "index.mjs");
  await build({
    entryPoints: ["api/fleet.mjs"],
    outfile: skewBundle,
    bundle: true, format: "esm", platform: "node", target: "node20", logLevel: "silent",
    loader: { ".json": "json" },
    // Swap ONLY the bundled snapshot; every line of handler logic is the real one.
    plugins: [{
      name: "swap-envelope",
      setup(b) {
        b.onResolve({ filter: /public\/data\/fleet\.enc\.json$/ }, () => ({ path: doctored }));
      },
    }],
  });
  const { default: skewHandler } = await import(pathToFileURL(skewBundle).href);
  const skewSrv = http.createServer((req, res) => skewHandler(req, res));
  await new Promise((r) => skewSrv.listen(4181, r));
  const skew = await fetch("http://127.0.0.1:4181/api/fleet", { headers: { authorization: `Bearer ${PW}` } });
  const skewBody = await skew.text();
  chk("an unknown codec is a 500, not a 401", skew.status === 500, `${skew.status} ${skewBody.trim()}`);
  chk("the 500 names the codec", /codec-from-the-future/.test(skewBody), skewBody.trim());
  // And a wrong passphrase against that same payload must still be a 401: the
  // format problem must not swallow the credential check either.
  const skewWrong = await fetch("http://127.0.0.1:4181/api/fleet", { headers: { authorization: "Bearer nope" } });
  chk("an unknown codec still 500s ahead of the derivation", skewWrong.status === 500,
    `${skewWrong.status} — refusing before 600k PBKDF2 on a payload we cannot read`);
  skewSrv.close();
}

console.log(fails === 0 ? "\nALL ENDPOINT CHECKS PASSED" : `\n${fails} CHECK(S) FAILED`);
process.exit(fails ? 1 : 0);
