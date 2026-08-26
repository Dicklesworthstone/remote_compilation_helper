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

srv.close();
console.log(fails === 0 ? "\nALL ENDPOINT CHECKS PASSED" : `\n${fails} CHECK(S) FAILED`);
process.exit(fails ? 1 : 0);
