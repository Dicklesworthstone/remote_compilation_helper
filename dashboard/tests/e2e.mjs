/**
 * End-to-end smoke test for the fleet dashboard.
 *
 * Drives a real Chromium against a real encrypted snapshot: gate, wrong-vs-right
 * passphrase, rendering, drawer, filtering, theme, cookie session, lock, and
 * mobile overflow. This is the test that caught the slot double-count
 * (dispatcher queue totals summed the same worker once per dispatcher and
 * reported 198 slots for an 80-slot fleet).
 *
 * Usage:
 *   npm run build
 *   python3 -m http.server 4174 --directory dist &
 *   RCH_DASH_PASSPHRASE='...' node tests/e2e.mjs
 *
 * Set RCH_DASH_E2E_PORT to use a different port. Worth doing whenever anything
 * else on the box might already be serving 4174: a second server silently loses
 * the bind and the FIRST one answers, so the suite would happily validate a
 * stale bundle it did not build and report a pass (or a mystery timeout).
 */
import { chromium } from "playwright";
import { createHash, webcrypto as nodeCrypto } from "node:crypto";
import { gunzipSync, gzipSync } from "node:zlib";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
let env = {};
if (existsSync(`${root}/.env`)) {
  env = Object.fromEntries(
    readFileSync(`${root}/.env`, "utf8").split("\n").filter((l) => l.includes("="))
      .map((l) => [l.slice(0, l.indexOf("=")).trim(), l.slice(l.indexOf("=") + 1).trim().replace(/^['"]|['"]$/g, "")]),
  );
}

const BASE = process.env.RCH_DASH_BASE ?? "/remote_compilation_helper/";
const PORT = process.env.RCH_DASH_E2E_PORT ?? "4174";
const URL = `http://127.0.0.1:${PORT}${BASE}`;
const PASS = process.env.RCH_DASH_PASSPHRASE || env.RCH_DASH_PASSPHRASE;
const browser = await chromium.launch();
const page = await browser.newPage();
const errors = [];
page.on("pageerror", (e) => errors.push(String(e)));
page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });

let failures = 0;
const check = (name, cond, detail = "") => {
  if (cond) console.log(`  PASS  ${name}${detail ? " — " + detail : ""}`);
  else { console.log(`  FAIL  ${name}${detail ? " — " + detail : ""}`); failures++; }
};

await page.goto(URL, { waitUntil: "load" });
await page.waitForSelector(".gate-card", { timeout: 20000 });
check("gate renders", await page.locator(".gate-card h1").isVisible());

// wrong passphrase must be rejected
await page.fill("#pp", "definitely-the-wrong-passphrase-xyz");
await page.click("button.btn");
await page.waitForSelector(".gate-err", { timeout: 30000 });
check("wrong passphrase rejected", true, await page.locator(".gate-err").innerText());

// correct passphrase unlocks
await page.fill("#pp", PASS);
await page.click("button.btn");
await page.waitForSelector(".kpis", { timeout: 40000 });
const kpis = await page.locator(".kpi-value").allInnerTexts();
check("unlocks with correct passphrase", kpis.length >= 5, kpis.join(" | "));

// ── transport compression ──────────────────────────────────────────────────
//
// The snapshot is gzip'd BEFORE it is encrypted, because the published file is
// base64 of AES-GCM ciphertext and ciphertext is incompressible — gzip at the
// CDN, at the origin, or in the browser's transfer decoding can do nothing for
// it. That puts an inflate step on the only path that renders this app, using
// `DecompressionStream`, which every check above already depends on: if it were
// broken, `.kpis` would never have appeared.
//
// This block proves the stronger property those checks cannot: that the bytes
// the browser produces are IDENTICAL to what Node compressed, not merely
// parseable. A codec mismatch that happened to inflate to valid-looking JSON
// would pass every rendering assertion in this file. It runs its own decrypt
// (independent of the app's code path) and compares SHA-256 against Node's.
{
  const envUrl = new global.URL("data/fleet.enc.json", URL).href;
  const envelope = await (await fetch(envUrl)).json();
  const b64ToBuf = (b64) => { const b = Buffer.from(b64, "base64"); return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength); };
  const nodeKey = await nodeCrypto.subtle.deriveKey(
    { name: "PBKDF2", salt: b64ToBuf(envelope.kdf.salt), iterations: envelope.kdf.iterations, hash: envelope.kdf.hash },
    await nodeCrypto.subtle.importKey("raw", new TextEncoder().encode(PASS), "PBKDF2", false, ["deriveKey"]),
    { name: "AES-GCM", length: 256 }, false, ["decrypt"],
  );
  let nodePlain = Buffer.from(await nodeCrypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64ToBuf(envelope.cipher.iv) }, nodeKey, b64ToBuf(envelope.ciphertext)));
  const compressed = nodePlain.length;
  if (envelope.compression === "gzip") nodePlain = gunzipSync(nodePlain);
  const nodeDigest = createHash("sha256").update(nodePlain).digest("hex");

  const inBrowser = await page.evaluate(async ({ envUrl, pass }) => {
    const env = await (await fetch(envUrl, { cache: "no-store" })).json();
    const b64 = (s) => { const bin = atob(s); const b = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) b[i] = bin.charCodeAt(i); return b.buffer; };
    const key = await crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: b64(env.kdf.salt), iterations: env.kdf.iterations, hash: env.kdf.hash },
      await crypto.subtle.importKey("raw", new TextEncoder().encode(pass), "PBKDF2", false, ["deriveKey"]),
      { name: "AES-GCM", length: 256 }, false, ["decrypt"],
    );
    const cipherBytes = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(env.cipher.iv) }, key, b64(env.ciphertext));

    const inflate = async () => {
      if (!env.compression || env.compression === "none") return new Uint8Array(cipherBytes);
      const s = new Blob([cipherBytes]).stream().pipeThrough(new DecompressionStream(env.compression));
      return new Uint8Array(await new Response(s).arrayBuffer());
    };
    // Warm, then time: this is the CPU the change adds to every 5-minute refresh
    // in the browser, and it is the number that has to be paid against the bytes.
    for (let i = 0; i < 3; i++) await inflate();
    const samples = [];
    for (let i = 0; i < 15; i++) { const t = performance.now(); await inflate(); samples.push(performance.now() - t); }
    samples.sort((a, b) => a - b);

    const out = await inflate();
    const digest = [...new Uint8Array(await crypto.subtle.digest("SHA-256", out))]
      .map((x) => x.toString(16).padStart(2, "0")).join("");
    return {
      hasDecompressionStream: typeof DecompressionStream !== "undefined",
      compression: env.compression ?? null,
      bytes: out.length,
      digest,
      minMs: samples[0],
      medianMs: samples[Math.floor(samples.length / 2)],
    };
  }, { envUrl, pass: PASS });

  check("browser exposes DecompressionStream", inBrowser.hasDecompressionStream);
  check("browser inflates to byte-identical plaintext", inBrowser.digest === nodeDigest,
    `${inBrowser.bytes}B sha256 ${inBrowser.digest.slice(0, 16)}… (node ${nodeDigest.slice(0, 16)}…)`);
  check("compression is declared in the envelope", inBrowser.compression !== undefined,
    `compression=${JSON.stringify(inBrowser.compression)} · ` +
    `${compressed}B on the wire -> ${inBrowser.bytes}B plaintext ` +
    `(${(inBrowser.bytes / compressed).toFixed(2)}x)`);
  // Not a threshold anybody should tune — a ceiling loose enough that only a
  // real regression (a JS fallback, a per-chunk copy) can trip it.
  check("browser inflate stays under 5ms", inBrowser.medianMs < 5,
    `min ${inBrowser.minMs.toFixed(3)}ms · median ${inBrowser.medianMs.toFixed(3)}ms per refresh`);

  // ── the deflate LEVEL is invisible to this reader ────────────────────────
  //
  // `tools/envelope.mjs` pins level 9 and argues from measurement that it must
  // not be adaptive on fleet size. The reason that constant is safe to pin —
  // and revisitable without an envelope-format change — is that the envelope
  // says only `compression: "gzip"`, and a gzip stream does not carry its level
  // in any way an inflater consults. Node proves that on its own side; this
  // proves it where it actually matters, in the engine that renders the app.
  //
  // The SAME plaintext is re-compressed at levels 1 and 9 and both are handed to
  // Chromium's `DecompressionStream("gzip")`. Different bytes in, identical
  // bytes out, and the browser is never told which is which.
  {
    const atLevel = (lv) => gzipSync(nodePlain, { level: lv });
    const l1 = atLevel(1), l9 = atLevel(9);
    const levelProbe = await page.evaluate(async ({ a, b }) => {
      const un64 = (s) => { const bin = atob(s); const u = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u; };
      const inflate = async (s) => {
        const st = new Blob([un64(s)]).stream().pipeThrough(new DecompressionStream("gzip"));
        return new Uint8Array(await new Response(st).arrayBuffer());
      };
      const sha = async (u) => [...new Uint8Array(await crypto.subtle.digest("SHA-256", u))]
        .map((x) => x.toString(16).padStart(2, "0")).join("");
      const [ua, ub] = [await inflate(a), await inflate(b)];
      return { a: await sha(ua), b: await sha(ub), bytesA: ua.length, bytesB: ub.length };
    }, { a: l1.toString("base64"), b: l9.toString("base64") });

    check("level 1 and level 9 are genuinely different encodings",
      !l1.equals(l9), `${l1.length}B vs ${l9.length}B of the same ${nodePlain.length}B plaintext`);
    check("the browser inflates both levels to the same plaintext, unaided",
      levelProbe.a === levelProbe.b && levelProbe.a === nodeDigest
      && levelProbe.bytesA === nodePlain.length,
      `L1 -> ${levelProbe.a.slice(0, 16)}… · L9 -> ${levelProbe.b.slice(0, 16)}… · node ${nodeDigest.slice(0, 16)}…`);
  }
}

const cards = await page.locator(".wcard").count();  // dev machines + workers
check("worker cards render", cards > 0, `${cards} cards`);
const names = await page.locator(".wname").allInnerTexts();
check("worker names present", names.length === cards, names.slice(0, 5).join(", ") + " …");

// bars/meters rendered
// dev-machine cards carry 2 meters (offload, slots); worker cards carry 3
// (slots, cpu, disk). Assert every card has at least two rather than guessing
// a single multiplier for two different card shapes.
const meters = await page.locator(".bar").count();
check("metric bars render", meters >= cards * 2, `${meters} bars across ${cards} cards`);

// drawer
await page.locator(".wcard").first().click();
await page.waitForSelector(".drawer", { timeout: 15000 });
const drawerTitle = await page.locator(".drawer h3").innerText();
check("detail drawer opens", drawerTitle.length > 0, drawerTitle);
const rows = await page.locator(".drawer .kv").count();
check("drawer shows detail rows", rows > 10, `${rows} rows`);
await page.keyboard.press("Escape");
await page.waitForTimeout(300);
check("drawer closes on Escape", (await page.locator(".drawer").count()) === 0);

// filtering
await page.fill(".search", "hz");
await page.waitForTimeout(400);
const filtered = await page.locator(".wcard").count();
check("search filters", filtered > 0 && filtered < cards, `${filtered} of ${cards}`);
check("filter persists in URL hash", page.url().includes("q=hz"), page.url());
await page.fill(".search", "");

// status chip filter
await page.locator('button.chip', { hasText: "healthy" }).first().click();
await page.waitForTimeout(400);
check("status chip filters", (await page.locator(".wcard").count()) > 0);
await page.locator('button.chip', { hasText: "all" }).first().click();
await page.waitForTimeout(300);

// theme toggle
const before = await page.evaluate(() => document.documentElement.dataset.theme);
await page.locator("button.icon-btn", { hasText: /Light|Dark/ }).first().click();
await page.waitForTimeout(300);
const after = await page.evaluate(() => document.documentElement.dataset.theme);
check("theme toggles", before !== after, `${before} -> ${after}`);

// dispatcher section
// dev machines render as cards with a dev-* pill
const devPills = await page.locator('[class*="pill dev-"]').count();
check("dev machine cards render", devPills > 0, `${devPills} dev machines`);
// open a dev machine drawer and confirm its offload panel
await page.locator('[class*="pill dev-"]').first().click();
await page.waitForSelector(".drawer", { timeout: 15000 });
const devHeads = await page.locator(".drawer .kv-group h4").allInnerTexts();
check("dev drawer shows offload posture", devHeads.some((h) => /offload/i.test(h)), devHeads.join(", "));
check("dev drawer shows this machine's pool view",
  devHeads.some((h) => /view of the pool/i.test(h)), devHeads.join(", "));

// recent builds: relative ages + cross-link to the worker drawer when the id
// is a fleet worker.
//
// Hunt for a machine that HAS builds rather than assuming the first card does.
// Dev cards sort most-urgent-first, so an unreachable machine leads — and an
// unreachable machine legitimately has no build history, which turned a correct
// observation about the fleet into a red suite the moment one box stopped
// answering. "Some dev machine lists builds" is the invariant about the app.
{
  const pills = page.locator('[class*="pill dev-"]');
  const n = await pills.count();
  let found = false;
  for (let i = 0; i < n && !found; i++) {
    await page.keyboard.press("Escape");
    await page.waitForTimeout(150);
    await pills.nth(i).click();
    await page.waitForSelector(".drawer", { timeout: 15000 });
    found = (await page.locator(".drawer .build-row").count()) > 0;
  }
  check("recent builds listed on some dev machine", found, `checked ${n} dev machines`);
  if (found) {
    const buildText = await page.locator(".drawer .builds").innerText();
    check("recent builds show relative age", /ago/.test(buildText), buildText.split("\n")[0]);
    // Builds travel as positional tuples now. An index shifted by one still
    // renders text everywhere — `command` lands in the project cell and reads
    // fine — but a non-numeric value reaches fmtDuration and every duration
    // collapses to "—". Assert a real duration is on screen.
    check("recent builds show a real duration", /\d+(\.\d+)?(ms|s|m)\b/.test(buildText),
      buildText.split("\n").slice(0, 2).join(" / "));
    // Same trap for `location`: it decides the remote/local pill on every row,
    // and misreading it paints an offloading fleet as local-only.
    // innerText is the RENDERED text and the pill is text-transform:uppercase,
    // so match case-insensitively rather than against the source casing.
    const pillTexts = await page.locator(".drawer .build-row .pill").allInnerTexts();
    check("every build row is labelled remote or local",
      pillTexts.length > 0 && pillTexts.every((t) => /^(remote|local)$/i.test(t.trim())),
      pillTexts.slice(0, 4).join(", "));
    // `project`, `command` and `worker_id` are now INDICES into the snapshot's
    // string table, resolved by rehydrateStrings() at the transport boundary in
    // src/crypto.ts. When that resolution fails there is no error and no blank
    // cell — the raw index renders, so the project column fills with small
    // integers. That is invisible to every other check here, and to the type
    // checker, so assert the rendered text is not a bare number.
    const projTexts = (await page.locator(".drawer .build-row .build-proj").allInnerTexts())
      .map((t) => t.trim()).filter((t) => t !== "" && t !== "—");
    check("build project names resolve out of the string table",
      projTexts.length > 0 && projTexts.some((t) => !/^\d+$/.test(t)),
      projTexts.slice(0, 4).join(", "));
    // `command` is only ever the row tooltip, so an unresolved index would
    // never be visible on screen at all.
    const cmdTitle = await page.locator(".drawer .build-row .build-proj").first().getAttribute("title");
    check("build command tooltips resolve out of the string table",
      cmdTitle == null || !/^\d+$/.test(cmdTitle.trim()), String(cmdTitle).slice(0, 60));
    const workerLink = page.locator(".drawer .build-row .link").first();
    if ((await workerLink.count()) > 0) {
      const linkedId = (await workerLink.innerText()).trim();
      await workerLink.click();
      await page.waitForSelector(".drawer", { timeout: 15000 });
      const wTitle = (await page.locator(".drawer h3").innerText()).trim();
      check("dev drawer cross-links to worker drawer", wTitle === linkedId, `${wTitle} (want ${linkedId})`);
    }
  }
  await page.keyboard.press("Escape");
  await page.waitForTimeout(300);
}

// Remediation hints. Like recent builds, these now travel as positional tuples
// (the key names were 6.5KB of the payload) and are expanded by
// classifyDispatcher. A wrong index expands silently — every hint would render
// with a blank message and an "info" pill instead of its real severity — so
// assert on the TEXT, not just on the panel being present.
//
// A genuinely healthy fleet reports no hints at all, which is not a failure;
// hunt for a machine that has some and only then assert, exactly as the recent
// builds block above does.
{
  const pills = page.locator('[class*="pill dev-"]');
  const n = await pills.count();
  let hintText = null;
  let hintSeverity = null;
  let hintAction = [];
  for (let i = 0; i < n && hintText === null; i++) {
    await page.keyboard.press("Escape");
    await page.waitForTimeout(150);
    await pills.nth(i).click();
    await page.waitForSelector(".drawer", { timeout: 15000 });
    if ((await page.locator(".drawer .hint").count()) > 0) {
      hintText = (await page.locator(".drawer .hint .hint-msg").first().innerText()).trim();
      hintSeverity = (await page.locator(".drawer .hint .hint-top .pill").first().innerText()).trim();
      hintAction = (await page.locator(".drawer .hint .hint-action").allInnerTexts()).map((t) => t.trim());
    }
  }
  if (hintText === null) {
    check("no dev machine reported remediation hints (nothing to expand)", true, `checked ${n} dev machines`);
  } else {
    check("remediation hint messages survive the wire projection", hintText.length > 0, hintText.slice(0, 80));
    // Hint messages and suggested actions are the string table's biggest win —
    // 113 hints carry 30 distinct messages and 20 distinct actions, because
    // every dispatcher repeats the same advice about the same shared worker. An
    // index that fails to resolve renders as a small integer rather than as an
    // error or a blank, which the length check above would happily accept.
    check("hint messages resolve out of the string table", !/^\d+$/.test(hintText), hintText.slice(0, 80));
    check("hint suggested actions resolve out of the string table",
      hintAction.length === 0 || hintAction.some((t) => !/^→?\s*\d+$/.test(t)),
      hintAction.slice(0, 2).join(" | ").slice(0, 100));
    // "info" is the fallback the drawer prints when `severity` is missing, so a
    // panel full of "info" is what a dropped field looks like.
    check("remediation hint severities survive the wire projection",
      hintSeverity.length > 0 && hintSeverity !== "info", hintSeverity);
    const header = await page.locator(".drawer .kv-group h4", { hasText: /Remediation hints/ }).first().innerText();
    check("hint panel counts the expanded rows", /Remediation hints \(\d+\)/i.test(header), header);
  }
  await page.keyboard.press("Escape");
  await page.waitForTimeout(300);
}

// The dispatcher's OWN derated view of the pool. The collector no longer ships
// a full worker record per dispatcher (it was 54.6% of the payload and every
// field was already in the merged `workers[]`); it ships `[used, total]` pairs
// that classifyDispatcher expands back. If that expansion ever breaks, this
// panel reads "0 workers seen / 0 used / 0 total" on a live fleet and nothing
// else on the page changes — so assert a real reachable machine reports one.
{
  const pills = page.locator('[class*="pill dev-"]');
  const n = await pills.count();
  let poolText = null;
  for (let i = 0; i < n && poolText === null; i++) {
    await page.keyboard.press("Escape");
    await page.waitForTimeout(150);
    await pills.nth(i).click();
    await page.waitForSelector(".drawer", { timeout: 15000 });
    const group = page.locator(".drawer .kv-group").filter({
      has: page.locator("h4", { hasText: /view of the pool/i }),
    });
    const text = await group.innerText();
    // An unreachable dev machine legitimately sees nothing; keep looking.
    if (Number((text.match(/Workers seen\D*(\d+)/) ?? [])[1] ?? 0) > 0) poolText = text;
  }
  const flat = (poolText ?? "").replace(/\s+/g, " ").trim();
  check("a reachable dev machine reports its derated pool view", poolText !== null, flat);
  check("derated slot totals render", /Derated slots\D*\d+ used \/ \d+ total/.test(poolText ?? ""), flat);
  // Zero-slot workers are the local-only smoking gun; "none" is the healthy text.
  check("zero-slot workers are accounted for", /Zero-slot workers\s*(none|\d+ of \d+)/.test(flat), flat);
  await page.keyboard.press("Escape");
  await page.waitForTimeout(300);
}

// worker drawer: slots-per-dev-machine rows cross-link to dev drawers
const workersSection = page.locator(".section").filter({
  has: page.locator(".section-head h2", { hasText: /^Workers$/ }),
});
await workersSection.locator(".wcard").first().click();
await page.waitForSelector(".drawer", { timeout: 15000 });
const seenByText = await page.locator(".drawer").innerText();
check("worker drawer shows seen-by machines", /Seen by/.test(seenByText));
const kvLinks = page.locator(".drawer .kv-link");
if ((await kvLinks.count()) > 0) {
  const devId = (await kvLinks.first().locator(".kv-k").innerText()).trim();
  await kvLinks.first().click();
  await page.waitForSelector(".drawer", { timeout: 15000 });
  const dTitle = (await page.locator(".drawer h3").innerText()).trim();
check("worker drawer cross-links to dev drawer", dTitle === devId, `${dTitle} (want ${devId})`);
}
await page.keyboard.press("Escape");
await page.waitForTimeout(300);

// fleet map: bipartite graph with real dispatch edges; a node click opens a drawer
const mapNodeCount = await page.locator(".fm-node").count();
check("fleet map nodes render", mapNodeCount > 0, `${mapNodeCount} nodes`);
const mapEdgeCount = await page.locator(".fm-edge").count();
check("fleet map edges render", mapEdgeCount > 0, `${mapEdgeCount} edges`);
const mapWorker = page.locator(".fm-node.worker").first();
if ((await mapWorker.count()) > 0) {
  await mapWorker.click();
  await page.waitForSelector(".drawer", { timeout: 15000 });
  check("map node opens worker drawer", ((await page.locator(".drawer h3").innerText()) || "").length > 0);
  await page.keyboard.press("Escape");
  await page.waitForTimeout(300);
}

// cookie session survives reload
await page.reload({ waitUntil: "load" });
await page.waitForSelector(".kpis", { timeout: 30000 });
check("cookie session survives reload", true);

// lock clears it
await page.locator("button.icon-btn", { hasText: "Lock" }).click();
await page.waitForSelector(".gate-card", { timeout: 15000 });
check("Lock returns to gate", true);
await page.reload({ waitUntil: "load" });
await page.waitForSelector(".gate-card", { timeout: 20000 });
check("stays locked after Lock + reload", true);

// mobile viewport
await page.setViewportSize({ width: 390, height: 844 });
await page.waitForTimeout(300);
const overflow = await page.evaluate(() =>
  document.documentElement.scrollWidth > document.documentElement.clientWidth + 2);
check("no horizontal overflow at 390px", !overflow);

check("no page errors", errors.length === 0, errors.slice(0, 2).join(" | "));

await browser.close();
console.log(failures === 0 ? "\nALL CHECKS PASSED" : `\n${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
