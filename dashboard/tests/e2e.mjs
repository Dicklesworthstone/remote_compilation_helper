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

const BASE = process.env.RCH_DASH_BASE ?? "/remote_compilation_helper/";
const PORT = process.env.RCH_DASH_E2E_PORT ?? "4174";
const URL = `http://127.0.0.1:${PORT}${BASE}`;
const PASS = process.env.RCH_DASH_PASSPHRASE;
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

// recent builds: relative ages + cross-link to the worker drawer when the id
// is a fleet worker
const buildRows = await page.locator(".drawer .build-row").count();
check("recent builds listed", buildRows > 0, `${buildRows} rows`);
if (buildRows > 0) {
  const buildText = await page.locator(".drawer .builds").innerText();
  check("recent builds show relative age", /ago/.test(buildText), buildText.split("\n")[0]);
  const workerLink = page.locator(".drawer .build-row .link").first();
  if ((await workerLink.count()) > 0) {
    const linkedId = (await workerLink.innerText()).trim();
    await workerLink.click();
    await page.waitForSelector(".drawer", { timeout: 15000 });
    const wTitle = (await page.locator(".drawer h3").innerText()).trim();
    check("dev drawer cross-links to worker drawer", wTitle === linkedId, `${wTitle} (want ${linkedId})`);
    await page.keyboard.press("Escape");
    await page.waitForTimeout(300);
  } else {
    await page.keyboard.press("Escape");
    await page.waitForTimeout(300);
  }
} else {
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
