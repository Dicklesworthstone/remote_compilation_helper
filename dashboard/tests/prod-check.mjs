/* Production smoke check: unlock the DEPLOYED dashboard and prove the fleet
 * map renders from the live envelope — the full user path, in the real
 * browser, against the real URL.
 *
 *   PROD_URL=https://rch-fleet.vercel.app npm run test:prod
 *
 * Needs RCH_DASH_PASSPHRASE (reads .env like the sibling harnesses). */
import { chromium } from "playwright";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const env = Object.fromEntries(
  readFileSync(join(root, ".env"), "utf8")
    .split("\n").filter((l) => l.includes("="))
    .map((l) => [l.slice(0, l.indexOf("=")).trim(), l.slice(l.indexOf("=") + 1).trim().replace(/^['"]|['"]$/g, "")]),
);
const url = process.env.PROD_URL ?? "https://rch-fleet.vercel.app/";

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
const errs = [];
page.on("pageerror", (e) => errs.push(String(e)));
page.on("console", (m) => { if (m.type() === "error") errs.push(m.text()); });

let failures = 0;
const check = (name, ok, detail = "") => {
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${name}${ok ? "" : ` — ${detail}`}`);
  if (!ok) failures++;
};

await page.goto(url, { waitUntil: "load" });
await page.waitForSelector(".gate-card", { timeout: 30000 });
check("gate renders on production",
  (await page.locator(".gate-card").count()) === 1 && (await page.locator("#pp").count()) === 1 &&
  (await page.locator(".kpis").count()) === 0);

await page.fill("#pp", env.RCH_DASH_PASSPHRASE);
await page.click("button.btn");
await page.waitForSelector(".kpis", { timeout: 40000 });
const kpis = await page.locator(".kpi-value").allInnerTexts();
check("unlocks against the live envelope", kpis.length >= 5, kpis.slice(0, 3).join(" | "));

await page.waitForSelector('section[aria-label="Problems"]', { timeout: 15000 });
const problemRows = await page.locator("table.problems tbody tr").count();
const allClear = await page.locator('section[aria-label="Problems"] .empty.ok').count();
check("problems panel renders rows or an explicit all-clear", problemRows > 0 || allClear === 1,
  `${problemRows} rows, ${allClear} all-clear`);

// The agent endpoint on the same deployment, with the same passphrase: help
// needs no key, problems needs one and must agree with the page.
const api = new URL("/api/fleet", url);
const help = await fetch(`${api}?view=help&format=json`);
check("/api/fleet?view=help answers without a key", help.status === 200 &&
  Object.keys((await help.json()).params ?? {}).includes("target"), String(help.status));
const probs = await fetch(`${api}?view=problems&format=json`, { headers: { authorization: `Bearer ${env.RCH_DASH_PASSPHRASE}` } });
const probsBody = probs.status === 200 ? await probs.json() : null;
check("/api/fleet?view=problems decrypts with the fleet passphrase",
  probs.status === 200 && probsBody?.schema === "rch.fleet.llm.v2", String(probs.status));
if (probsBody) {
  check("the page and the endpoint show the same number of problems",
    probsBody.problems_total === problemRows, `page ${problemRows} vs api ${probsBody.problems_total}`);
}

await page.waitForSelector(".fm-node", { timeout: 15000 });
const nodes = await page.locator(".fm-node").count();
const edges = await page.locator(".fm-edge").count();
check("fleet map renders with edges", nodes > 0 && edges > 0, `${nodes} nodes, ${edges} edges`);

const overflow = await page.evaluate(
  () => document.documentElement.scrollWidth > document.documentElement.clientWidth + 2,
);
check("no horizontal overflow", !overflow);

check("no console or page errors", errs.length === 0, errs.slice(0, 2).join(" | "));

await browser.close();
if (failures > 0) {
  console.log(`\n${failures} CHECK(S) FAILED`);
  process.exit(1);
}
console.log("\nPRODUCTION SMOKE PASSED");
