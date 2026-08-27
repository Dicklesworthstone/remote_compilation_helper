/* Hover-focus verification for the fleet map: hovering a node must light
 * exactly its own edges (lit + dimmed === total), and leaving the map must
 * relight everything. Reads .env itself; prints nothing secret. */
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
const PORT = process.env.RCH_DASH_E2E_PORT ?? "4174";
const URL = `http://127.0.0.1:${PORT}${process.env.RCH_DASH_BASE ?? "/remote_compilation_helper/"}`;

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
await page.goto(URL, { waitUntil: "load" });
await page.fill("#pp", env.RCH_DASH_PASSPHRASE);
await page.click("button.btn");
await page.waitForSelector(".kpis", { timeout: 40000 });
await page.waitForSelector(".fm-node");

let failures = 0;
const check = (name, ok, detail = "") => {
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${name}${ok ? "" : ` — ${detail}`}`);
  if (!ok) failures++;
};

const total = await page.locator(".fm-edge").count();

const node = page.locator(".fm-node.worker").first();
await node.hover();
await page.waitForTimeout(250);
const lit = await page.locator(".fm-edge:not(.dim)").count();
const dimmed = await page.locator(".fm-edge.dim").count();
const id = (await node.locator(".fm-name").innerText()).trim();
check(`hover ${id}: lit + dimmed === total`, lit + dimmed === total, `${lit} + ${dimmed} vs ${total}`);
check(`hover ${id}: some edges lit`, lit > 0, `${lit}`);

const dev = page.locator(".fm-node.dev").first();
await dev.hover();
await page.waitForTimeout(250);
const lit2 = await page.locator(".fm-edge:not(.dim)").count();
const dimmed2 = await page.locator(".fm-edge.dim").count();
const devId = (await dev.locator(".fm-name").innerText()).trim();
check(`hover ${devId}: lit + dimmed === total`, lit2 + dimmed2 === total, `${lit2} + ${dimmed2} vs ${total}`);

await page.mouse.move(10, 10);
await page.waitForTimeout(250);
check("leaving the map relights every edge", (await page.locator(".fm-edge.dim").count()) === 0);

await browser.close();
if (failures > 0) {
  console.log(`\n${failures} CHECK(S) FAILED`);
  process.exit(1);
}
console.log("\nALL HOVER CHECKS PASSED");
