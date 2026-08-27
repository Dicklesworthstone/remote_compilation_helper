/* Visual audit driver for the rch dashboard. Reads .env itself; prints nothing secret. */
import { chromium } from "playwright";
import { readFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const env = Object.fromEntries(
  readFileSync(`${root}/.env`, "utf8").split("\n").filter((l) => l.includes("="))
    .map((l) => [l.slice(0, l.indexOf("=")).trim(), l.slice(l.indexOf("=") + 1).trim().replace(/^['"]|['"]$/g, "")]),
);
const PASS = env.RCH_DASH_PASSPHRASE;
const PORT = process.env.RCH_DASH_E2E_PORT ?? "4174";
const BASE = process.env.RCH_DASH_BASE ?? "/remote_compilation_helper/";
const URL = `http://127.0.0.1:${PORT}${BASE}`;
mkdirSync("/tmp/dash-audit", { recursive: true });

const browser = await chromium.launch();
const errors = [];
async function newPage(w, h) {
  const page = await browser.newPage({ viewport: { width: w, height: h }, deviceScaleFactor: 2 });
  page.on("pageerror", (e) => errors.push(String(e)));
  page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
  return page;
}

// ---------- desktop ----------
const d = await newPage(1440, 900);
await d.goto(URL, { waitUntil: "load" });
await d.waitForSelector(".gate-card");
await d.screenshot({ path: "/tmp/dash-audit/01-gate.png" });
await d.fill("#pp", PASS);
await d.click("button.btn");
await d.waitForSelector(".kpis", { timeout: 40000 });
await d.waitForTimeout(500);
await d.screenshot({ path: "/tmp/dash-audit/02-desktop-full.png", fullPage: true });

// worker drawer: "Workers" must anchor to the section HEADING — the dev-machine
// cards also contain the substring "workers" ("13/14 workers · up 2h").
const workersSection = d.locator(".section").filter({
  has: d.locator(".section-head h2", { hasText: /^Workers$/ }),
});
await workersSection.locator(".wcard").first().click();
await d.waitForSelector(".drawer");
await d.waitForTimeout(300);
await d.screenshot({ path: "/tmp/dash-audit/03-worker-drawer.png" });

// regression: a click on the drawer's own padding must NOT close it
await d.locator(".drawer").click({ position: { x: 8, y: 320 } });
await d.waitForTimeout(200);
if ((await d.locator(".drawer").count()) === 0) {
  throw new Error("drawer closed on padding click (backdrop-click guard regressed)");
}

// dev machine drawer
await d.keyboard.press("Escape");
await d.waitForTimeout(250);
await d.locator(".section", { hasText: "Dev machines" }).locator(".wcard").first().click();
await d.waitForSelector(".drawer");
await d.waitForTimeout(300);
await d.screenshot({ path: "/tmp/dash-audit/04-dev-drawer.png" });
await d.keyboard.press("Escape");
await d.waitForTimeout(250);

// light theme
await d.locator("button.icon-btn", { hasText: /Light|Dark/ }).first().click();
await d.waitForTimeout(300);
await d.screenshot({ path: "/tmp/dash-audit/05-desktop-light.png" });
await d.locator("button.icon-btn", { hasText: /Light|Dark/ }).first().click();
await d.waitForTimeout(200);
await d.close();

// ---------- narrow desktop / tablet ----------
const t = await newPage(820, 1180); // iPad-ish portrait
await t.goto(URL, { waitUntil: "load" });
await t.waitForSelector(".gate-card");
await t.fill("#pp", PASS);
await t.click("button.btn");
await t.waitForSelector(".kpis");
await t.waitForTimeout(400);
await t.screenshot({ path: "/tmp/dash-audit/06-tablet-full.png", fullPage: true });
await t.close();

// ---------- mobile ----------
const m = await newPage(390, 844);
await m.goto(URL, { waitUntil: "load" });
await m.waitForSelector(".gate-card");
await m.screenshot({ path: "/tmp/dash-audit/07-mobile-gate.png" });
await m.fill("#pp", PASS);
await m.click("button.btn");
await m.waitForSelector(".kpis", { timeout: 40000 });
await m.waitForTimeout(400);
await m.screenshot({ path: "/tmp/dash-audit/08-mobile-top.png" });
await m.screenshot({ path: "/tmp/dash-audit/09-mobile-full.png", fullPage: true });
const overflow = await m.evaluate(() =>
  document.documentElement.scrollWidth - document.documentElement.clientWidth);
console.log(`mobile horizontal overflow px: ${overflow}`);

// mobile worker drawer
const mobileWorkers = m.locator(".section").filter({
  has: m.locator(".section-head h2", { hasText: /^Workers$/ }),
});
await mobileWorkers.locator(".wcard").first().click();
await m.waitForSelector(".drawer");
await m.waitForTimeout(300);
await m.screenshot({ path: "/tmp/dash-audit/10-mobile-drawer.png" });
const drawerW = await m.evaluate(() => document.querySelector(".drawer").getBoundingClientRect().width);
console.log(`mobile drawer width px: ${drawerW}`);
// filter row wrapping check
const filters = await m.evaluate(() => {
  const el = document.querySelector(".filters");
  if (!el) return null;
  const box = el.getBoundingClientRect();
  return { w: Math.round(box.width), h: Math.round(box.height) };
});
await m.close();

// ---------- 320px narrow mobile ----------
const s320 = await newPage(320, 568);
await s320.goto(URL, { waitUntil: "load" });
await s320.waitForSelector(".gate-card");
await s320.fill("#pp", PASS);
await s320.click("button.btn");
await s320.waitForSelector(".kpis", { timeout: 40000 });
await s320.waitForTimeout(400);
const overflow320 = await s320.evaluate(() =>
  document.documentElement.scrollWidth - document.documentElement.clientWidth);
console.log(`320px narrow mobile horizontal overflow px: ${overflow320}`);
if (overflow320 > 0) {
  errors.push(`horizontal overflow on 320px viewport: ${overflow320}px`);
}
await s320.close();

await browser.close();
console.log("errors:", errors.length ? errors.join(" | ") : "none");
