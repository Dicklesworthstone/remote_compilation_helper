/* Visual audit driver for the rch dashboard. Reads .env itself; prints nothing secret. */
import { chromium } from "playwright";
import { readFileSync, mkdirSync } from "node:fs";

const root = "/Users/jemanuel/projects/remote_compilation_helper/dashboard";
const env = Object.fromEntries(
  readFileSync(`${root}/.env`, "utf8").split("\n").filter((l) => l.includes("="))
    .map((l) => [l.slice(0, l.indexOf("=")).trim(), l.slice(l.indexOf("=") + 1).trim().replace(/^['"]|['"]$/g, "")]),
);
const PASS = env.RCH_DASH_PASSPHRASE;
const BASE = process.env.RCH_DASH_BASE ?? "/remote_compilation_helper/";
const URL = `http://127.0.0.1:4174${BASE}`;
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

// drawer (worker)
await d.locator(".grid .wcard").first().click();
await d.waitForSelector(".drawer");
await d.waitForTimeout(300);
await d.screenshot({ path: "/tmp/dash-audit/03-worker-drawer.png" });
await d.keyboard.press("Escape");
await d.waitForTimeout(250);

// dev machine drawer
await d.locator(".section").first().locator(".wcard").first().click();
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
await m.locator(".section:not(:first-of-type)").filter({ hasText: "Workers" }).locator(".wcard").first().click();
const hasDrawer = await m.locator(".drawer").count();
if (!hasDrawer) await m.locator(".wcard").nth(2).click();
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
console.log("mobile filters box:", JSON.stringify(filters));
await m.close();
await browser.close();
console.log("errors:", errors.length ? errors.join(" | ") : "none");
