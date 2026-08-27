/* Render-cost probe (measurement only): unlock, then
 * a) typing in search: CDP Performance metric deltas (RecalcStyleCount, LayoutCount) + long tasks
 * b) one 30s tick: long-task observer window
 * c) scripted full-page scroll: metric deltas (for content-visibility A/B)
 */
import { chromium } from "playwright";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const env = Object.fromEntries(
  readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", ".env"), "utf8")
    .split("\n").filter((l) => l.includes("="))
    .map((l) => [l.slice(0, l.indexOf("=")).trim(), l.slice(l.indexOf("=") + 1).trim().replace(/^['"]|['"]$/g, "")]),
);
const PORT = process.env.RCH_DASH_E2E_PORT ?? "4174";
const URL = `http://127.0.0.1:${PORT}${process.env.RCH_DASH_BASE ?? "/remote_compilation_helper/"}`;

// VIEWPORT env: "390x844" for the mobile pass, default desktop.
const browser = await chromium.launch();
const [vw, vh] = (process.env.VIEWPORT ?? "1440x900").split("x").map(Number);
// CPU_THROTTLE=4 simulates a mid-range phone (Emulation.setCPUThrottlingRate).
const throttle = Number(process.env.CPU_THROTTLE ?? 0);
const page = await browser.newPage({ viewport: { width: vw, height: vh } });
const cdp = await page.context().newCDPSession(page);
await cdp.send("Performance.enable");
if (throttle > 0) await cdp.send("Emulation.setCPUThrottlingRate", { rate: throttle });
const metrics = async () => (await cdp.send("Performance.getMetrics")).metrics
  .filter((m) => ["RecalcStyleCount", "LayoutCount", "ScriptDuration", "TaskDuration"].includes(m.name))
  .reduce((a, m) => ((a[m.name] = m.value), a), {});
await page.addInitScript(() => {
  window.__lt = [];
  new PerformanceObserver((l) => window.__lt.push(...l.getEntries().map((e) => e.duration)))
    .observe({ entryTypes: ["longtask"] });
});

await page.goto(URL, { waitUntil: "load" });
await page.fill("#pp", env.RCH_DASH_PASSPHRASE);
await page.click("button.btn");
await page.waitForSelector(".kpis");
const loadM = await metrics();
const out = {
  load: {
    layouts: loadM.LayoutCount,
    recalcStyles: loadM.RecalcStyleCount,
    scriptSec: +loadM.ScriptDuration.toFixed(3),
    domNodes: await page.evaluate(() => document.getElementsByTagName("*").length),
    longTasks: await page.evaluate(() => window.__lt.splice(0)),
  },
};

// a) typing
await page.click(".search");
for (const ch of "vmill112") { await page.type(".search", ch, { delay: 120 }); }
await page.waitForTimeout(300);
// Second burst in the same session: isolates first-input paint overhead from
// per-keystroke render cost. If the long task only appears in burst one, it
// is first-input style/paint, not React.
const firstBurst = { longTasks: await page.evaluate(() => window.__lt.splice(0)) };
let m1b0 = await metrics();
await page.fill(".search", "");
for (const ch of "omarchy") { await page.type(".search", ch, { delay: 120 }); }
await page.waitForTimeout(300);
let m1b = await metrics();
out.typing = {
  firstBurst,
  secondBurst: {
    recalcStyles: m1b.RecalcStyleCount - m1b0.RecalcStyleCount,
    layouts: m1b.LayoutCount - m1b0.LayoutCount,
    scriptSec: +(m1b.ScriptDuration - m1b0.ScriptDuration).toFixed(3),
    longTasks: await page.evaluate(() => window.__lt.splice(0)),
  },
};

// b) 30s clock tick (App sets `now` every 30s)
await page.waitForTimeout(31_500);
out.tick = { longTasks: await page.evaluate(() => window.__lt.splice(0)) };

// c) full-page scroll
const ms0 = await metrics();
await page.evaluate(async () => {
  const step = window.innerHeight / 2;
  for (let y = 0; y < document.body.scrollHeight; y += step) {
    window.scrollTo(0, y);
    await new Promise((r) => setTimeout(r, 60));
  }
});
await page.waitForTimeout(400);
const ms1 = await metrics();
out.scroll = {
  recalcStyles: ms1.RecalcStyleCount - ms0.RecalcStyleCount,
  layouts: ms1.LayoutCount - ms0.LayoutCount,
  scriptSec: +(ms1.ScriptDuration - ms0.ScriptDuration).toFixed(3),
  longTasks: await page.evaluate(() => window.__lt.splice(0)),
};
console.log(JSON.stringify(out, null, 2));
await browser.close();
