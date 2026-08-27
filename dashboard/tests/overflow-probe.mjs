/* Find which elements overflow a 320px viewport. */
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
const URL = `http://127.0.0.1:${process.env.RCH_DASH_E2E_PORT ?? "4174"}${process.env.RCH_DASH_BASE ?? "/remote_compilation_helper/"}`;

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 320, height: 568 } });
await page.goto(URL, { waitUntil: "load" });
await page.fill("#pp", env.RCH_DASH_PASSPHRASE);
await page.click("button.btn");
await page.waitForSelector(".kpis", { timeout: 40000 });
const wide = await page.evaluate(() => {
  const vw = document.documentElement.clientWidth;
  const bad = [];
  for (const el of document.querySelectorAll("*")) {
    const r = el.getBoundingClientRect();
    if (r.right > vw + 1 && r.width > 8) {
      bad.push(`${el.tagName.toLowerCase()}.${String(el.className).slice(0, 40)} right=${Math.round(r.right)} w=${Math.round(r.width)}`);
    }
  }
  return { vw, scrollW: document.documentElement.scrollWidth, bad: bad.slice(0, 12) };
});
console.log(JSON.stringify(wide, null, 2));
await browser.close();
