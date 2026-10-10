// Render SVG diagrams to PNG (for the Word edition of the client review pack).
// Usage: node scripts/ui_tour/render_svg.js <out-dir> <file.svg> [<file.svg> ...]
// Uses the installed Chrome / Edge through playwright-core, like the browser tour.
'use strict';
const fs = require('fs');
const path = require('path');
const {chromium} = require('playwright-core');

const BROWSER = process.env.SOC_BROWSER || ['C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', '/usr/bin/google-chrome', '/usr/bin/chromium',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'].find(p => fs.existsSync(p));

(async () => {
  const [out, ...files] = process.argv.slice(2);
  if (!out || !files.length) { console.error('usage: render_svg.js <out-dir> <file.svg>...'); process.exit(2); }
  if (!BROWSER) { console.error('no Chrome / Edge found (set SOC_BROWSER)'); process.exit(2); }
  fs.mkdirSync(out, {recursive: true});
  const browser = await chromium.launch({executablePath: BROWSER, headless: true});
  const page = await browser.newPage({deviceScaleFactor: 2});
  for (const f of files) {
    const svg = fs.readFileSync(f, 'utf8');
    const vb = /viewBox="0 0 (\d+) (\d+)"/.exec(svg);
    const [w, h] = vb ? [Number(vb[1]), Number(vb[2])] : [1200, 800];
    await page.setViewportSize({width: w, height: h});
    await page.setContent(`<html><body style="margin:0;background:#fff">${svg}</body></html>`);
    const target = path.join(out, path.basename(f).replace(/\.svg$/, '.png'));
    await page.locator('svg').screenshot({path: target});
    console.log(target);
  }
  await browser.close();
})().catch(e => { console.error(e); process.exit(1); });
