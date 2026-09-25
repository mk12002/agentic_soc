// Browser tour: drives the real console in Chrome/Edge against a running server, loads the sample estate through
// the API, visits every screen (3 roles, light + dark), audits layout at 1440/1280/1024 px, saves screenshots.
//   npm install            (once, in this folder; uses the installed Chrome/Edge - no browser download)
//   SOC_BASE=http://127.0.0.1:8765 node tour.js
// Exit code 0 = no problems. Problems (JS errors, HTTP 5xx, clipped / off-screen / squeezed content) are listed.
// Needs a server started with a fresh database (see scripts/verify_features.py --browser, which does this).
const {chromium} = require('playwright-core');
const fs = require('fs');
const path = require('path');
const REPO = path.resolve(__dirname, '..', '..');
const BASE = process.env.SOC_BASE || 'http://127.0.0.1:8765';
const OUT = process.env.SOC_SHOTS || path.join(REPO, 'docs', 'screenshots');
const CORPUS = path.join(REPO, 'artifacts', 'phishing', 'corpus');
const BROWSER = process.env.SOC_BROWSER || ['C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', '/usr/bin/google-chrome', '/usr/bin/chromium',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'].find(p => fs.existsSync(p));
fs.mkdirSync(OUT, {recursive: true});
const problems = [];

async function token(user, roles) { return (await (await fetch(`${BASE}/api/v1/dev/token?user=${user}&roles=${roles}`)).json()).token; }
async function call(tok, method, p, body) {
  const r = await fetch(BASE + p, {method, headers: {Authorization: 'Bearer ' + tok, 'Content-Type': 'application/json'}, body: body ? JSON.stringify(body) : undefined});
  if (!r.ok) problems.push(`${method} ${p} -> ${r.status} ${(await r.text()).slice(0, 200)}`);
  return r.headers.get('content-type')?.includes('json') ? r.json() : null;
}
async function upload(tok, file) {
  const fd = new FormData();
  fd.append('file', new Blob([fs.readFileSync(path.join(CORPUS, file))], {type: 'message/rfc822'}), file);
  const r = await fetch(BASE + '/api/v1/phishing/submit', {method: 'POST', headers: {Authorization: 'Bearer ' + tok}, body: fd});
  if (!r.ok) problems.push(`upload ${file} -> ${r.status}`);
  return r.json();
}

async function settle(page) {
  await page.waitForFunction(() => !document.querySelector('#main .skeleton'), null, {timeout: 30000}).catch(() => problems.push('timeout ' + page.url()));
  await page.waitForTimeout(350);
}
const AUDIT = () => {
  const out = [], vw = document.documentElement.clientWidth;
  const desc = el => `${el.tagName.toLowerCase()}${el.className && typeof el.className === 'string' ? '.' + el.className.trim().split(/\s+/).join('.') : ''} "${(el.textContent || '').trim().slice(0, 40)}"`;
  const inScroller = el => { for (let p = el.parentElement; p; p = p.parentElement) { const o = getComputedStyle(p).overflowX; if (o === 'auto' || o === 'scroll') return true; } return false; };
  for (const el of document.querySelectorAll('body *')) {
    if (el.closest('svg') || el.closest('#toast')) continue;
    const cs = getComputedStyle(el);
    if (cs.display === 'none' || cs.visibility === 'hidden') continue;
    const r = el.getBoundingClientRect();
    if (!el.children.length && (el.textContent || '').trim() && cs.display !== 'inline' && r.height > 0 && r.width < 24 && el.scrollWidth > r.width + 4)
      out.push('squeezed ' + desc(el));  // text box collapsed by its neighbours
    if (!r.width || !r.height) continue;
    if ((cs.overflowX === 'hidden' || cs.overflowX === 'clip') && el.scrollWidth > el.clientWidth + 1 && !el.classList.contains('clamp') && el.tagName !== 'SELECT')
      out.push('clipped ' + desc(el));
    if (r.right > vw + 1 && !inScroller(el)) out.push('off-screen ' + desc(el));
    if (!el.children.length && cs.display !== 'inline' && cs.overflowX === 'visible' && el.clientWidth > 0 && el.scrollWidth > el.clientWidth + 1 && !inScroller(el))
      out.push('text-overflow ' + desc(el));
  }
  return [...new Set(out)].slice(0, 12);
};
async function audit(page, label) {
  const issues = await page.evaluate(AUDIT);
  issues.forEach(i => problems.push(`${label}: ${i}`));
}
async function shot(page, name, full = true) {
  await audit(page, name);
  await page.screenshot({path: `${OUT}/${name}.png`, fullPage: full});
  console.log('saved', name);
}
async function visit(page, hash, name, full = true) {
  await page.goto(`${BASE}/#/${hash}`);
  await settle(page);
  const t = await page.evaluate(() => { const x = document.getElementById('toast'); return x && !x.hidden && x.classList.contains('err') ? x.textContent : ''; });
  if (t) problems.push(`${hash}: ${t}`);
  const ov = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  if (ov > 2) problems.push(`${hash}: horizontal overflow ${ov}px`);
  await shot(page, name, full);
}

(async () => {
  // ---------- sample data through the real API, as the scheduler would load it
  const lead = await token('lena@cci-demo.com', 'lead');
  console.log('loading samples...');
  await call(lead, 'POST', '/api/v1/vm/refresh');
  await call(lead, 'POST', '/api/v1/incidents/run');
  await call(lead, 'POST', '/api/v1/phishing/ingest');
  for (const f of ['supplier_bank_change.eml', 'supplier_lookalike_payment.eml', 'bec_ceo_fraud.eml', 'quishing_qr.eml', 'legit_vendor_invoice.eml', 'marketing_spam.eml'])
    await upload(lead, f);
  await call(lead, 'POST', '/api/v1/vm/campaigns', {cve: 'CVE-2021-44228', notify_via: 'ticket'});
  await call(lead, 'POST', '/api/v1/vm/misconfigurations/route');
  await call(lead, 'POST', '/api/v1/intelligence/refresh');
  const ops = await token('otto@cci-demo.com', 'automation_admin');
  for (const j of ['intelligence', 'follow_up', 'retention']) await call(ops, 'POST', `/api/v1/jobs/${j}/run`);
  const cases = await call(lead, 'GET', '/api/v1/cases');
  const phishCase = cases.find(c => c.domain === 'phishing' && c.title.includes('password expires')) || cases.find(c => c.domain === 'phishing');
  const incCase = cases.find(c => c.domain === 'incident' && c.severity === 'critical') || cases.find(c => c.domain === 'incident');
  const jane = await call(lead, 'GET', '/api/v1/entities/find?kind=identity&key=upn&value=jane.doe@cci-demo.com');

  const browser = await chromium.launch({executablePath: BROWSER, headless: true, ignoreDefaultArgs: ['--hide-scrollbars']});
  const ctx = await browser.newContext({viewport: {width: 1440, height: 900}, deviceScaleFactor: 1, bypassCSP: true}); // harness only: CSP blocks Playwright's eval-based waits
  const page = await ctx.newPage();
  page.on('pageerror', e => problems.push('pageerror: ' + e.message));
  page.on('console', m => { if (m.type() === 'error') problems.push('console: ' + m.text()); });
  page.on('response', r => { if (r.status() >= 500) problems.push(`HTTP ${r.status()} ${r.url()}`); });

  // ---------- sign-in (light), then real UI sign-in as lead
  await page.goto(BASE + '/');
  await page.waitForSelector('#si-user');
  if (process.env.SOC_TOUR_MODE === 'deep') {
    // separate pass against a local STUB model (the model name on screen says so): shows the guardrails at work
    await page.fill('#si-user', 'lena@cci-demo.com'); await page.selectOption('#si-role', 'lead');
    await page.click('[data-fn="signIn"]'); await page.waitForSelector('.sidebar');
    await page.goto(`${BASE}/#/story/${phishCase.id}`); await settle(page);
    await page.click('[data-fn="runDeep"]');
    await page.waitForFunction(() => document.querySelector('#deep .prose'), null, {timeout: 30000});
    await settle(page);
    await page.evaluate(() => { const t = document.querySelector('#toast'); if (t) t.remove(); });
    await page.locator('#deep').locator('xpath=ancestor::section[1]').screenshot({path: `${OUT}/28-deep-analysis-stub-llm.png`});
    console.log('saved 28-deep-analysis-stub-llm');
    await audit(page, 'deep analysis');
    await browser.close();
    console.log('PROBLEMS:', problems.length ? problems.join(' | ') : 'none');
    process.exit(problems.length ? 1 : 0);
  }
  await shot(page, '00-sign-in', false);
  await page.fill('#si-user', 'lena@cci-demo.com');
  await page.selectOption('#si-role', 'lead');
  await page.click('[data-fn="signIn"]');
  await page.waitForSelector('.sidebar');
  await settle(page);

  await visit(page, 'overview', '01-overview');
  await page.goto(`${BASE}/#/intelligence`); await settle(page);
  await page.fill('#iq', 'Is jane.doe@cci-demo.com compromised and what should we do first?');
  await page.click('[data-fn="askIntel"]');
  await page.waitForFunction(() => !document.querySelector('#ia .spin') && document.querySelector('#ia').textContent.length > 40, null, {timeout: 20000});
  await shot(page, '02-intelligence');
  await visit(page, 'cases', '03-cases', false);
  await visit(page, `cases/${phishCase.id}`, '04-case-phishing');
  await page.hover('abbr.cite').catch(() => {});
  await visit(page, `cases/${incCase.id}`, '05-case-incident');
  await visit(page, `entity/${jane.id}`, '06-entity-360');
  await visit(page, 'approvals', '07-approvals');
  await visit(page, `story/${phishCase.id}`, '24-attack-story');
  await visit(page, 'phishing', '08-phishing', false);
  await visit(page, 'suppliers', '09-supplier-risk');
  await page.goto(`${BASE}/#/vulnerabilities`); await settle(page);
  await page.fill('#vq', 'which internet facing hosts have KEV vulnerabilities?');
  await page.click('[data-fn="vmAsk"]'); await page.waitForTimeout(1200);
  await shot(page, '10-vulnerabilities');
  await visit(page, 'cloud', '11-cloud-posture', false);
  await visit(page, 'coverage', '12-attack-coverage');
  await visit(page, 'shadow-it', '13-shadow-it');
  await visit(page, 'integrations', '14-integrations');
  await visit(page, 'policy', '15-automation-policy');
  await visit(page, 'reports', '16-reports', false);
  await page.fill('#rq', 'A one-page board brief on phishing and supplier risk this quarter, as slides');
  await page.click('[data-fn="reportPlan"]');
  await page.waitForSelector('#rplan .plan-box', {timeout: 20000});
  await shot(page, '25-report-plan', false);
  await page.click('[data-fn="buildPlanned"]');
  await page.waitForSelector('#rout .rep-sec', {timeout: 60000});
  await settle(page);
  await audit(page, 'report generated');
  await page.evaluate(() => { const t = document.querySelector('#toast'); if (t) t.remove(); });
  await page.evaluate(() => window.scrollTo(0, document.querySelector('#rout').getBoundingClientRect().top + window.scrollY - 70));
  await page.waitForTimeout(300);
  await shot(page, '26-report-generated', false);
  await visit(page, 'audit', '17-audit', false);

  // ---------- dark mode via the real toggle
  await page.goto(`${BASE}/#/overview`); await settle(page);
  await page.click('#theme-btn'); await page.waitForTimeout(300);
  await shot(page, '20-dark-overview');
  await visit(page, `cases/${phishCase.id}`, '21-dark-case');
  await visit(page, 'coverage', '22-dark-coverage');
  await visit(page, `entity/${jane.id}`, '23-dark-entity-360');
  await visit(page, `story/${phishCase.id}`, '27-dark-attack-story');
  await page.click('#theme-btn');

  // ---------- admin: access management, with a service-account key created in the UI
  await page.click('.user'); await page.click('[data-fn="signOut"]'); await page.waitForSelector('#si-user');
  await page.fill('#si-user', 'ada@cci-demo.com'); await page.selectOption('#si-role', 'admin');
  await page.click('[data-fn="signIn"]'); await page.waitForSelector('.sidebar');
  await page.goto(`${BASE}/#/access`); await settle(page);
  await page.fill('#kn', 'prometheus'); await page.click('[data-fn="newKey"]'); await page.waitForTimeout(1200);
  await shot(page, '18-access');
  // auditor: compliance pack
  await page.click('.user'); await page.click('[data-fn="signOut"]'); await page.waitForSelector('#si-user');
  await page.fill('#si-user', 'audrey@cci-demo.com'); await page.selectOption('#si-role', 'auditor');
  await page.click('[data-fn="signIn"]'); await page.waitForSelector('.sidebar');
  await page.goto(`${BASE}/#/reports`); await settle(page);
  await page.click('[data-fn="compliancePack"]'); await page.waitForTimeout(3000);
  await shot(page, '19-compliance-pack', false);

  // ---------- layout audit at narrower widths, every screen, both themes
  await page.click('.user'); await page.click('[data-fn="signOut"]'); await page.waitForSelector('#si-user');
  await page.fill('#si-user', 'lena@cci-demo.com'); await page.selectOption('#si-role', 'lead');
  await page.click('[data-fn="signIn"]'); await page.waitForSelector('.sidebar');
  const routes = ['overview', 'intelligence', 'cases', `cases/${phishCase.id}`, `cases/${incCase.id}`, `entity/${jane.id}`, 'approvals',
    `story/${phishCase.id}`, 'phishing', 'suppliers', 'vulnerabilities', 'cloud', 'coverage', 'shadow-it', 'integrations', 'policy', 'reports', 'access', 'audit'];
  for (const [w, theme] of [[1280, 'light'], [1024, 'light'], [1024, 'dark']]) {
    await page.setViewportSize({width: w, height: 900});
    await page.evaluate(t => { document.documentElement.setAttribute('data-theme', t); }, theme);
    for (const r of routes) { await page.goto(`${BASE}/#/${r}`); await settle(page); await audit(page, `${w}px ${theme} ${r}`);
      const ov = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
      if (ov > 2) problems.push(`${w}px ${r}: page overflow ${ov}px`); }
    console.log('audited', w, theme, routes.length, 'screens');
  }
  await browser.close();
  console.log('\nPROBLEMS:', problems.length ? '\n - ' + problems.join('\n - ') : 'none');
  fs.writeFileSync(path.join(OUT, 'tour-result.json'), JSON.stringify({problems,
    screenshots: fs.readdirSync(OUT).filter(f => f.endsWith('.png')).length, audited_widths: [1440, 1280, 1024]}, null, 1));
  process.exit(problems.length ? 1 : 0);
})().catch(e => { console.error('CRASH', e); console.log('PROBLEMS so far:', problems); process.exit(2); });
