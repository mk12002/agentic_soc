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
// SOC_TOUR_ESTATE=<estate.json from scripts/build_estate_variant.py> runs the tour on another sample estate
const EST = process.env.SOC_TOUR_ESTATE ? JSON.parse(fs.readFileSync(process.env.SOC_TOUR_ESTATE, 'utf8')) : {
  org: 'acme-demo.com', lead: 'lena@acme-demo.com', focus_upn: 'jane.doe@acme-demo.com', campaign_cve: 'CVE-2021-44228',
  phish_subject_token: 'password expires', corpus_dir: path.join(REPO, 'artifacts', 'phishing', 'corpus'),
  uploads: ['supplier_bank_change.eml', 'supplier_lookalike_payment.eml', 'bec_ceo_fraud.eml', 'quishing_qr.eml',
            'legit_vendor_invoice.eml', 'marketing_spam.eml']};
const CORPUS = EST.corpus_dir;
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
  await page.waitForFunction(() => !document.querySelector('#main .skeleton'), null, {timeout: 90000}).catch(() => problems.push('timeout ' + page.url()));
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
  if (vw >= 1260)   // at desktop widths no table should need sideways scrolling (narrower screens may scroll)
    for (const t of document.querySelectorAll('.table-wrap'))
      if (t.scrollWidth > t.clientWidth + 1) out.push(`table needs sideways scroll (${t.scrollWidth - t.clientWidth}px) ` + desc(t.querySelector('th') || t));
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
  const lead = await token(EST.lead, 'lead');
  console.log('loading samples...');
  await call(lead, 'POST', '/api/v1/vm/refresh');
  await call(lead, 'POST', '/api/v1/incidents/run');
  await call(lead, 'POST', '/api/v1/phishing/ingest');
  for (const f of EST.uploads)
    await upload(lead, f);
  await call(lead, 'POST', '/api/v1/vm/campaigns', {cve: EST.campaign_cve, notify_via: 'ticket'});
  await call(lead, 'POST', '/api/v1/vm/misconfigurations/route');
  await call(lead, 'POST', '/api/v1/intelligence/refresh');
  const ops = await token(`otto@${EST.org}`, 'automation_admin');
  for (const j of ['intelligence', 'follow_up', 'retention']) await call(ops, 'POST', `/api/v1/jobs/${j}/run`);
  const cases = await call(lead, 'GET', '/api/v1/cases');
  const phishCase = cases.find(c => c.domain === 'phishing' && c.title.includes(EST.phish_subject_token)) || cases.find(c => c.domain === 'phishing');
  const incCase = cases.find(c => c.domain === 'incident' && c.severity === 'critical') || cases.find(c => c.domain === 'incident');
  const jane = await call(lead, 'GET', `/api/v1/entities/find?kind=identity&key=upn&value=${encodeURIComponent(EST.focus_upn)}`);

  const browser = await chromium.launch({executablePath: BROWSER, headless: true, ignoreDefaultArgs: ['--hide-scrollbars']});
  const ctx = await browser.newContext({viewport: {width: 1440, height: 900}, deviceScaleFactor: 1, bypassCSP: true}); // harness only: CSP blocks Playwright's eval-based waits
  const page = await ctx.newPage();
  page.on('pageerror', e => problems.push('pageerror: ' + e.message));
  page.on('console', m => { if (m.type() === 'error') problems.push('console: ' + m.text()); });
  page.on('response', r => { if (r.status() >= 500) problems.push(`HTTP ${r.status()} ${r.url()}`); });

  // ---------- sign-in (light), then real UI sign-in as lead
  await page.goto(BASE + '/');
  await page.waitForSelector('#si-user');
  await shot(page, '00-sign-in', false);
  await page.fill('#si-user', EST.lead);
  await page.selectOption('#si-role', 'lead');
  await page.click('[data-fn="signIn"]');
  await page.waitForSelector('.sidebar');
  await settle(page);

  await visit(page, 'overview', '01-overview');
  await page.goto(`${BASE}/#/intelligence`); await settle(page);
  await page.fill('#iq', `Is ${EST.focus_upn} compromised and what should we do first?`);
  await page.click('[data-fn="askIntel"]');
  await page.waitForFunction(() => !document.querySelector('#ia .spin') && document.querySelector('#ia').textContent.length > 40, null, {timeout: 120000});
  await shot(page, '02-intelligence');
  await visit(page, 'cases', '03-cases', false);
  await visit(page, `cases/${phishCase.id}`, '04-case-phishing');
  await page.hover('abbr.cite').catch(() => {});
  await visit(page, `cases/${incCase.id}`, '05-case-incident');
  await visit(page, `entity/${jane.id}`, '06-entity-360');
  await visit(page, 'approvals', '07-approvals');
  await visit(page, `story/${phishCase.id}`, '24-attack-story');
  const llmOn = (await call(lead, 'GET', '/api/v1/llm/status')).configured;
  if (llmOn) {                                  // real model: the evidence-bound review, photographed as it renders
    await page.click('[data-fn="runDeep"]');
    await page.waitForFunction(() => document.querySelector('#deep .prose') || document.querySelector('#deep .callout'), null, {timeout: 180000});
    await settle(page);
    if (!(await page.$('#deep .prose'))) problems.push('deep analysis did not complete');
    await page.evaluate(() => { const t = document.querySelector('#toast'); if (t) t.remove(); });
    await page.setViewportSize({width: 1440, height: 4000});        // whole card on screen: no scrolling under the sticky bar
    await page.waitForTimeout(300);
    await page.locator('#deep').locator('xpath=ancestor::section[1]').screenshot({path: `${OUT}/28-deep-analysis.png`});
    await page.setViewportSize({width: 1440, height: 900});
    console.log('saved 28-deep-analysis');
    await audit(page, 'deep analysis');
  }
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
  await page.waitForSelector('#rplan .plan-box', {timeout: 90000});
  await shot(page, '25-report-plan', false);
  await page.click('[data-fn="buildPlanned"]');
  await page.waitForSelector('#rout .rep-sec', {timeout: 180000});
  await settle(page);
  await audit(page, 'report generated');
  await page.evaluate(() => { const t = document.querySelector('#toast'); if (t) t.remove(); });
  await page.evaluate(() => window.scrollTo(0, document.querySelector('#rout').getBoundingClientRect().top + window.scrollY - 70));
  await page.waitForTimeout(300);
  await shot(page, '26-report-generated', false);
  await visit(page, 'audit', '17-audit', false);

  // ---------- what the screens show must equal what the API computes (every KPI, badge and tab count)
  const kpis = async (hash) => { await page.goto(`${BASE}/#/${hash}`); await settle(page);
    return page.$$eval('.kpi', els => Object.fromEntries(els.map(e => [e.querySelector('.label').textContent.trim(), e.querySelector('.value').textContent.trim()]))); };
  const same = (where, label, shown, expected) => { if (String(shown) !== String(expected)) problems.push(`screen/API mismatch - ${where} "${label}": screen ${shown}, API ${expected}`); };
  const ov = await call(lead, 'GET', '/api/v1/dashboard/overview');
  let k = await kpis('overview');
  same('overview', 'Open cases', k['Open cases'], ov.cases.open);
  same('overview', 'Awaiting approval', k['Awaiting approval'], ov.actions.pending_approval);
  same('overview', 'Open insights', k['Open insights'], ov.insights.open);
  same('overview', 'Open vulnerabilities', k['Open vulnerabilities'], ov.vulnerability.open_findings);
  const asum = await call(lead, 'GET', '/api/v1/actions/summary?status=recommended,pending_approval');
  same('sidebar', 'Approvals badge', (await page.textContent('#nav-approvals')).trim(), asum.total);
  await page.goto(`${BASE}/#/approvals`); await settle(page);
  const tabs = await page.$$eval('.seg button', bs => Object.fromEntries(bs.map(b => [b.childNodes[0].textContent.trim().toLowerCase(), b.querySelector('.muted') ? b.querySelector('.muted').textContent.trim() : ''])));
  same('approvals', 'All tab', tabs.all, asum.total);
  for (const [d, n] of Object.entries(asum.by_domain)) same('approvals', `${d} tab`, tabs[d], n);
  same('approvals', 'rows listed', await page.$$eval('table tbody tr', r => r.length), Math.min(asum.total, 500));
  const csum = await call(lead, 'GET', '/api/v1/cases/summary');
  await page.goto(`${BASE}/#/cases`); await settle(page);
  const ctabs = await page.$$eval('.seg button', bs => Object.fromEntries(bs.map(b => [b.childNodes[0].textContent.trim().toLowerCase(), b.querySelector('.muted') ? b.querySelector('.muted').textContent.trim() : ''])));
  same('cases', 'All tab', ctabs.all, csum.total);
  for (const d of ['phishing', 'incident', 'vulnerability']) same('cases', `${d} tab`, ctabs[d], csum.by_domain[d] || 0);
  const pm = await call(lead, 'GET', '/api/v1/phishing/metrics'); k = await kpis('phishing');
  same('phishing', 'Reported', k['Reported'], pm.reported); same('phishing', 'Auto-closed', k['Auto-closed'], pm.auto_closed);
  same('phishing', 'Campaigns', k['Campaigns'], pm.campaigns); same('phishing', 'Repeat clickers', k['Repeat clickers'], pm.repeat_clickers.length);
  const vm = await call(lead, 'GET', '/api/v1/vm/metrics'); k = await kpis('vulnerabilities');
  same('vulnerabilities', 'Open findings', k['Open findings'], vm.open); same('vulnerabilities', 'CISA KEV', k['CISA KEV'], vm.kev_open);
  same('vulnerabilities', 'Internet-exposed', k['Internet-exposed'], vm.internet_exposed_open); same('vulnerabilities', 'Past SLA', k['Past SLA'], vm.sla_breached);
  const mis = (await call(lead, 'GET', '/api/v1/vm/misconfigurations')).metrics; k = await kpis('cloud');
  same('cloud', 'Open', k['Open'], mis.open); same('cloud', 'Past SLA', k['Past SLA'], mis.overdue); same('cloud', 'False closures', k['False closures'], mis.false_closures);
  const sh = (await call(lead, 'GET', '/api/v1/dashboard/shadow-it')).summary; k = await kpis('shadow-it');
  same('shadow IT', 'Unsanctioned services', k['Unsanctioned services'], sh.unsanctioned_services);
  same('shadow IT', 'Users involved', k['Users involved'], sh.users_on_unsanctioned_services);
  same('shadow IT', 'Risky sites reached', k['Risky sites reached'], sh.risky_destinations_reached);
  const cv = (await call(lead, 'GET', '/api/v1/dashboard/attack-coverage')).summary; k = await kpis('coverage');
  same('coverage', 'Weighted coverage', k['Weighted coverage'], cv.weighted_coverage_pct + '%'); same('coverage', 'Firing', k['Firing'], cv.firing);
  same('coverage', 'Priority blind spots', k['Priority blind spots'], cv.priority_blind_spots);
  const story = await call(lead, 'GET', `/api/v1/cases/${phishCase.id}/story`); k = await kpis(`story/${phishCase.id}`);
  same('attack story', 'Steps', k['Steps'], story.steps.length); same('attack story', 'Hosts', k['Hosts'], story.blast_radius.stats.hosts);
  same('attack story', 'Users reached', k['Users reached'], `${story.blast_radius.stats.users_interacted} / ${story.blast_radius.stats.users_received}`);
  const risk = await call(lead, 'GET', `/api/v1/intelligence/entities/${jane.id}/risk`);
  await page.goto(`${BASE}/#/entity/${jane.id}`); await settle(page);
  same('entity 360', 'risk score', (await page.$eval('.kpi .value', e => e.childNodes[0].textContent.trim())), risk.score);
  console.log('screen/API cross-check done');

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
  await page.fill('#si-user', `ada@${EST.org}`); await page.selectOption('#si-role', 'admin');
  await page.click('[data-fn="signIn"]'); await page.waitForSelector('.sidebar');
  await page.goto(`${BASE}/#/access`); await settle(page);
  await page.fill('#kn', 'prometheus'); await page.click('[data-fn="newKey"]'); await page.waitForTimeout(1200);
  if (!(await page.$('#kout code'))) problems.push('service-account key was not shown');
  await page.evaluate(() => { const c = document.querySelector('#kout code'); if (c) c.textContent = c.textContent.slice(0, 7) + '•'.repeat(24) + '  (masked for the screenshot)'; });
  await shot(page, '18-access');
  // auditor: compliance pack
  await page.click('.user'); await page.click('[data-fn="signOut"]'); await page.waitForSelector('#si-user');
  await page.fill('#si-user', `audrey@${EST.org}`); await page.selectOption('#si-role', 'auditor');
  await page.click('[data-fn="signIn"]'); await page.waitForSelector('.sidebar');
  await page.goto(`${BASE}/#/reports`); await settle(page);
  await page.click('[data-fn="compliancePack"]');
  await page.waitForSelector('#comp .callout', {timeout: 60000});
  await page.evaluate(() => { document.querySelector('#comp').closest('section').scrollIntoView({block: 'center'}); });
  await page.waitForTimeout(400);
  await shot(page, '19-compliance-pack', false);

  // ---------- layout audit at narrower widths, every screen, both themes
  await page.click('.user'); await page.click('[data-fn="signOut"]'); await page.waitForSelector('#si-user');
  await page.fill('#si-user', EST.lead); await page.selectOption('#si-role', 'lead');
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
    screenshots: fs.readdirSync(OUT).filter(f => f.endsWith('.png')).length, audited_widths: [1440, 1280, 1024], llm: llmOn}, null, 1));
  process.exit(problems.length ? 1 : 0);
})().catch(e => { console.error('CRASH', e); console.log('PROBLEMS so far:', problems); process.exit(2); });
