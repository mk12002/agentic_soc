// Agentic SOC console - core: auth, API client, router, shell, shared components.
// No inline handlers anywhere: clicks are delegated through data-fn / data-go so the page runs under a strict CSP.
'use strict';

const $ = s => document.querySelector(s);
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
const safeUrl = u => /^https?:\/\//i.test(String(u || '')) ? String(u) : '#';
const arg = (...a) => esc(JSON.stringify(a));
const nf = n => (n == null || n === '') ? '–' : Number(n).toLocaleString();
const pct = (x, d = 0) => x == null ? '–' : (x * 100).toFixed(d) + '%';
const cap = s => { const t = String(s || '').replace(/_/g, ' ').trim(); return t.charAt(0).toUpperCase() + t.slice(1); };
const dt = s => s ? String(s).slice(0, 16).replace('T', ' ') : '–';
const day = s => s ? String(s).slice(0, 10) : '–';

let TOKEN = '';
try { TOKEN = localStorage.getItem('soc_token') || ''; } catch (e) { /* storage blocked */ }
window.ME = null;

// ---------------------------------------------------------------- feedback
function toast(msg, err = false) {
  let t = document.getElementById('toast');
  if (!t) { t = document.createElement('div'); t.id = 'toast'; document.body.appendChild(t); }
  t.className = 'toast' + (err ? ' err' : '');
  t.textContent = String(msg);
  t.hidden = false;
  clearTimeout(window._tt);
  window._tt = setTimeout(() => { t.hidden = true; }, err ? 8000 : 5000);
}

// ---------------------------------------------------------------- API
async function api(path, opts = {}) {
  const headers = {'Content-Type': 'application/json', ...(opts.headers || {})};
  if (TOKEN) headers.Authorization = 'Bearer ' + TOKEN;
  const r = await fetch(path, {...opts, headers});
  if (r.status === 401 && TOKEN) { signOut(true); throw new Error('session expired'); }
  if (!r.ok) {
    const t = await r.text(); let d = t;
    try { d = JSON.parse(t).detail || t; } catch (e) { /* not JSON */ }
    toast((typeof d === 'string' ? d : JSON.stringify(d)).slice(0, 300), true);
    throw new Error(t);
  }
  return (r.headers.get('content-type') || '').includes('json') ? r.json() : r;
}
const post = (p, body) => api(p, {method: 'POST', body: body === undefined ? undefined : JSON.stringify(body)});
const can = p => ((window.ME && window.ME.permissions) || []).includes(p);
const inDomain = d => { const ds = (window.ME && window.ME.domains) || []; return ds.includes('*') || (d !== '*' && ds.includes(d)); };

async function dl(path) {
  const r = await api(path);
  const b = await r.blob();
  const a = document.createElement('a');
  a.href = URL.createObjectURL(b);
  a.download = ((r.headers.get('content-disposition') || '').split('filename=')[1] || 'download').replace(/"/g, '');
  document.body.appendChild(a); a.click(); a.remove();
  toast('Downloaded ' + a.download);
}

// ---------------------------------------------------------------- icons (hand-drawn 24px line set)
const I = {
  overview: '<path d="M3 13h8V3H3zM13 21h8V11h-8zM13 3v6h8V3zM3 21h8v-6H3z"/>',
  intel: '<path d="M12 3a6 6 0 0 0-6 6c0 2.2 1.2 3.6 2.4 4.8.8.8 1.1 1.6 1.1 2.7V18h5v-1.5c0-1.1.3-1.9 1.1-2.7C16.8 12.6 18 11.2 18 9a6 6 0 0 0-6-6zM10 21h4"/>',
  cases: '<path d="M4 7h16v12H4zM9 7V5h6v2M4 12h16"/>',
  approvals: '<path d="M9 12l2 2 4-4M12 3l7 3v5c0 5-3.5 8.5-7 10-3.5-1.5-7-5-7-10V6z"/>',
  phishing: '<path d="M4 6h16v12H4zM4 7l8 6 8-6"/>',
  vuln: '<path d="M12 3l8 4v5c0 4.5-3.2 8-8 9-4.8-1-8-4.5-8-9V7zM12 8v5M12 16h.01"/>',
  cloud: '<path d="M7 18h10a4 4 0 0 0 .6-7.95A6 6 0 0 0 6.1 9.5 4.3 4.3 0 0 0 7 18z"/>',
  coverage: '<path d="M4 4h4v4H4zM10 4h4v4h-4zM16 4h4v4h-4zM4 10h4v4H4zM10 10h4v4h-4zM4 16h4v4H4z"/>',
  shadow: '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12zM12 9a3 3 0 1 1 0 6 3 3 0 0 1 0-6z"/>',
  supplier: '<path d="M3 21V9l6 3V9l6 3V6l6 3v12zM7 17h2M12 17h2M17 17h2"/>',
  plug: '<path d="M9 2v5M15 2v5M7 7h10v4a5 5 0 0 1-10 0zM12 16v6"/>',
  policy: '<path d="M4 6h10M18 6h2M4 12h4M12 12h8M4 18h12M20 18h0M14 4v4M8 10v4M16 16v4"/>',
  access: '<path d="M8 11V7a4 4 0 0 1 8 0v4M5 11h14v10H5zM12 15v2"/>',
  audit: '<path d="M6 3h9l4 4v14H6zM14 3v5h5M9 13h7M9 17h7"/>',
  reports: '<path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/>',
  sun: '<path d="M12 4V2M12 22v-2M4 12H2M22 12h-2M5.6 5.6 4.2 4.2M19.8 19.8l-1.4-1.4M5.6 18.4l-1.4 1.4M19.8 4.2l-1.4 1.4M12 7a5 5 0 1 1 0 10 5 5 0 0 1 0-10z"/>',
  moon: '<path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z"/>',
  refresh: '<path d="M20 11a8 8 0 0 0-14.9-3M4 5v4h4M4 13a8 8 0 0 0 14.9 3M20 19v-4h-4"/>',
  download: '<path d="M12 4v11M7 10l5 5 5-5M5 20h14"/>',
  play: '<path d="M7 5l12 7-12 7z"/>',
  back: '<path d="M15 6l-6 6 6 6"/>',
};
const icon = (n, cls = '') => `<svg viewBox="0 0 24 24" class="${cls}" aria-hidden="true">${I[n] || ''}</svg>`;

// ---------------------------------------------------------------- shared components
const chip = (s, extra = '') => `<span class="chip ${esc(String(s || '').toLowerCase())} ${extra}">${esc(cap(s))}</span>`;
const kpi = (label, value, foot = '', alert = false) =>
  `<div class="card kpi${alert ? ' alert' : ''}"><div class="label">${esc(label)}</div><div class="value">${esc(value)}</div>${foot ? `<div class="foot">${foot}</div>` : ''}</div>`;
function card(title, body, o = {}) {
  return `<section class="card ${o.cls || ''}"${o.id ? ` id="${esc(o.id)}"` : ''}>${title ? `<div class="card-h"><h2>${title}</h2>${o.sub ? `<span class="sub">${o.sub}</span>` : ''}${o.right ? `<div class="right">${o.right}</div>` : ''}</div>` : ''}
    <div class="card-b${o.flush ? ' flush' : ''}">${body}</div></section>`;
}
function table(cols, rows, o = {}) {
  if (!rows.length) return `<div class="empty">${esc(o.empty || 'Nothing to show yet.')}</div>`;
  return `<div class="table-wrap"><table><thead><tr>${cols.map(c => `<th class="${c.num ? 'num' : ''}">${esc(c.h || c)}</th>`).join('')}</tr></thead>
    <tbody>${rows.join('')}</tbody></table></div>`;
}
const btn = (label, fn, args = [], cls = '', ic = '') =>
  `<button class="btn ${cls}" data-fn="${esc(fn)}" data-args="${arg(...args)}">${ic ? icon(ic) : ''}${esc(label)}</button>`;
const go = (href, label, cls = '') => `<a href="${esc(href)}" class="${cls}">${esc(label)}</a>`;
const empty = t => `<div class="empty">${esc(t)}</div>`;
const skeleton = () => `<div class="card"><div class="card-b">${'<div class="skeleton"></div>'.repeat(6)}</div></div>`;
const cite = x => {
  const ev = x.evidence || [];
  if (ev.length) return ev.map(e => `<abbr class="cite" title="${esc((e.source || '') + ': ' + (e.summary || ''))}">${esc(e.ref)}</abbr>`).join('');
  return (x.evidence_ids || []).map(r => `<abbr class="cite">${esc(r)}</abbr>`).join('');
};
function page(title, sub, actions, body) {
  return `<div class="page-head"><div><h1>${esc(title)}</h1>${sub ? `<p>${sub}</p>` : ''}</div>${actions ? `<div class="actions">${actions}</div>` : ''}</div>${body}`;
}

// charts (inline SVG coloured from theme tokens)
function stackedBars(series, keys, h = 170) {
  const n = series.length || 1, w = 720, pad = 22, bw = (w - pad) / n - 6;
  const max = Math.max(1, ...series.map(d => keys.reduce((a, k) => a + (d[k] || 0), 0)));
  let g = '';
  for (let i = 0; i <= 2; i++) { const y = 8 + (h - 30) * i / 2; g += `<line x1="${pad}" x2="${w}" y1="${y}" y2="${y}" style="stroke:var(--border)"/>`; }
  g += `<text x="0" y="12">${max}</text><text x="0" y="${h - 22}">0</text>`;
  series.forEach((d, i) => {
    let y = h - 22; const x = pad + i * (bw + 6);
    keys.forEach(k => {
      const v = d[k] || 0, bh = v / max * (h - 30);
      if (v) g += `<rect x="${x}" y="${y - bh}" width="${bw}" height="${bh}" rx="2" style="fill:var(--c-${k})"><title>${esc(d.date)} · ${esc(k)}: ${v}</title></rect>`;
      y -= bh;
    });
    if (i % 2 === 0 || n < 10) g += `<text x="${x}" y="${h - 6}">${esc(String(d.date).slice(5))}</text>`;
  });
  return `<svg class="chart" viewBox="0 0 ${w} ${h}" width="100%" preserveAspectRatio="none" role="img" aria-label="daily volume">${g}</svg>
    <div class="legend">${keys.map(k => `<span><i style="background:var(--c-${k})"></i>${esc(cap(k))}</span>`).join('')}</div>`;
}
function donut(counts, colors = {}) {
  const e = Object.entries(counts || {}).filter(([, v]) => v > 0), total = e.reduce((a, [, v]) => a + v, 0);
  if (!total) return empty('No data in this window');
  const r = 46, c = 60, C = 2 * Math.PI * r; let off = 0, arcs = '';
  e.forEach(([k, v]) => {
    const len = v / total * C;
    arcs += `<circle cx="${c}" cy="${c}" r="${r}" fill="none" stroke-width="14" stroke-dasharray="${len} ${C - len}" stroke-dashoffset="${-off}"
      style="stroke:${colors[k] || `var(--c-${k}, var(--c-other))`}" transform="rotate(-90 ${c} ${c})"><title>${esc(cap(k))}: ${v}</title></circle>`;
    off += len;
  });
  return `<div class="inline" style="gap:20px"><svg class="chart" width="120" height="120" viewBox="0 0 120 120">
      <circle cx="${c}" cy="${c}" r="${r}" fill="none" stroke-width="14" style="stroke:var(--surface-3)"/>${arcs}
      <text x="${c}" y="${c + 5}" text-anchor="middle" style="fill:var(--text);font-size:18px;font-weight:650">${total}</text></svg>
    <div class="stack" style="gap:6px">${e.map(([k, v]) => `<div class="small"><i style="display:inline-block;width:8px;height:8px;border-radius:2px;margin-right:8px;background:${colors[k] || `var(--c-${k}, var(--c-other))`}"></i>${esc(cap(k))} <b>${v}</b></div>`).join('')}</div></div>`;
}
const meter = (v, max = 100) => `<div class="bar"><span style="width:${Math.max(2, Math.min(100, v / max * 100))}%;background:${v >= 75 ? 'var(--c-critical)' : v >= 50 ? 'var(--c-high)' : v >= 25 ? 'var(--c-medium)' : 'var(--c-low)'}"></span></div>`;

// ---------------------------------------------------------------- navigation model
const NAV = [
  ['Operate', [['overview', 'Overview', 'overview'], ['intelligence', 'Intelligence', 'intel', '*'], ['cases', 'Cases', 'cases'],
    ['approvals', 'Approvals', 'approvals']]],
  ['Domains', [['phishing', 'Phishing', 'phishing', 'phishing'], ['vulnerabilities', 'Vulnerabilities', 'vuln', 'vulnerability'],
    ['cloud', 'Cloud posture', 'cloud', 'vulnerability']]],
  ['Insight', [['coverage', 'ATT&CK coverage', 'coverage'], ['shadow-it', 'Shadow IT', 'shadow', 'incident'],
    ['suppliers', 'Supplier risk', 'supplier', 'phishing']]],
  ['Govern', [['integrations', 'Integrations', 'plug'], ['policy', 'Automation policy', 'policy'], ['reports', 'Reports', 'reports'],
    ['access', 'Access', 'access'], ['audit', 'Audit log', 'audit']]],
];
const TITLES = {...Object.fromEntries(NAV.flatMap(([, items]) => items.map(([id, label]) => [id, label]))), story: 'Attack story', entity: 'Entity'};

function route() {
  const parts = (location.hash.replace(/^#\/?/, '') || 'overview').split('/').map(decodeURIComponent);
  return {name: parts[0], params: parts.slice(1)};
}

function shell() {
  const me = window.ME;
  const initials = (me.name || '?').split(/[@.\s]/).filter(Boolean).slice(0, 2).map(x => x[0].toUpperCase()).join('');
  $('#app').innerHTML = `<div class="shell">
    <aside class="sidebar">
      <div class="brand"><div class="brand-mark">AS</div><div><div class="brand-name">Agentic SOC</div><div class="brand-sub">Security operations</div></div></div>
      ${NAV.map(([g, items]) => `<div class="nav-group">${g}</div>` + items.filter(([, , , d]) => !d || inDomain(d)).map(([id, label, ic]) =>
        `<a class="nav-item" href="#/${id}" data-nav="${id}">${icon(ic)}<span>${esc(label)}</span>${id === 'approvals' ? '<span class="count" id="nav-approvals" hidden></span>' : ''}</a>`).join('')).join('')}
      <div class="sidebar-foot">Signed in as ${esc(me.auth_method === 'api_key' ? 'service account' : me.roles.join(', ') || 'no role')}<br>${esc(me.domains.includes('*') ? 'All domains' : me.domains.join(', '))}<br>All times UTC</div>
    </aside>
    <div class="main">
      <header class="topbar">
        <div class="crumbs" id="crumbs"></div><div class="spacer"></div>
        <span class="status-pill" id="kill-status" title="Automated action status"><span class="dot"></span>Automation active</span>
        <button class="icon-btn" data-fn="toggleTheme" data-args="[]" title="Toggle light / dark" aria-label="Toggle theme" id="theme-btn"></button>
        <div class="user" data-fn="toggleMenu" data-args="[]"><div class="avatar">${esc(initials)}</div><div class="who">${esc(me.name)}<small>${esc(me.roles.join(', '))}${me.mfa ? ' · MFA' : ''}</small></div>
          <div class="menu" id="user-menu" hidden>
            <div class="row-i">Permissions: ${esc(me.permissions.length)}</div>
            <div class="row-i">Data scope: ${esc(me.domains.includes('*') ? 'all domains' : me.domains.join(', '))}</div>
            <div class="row-i act" data-fn="goTo" data-args="${arg('#/access')}">Access &amp; roles</div>
            <div class="row-i act" data-fn="signOut" data-args="[]">Sign out</div>
          </div></div>
      </header>
      <main class="content" id="main"></main>
    </div></div>`;
  paintThemeButton();
  refreshStatus();
}

async function refreshStatus() {
  try {
    const h = await (await fetch('/health')).json();
    const el = $('#kill-status');
    if (el) { el.className = 'status-pill' + (h.kill_switch ? ' halt' : ''); el.innerHTML = `<span class="dot"></span>${h.kill_switch ? 'Automation halted' : 'Automation active'}`; }
    if (can('approve_action') || can('request_action')) {
      const sm = await api('/api/v1/actions/summary?status=recommended,pending_approval');
      const b = $('#nav-approvals'); if (b) { b.hidden = !sm.total; b.textContent = sm.total; }
    }
  } catch (e) { /* status is best-effort */ }
}

async function render() {
  if (!window.ME) return;
  const {name, params} = route();
  document.querySelectorAll('[data-nav]').forEach(a => a.classList.toggle('on', a.dataset.nav === name));
  const title = TITLES[name] || cap(name);
  const parent = {story: 'cases', entity: 'cases'}[name] || name;
  $('#crumbs').innerHTML = params.length ? `<a href="#/${esc(parent)}">${esc(TITLES[parent] || title)}</a> <span class="muted">/</span> <b>${esc(name === 'story' ? 'Attack story' : name === 'entity' ? 'Entity 360' : 'Detail')}</b>` : `<b>${esc(title)}</b>`;
  document.title = title + ' · Agentic SOC';
  const view = (window.VIEWS || {})[name];
  const main = $('#main');
  GEN += 1;
  main.innerHTML = skeleton();
  if (!view) { main.innerHTML = empty('Page not found'); return; }
  try { await view(...params); } catch (e) { if (!main.innerHTML || main.querySelector('.skeleton')) main.innerHTML = empty('This page could not be loaded. ' + (e.message || '').slice(0, 160)); }
  window.scrollTo(0, 0);
}
// Navigation generation: a slow page that finishes after the user moved on must not paint over the new page.
let GEN = 0;
const setMainG = (g, html) => { if (g === GEN && $('#main')) $('#main').innerHTML = html; };
const setMain = html => setMainG(GEN, html);

// ---------------------------------------------------------------- auth
async function boot() {
  if (!TOKEN) return signInScreen();
  try { window.ME = await api('/api/v1/me'); } catch (e) { return signInScreen(); }
  shell();
  await render();
}
function signInScreen() {
  window.ME = null;
  $('#app').innerHTML = `<div class="auth"><section class="card auth-card"><div class="card-b">
    <div class="brand" style="padding:0"><div class="brand-mark">AS</div><div><div class="brand-name">Agentic SOC</div><div class="brand-sub">Security operations platform</div></div></div>
    <h1>Sign in</h1>
    <div class="field"><label for="si-user">Work email</label><input class="input" id="si-user" value="lena@acme-demo.com" autocomplete="username"></div>
    <div class="field"><label for="si-role">Role</label><select id="si-role">${['lead', 'analyst', 'auditor', 'automation_admin', 'admin'].map(r => `<option value="${r}">${cap(r)}</option>`).join('')}</select></div>
    <button class="btn primary" data-fn="signIn" data-args="[]" style="justify-content:center;height:36px">Continue</button>
    <div class="foot">Development sign-in. In production the console uses Microsoft Entra ID single sign-on with MFA; this form is only available when <code>SOC_AUTH_MODE=dev</code>.</div>
    <button class="btn ghost sm" data-fn="toggleTheme" data-args="[]" id="theme-btn" style="align-self:flex-start"></button>
  </div></section></div>`;
  paintThemeButton();
}
async function signIn() {
  const u = $('#si-user').value.trim(), role = $('#si-role').value;
  const r = await fetch(`/api/v1/dev/token?user=${encodeURIComponent(u)}&roles=${encodeURIComponent(role)}`);
  if (!r.ok) { toast('Development sign-in is disabled on this server. Use Entra ID SSO.', true); return; }
  TOKEN = (await r.json()).token;
  try { localStorage.setItem('soc_token', TOKEN); } catch (e) { /* ignore */ }
  if (!location.hash) location.hash = '#/overview';
  boot();
}
async function signOut(expired = false) {
  if (!expired && TOKEN) { try { await fetch('/api/v1/auth/logout', {method: 'POST', headers: {Authorization: 'Bearer ' + TOKEN}}); } catch (e) { /* ignore */ } }
  TOKEN = '';
  try { localStorage.removeItem('soc_token'); } catch (e) { /* ignore */ }
  signInScreen();
  if (expired) toast('Your session has expired. Please sign in again.');
}

// ---------------------------------------------------------------- theme & menus
function toggleTheme() {
  const next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  try { localStorage.setItem('soc_theme', next); } catch (e) { /* ignore */ }
  paintThemeButton();
}
function paintThemeButton() {
  const b = $('#theme-btn'); if (!b) return;
  const dark = document.documentElement.getAttribute('data-theme') === 'dark';
  b.innerHTML = b.classList.contains('icon-btn') ? icon(dark ? 'sun' : 'moon') : (dark ? 'Switch to light' : 'Switch to dark');
}
function toggleMenu() { const m = $('#user-menu'); if (m) m.hidden = !m.hidden; }
function goTo(h) { location.hash = h; }

// ---------------------------------------------------------------- delegation
const ALLOWED = {toggleTheme, toggleMenu, goTo, signIn, signOut, dl, refreshPage: () => render()};
document.addEventListener('click', ev => {
  const menu = $('#user-menu');
  if (menu && !menu.hidden && !ev.target.closest('.user')) menu.hidden = true;
  const el = ev.target.closest('[data-fn]');
  if (!el) return;
  ev.preventDefault();
  const fn = ALLOWED[el.dataset.fn];
  if (!fn) return;
  let args = [];
  try { args = JSON.parse(el.dataset.args || '[]'); } catch (e) { return; }
  if (el.tagName === 'BUTTON') { el.disabled = true; setTimeout(() => { el.disabled = false; }, 400); }
  Promise.resolve().then(() => fn(...args)).catch(() => { /* reported via toast */ });
});
document.addEventListener('keydown', ev => {
  if (ev.key === 'Enter' && ev.target.matches('input[data-enter]')) {
    const fn = ALLOWED[ev.target.dataset.enter]; if (fn) fn();
  }
});
window.addEventListener('hashchange', render);
window.addEventListener('DOMContentLoaded', boot);
