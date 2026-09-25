// Dashboards: SOC overview, ATT&CK coverage, shadow IT, supplier risk, cloud misconfigurations,
// entity 360, connector freshness and access management. Pure DOM + inline SVG (no external libraries,
// strict CSP). Every number links to, or is shown next to, the records it was computed from.
const can = p => ((window.ME && window.ME.permissions) || []).includes(p);
const nf = n => (n ?? 0).toLocaleString();
const kpi = (label, value, sub) => `<div class="card"><div class="muted">${esc(label)}</div><div class="kpi">${esc(value)}</div>${sub ? `<div class="muted">${sub}</div>` : ''}</div>`;
const COLORS = {phishing: '#4ea1ff', incident: '#ff9f43', vulnerability: '#b388ff', critical: '#ff5c5c', high: '#ff9f43', medium: '#f7d154', low: '#6dd17c'};

function stackedBars(series, keys, h = 140) {
  const w = Math.max(320, series.length * 28), max = Math.max(1, ...series.map(d => keys.reduce((a, k) => a + (d[k] || 0), 0)));
  const bw = w / series.length - 6;
  let bars = '';
  series.forEach((d, i) => {
    let y = h - 18;
    keys.forEach(k => {
      const v = d[k] || 0, bh = (v / max) * (h - 30);
      if (v) bars += `<rect x="${i * (bw + 6)}" y="${y - bh}" width="${bw}" height="${bh}" fill="${COLORS[k] || '#888'}"><title>${esc(d.date)} ${esc(k)}: ${v}</title></rect>`;
      y -= bh;
    });
    if (i % 2 === 0) bars += `<text x="${i * (bw + 6)}" y="${h - 4}" fill="#8a97a6" font-size="10">${esc(String(d.date).slice(5))}</text>`;
  });
  const legend = keys.map(k => `<span class="pill" style="background:${COLORS[k]};color:#000">${esc(k)}</span>`).join(' ');
  return `<div style="overflow-x:auto"><svg width="${w}" height="${h}" role="img" aria-label="cases per day">${bars}</svg></div>${legend}`;
}

function donut(counts, size = 120) {
  const entries = Object.entries(counts || {}).filter(([, v]) => v > 0), total = entries.reduce((a, [, v]) => a + v, 0);
  if (!total) return '<span class="muted">none</span>';
  let a0 = 0, paths = '';
  const r = size / 2 - 8, c = size / 2;
  entries.forEach(([k, v]) => {
    const a1 = a0 + (v / total) * Math.PI * 2, large = a1 - a0 > Math.PI ? 1 : 0;
    const p = entries.length === 1 ? `M ${c} ${c - r} A ${r} ${r} 0 1 1 ${c - 0.01} ${c - r}` :
      `M ${c + r * Math.sin(a0)} ${c - r * Math.cos(a0)} A ${r} ${r} 0 ${large} 1 ${c + r * Math.sin(a1)} ${c - r * Math.cos(a1)}`;
    paths += `<path d="${p}" stroke="${COLORS[k] || '#6a7a8c'}" stroke-width="14" fill="none"><title>${esc(k)}: ${v}</title></path>`;
    a0 = a1;
  });
  return `<svg width="${size}" height="${size}">${paths}<text x="${c}" y="${c + 6}" text-anchor="middle" fill="#dbe2ea" font-size="18">${total}</text></svg>
    <div>${entries.map(([k, v]) => `<span class="pill" style="background:${COLORS[k] || '#6a7a8c'};color:#000">${esc(k)} ${v}</span>`).join(' ')}</div>`;
}

async function Overview() {
  const [o, conns, dr] = await Promise.all([api('/api/v1/dashboard/overview?days=14'), api('/api/v1/dashboard/connectors'), api('/api/v1/metrics/drift')]);
  const c = o.cases, a = o.actions, vm = o.vulnerability || {}, ctx = o.context;
  const unhealthy = conns.filter(x => x.enabled && x.state !== 'healthy');
  $('#main').innerHTML = `<div class="row">
    ${kpi('Open cases', nf(c.open), Object.entries(c.open_by_domain).map(([k, v]) => `${esc(k)} ${v}`).join(' · '))}
    ${kpi('Awaiting approval', nf(a.pending_approval), `${nf(c.awaiting_approval)} cases`)}
    ${kpi('Automation rate', a.automation_rate_pct + '%', `${nf(a.autonomous)} of ${nf(a.in_window)} actions ran under policy`)}
    ${kpi('Median time to close', c.median_hours_to_close == null ? 'n/a' : c.median_hours_to_close + ' h', 'closed cases')}
    ${kpi('Open insights', nf(o.insights.open), Object.entries(o.insights.by_severity).map(([k, v]) => `${esc(k)} ${v}`).join(' · '))}
    ${vm.open_findings != null ? kpi('Open vulnerabilities', nf(vm.open_findings), `${nf(vm.sla_breached)} past SLA · ${nf(vm.internet_exposed)} internet-exposed`) : ''}
  </div>
  <div class="row"><div class="card" style="flex:2"><h2>New cases per day (last ${o.window_days} days)</h2>${stackedBars(o.trend, ['phishing', 'incident', 'vulnerability'])}</div>
    <div class="card"><h2>Open cases by severity</h2>${donut(c.open_by_severity)}</div>
    <div class="card"><h2>Verdicts (window)</h2>${donut(c.verdicts)}</div></div>
  <div class="row"><div class="card" style="flex:2"><h2>Top insights</h2>${o.insights.top.map(i => `<div class="fact">${sev(i.severity)} ${esc(i.title)} <span class="muted">${esc(i.rule)}</span></div>`).join('') || '<span class="muted">none open</span>'}</div>
    <div class="card"><h2>Data quality</h2>
      <div>Asset match rate <b>${esc(Math.round((ctx.asset_match_rate.match_rate || 0) * 1000) / 10)}%</b></div>
      <div>Identity match rate <b>${esc(Math.round((ctx.identity_match_rate.match_rate || 0) * 1000) / 10)}%</b></div>
      <div>Records awaiting resolution <b>${nf(ctx.unresolved_queue)}</b></div>
      <div class="muted">${Object.entries(ctx.entities).map(([k, v]) => `${esc(k)} ${nf(v)}`).join(' · ')}</div></div>
    <div class="card"><h2>Integrations</h2>${unhealthy.length ? unhealthy.map(x => `<div><span class="pill ${x.state === 'healthy' ? 'low' : x.state === 'stale' ? 'medium' : 'high'}">${esc(x.state)}</span> ${esc(x.tool)}</div>`).join('') : '<span class="pill low">all enabled connectors healthy</span>'}
      <p><button class="b g" data-fn="show" data-args="[&quot;Connectors&quot;]">Details</button></p></div>
    <div class="card"><h2>Enrichment latency</h2>${Object.entries(o.performance.investigation_enrichment_ms).map(([d, x]) => `<div>${esc(d)}: median <b>${x.median} ms</b>, p95 ${x.p95} ms <span class="muted">(${x.n})</span></div>`).join('') || '<span class="muted">no investigations yet</span>'}
      <details><summary class="muted">per tool</summary>${Object.entries(o.performance.lookup_ms_by_tool).map(([t, x]) => `<div class="muted">${esc(t)}: ${x.median} / ${x.p95} ms</div>`).join('')}</details></div>
    <div class="card"><h2>Verdict quality (drift)</h2>${Object.entries(dr.domains).map(([d, x]) => `<div><b>${esc(d)}</b> <span class="pill ${x.status === 'stable' ? 'low' : x.status === 'drift' ? 'critical' : 'informational'}">${esc(x.status.replace('_', ' '))}</span>
      <span class="muted">agreement ${x.agreement.recent == null ? 'n/a' : Math.round(x.agreement.recent * 100) + '%'} · PSI ${x.psi_verdicts ?? 'n/a'}</span>${x.reasons.map(r => '<div class="muted">' + esc(r) + '</div>').join('')}</div>`).join('')}
      <p class="muted">Recent ${dr.window.recent_days} d vs previous ${dr.window.baseline_days} d, against analyst dispositions.</p></div></div>`;
}

async function Coverage() {
  const c = await api('/api/v1/dashboard/attack-coverage');
  const cell = t => {
    const bg = t.coverage === 'full' ? (t.observed ? '#2f7d3a' : '#285a33') : t.coverage === 'partial' ? '#7a6a1c' : (t.priority ? '#7a2323' : '#3a2a2a');
    const tip = `${t.technique} ${t.name}\ncoverage: ${t.coverage}\ndetected by: ${Object.entries(t.detected_by).map(([k, v]) => k + ' (' + v + ')').join(', ') || 'nothing enabled'}\nobserved: ${t.observed}`;
    return `<div title="${esc(tip)}" style="background:${bg};border-radius:4px;padding:4px 6px;margin:3px 0;font-size:12px">${esc(t.technique)}<br><span style="opacity:.8">${esc(t.name)}</span>${t.observed ? ` <b>●${t.observed}</b>` : ''}</div>`;
  };
  $('#main').innerHTML = `<div class="row">${kpi('Weighted coverage', c.summary.weighted_coverage_pct + '%', `${c.summary.covered}/${c.summary.techniques} techniques`)}
    ${kpi('Priority blind spots', c.summary.priority_blind_spots, 'no enabled tool detects these')}
    ${kpi('Single-source priority', c.summary.single_source_priority, 'one tool failing = blind')}
    ${kpi('Techniques firing', c.summary.firing, 'seen in alerts/cases')}</div>
    <div class="card"><h2>MITRE ATT&amp;CK detection coverage <span class="muted">(${esc(c.enabled_detection_tools.join(', '))})</span></h2>
    <p class="muted">Green = full, amber = partial, red = priority blind spot. ● = times observed. Hover a cell for the tools behind it.</p>
    <div style="display:grid;grid-template-columns:repeat(${c.tactics.length},minmax(120px,1fr));gap:6px;overflow-x:auto">
    ${c.tactics.map(t => `<div><div class="muted" style="font-size:12px">${esc(t.name)}<br>${t.coverage_pct}%</div>${t.techniques.map(cell).join('')}</div>`).join('')}</div></div>
    ${c.priority_blind_spots.length ? `<div class="card"><h2>Blind spots to close</h2>${c.priority_blind_spots.map(b => `<div class="fact">${esc(b.technique)} ${esc(b.name)}</div>`).join('')}</div>` : ''}`;
}

async function ShadowIT() {
  const r = await api('/api/v1/dashboard/shadow-it?since=-7days');
  if (!r.available) { $('#main').innerHTML = `<div class="card"><h2>Shadow IT</h2><p class="muted">${esc(r.reason)}</p></div>`; return; }
  const s = r.summary;
  $('#main').innerHTML = `<div class="row">${kpi('Unsanctioned services', s.unsanctioned_services)}${kpi('High-risk services', s.high_risk_services)}
    ${kpi('Users on unsanctioned services', s.users_on_unsanctioned_services)}${kpi('Risky destinations reached', s.risky_destinations_reached)}</div>
    <div class="row"><div class="card" style="flex:2"><h2>Unsanctioned services (Umbrella, ${esc(r.window)})</h2><table><tr><th>Service</th><th>Categories</th><th>Risk</th><th>Users</th><th>Hosts</th><th>Requests</th><th>Blocked</th></tr>
    ${r.unsanctioned_services.map(x => `<tr><td><b>${esc(x.service)}</b></td><td class="muted">${esc(x.categories.join(', '))}</td><td>${sev(x.risk)}</td><td title="${esc(x.user_list.join(', '))}">${x.users}</td><td>${x.hosts}</td><td>${x.requests}</td><td>${x.blocked}</td></tr>`).join('')}</table></div>
    <div class="card"><h2>By category</h2>${Object.entries(r.by_category).map(([k, v]) => `<div>${esc(k)} <b>${v}</b></div>`).join('') || '<span class="muted">none</span>'}</div></div>
    <div class="card"><h2>Risky destinations</h2><table><tr><th>Domain</th><th>Categories</th><th>Status</th><th>Users</th><th>Hosts</th></tr>
    ${r.risky_destinations.map(x => `<tr><td>${esc(x.domain)}</td><td>${esc(x.categories.join(', '))}</td><td>${x.status === 'reached' ? sev('critical') + ' reached' : '<span class="pill low">blocked</span>'}</td><td>${esc(x.users.join(', '))}</td><td>${esc(x.hosts.join(', '))}</td></tr>`).join('')}</table>
    <p class="muted">Sanctioned services are configured in config/sanctioned_services.yaml. Rows are aggregated per request and not stored.</p></div>`;
}

async function Suppliers() {
  const r = await api('/api/v1/phishing/suppliers?days=90');
  const st = {ok: 'low', watch: 'medium', at_risk: 'high', critical: 'critical'};
  $('#main').innerHTML = `<div class="card"><h2>Supplier &amp; partner email risk (last ${r.window_days} days, ${r.configured} suppliers)</h2><table><tr><th>Supplier</th><th>Domains</th><th>Status</th><th>Messages</th><th>Findings</th></tr>
    ${Object.entries(r.suppliers).map(([n, v]) => `<tr><td><b>${esc(n)}</b><br><span class="muted">criticality ${esc(v.criticality)}</span></td><td class="muted">${esc(v.domains.join(', '))}</td><td><span class="pill ${st[v.status]}">${esc(v.status)}</span></td><td>${v.messages || 0}</td>
    <td>${v.findings.map(f => `<div class="fact">${sev(f.severity)} ${esc(f.type.replace('supplier_', '').replace(/_/g, ' '))}: ${esc(f.detail)} <a href="#" data-fn="caseView" data-args="[&quot;${esc(f.case_id)}&quot;]">case</a></div>`).join('') || '<span class="muted">none</span>'}</td></tr>`).join('')}</table>
    <p class="muted">Suppliers are configured in config/suppliers.yaml (owned by procurement / finance).</p></div>`;
}

async function Misconfigs() {
  const r = await api('/api/v1/vm/misconfigurations'), m = r.metrics;
  $('#main').innerHTML = `<div class="row">${kpi('Open misconfigurations', m.open)}${kpi('Past SLA', m.overdue)}${kpi('False closures', m.false_closures, 'fix claimed, Wiz still reports it')}</div>
    <div class="card"><h2>Cloud misconfigurations (Wiz) ${can('request_action') ? '<button class="b" data-fn="misRoute" data-args="[]">Route to owners</button>' : ''}</h2><table><tr><th>Severity</th><th>Rule</th><th>Resource</th><th>Team</th><th>Status</th><th>SLA due</th><th></th></tr>
    ${r.items.map(x => `<tr><td>${sev(x.severity)}</td><td>${esc(x.rule)}</td><td>${esc(x.resource)}<br><span class="muted">${esc(x.resource_type)} · ${esc(x.cloud)} ${esc(x.subscription)}</span></td><td>${esc(x.platform_team || 'UNKNOWN OWNER')}</td><td>${esc(x.status)}${x.reopened ? ' <span class="pill high">reopened ' + x.reopened + '</span>' : ''}</td>
    <td class="${x.overdue ? '' : 'muted'}" style="${x.overdue ? 'color:var(--crit)' : ''}">${esc((x.sla_due || '').slice(0, 10))}</td>
    <td><button class="b g" data-fn="misVerb" data-args="[&quot;${esc(x.id)}&quot;,&quot;fixed&quot;]">Mark fixed</button> <button class="b g" data-fn="misVerb" data-args="[&quot;${esc(x.id)}&quot;,&quot;validate&quot;]">Validate</button></td></tr>`).join('')}</table></div>`;
}
async function misRoute() { const r = await api('/api/v1/vm/misconfigurations/route', {method: 'POST'}); toast('Routed to ' + Object.keys(r.routed).join(', ') + ' (tickets await approval per policy)'); Misconfigs(); }
async function misVerb(id, verb) { const r = await api(`/api/v1/vm/misconfigurations/${id}/${verb}`, {method: 'POST'}); toast(r.result ? 'Validation: ' + r.result + (r.false_closure ? ' (false closure)' : '') : 'Marked ' + r.status); Misconfigs(); }

async function entity360(id) {
  const e = await api('/api/v1/entities/' + id + '/360');
  const risk = e.risk ? `<span class="pill ${esc(e.risk.band)}">${esc(e.risk.band)} ${Math.round(e.risk.score)}/100</span> <span class="muted">${esc(e.risk.dimensions.join(', '))}</span>` : '<span class="muted">no risk signals</span>';
  $('#main').innerHTML = `<div class="card"><h2>${esc(e.kind)}: ${esc(e.name)} ${risk}</h2>
    <div class="muted">Seen by: ${esc(e.seen_by.join(', '))} · keys: ${Object.entries(e.keys).map(([k, v]) => esc(k) + '=' + esc(v)).join(', ')}</div></div>
    <div class="row"><div class="card"><h2>Why this risk score</h2>${(e.risk?.factors || []).map(f => `<div class="fact"><b>${esc(f.signal)}</b> +${Math.round(f.decayed)} <span class="muted">${esc(f.source)} · ${esc(f.when || '')}</span><div class="muted">${esc(f.detail)}</div></div>`).join('') || '<span class="muted">none</span>'}</div>
    <div class="card"><h2>Per-tool view</h2>${Object.entries(e.per_tool).map(([t, a]) => `<h3>${esc(t)}</h3><div class="muted" style="font-size:12px">${Object.entries(a).slice(0, 12).map(([k, v]) => esc(k) + ': ' + esc(typeof v === 'object' ? JSON.stringify(v) : v)).join('<br>')}</div>`).join('')}</div></div>
    <div class="row"><div class="card"><h2>Cases</h2>${e.cases.map(c => `<div class="fact"><a href="#" data-fn="caseView" data-args="[&quot;${esc(c.id)}&quot;]">${esc(c.title)}</a> ${sev(c.severity)} <span class="muted">${esc(c.domain)} · ${esc(c.status)}</span></div>`).join('') || '<span class="muted">none</span>'}
      <h2>Insights</h2>${e.insights.map(i => `<div class="fact">${sev(i.severity)} ${esc(i.title)}</div>`).join('') || '<span class="muted">none</span>'}
      ${e.vulnerabilities.length ? `<h2>Vulnerabilities</h2>${e.vulnerabilities.map(v => `<div>${esc(v.cve)} <span class="pill">${esc(v.band)}</span> ${esc(v.status)} <span class="muted">${esc(v.sources.join(', '))}</span></div>`).join('')}` : ''}</div>
    <div class="card"><h2>Related</h2>${Object.entries(e.related).map(([k, xs]) => `<h3>${esc(k)}</h3>${xs.slice(0, 20).map(x => `<div><a href="#" data-fn="entity360" data-args="[&quot;${esc(x.id)}&quot;]">${esc(x.name)}</a> <span class="muted">${esc(x.rel)}</span></div>`).join('')}`).join('')}</div></div>
    <div class="card"><h2>Timeline (all tools)</h2><table>${e.timeline.map(t => `<tr><td class="muted">${esc(String(t.ts || '').slice(0, 19))}</td><td>${esc(t.tool || t.source || '')}</td><td>${esc(t.kind || '')}</td><td>${esc(t.title || t.summary || '')}</td></tr>`).join('')}</table></div>`;
}

async function Access() {
  const me = await api('/api/v1/me');
  if (!me.permissions.includes('manage_access')) {
    $('#main').innerHTML = `<div class="card"><h2>Access</h2><p>Signed in as <b>${esc(me.name)}</b> (${esc(me.roles.join(', '))}) · domains ${esc(me.domains.join(', '))} · MFA ${me.mfa ? 'yes' : 'no'}.</p><p class="muted">Access management needs the admin role with MFA.</p></div>`;
    return;
  }
  const [grants, keys, perms] = await Promise.all([api('/api/v1/admin/roles'), api('/api/v1/admin/api-keys'), api('/api/v1/admin/permissions')]);
  $('#main').innerHTML = `<div class="row"><div class="card"><h2>Role assignments</h2><table><tr><th>Principal</th><th>Role</th><th>Domains</th><th>Expires</th><th>Granted by</th><th></th></tr>
    ${grants.map(g => `<tr><td>${esc(g.principal_id)}</td><td>${esc(g.role)}</td><td>${esc(g.domains.join(', '))}</td><td class="muted">${esc((g.expires_at || 'never').slice(0, 10))}</td><td class="muted">${esc(g.granted_by)}<br>${esc(g.reason)}</td>
    <td><button class="b r" data-fn="revokeGrant" data-args="[&quot;${esc(g.id)}&quot;]">Revoke</button></td></tr>`).join('')}</table>
    <h3>Grant</h3><input id="gp" placeholder="user@cci.com"> <select id="gr">${['analyst', 'lead', 'auditor', 'automation_admin', 'admin'].map(r => `<option>${r}</option>`).join('')}</select>
    <select id="gd"><option>*</option><option>phishing</option><option>incident</option><option>vulnerability</option></select> <input id="gdays" size="4" placeholder="days"> <input id="greason" placeholder="justification"> <button class="b" data-fn="grant" data-args="[]">Grant</button></div>
    <div class="card"><h2>Service-account API keys</h2><table><tr><th>Name</th><th>Roles</th><th>Domains</th><th>Expires</th><th>Last used</th><th></th></tr>
    ${keys.map(k => `<tr><td>${esc(k.name)}</td><td>${esc(k.roles.join(', '))}</td><td>${esc(k.domains.join(', '))}</td><td class="muted">${esc(k.expires_at.slice(0, 10))}</td><td class="muted">${esc((k.last_used_at || 'never').slice(0, 16))}</td>
    <td>${k.active ? `<button class="b r" data-fn="revokeKey" data-args="[&quot;${esc(k.id)}&quot;]">Revoke</button>` : '<span class="muted">inactive</span>'}</td></tr>`).join('')}</table>
    <h3>New key</h3><input id="kn" placeholder="name (e.g. prometheus)"> <select id="kr"><option>auditor</option><option>analyst</option><option>automation_admin</option></select> <button class="b" data-fn="newKey" data-args="[]">Create</button><div id="kout"></div></div></div>
    <div class="card"><h2>Role → permission matrix</h2><table>${Object.entries(perms).map(([r, ps]) => `<tr><td><b>${esc(r)}</b></td><td class="muted">${esc(ps.join(', '))}</td></tr>`).join('')}</table></div>`;
}
async function grant() {
  await api('/api/v1/admin/roles', {method: 'POST', body: JSON.stringify({principal_id: $('#gp').value, role: $('#gr').value, domains: [$('#gd').value], days: parseInt($('#gdays').value) || null, reason: $('#greason').value})});
  Access();
}
async function revokeGrant(id) { await api('/api/v1/admin/roles/' + id, {method: 'DELETE'}); Access(); }
async function revokeKey(id) { await api('/api/v1/admin/api-keys/' + id, {method: 'DELETE'}); Access(); }
async function newKey() {
  const r = await api('/api/v1/admin/api-keys', {method: 'POST', body: JSON.stringify({name: $('#kn').value, roles: [$('#kr').value], days: 90})});
  await Access();
  $('#kout').innerHTML = `<div class="warn">Copy now, it is shown once: <code>${esc(r.api_key)}</code></div>`;
}

async function ConnectorsFresh() {
  const [cs, jr] = await Promise.all([api('/api/v1/dashboard/connectors'), api('/api/v1/jobs?limit=200')]);
  const lastRun = {};
  jr.runs.forEach(r => { if (!lastRun[r.job]) lastRun[r.job] = r; });
  const jcls = {ok: 'low', error: 'high', dead_letter: 'critical'};
  const cls = {healthy: 'low', stale: 'medium', never_synced: 'medium', error: 'high', misconfigured: 'high', disabled: 'informational'};
  $('#main').innerHTML = `<div class="card"><h2>Integration health &amp; data freshness</h2><table><tr><th>Tool</th><th>State</th><th>Mode</th><th>Streams (age / expected)</th><th></th></tr>
    ${cs.map(c => `<tr><td><b>${esc(c.tool)}</b><br><span class="muted">${esc(c.name)} · ${esc(c.category)}</span></td><td><span class="pill ${cls[c.state]}">${esc(c.state)}</span>${c.config_problems.map(p => '<div style="color:var(--high)">' + esc(p) + '</div>').join('')}</td><td>${esc(c.mode || '')}</td>
    <td>${c.streams.map(s => `<div>${esc(s.stream)}: ${s.age_hours == null ? 'never' : s.age_hours + ' h'} / ${s.expected_within_hours} h ${s.fresh ? '' : '<span class="pill medium">stale</span>'} ${s.last_error ? '<span style="color:var(--crit)">' + esc(s.last_error) + '</span>' : ''}</div>`).join('') || '<span class="muted">lookup-only / not yet synced</span>'}</td>
    <td>${c.enabled && can('manage_connectors') ? `<button class="b g" data-fn="testConn" data-args="[&quot;${esc(c.name)}&quot;]">Test</button>` : ''}</td></tr>`).join('')}</table></div>
    <div class="card"><h2>Scheduled jobs</h2><table><tr><th>Job</th><th>Last run</th><th>Status</th><th>Duration</th><th>Detail</th><th></th></tr>
    ${Object.keys(jr.jobs).map(j => { const r = lastRun[j]; return `<tr><td><b>${esc(j)}</b></td><td class="muted">${r ? esc(r.started_at.slice(0, 16)) : 'never'}</td>
      <td>${r ? `<span class="pill ${jcls[r.status]}">${esc(r.status)}</span>${r.attempts > 1 ? ' <span class="muted">' + r.attempts + ' attempts</span>' : ''}` : ''}</td><td>${r && r.duration_s != null ? r.duration_s + ' s' : ''}</td>
      <td class="muted">${r ? esc(r.error || JSON.stringify(r.summary)).slice(0, 160) : ''}</td>
      <td>${can('manage_connectors') ? `<button class="b g" data-fn="replayJob" data-args="[&quot;${esc(j)}&quot;]">Run now</button>` : ''}</td></tr>`; }).join('')}</table></div>`;
}
async function replayJob(name) { const r = await api('/api/v1/jobs/' + name + '/run', {method: 'POST'}); toast(name + ': ' + r.status + (r.error ? ' - ' + r.error : '')); ConnectorsFresh(); }
async function testConn(name) { const r = await api('/api/v1/connectors/' + name + '/test', {method: 'POST'}); toast(name + ': ' + (r.ok ? `OK (${r.latency_ms} ms, ${r.sample_records ?? 0} records)` : 'FAILED ' + r.error)); }

window.VIEWS = {Overview, Coverage, 'Shadow IT': ShadowIT, Connectors: ConnectorsFresh, Access,
  Phishing: async () => { await Phishing(); const d = document.createElement('div'); d.innerHTML = '<button class="b g" data-fn="show" data-args="[&quot;Suppliers&quot;]">Supplier risk</button>'; $('#main').prepend(d); },
  Vulnerabilities: async () => { await Vulnerabilities(); const d = document.createElement('div'); d.innerHTML = '<button class="b g" data-fn="show" data-args="[&quot;Misconfigs&quot;]">Cloud misconfigurations</button>'; $('#main').prepend(d); },
  Suppliers, Misconfigs};
Object.assign(ALLOWED, {replayJob, entity360, grant, revokeGrant, revokeKey, newKey, testConn, misRoute, misVerb});
