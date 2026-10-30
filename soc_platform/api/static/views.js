// Agentic SOC console - pages. Each view renders into #main; every figure comes from the API.
'use strict';

const dot = k => `<span class="dot-i ${esc(k)}"></span>`;
const status = (k, label) => `<span class="status">${dot(k)}${esc(label)}</span>`;
const hours = h => h == null ? '–' : h < 1 ? Math.max(1, Math.round(h * 60)) + ' min' : h < 48 ? h.toFixed(1) + ' h' : (h / 24).toFixed(1) + ' d';
const PBAND = {P1: 'critical', P2: 'high', P3: 'medium', P4: 'low'};
const pchip = p => `<span class="chip ${PBAND[p] || ''}">${esc(p)}</span>`;
const entLink = (id, name) => `<a href="#/entity/${encodeURIComponent(id)}">${esc(name)}</a>`;
const caseLink = (id, name) => `<a href="#/cases/${encodeURIComponent(id)}">${esc(name)}</a>`;
// a list that shows its first n items (already-escaped HTML) and opens the rest in place: "+N more" is a button,
// never text you can only hover (it did nothing when clicked, and touch screens have no hover)
let MORE_SEQ = 0;
const moreList = (items, n = 3, sep = '<br>', label = k => `+${k} more`) => {
  if (items.length <= n) return items.join(sep);
  const id = 'more-' + (++MORE_SEQ), tag = sep ? 'span' : 'div';   // rows of <div>s are wrapped in a div
  return items.slice(0, n).join(sep) + `<${tag} id="${id}" hidden>${sep}${items.slice(n).join(sep)}</${tag}>${sep === '<br>' ? '<br>' : ' '}`
    + `<button type="button" class="linkbtn" data-fn="showMore" data-args="${arg(id)}" data-more="${esc(label(items.length - n))}" aria-expanded="false" aria-controls="${id}">${esc(label(items.length - n))}</button>`;
};
function showMore(id) {
  const el = document.getElementById(id), b = document.querySelector(`[aria-controls="${CSS.escape(id)}"]`);
  if (!el) return;
  el.hidden = !el.hidden;
  if (b) { b.setAttribute('aria-expanded', String(!el.hidden)); b.textContent = el.hidden ? b.dataset.more : 'Show fewer'; }
}

// ================================================================= Overview
async function Overview() {
  const __g = GEN;
  const [o, conns, dr, top, val] = await Promise.all([api('/api/v1/dashboard/overview?days=14'), api('/api/v1/dashboard/connectors'),
    api('/api/v1/metrics/drift'), inDomain('*') ? api('/api/v1/intelligence/risk/top?limit=6') : Promise.resolve([]),
    api('/api/v1/value/scorecard?days=30')]);
  const c = o.cases, a = o.actions, vm = o.vulnerability || {}, ctx = o.context;
  const bad = conns.filter(x => x.enabled && ['error', 'stale', 'misconfigured'].includes(x.state));
  const perf = o.performance.investigation_enrichment_ms;
  setMainG(__g, page('Overview', `Last ${o.window_days} days across phishing, incidents and vulnerabilities. Every figure is computed from stored records.`,
    btn('Refresh', 'refreshPage', [], 'ghost', 'refresh'),
    `<div class="grid g-kpi">
      ${kpi('Open cases', nf(c.open), Object.entries(c.open_by_domain).map(([k, v]) => `${esc(cap(k))} ${v}`).join(' · ') || 'none')}
      ${kpi('Awaiting approval', nf(a.pending_approval), `<a href="#/approvals">Review queue</a>`, a.pending_approval > 0)}
      ${kpi('Automation rate', pct(a.automation_rate_pct / 100, 1), `${nf(a.autonomous)} of ${nf(a.in_window)} actions ran under policy`)}
      ${kpi('Median time to close', hours(c.median_hours_to_close), 'closed cases in window')}
      ${kpi('Open insights', nf(o.insights.open), Object.entries(o.insights.by_severity).map(([k, v]) => `${esc(k)} ${v}`).join(' · ') || 'none')}
      ${vm.open_findings != null ? kpi('Open vulnerabilities', nf(vm.open_findings), `${nf(vm.sla_breached)} past SLA · ${nf(vm.internet_exposed)} exposed`, vm.sla_breached > 0) : ''}
    </div>
    <div class="mt">${valueCard(val)}</div>
    <div class="grid g-2 mt">
      ${card('New cases per day', stackedBars(o.trend, ['phishing', 'incident', 'vulnerability']), {sub: 'by domain'})}
      ${card('Open cases by severity', donut(c.open_by_severity))}
    </div>
    <div class="grid g-2 mt">
      ${card('Highest-priority insights', o.insights.top.map(i => `<div class="list-row">${chip(i.severity)}<div class="grow"><div class="t-title">${esc(i.title)}</div><div class="t-sub">${esc(cap(i.rule))}</div></div></div>`).join('') || empty('No open insights'),
        {right: go('#/intelligence', 'All insights', 'small')})}
      ${card('Riskiest users and hosts', top.map(p => `<div class="list-row"><div class="grow"><div class="t-title">${entLink(p.entity_id, p.name)}</div><div class="t-sub">${esc(p.dimensions.map(dimLabel).join(' · '))}</div></div>
          <div style="width:90px">${meter(p.score)}</div><span class="score">${Math.round(p.score)}</span></div>`).join('') || empty('No risk signals'))}
    </div>
    <div class="grid g-kpi mt" style="grid-template-columns:repeat(auto-fit,minmax(260px,1fr))">
      ${card('Data quality', `<dl class="kv"><dt>Asset match rate</dt><dd class="strong">${pct(ctx.asset_match_rate.match_rate, 1)}</dd>
        <dt>Identity match rate</dt><dd class="strong">${pct(ctx.identity_match_rate.match_rate, 1)}</dd><dt>Awaiting resolution</dt><dd>${nf(ctx.unresolved_queue)}</dd>
        <dt>Hosts / users</dt><dd>${nf(ctx.entities.asset)} / ${nf(ctx.entities.identity)}</dd><dt>Records correlated</dt><dd>${nf(Object.values(ctx.entities).reduce((a, b) => a + b, 0))}</dd></dl>`)}
      ${card('Integrations', bad.length ? bad.map(x => `<div class="list-row"><span class="grow">${esc(x.tool)}</span>${status(x.state === 'stale' ? 'medium' : 'high', cap(x.state))}</div>`).join('')
        : `<div class="list-row">${status('ok', 'All ' + conns.filter(x => x.enabled).length + ' enabled connectors healthy')}</div>`, {right: go('#/integrations', 'Details', 'small')})}
      ${card('Enrichment latency', Object.keys(perf).length ? `<dl class="kv">${Object.entries(perf).map(([d, x]) => `<dt>${esc(cap(d))} · median</dt><dd class="strong">${nf(Math.round(x.median))} ms</dd><dt>${esc(cap(d))} · p95</dt><dd>${nf(Math.round(x.p95))} ms</dd>`).join('')}</dl>` : empty('No investigations yet'), {sub: 'per investigation'})}
      ${card('Verdict quality', Object.entries(dr.domains).map(([d, x]) => `<div class="list-row"><span class="grow">${esc(cap(d))}</span>${status(x.status === 'stable' ? 'ok' : x.status === 'drift' ? 'critical' : 'info', x.status === 'insufficient_data' ? 'Needs more dispositions' : cap(x.status))}</div>
        ${x.reasons.map(r => `<div class="small muted">${esc(r)}</div>`).join('')}`).join(''), {sub: `recent ${dr.window.recent_days} d vs ${dr.window.baseline_days} d`})}
    </div>`));
}

// The benefits the platform is deployed for, against the organisation's baseline (reporting/value.py). Every figure
// is computed by the server; a lead enters what software cannot measure (baselines, targets, time-study effort).
const VALUE_STATUS = {met: ['ok', 'On target'], improving: ['info', 'Improving'], not_improved: ['high', 'Not improved'],
  no_baseline: ['info', 'Awaiting baseline'], no_data: ['info', 'No data yet']};
const VALUE_SOURCE = {platform: 'measured by the platform', time_study: 'time study', derived: 'derived'};
function valueCard(v) {
  const fmt = (x, u) => x == null ? '–' : `${nf(x)}${u === '%' ? ' %' : ' ' + esc(u)}`;
  const rows = v.kpis.map(k => `<tr><td><div class="t-title">${esc(k.label)}</div><div class="t-sub">${esc(VALUE_SOURCE[k.source] || k.source)} · ${esc(k.measured_from)}</div></td>
    <td class="num">${fmt(k.baseline, k.unit)}</td><td class="num strong">${fmt(k.current, k.unit)}</td><td class="num">${fmt(k.target, k.unit)}</td>
    <td>${status(...(VALUE_STATUS[k.status] || ['info', k.status]))}</td></tr>`);
  const keys = [...v.kpis.map(k => [k.id, k.label]), ...Object.entries(v.inputs || {}).map(([k, x]) => [k, x.label])];
  const form = can('approve_policy') && inDomain('*') ? `<details class="mt"><summary>Enter a baseline, target or time-study figure</summary>
    <div class="inline mt" style="flex-wrap:wrap;gap:8px">
      <select id="vkpi" aria-label="KPI">${keys.map(([k, l]) => `<option value="${esc(k)}">${esc(l)}</option>`).join('')}</select>
      <select id="vkind" aria-label="Kind">${['baseline', 'target', 'measured'].map(o => `<option value="${o}">${cap(o)}</option>`).join('')}</select>
      <input class="input" id="vval" type="number" min="0" step="any" style="width:120px" aria-label="Value" placeholder="Value">
      <input class="input" id="vnote" maxlength="500" style="flex:1;min-width:220px" aria-label="Source" placeholder="Source, e.g. ServiceNow tickets Jan-Mar">
      ${btn('Save', 'saveValueInput', [], 'primary')}</div></details>` : '';
  const gate = v.automation_gate_open == null ? '' : `<div class="small muted mt">Automation quality gate (agreement ≥ 90 %, missed threats ≤ 2 %): <b>${v.automation_gate_open ? 'open' : 'not yet met'}</b></div>`;
  return card('Value scorecard', table(['KPI', {h: 'Baseline', num: true}, {h: 'Now', num: true}, {h: 'Target', num: true}, 'Status'], rows,
    {empty: 'No KPIs in your scope'}) + gate + form, {sub: `last ${v.period_days} days against the organisation's baseline`});
}
async function saveValueInput() {
  const value = parseFloat($('#vval').value);
  if (!Number.isFinite(value)) { toast('Enter a number', true); return; }
  await api('/api/v1/value/inputs', {method: 'PUT', body: JSON.stringify({kpi: $('#vkpi').value, kind: $('#vkind').value, value, note: $('#vnote').value.trim()})});
  toast('Saved'); Overview();
}

// ================================================================= Intelligence
let INTEL_FILTER = 'all', INTEL_ALL = false;
async function Intelligence() {
  const __g = GEN;
  const [b, ins, top] = await Promise.all([api('/api/v1/intelligence/brief'), api('/api/v1/intelligence/insights'), api('/api/v1/intelligence/risk/top?limit=10')]);
  const filtered = INTEL_FILTER === 'all' ? ins : ins.filter(i => i.severity === INTEL_FILTER);
  const shown = INTEL_ALL ? filtered : filtered.slice(0, 8);
  const actions = can('investigate') ? btn('Re-correlate', 'refreshIntel', [], '', 'refresh') : '';
  setMainG(__g, page('Intelligence', 'Cross-domain correlation over every data source. Findings are raised by deterministic rules; the analyst assistant only explains, citing evidence.', actions,
    `<div class="grid g-2">
      <div class="stack">
        ${card('Situation brief', `<div class="prose">${esc(b.summary)}</div>`, {right: chip(b.source === 'llm' ? 'AI narrative' : 'Platform summary', 'plain')})}
        ${card('Ask the analyst', `<div class="inline"><input class="input" style="flex:1;min-width:260px" id="iq" data-enter="askIntel" placeholder="e.g. Is jane.doe@acme-demo.com compromised and what should we do first?">
          ${btn('Ask', 'askIntel', [], 'primary')}</div><div id="ia"></div>`)}
        ${card(`Correlated findings <span class="muted">(${ins.length})</span>`, shown.map(i => `
          <div class="list-row" style="align-items:flex-start;padding:14px 0">
            <div>${chip(i.severity)}</div>
            <div class="grow"><div class="t-title">${esc(i.title)}</div>
              <div class="t-sub"${(i.requirements || []).length ? ` title="${esc('Requirements: ' + i.requirements.join(', '))}"` : ''}>${esc(cap(i.rule))} · last confirmed ${dt(i.last_seen)}</div>
              ${i.narrative ? `<p class="small" style="margin:8px 0 6px;color:var(--text-2)">${esc(i.narrative)}</p>` : ''}
              ${(i.next_steps || []).length ? `<div class="small"><span class="strong">Next steps</span><ol style="margin:4px 0 0 18px;padding:0">${i.next_steps.map(n => `<li>${esc(n)}</li>`).join('')}</ol></div>` : ''}
              <details class="mt" style="margin-top:8px"><summary>Evidence (${(i.evidence || []).length})</summary>${(i.evidence || []).map(e => `<div class="ev"><span class="ref">${esc(e.source || '')}</span><span class="small">${esc(e.summary || e.signal || '')} <span class="muted">${esc(e.when ? dt(e.when) : '')}</span></span></div>`).join('')}</details>
            </div>
            <div class="inline">${can('investigate') ? btn('Acknowledge', 'insightAct', [i.id, 'acknowledge'], 'sm') + btn('Dismiss', 'insightAct', [i.id, 'dismiss'], 'sm ghost') : ''}</div>
          </div>`).join('') + (filtered.length > shown.length ? `<div style="padding-top:12px">${btn(`Show all ${filtered.length}`, 'intelAll', [], 'sm')}</div>` : '') || empty('No findings for this filter'),
          {right: `<div class="seg">${['all', 'critical', 'high', 'medium'].map(f => `<button class="${f === INTEL_FILTER ? 'on' : ''}" data-fn="intelFilter" data-args="${arg(f)}">${cap(f)}</button>`).join('')}</div>`})}
      </div>
      ${card('Risk by user and host', top.map(p => `<div class="list-row"><div class="grow"><div class="t-title">${entLink(p.entity_id, p.name)}</div><div class="t-sub">${esc(p.kind)} · ${esc(p.dimensions.map(dimLabel).join(', '))}</div>
        <div style="margin-top:6px">${meter(p.score)}</div></div><span class="score">${Math.round(p.score)}</span></div>`).join('') || empty('No risk signals yet'), {sub: 'time-decayed, explainable'})}
    </div>`));
}
async function askIntel() {
  const q = $('#iq').value.trim(); if (!q) return;
  $('#ia').innerHTML = `<div class="inline muted mt"><span class="spin"></span> Gathering evidence…</div>`;
  const r = await post('/api/v1/intelligence/ask', {question: q});
  $('#ia').innerHTML = `<div class="divider"></div><div class="prose">${esc(r.answer)}</div>
    ${(r.claims || []).length ? (() => { const row = c => `<div class="${c.kind === 'fact' ? 'fact' : 'inf'}">${esc(c.text)} ${(c.evidence_ids || []).map(x => `<abbr class="cite">${esc(x)}</abbr>`).join('')}</div>`;
      return `<div class="mt small"><div class="strong" style="margin-bottom:4px">Evidence behind the answer</div>${r.claims.slice(0, 6).map(row).join('')}${r.claims.length > 6 ? `<details><summary>${r.claims.length - 6} more</summary>${r.claims.slice(6).map(row).join('')}</details>` : ''}</div>`; })() : ''}
    <div class="small muted mt">How this was answered: ${r.planner === 'llm' ? 'AI-planned look-ups' : 'rule-based look-ups'} · ${r.tool_calls.map(t => `<span class="tag">${esc(t.tool)}</span>`).join('')}</div>${llmNotice(r)}`;
}
async function refreshIntel() { await post('/api/v1/intelligence/refresh'); toast('Correlation refreshed'); Intelligence(); }
async function insightAct(id, verb) { await post(`/api/v1/intelligence/insights/${id}/${verb}`); toast(`Insight ${verb}d`); Intelligence(); }
function intelFilter(f) { INTEL_FILTER = f; INTEL_ALL = false; Intelligence(); }
function intelAll() { INTEL_ALL = true; Intelligence(); }

// ================================================================= Cases
let CASE_FILTER = 'all';
let OWNER_FILTER = 'all';
let CASE_OFFSET = 0;
// "Showing 1-500 of 1,240" with Newer / Older when a list is longer than one page
function pager(offset, count, total, fn, noun) {
  if (offset === 0 && count >= total) return '';
  const size = Math.max(count, 1);
  return `<div class="inline small muted" style="padding:10px 14px;gap:10px">Showing ${nf(count ? offset + 1 : 0)}-${nf(offset + count)} of ${nf(total)} ${noun}.
    ${offset > 0 ? btn('Newer', fn, [Math.max(0, offset - size)], 'sm') : ''}${offset + count < total ? btn('Older', fn, [offset + count], 'sm') : ''}</div>`;
}
async function Cases(id) {
  const __g = GEN;
  if (id) return CaseDetail(id);
  const qs = new URLSearchParams();
  if (CASE_FILTER !== 'all') qs.set('domain', CASE_FILTER);
  if (OWNER_FILTER !== 'all') qs.set('assignee', OWNER_FILTER);
  if (CASE_OFFSET) qs.set('offset', CASE_OFFSET);
  const [cs, csum] = await Promise.all([api('/api/v1/cases' + (qs.toString() ? '?' + qs : '')), api('/api/v1/cases/summary')]);
  const shown = OWNER_FILTER !== 'all' ? csum[OWNER_FILTER === 'me' ? 'mine' : 'unassigned']
    : CASE_FILTER === 'all' ? csum.total : (csum.by_domain[CASE_FILTER] || 0);
  const rows = cs.map(c => `
    <tr class="click" data-fn="goTo" data-args="${arg('#/cases/' + c.id)}"><td>${chip(c.severity)}</td>
      <td><div class="t-title">${esc(c.title)}</div><div class="t-sub">${esc(cap(c.domain))}${wlBadges(c.watchlists)}</div></td>
      <td>${esc(cap(c.verdict || 'pending'))}</td><td class="num">${c.confidence != null ? pct(c.confidence) : '–'}</td>
      <td>${esc(cap(c.status))}</td><td class="small">${c.assignee ? esc(c.assignee) : '<span class="muted">unassigned</span>'}</td><td class="muted">${dt(c.created_at)}</td></tr>`);
  const actions = (can('investigate') && inDomain('incident') ? btn('Run incident pipeline', 'runInc', [], '', 'play') : '') +
    (can('investigate') && inDomain('phishing') ? btn('Pull reported email', 'runPh', [], '', 'phishing') : '');
  setMainG(__g, page('Cases', 'Investigations across all domains. Open a case for the evidence, reasoning and recommended actions.', actions,
    card(null, `<div style="padding:12px 14px;border-bottom:1px solid var(--border)"><div class="seg">${['all', 'phishing', 'incident', 'vulnerability'].map(f =>
      `<button class="${f === CASE_FILTER ? 'on' : ''}" data-fn="caseFilter" data-args="${arg(f)}">${cap(f)} <span class="muted">${f === 'all' ? csum.total : (csum.by_domain[f] || 0)}</span></button>`).join('')}</div>
      <div class="seg" style="margin-left:10px" role="group" aria-label="Owner">${[['all', 'Everyone', csum.total], ['me', 'Mine', csum.mine], ['unassigned', 'Unassigned', csum.unassigned]].map(([f, label, n]) =>
      `<button class="${f === OWNER_FILTER ? 'on' : ''}" data-fn="ownerFilter" data-args="${arg(f)}">${label} <span class="muted">${n}</span></button>`).join('')}</div></div>` +
      table([{h: 'Severity'}, {h: 'Case'}, {h: 'Verdict'}, {h: 'Confidence', num: 1}, {h: 'Status'}, {h: 'Owner'}, {h: 'Opened'}], rows, {empty: OWNER_FILTER === 'me' ? 'No cases assigned to you.' : 'No cases yet - run a pipeline to ingest alerts and reported email.'}) +
      pager(CASE_OFFSET, cs.length, shown, 'casePage', 'cases'), {flush: true})));
}
function caseFilter(f) { CASE_FILTER = f; CASE_OFFSET = 0; Cases(); }
function casePage(o) { CASE_OFFSET = Math.max(0, Number(o) || 0); Cases(); }
function ownerFilter(f) { OWNER_FILTER = f; CASE_OFFSET = 0; Cases(); }
async function runInc() {
  toast('Running incident pipeline…');
  const r = await post('/api/v1/incidents/run');
  const down = (r.errors || []).length ? ` ${r.errors.length} tool(s) did not answer - shown as unavailable.` : '';
  toast(r.new_incidents ? `${r.new_incidents} new incident(s), ${r.investigated.length} investigated.${down}`
    : `No new alerts since the last run - every incident is already investigated.${down}`, !!down);
  render();
}
async function runPh() {
  toast('Pulling reported email…');
  const r = await post('/api/v1/phishing/ingest');
  const n = (r.processed || []).length;
  toast(n ? `${n} new reported e-mail(s) analysed.` : 'No new reported e-mail - every report in the mailbox is already analysed.');
  render();
}

async function CaseDetail(id) {
  const __g = GEN;
  const v = await api('/api/v1/cases/' + encodeURIComponent(id));
  const c = v.case, a = v.assessment || {};
  const un = (v.completeness && v.completeness.unavailable) || [];
  const acts = [...v.actions].sort((x, y) => (x.priority || 99) - (y.priority || 99));
  const astat = x => (x.result || {}).awaiting_second_approval && x.status === 'pending_approval' ? status('medium', 'Awaiting second approval')
    : status(x.status === 'executed' ? 'ok' : ['rejected', 'rolled_back'].includes(x.status) ? 'info' : x.status === 'failed' ? 'critical' : 'medium', cap(x.status));
  // the rank in the recommended order (contain first, communicate last); the stored priority is a sort weight, not a rank
  const actRow = (x, i) => `<tr><td class="num muted" title="recommended order">${i + 1}</td>
    <td style="min-width:190px"><div class="t-title mono" style="overflow-wrap:anywhere">${esc(x.action_type)}</div><div class="small" style="margin-top:3px;color:var(--text-2);overflow-wrap:anywhere">${esc(x.rationale)}</div>
      <div class="t-sub">L${esc(x.level)}${x.blast_radius ? ' · blast radius: ' + esc(x.blast_radius) : ''}${x.reversible === false ? ' · not reversible' : ''}</div>
      ${(x.policy_reasons || []).slice(1).map(r => `<div class="t-sub">${esc(r)}</div>`).join('')}</td>
    <td class="small wrap" style="min-width:110px">${moreList(x.targets.map(t => esc(t.name || t.recipient || t.id)))}</td>
    <td>${astat(x)}${x.approver ? `<div class="t-sub">${esc(x.approver)}</div>` : ''}</td>
    <td><div class="inline" style="flex-wrap:wrap;gap:6px">${['recommended', 'pending_approval'].includes(x.status) ? decideButtons(x, id) :
      x.status === 'executed' && can('rollback_action') ? btn('Roll back', 'act', [x.id, 'rollback', id], 'sm') : ''}</div></td></tr>`;
  const intel = v.intelligence || {};
  // phishing: which analysis ran, the trained models' verdict next to the rules', and every model's score
  const bd = a.backend_detail || {}, backend = (v.completeness || {}).analysis_backend;
  const MODEL = {header_agent: 'Header', content_agent: 'Content (text model)', url_agent: 'URLs', attachment_agent: 'Attachments',
    sandbox_agent: 'Sandbox', threat_intel_agent: 'Threat intel', user_behavior_agent: 'User behaviour'};
  const analysisCard = c.domain !== 'phishing' || !backend ? '' : card('Analysis', bd.engine
    ? `<div class="inline small" style="gap:18px;margin-bottom:10px;flex-wrap:wrap"><span>ML models ${chip(bd.engine.verdict, 'plain')} ${pct(bd.engine.score)}</span><span>Rules ${chip(bd.heuristic.verdict, 'plain')} ${pct(bd.heuristic.score)}</span></div>` +
      Object.entries(bd.engine.agent_scores || {}).map(([k, s]) => { const rel = (bd.model_reliability || {})[k];
        return `<div class="list-row small"><span class="grow">${esc(MODEL[k] || cap(k))}${rel ? ` <span class="tag" title="${esc(rel.note)}">${esc(rel.level)} reliability</span>` : ''}</span><div style="width:90px">${meter((s || 0) * 100)}</div><span class="score">${Math.round((s || 0) * 100)}</span></div>`; }).join('') +
      ((bd.corroborated_by || []).length ? `<div class="t-sub" style="margin-top:6px">Confirmed by: ${esc(bd.corroborated_by.map(k => MODEL[k] || k).join(', '))}</div>` : '') +
      ((v.completeness.missing_agents || []).length ? `<div class="t-sub" style="margin-top:6px">Did not answer: ${esc(v.completeness.missing_agents.join(', '))}</div>` : '') +
      (bd.fusion_note ? `<div class="t-sub" style="margin-top:8px">${esc(bd.fusion_note)}</div>` : '')
    : `<div class="small">Rule-based analyser${bd.engine_error ? ` only - the ML models could not run (${esc(String(bd.engine_error).slice(0, 140))})` : ' only (the ML models are not installed or switched off)'}.</div>`,
    {sub: bd.engine ? 'trained models and rules each give a verdict; the more severe one counts' : ''});
  // incident severity is computed by fixed rules (IncidentService._score): show every rule that applied
  const sevWhy = (cs, f) => {
    const CTX = {internet_exposed: 'internet-facing', business_critical: 'business-critical'};
    const rows = [`The tool rated the alert <b>${esc(f.base_alert_severity || 'unknown')}</b> - the starting point.`];
    if (f.deception_hit) rows.push('A decoy was touched (deception hit): <b>raised to critical</b> - decoys have no business use.');
    if (f.kev_exposure_boost) rows.push('A host in the case carries a vulnerability on the CISA known-exploited list: <b>one level up</b>.');
    if ((f.exposed_or_critical_host_with_kev || []).length) rows.push(`That host is ${esc(f.exposed_or_critical_host_with_kev.map(k => CTX[k] || k).join(' and '))}: <b>at least high</b>.`);
    const sig = [f.risky_signin && 'risky sign-in', f.mailbox_rule && 'suspicious mailbox rule', f.privileged_credential_access && 'privileged credential access',
      f.threat_intel_malicious && 'indicator rated malicious by threat intel', f.destination_reached && 'malicious destination reached'].filter(Boolean);
    if (sig.length) rows.push(`Signals found: ${esc(sig.join(', '))}.`);
    const dims = f.corroborating_dimensions || [];
    rows.push(`Corroborated in ${dims.length} area(s)${dims.length ? ` (${esc(dims.map(dimLabel).join(', '))})` : ''}${dims.length >= 3 ? ': three or more make it <b>at least high</b>' : ''}; confidence is 35 % + 10 % per area, at most 95 %.`);
    return `<h3 class="small strong" style="margin:16px 0 4px">Why ${esc(cs.severity)} - computed by fixed rules, the same evidence always gives the same result</h3>
      <ul class="small" style="margin:0;padding-left:18px">${rows.map(r => `<li>${r}</li>`).join('')}</ul>
      <div class="t-sub">Result: severity ${esc(cs.severity)}, confidence ${pct(cs.confidence)}.</div>`;
  };
  setMainG(__g, `<div class="page-head"><div>
      <div class="inline" style="margin-bottom:8px"><a href="#/cases" class="small" aria-label="Back to cases" title="Back to cases">${icon('back', '')}</a>${chip(c.severity)}${chip(c.verdict || 'pending', 'plain')}<span class="muted small">${esc(cap(c.domain))} · ${esc(cap(c.status))} · opened ${dt(c.created_at)}</span></div>
      <h1>${esc(c.title)}</h1><p>Confidence ${pct(c.confidence)} · automation mode ${esc(cap(c.autonomy_mode || 'recommend'))} ·
        owner <b>${c.assignee ? esc(c.assignee) : 'unassigned'}</b>
        ${can('investigate') && c.assignee !== ME.id.toLowerCase() ? btn('Take case', 'assignCase', [id, 'me'], 'sm') : ''}
        ${can('investigate') && c.assignee && (c.assignee === ME.id.toLowerCase() || can('approve_high_impact')) ? btn('Unassign', 'assignCase', [id, ''], 'sm ghost') : ''}</p></div>
      <div class="actions"><a class="btn primary" href="#/story/${encodeURIComponent(id)}">${icon('intel')}Attack story</a>${btn('Investigation record', 'dl', [`/api/v1/cases/${encodeURIComponent(id)}/report`], '', 'download')}</div></div>
    ${wlCallout(v.watchlists)}
    ${un.length ? `<div class="callout"><b>Incomplete picture.</b>&nbsp;Unavailable sources: ${un.map(u => esc(u.source)).join(', ')}. Conclusions below exclude them.</div>` : ''}
    <div class="grid g-2">
      <div class="stack">
        ${card('Assessment', `<div class="prose">${esc(c.summary)}</div>${a.narration_pending ? '<div class="t-sub" style="margin-top:6px">The written explanation is being prepared; the verdict, evidence and recommendations below are final. Refresh in a moment.</div>' : ''}
          ${(a.facts || []).length ? `<h3 class="small strong" style="margin:16px 0 4px">Facts</h3>${a.facts.map(x => `<div class="fact small">${esc(x.text)} ${cite(x)}</div>`).join('')}` : ''}
          ${(a.inferences || []).length ? `<h3 class="small strong" style="margin:16px 0 4px">Inferences</h3>${a.inferences.map(x => `<div class="inf small">${esc(x.text)} ${cite(x)}</div>`).join('')}` : ''}
          ${c.domain === 'incident' && a.scoring ? sevWhy(c, a.scoring) : ''}
          ${(a.mitre || []).length ? `<h3 class="small strong" style="margin:16px 0 6px">MITRE ATT&amp;CK</h3>${a.mitre.map(m => `<span class="tag">${esc(m.technique)} ${esc(m.name || '')}</span>`).join('')}` : ''}`,
          {sub: 'hover a reference to see the evidence it cites; click it to jump there'})}
        ${analysisCard}
        ${card(`Recommended actions <span class="muted">(${acts.length})</span>`, table(['#', 'Action and rationale', 'Targets', 'Status', ''], acts.map(actRow), {empty: 'No actions recommended'}), {flush: true})}
        ${card('Evidence', Object.entries(v.evidence).map(([d, items]) => `<div class="small strong" style="margin:10px 0 2px;text-transform:capitalize">${esc(cap(d))}</div>` +
          items.map(i => `<div class="ev" data-ref="${esc(i.ref || '')}"><span class="ref">${esc(i.ref || '')}</span><div class="grow small"><span class="muted">${esc(i.source)}</span> · ${esc(i.summary)}
            ${i.type !== 'fact' ? chip('inference', 'plain') : ''} ${i.deep_link ? `<a target="_blank" rel="noopener noreferrer" href="${esc(safeUrl(i.deep_link))}">open in tool</a>` : ''}</div></div>`).join('')).join('') || empty('No evidence'))}
      </div>
      <div class="stack">
        ${(intel.entity_risk || []).length || (intel.insights || []).length ? card('Cross-domain context',
          (intel.entity_risk || []).map(r => `<div class="list-row"><span class="grow">${entLink(r.entity_id, r.name)}</span><div style="width:70px">${meter(r.score)}</div><span class="score">${Math.round(r.score)}</span></div>`).join('') +
          (intel.insights || []).map(i => `<div class="list-row" style="align-items:flex-start">${chip(i.severity)}<div class="grow small">${esc(i.title)}</div></div>`).join('')) : ''}
        ${card('Entities', v.entities.map(e => `<div class="list-row"><span class="tag">${esc(e.kind)}</span><div class="grow"><div class="t-title">${['asset', 'identity'].includes(e.kind) ? entLink(e.id, e.name) : esc(e.name)}</div>
          <div class="t-sub">${esc(e.role)} · seen by ${esc(e.seen_by.join(', ') || '–')}</div></div></div>`).join('') || empty('No entities'))}
        ${can('investigate') ? card('Analyst decision', `<div class="stack" style="gap:10px"><select id="dv" aria-label="Analyst verdict">${['true_positive', 'malicious', 'suspicious', 'false_positive', 'benign'].map(o => `<option value="${o}">${cap(o)}</option>`).join('')}</select>
          <textarea id="dr" rows="3" placeholder="Reasoning (used as feedback for tuning)"></textarea>${btn('Record decision', 'decide', [id], 'primary')}</div>
          ${v.dispositions.map(d => `<div class="list-row small"><span class="grow">${esc(d.analyst)}: <b>${esc(cap(d.verdict))}</b> - ${esc(d.reasoning)}</span><span class="muted">${dt(d.at)}</span></div>`).join('')}`) : ''}
        ${card(`Analyst notes <span class="muted">(${(v.notes || []).length})</span>`, (can('investigate') ? `<div class="stack" style="gap:8px;margin-bottom:10px">
          <textarea id="note-text" rows="3" maxlength="4000" aria-label="New note" placeholder="Add a note for the team (notes are kept, never edited)"></textarea>${btn('Add note', 'addNote', [id], 'primary')}</div>` : '') +
          ((v.notes || []).map(n => `<div class="list-row small" style="align-items:flex-start"><div class="grow"><div class="t-sub">${esc(n.author)} · ${dt(n.at)}</div><div style="white-space:pre-wrap">${esc(n.text)}</div></div></div>`).join('') || empty('No notes yet')))}
        ${card('Timeline', v.timeline.slice(-30).reverse().map(t => `<div class="tl-row"><div class="tl-meta"><span class="mono muted">${dt(t.ts)}</span><span class="tag">${esc(t.tool || '')}</span></div><div class="tl-title">${esc(t.title)}</div></div>`).join('') || empty('No events'))}
        ${card('Audit trail', `<details><summary>${v.audit.length} audited events</summary>${v.audit.map(x => `<div class="list-row small"><span class="mono muted">#${x.seq}</span><span class="grow">${esc(x.event)}</span><span class="muted">${esc(x.actor)}</span></div>`).join('')}</details>`)}
      </div>
    </div>`);
}
async function act(aid, verb, cid) {
  const r = await post(`/api/v1/actions/${aid}/${verb}`, {note: 'via console'});
  toast(verb === 'approve' && (r.result || {}).awaiting_second_approval && r.status === 'pending_approval' ? 'First approval recorded - a second lead must approve before it runs'
    : `Action ${verb === 'approve' ? `approved - ${cap(r.status || 'done')}` : verb === 'reject' ? 'rejected' : 'rolled back'}`); refreshStatus(); cid ? CaseDetail(cid) : Approvals(); }
async function assignCase(id, who) { await post(`/api/v1/cases/${id}/assign`, {assignee: who === 'me' ? ME.id : (who || null)}); toast(who ? 'Case assigned' : 'Case unassigned'); CaseDetail(id); }
async function addNote(id) { const t = $('#note-text').value.trim(); if (!t) { toast('Write a note first', true); return; } await post(`/api/v1/cases/${id}/notes`, {text: t}); toast('Note added'); CaseDetail(id); }
async function decide(id) { await post(`/api/v1/cases/${id}/disposition`, {verdict: $('#dv').value, reasoning: $('#dr').value}); toast('Decision recorded'); CaseDetail(id); }

// ================================================================= Search
async function Search(q) {
  const __g = GEN;
  q = (q || '').trim();
  const box = $('#global-q'); if (box) box.value = q;
  if (q.length < 2) { setMainG(__g, page('Search', 'Type at least two characters in the search box.', '', empty('Nothing to search for'))); return; }
  const r = await api('/api/v1/search?q=' + encodeURIComponent(q));
  const group = (title, rows, empty_) => card(`${title} <span class="muted">(${rows.length})</span>`, rows.join('') || empty(empty_));
  const sections = [
    group('Cases', r.cases.map(c => `<div class="list-row click" data-fn="goTo" data-args="${arg('#/cases/' + c.id)}">${chip(c.severity)}<div class="grow"><div class="t-title">${esc(c.title)}</div><div class="t-sub">${esc(cap(c.domain))} · ${esc(cap(c.status))}${c.assignee ? ' · ' + esc(c.assignee) : ''}</div></div></div>`), 'No matching cases'),
  ];
  if (r.entities) sections.push(group('People, hosts and indicators', r.entities.map(e => `<div class="list-row"><span class="tag">${esc(e.kind)}</span><div class="grow">${['asset', 'identity'].includes(e.kind) ? entLink(e.id, e.name) : esc(e.name)}</div></div>`), 'No matching people, hosts or indicators'));
  if (r.insights) sections.push(group('Correlated findings', r.insights.map(i => `<div class="list-row">${chip(i.severity)}<div class="grow small">${esc(i.title)}</div><span class="muted small">${esc(cap(i.status))}</span></div>`), 'No matching findings'));
  if (r.findings) sections.push(group('Vulnerabilities', r.findings.map(f => `<div class="list-row"><span class="tag">${esc(f.priority)}</span><div class="grow"><div class="t-title mono">${esc(f.cve)}</div><div class="t-sub">${esc(f.asset)} · ${esc(cap(f.status))}</div></div></div>`), 'No matching vulnerabilities'));
  setMainG(__g, page(`Search: “${esc(q)}”`, 'Matches in cases, identifiers from every connected tool, correlated findings and vulnerabilities - limited to what your role and data scope allow.', '',
    `<div class="grid g-2">${sections.join('')}</div>`));
}

// ================================================================= Entity 360
async function Entity(id) {
  const __g = GEN;
  const e = await api('/api/v1/entities/' + encodeURIComponent(id) + '/360');
  const r = e.risk;
  setMainG(__g, `<div class="page-head"><div class="ph-main"><div class="inline" style="margin-bottom:8px"><span class="tag">${esc(e.kind)}</span>${r && r.score > 0 ? chip(r.band) : chip('no risk signals', 'plain')}</div>
      <h1>${esc(e.name)}</h1><p>Seen by ${esc(e.seen_by.join(', ') || '–')}</p></div>
      ${r ? `<div class="ph-score"><div class="card kpi"><div class="label">Risk score</div><div class="value">${Math.round(r.score)}<span class="muted" style="font-size:14px">/100</span></div><div class="foot">${esc(r.dimensions.map(dimLabel).join(' · '))}</div></div></div>` : ''}</div>
    <div class="grid g-2">
      <div class="stack">
        ${card('Why this score', (r && r.factors.length) ? (r.points != null ? `<div class="small muted" style="margin-bottom:8px">Each signal adds risk points (below, fading with age). The points add up to <b>${nf(Math.round(r.points))}</b>; the score is 100 × (1 − e<sup>−points ÷ ${esc(r.points_scale)}</sup>) - every signal raises it, each by less as the total grows, so ${esc(r.points_scale)} points give 63 and it never passes 100.</div>` : '') + r.factors.map(f => `<div class="list-row" style="align-items:flex-start"><span class="score mono" style="min-width:42px">+${Math.round(f.decayed)}</span>
          <div class="grow"><div class="t-title">${esc(cap(f.signal))}</div><div class="t-sub">${esc(f.detail)}</div></div><span class="tag">${esc(f.source)}</span><span class="muted small">${dt(f.when)}</span></div>`).join('') : empty('No risk factors in the window'),
          {sub: 'weights decay with age', right: r && r.points != null ? `<span class="small muted" title="score = 100 × (1 − e^(−points ÷ ${esc(r.points_scale)})): each signal adds, each adds less as the total grows, and the score never passes 100">${nf(Math.round(r.points))} points → score ${Math.round(r.score)} <span class="mono">ⓘ</span></span>` : ''})}
        ${card('Timeline across tools', e.timeline.slice(-40).reverse().map(t => `<div class="tl-row"><div class="tl-meta"><span class="mono muted">${dt(t.ts)}</span><span class="tag">${esc(t.tool || '')}</span></div><div class="tl-title">${esc(t.title)}</div></div>`).join('') || empty('No events'))}
      </div>
      <div class="stack">
        ${card('Identifiers', `<dl class="kv">${Object.entries(e.keys).map(([k, v]) => `<dt>${esc(cap(k))}</dt><dd class="mono">${esc(v)}</dd>`).join('')}</dl>`)}
        ${card('Cases', e.cases.map(c => `<div class="list-row">${chip(c.severity)}<div class="grow small">${caseLink(c.id, c.title)}<div class="t-sub">${esc(cap(c.domain))} · ${esc(cap(c.status))}</div></div></div>`).join('') || empty('No cases'))}
        ${e.insights.length ? card('Insights', e.insights.map(i => `<div class="list-row">${chip(i.severity)}<span class="grow small">${esc(i.title)}</span></div>`).join('')) : ''}
        ${e.vulnerabilities.length ? card('Vulnerabilities', e.vulnerabilities.map(x => `<div class="list-row">${pchip(x.band)}<span class="grow mono small">${esc(x.cve)}</span><span class="small muted">${esc(cap(x.status))}</span></div>`).join('')) : ''}
        ${card('Related', Object.entries(e.related).map(([k, xs]) => `<div class="small strong" style="margin:8px 0 2px">${esc(cap(k))}</div>` +
          xs.slice(0, 15).map(x => `<div class="list-row small"><span class="grow">${k === 'indicator' ? esc(x.name) : entLink(x.id, x.name)}</span><span class="muted">${esc(x.rel)}</span></div>`).join('')).join('') || empty('Nothing related'))}
        ${card('Per-tool attributes', `<details><summary>${Object.keys(e.per_tool).length} tools</summary>${Object.entries(e.per_tool).map(([t, attrs]) => `<div class="small strong" style="margin:10px 0 4px">${esc(t)}</div><dl class="kv">${Object.entries(attrs).slice(0, 14).map(([k, v]) => `<dt>${esc(cap(k))}</dt><dd>${esc(typeof v === 'object' ? JSON.stringify(v) : v)}</dd>`).join('')}</dl>`).join('')}</details>`)}
      </div>
    </div>`);
}

// ================================================================= Approvals
let APPROVAL_FILTER = 'all';
let APPROVAL_OFFSET = 0;
async function Approvals() {
  const __g = GEN;
  const scope = APPROVAL_FILTER === 'all' ? '' : APPROVAL_FILTER === 'mine' ? '&mine=true' : '&domain=' + encodeURIComponent(APPROVAL_FILTER);
  const [xs, sm] = await Promise.all([api('/api/v1/actions?status=recommended,pending_approval' + scope + (APPROVAL_OFFSET ? '&offset=' + APPROVAL_OFFSET : '')),
    api('/api/v1/actions/summary?status=recommended,pending_approval')]);
  const doms = Object.keys(sm.by_domain).sort();
  const count = f => f === 'all' ? sm.total : f === 'mine' ? (sm.mine || 0) : (sm.by_domain[f] || 0);
  const total = count(APPROVAL_FILTER);
  const types = Object.entries(sm.by_type || {}).slice(0, 8);
  setMainG(__g, page('Approvals', 'Actions the platform recommends. Nothing here runs until someone with the right role approves it; four-eyes actions need two different people.', '',
    `<div class="grid g-2">
      ${card('Waiting by domain', donut(sm.by_domain), {sub: `${nf(sm.total)} actions awaiting a decision`})}
      ${card('Waiting by action type', hbars(types.map(([t, n]) => ({label: t, values: {actions: n}})), ['actions'], {label: 'actions by type', empty: 'Nothing is waiting'}))}
    </div><div class="mt"></div>` +
    card(null, `<div style="padding:12px 14px;border-bottom:1px solid var(--border)"><div class="seg">${['all', 'mine', ...doms].map(f =>
      `<button class="${f === APPROVAL_FILTER ? 'on' : ''}" data-fn="approvalFilter" data-args="${arg(f)}"${f === 'mine' ? ' title="Actions on the cases you have taken"' : ''}>${esc(f === 'mine' ? 'My cases' : cap(f))} <span class="muted">${count(f)}</span></button>`).join('')}</div></div>` +
      table(['Action', 'Targets', 'Rationale', 'Policy', ''], xs.map(x => `<tr>
      <td class="nowrap"><div class="t-title mono">${esc(x.action_type)}</div><div class="t-sub">${esc(cap(x.domain))} · L${esc(x.level)}</div></td>
      <td class="small wrap">${actTargets(x)}</td><td class="small wrap">${esc(x.rationale)}${actOrigin(x)}</td>
      <td class="small muted">${(x.policy_reasons || []).slice(1).map(esc).join('<br>') || 'recommend (L2)'}${(x.result || {}).awaiting_second_approval && x.status === 'pending_approval' ? `<div class="t-sub" style="color:var(--high)">First approval by ${esc(x.approver)} - a second lead must approve</div>` : ''}</td>
      <td><div class="inline" style="flex-wrap:wrap;gap:6px">${decideButtons(x)}
        <button class="btn sm ghost" data-fn="actDetail" data-args="${arg(x.id)}" aria-expanded="false" aria-controls="ad-${esc(x.id)}">Why and what</button></div></td></tr>
      <tr class="adetail" id="ad-${esc(x.id)}" hidden><td colspan="5"><div class="adbox" aria-live="polite"></div></td></tr>`),
      {empty: APPROVAL_FILTER === 'mine' ? 'Nothing is waiting on the cases you have taken. Take a case from Cases to see its actions here.' : 'Nothing is waiting for approval.'}) +
      pager(APPROVAL_OFFSET, xs.length, total, 'approvalPage', 'actions'), {flush: true})));
}
// Approve / Reject only where this person's approval can count: a high-impact action needs a lead, and the first
// approver of a four-eyes action waits for someone else (the server refuses both anyway; the screen says so up front)
function decideButtons(x, ...back) {
  if (!['recommended', 'pending_approval'].includes(x.status) || !can('approve_action')) return '';
  const r = x.result || {}, reject = btn('Reject', 'act', [x.id, 'reject', ...back], 'sm');
  if (r.high_impact && !can('approve_high_impact')) return `<span class="small muted" title="High-impact action: a lead approves it">Needs a lead's approval</span>${reject}`;
  if (r.awaiting_second_approval && x.status === 'pending_approval' && String(x.approver || '').toLowerCase() === String(window.ME.id || '').toLowerCase())
    return `<span class="small muted">You approved first - a second lead must approve</span>`;
  return btn('Approve', 'act', [x.id, 'approve', ...back], 'sm primary') + reject;
}
// what an action was raised on: its case (severity and title) or, for a remediation ticket, its campaign
const actOrigin = x => x.case ? `<div class="t-sub origin">${chip(x.case.severity)} ${caseLink(x.case.id, x.case.title)}</div>`
  : x.campaign ? `<div class="t-sub origin">Remediation campaign ${go('#/vulnerabilities', x.campaign.cve || x.campaign.title)} · ${esc(cap(x.campaign.status))}</div>` : '';
// a ticket has no targets: the team it goes to is who it acts on
const actTargets = x => x.targets.length ? moreList(x.targets.map(t => esc(t.name || t.recipient || t.id)))
  : (x.params || {}).group ? `<span class="muted">team</span> ${esc(x.params.group)}` : '<span class="muted">-</span>';
// "Why and what": the evidence the action cites, what the tool will be asked to do and the impact - fetched on first open
async function actDetail(id) {
  const row = document.getElementById('ad-' + id);
  if (!row) return;
  const open = row.hidden;
  row.hidden = !open;
  const b = document.querySelector(`[aria-controls="ad-${CSS.escape(id)}"]`);
  if (b) b.setAttribute('aria-expanded', String(open));
  if (!open || row.dataset.loaded) return;
  const box = row.querySelector('.adbox');
  box.innerHTML = '<div class="small muted">Loading…</div>';
  const c = await api('/api/v1/actions/' + encodeURIComponent(id) + '/context');
  row.dataset.loaded = '1';
  box.innerHTML = actContext(c);
}
function actContext(c) {
  const a = c.action, p = a.params || {};
  const shown = new Set(['title', 'description', 'group', 'correlation_id']);
  const extra = Object.entries(p).filter(([k, v]) => !shown.has(k) && v !== null && v !== '' && typeof v !== 'object');
  const why = c.evidence.length ? c.evidence.map(e => `<div class="list-row small" style="align-items:flex-start"><span class="mono strong" style="min-width:34px">${esc(e.ref)}</span>
      <div class="grow">${esc(e.summary)}<div class="t-sub">${esc(e.source)}${e.observed_at ? ' · ' + dt(e.observed_at) : ''}${e.type === 'inference' ? ' · inference' : ''}</div></div></div>`).join('')
    : `<div class="small muted">${c.campaign ? `Raised by the remediation campaign for ${esc(c.campaign.cve || c.campaign.title)}: priority, owner and due date come from the scanner findings in the ticket.`
      : c.case ? 'This action cites no case evidence; see the case for the full picture.' : 'Raised outside a case from the findings named in the request below.'}</div>`;
  const targets = a.targets.map(t => `<div class="list-row small"><span class="grow" style="overflow-wrap:anywhere">${esc(t.name || t.recipient || t.value || t.id)}</span>
      ${t.criticality ? `<span class="muted">${esc(t.criticality)}</span>` : ''}${(t.tags || []).map(g => `<span class="tag">${esc(g)}</span>`).join('')}</div>`).join('');
  const impact = [c.destructive ? chip('destructive', 'high plain') : '', c.reversible ? chip('reversible', 'ok plain') : chip('not reversible', 'plain'),
    c.blast_radius ? `<span class="small">blast radius: ${esc(c.blast_radius)}</span>` : '', c.expected_impact ? `<span class="small">${esc(c.expected_impact)}</span>` : ''].filter(Boolean).join(' ');
  return `<div class="grid g-2 adgrid">
    <div><div class="small strong">Why</div>${actOrigin(c)}<div class="mt-s">${why}</div></div>
    <div><div class="small strong">What happens if approved</div>
      <div class="small" style="margin:4px 0">${esc(c.description || a.action_type)}${c.tool ? ` - via <b>${esc(c.tool)}</b>` : ''}</div>
      ${targets}${p.group ? `<div class="small">Sent to team <b>${esc(p.group)}</b>${p.priority ? ` · priority ${esc(p.priority)}` : ''}</div>` : ''}
      ${p.title || p.description ? `<div class="adpre"><div class="strong">${esc(p.title || '')}</div>${esc(p.description || '')}</div>` : ''}
      ${extra.length ? `<dl class="kv small">${extra.map(([k, v]) => `<dt>${esc(cap(k))}</dt><dd>${esc(v)}</dd>`).join('')}</dl>` : ''}
      <div class="inline mt-s" style="flex-wrap:wrap;gap:6px">${impact}</div>
      ${(a.policy_reasons || []).map(r => `<div class="t-sub">${esc(r)}</div>`).join('')}
      ${c.precondition_failures.length ? `<div class="t-sub" style="color:var(--high)">Preconditions not met: ${esc(c.precondition_failures.join('; '))}</div>` : ''}
      <div class="t-sub mt-s">Recommended by ${esc(a.requested_by)} · ${dt(a.created_at)}</div></div></div>`;
}
function approvalFilter(f) { APPROVAL_FILTER = f; APPROVAL_OFFSET = 0; Approvals(); }
function approvalPage(o) { APPROVAL_OFFSET = Math.max(0, Number(o) || 0); Approvals(); }

// ================================================================= Phishing
async function Phishing() {
  const __g = GEN;
  const m = await api('/api/v1/phishing/metrics');
  const clickers = Object.entries(m.clickers || {}).sort((a, b) => b[1] - a[1]);
  setMainG(__g, page('Phishing', 'User-reported email: analysis, campaign scope, who clicked, endpoint and identity impact, gated remediation.',
    (can('investigate') ? btn('Pull reporting mailbox', 'runPh', [], '', 'refresh') : '') + go('#/suppliers', 'Supplier risk', 'btn'),
    `<div class="grid g-kpi">${kpi('Reported', nf(m.reported))}${kpi('Auto-closed', nf(m.auto_closed), `${nf(m.sampled_for_qa)} sampled for QA`)}
      ${kpi('Campaigns', nf(m.campaigns))}${kpi('Repeat clickers', nf((m.repeat_clickers || []).length), '', (m.repeat_clickers || []).length > 0)}
      ${kpi('Time to containment', m.time_to_containment_minutes && m.time_to_containment_minutes.median != null ? Math.round(m.time_to_containment_minutes.median) + ' min' : '–', m.time_to_containment_minutes && m.time_to_containment_minutes.median != null ? 'median, report to first containment' : 'no containment executed yet')}</div>
    <div class="grid g-3 mt">
      ${card('Verdict mix', donut(m.verdict_mix, {malicious: 'var(--c-critical)', suspicious: 'var(--c-high)', spam: 'var(--c-medium)', safe: 'var(--c-low)'}))}
      ${card('Users who clicked', hbars(clickers.slice(0, 8).map(([u, n]) => ({label: u, values: {clicks: n}})), ['clicks'],
        {label: 'clicks per user', empty: 'No clicks recorded'}), {sub: (m.repeat_clickers || []).length ? `${(m.repeat_clickers || []).length} clicked more than one campaign` : 'campaigns clicked per user'})}
      ${can('investigate') ? card('Analyse a message', `<div class="stack" style="gap:10px"><input type="file" id="eml" aria-label="Email file to analyse (.eml)" accept=".eml,message/rfc822" class="input" style="padding:5px">
        ${btn('Analyse', 'upload', [], 'primary')}<div class="small muted">The original is stored encrypted; the verdict, evidence and recommended actions open as a case.</div></div>`) : ''}
    </div>
    <div class="grid g-2 mt">
      ${card('Most active reporters', hbars((m.top_reporters || []).map(([u, n]) => ({label: u, values: {reports: n}})), ['reports'],
        {label: 'reports per person', empty: 'No reports yet'}), {sub: 'people who report suspicious e-mail - worth recognising'})}
      ${card('How reports were handled', hbars([{label: 'Closed automatically (QA-sampled)', values: {safe: m.auto_closed || 0}},
        {label: 'Analysed by the platform', values: {reports: Math.max(0, (m.reported || 0) - (m.auto_closed || 0))}},
        {label: 'Part of a campaign', values: {suspicious: m.campaigns || 0}}], ['safe', 'reports', 'suspicious'], {label: 'report handling'}))}
    </div>`));
}
async function upload() {
  const f = $('#eml').files[0]; if (!f) { toast('Choose an .eml file first', true); return; }
  const fd = new FormData(); fd.append('file', f);
  const r = await fetch('/api/v1/phishing/submit', {method: 'POST', headers: {Authorization: 'Bearer ' + TOKEN}, body: fd});
  if (!r.ok) { toast((await r.text()).slice(0, 200), true); return; }
  const v = await r.json(); toast('Analysis complete'); location.hash = '#/cases/' + (v.case ? v.case.id : v.case_id);
}

async function Suppliers() {
  const __g = GEN;
  const r = await api('/api/v1/phishing/suppliers?days=90');
  const st = {ok: 'ok', watch: 'medium', at_risk: 'high', critical: 'critical'};
  setMainG(__g, page('Supplier risk', `Vendor email compromise, impersonation and payment-diversion signals for ${r.configured} key suppliers over ${r.window_days} days. Suppliers are configured in <code>config/suppliers.yaml</code>.`, '',
    `<div class="stack">${Object.entries(r.suppliers).map(([n, v]) => card(`${esc(n)}`, v.findings.map(f => `<div class="list-row" style="align-items:flex-start">${chip(f.severity)}
        <div class="grow"><div class="t-title">${esc(cap(f.type.replace('supplier_', '')))}</div><div class="t-sub">${esc(f.detail)}</div><div class="t-sub">${esc(f.sender)} · ${caseLink(f.case_id, 'open case')}</div></div></div>`).join('') || `<span class="muted small">No findings. ${nf(v.messages || 0)} message(s) analysed.</span>`,
      {sub: `${esc(v.domains.join(', '))} · criticality ${esc(v.criticality)}`, right: `<span class="chip ${st[v.status]}">${esc(cap(v.status))}</span>`})).join('')}</div>`));
}

// ================================================================= Vulnerabilities
// a list a person can take in at real-tenant volume: the count, the first few, how many more (the rest on hover)
const names = (xs, n = 6) => !xs || !xs.length ? 'none' : `<b>${nf(xs.length)}</b> · ${moreList(xs.map(esc), n, ', ', k => `and ${nf(k)} more`)}`;
async function Vulnerabilities(id) {
  if (id) return VulnDetail(id);
  const __g = GEN;
  const [m, f, cov] = await Promise.all([api('/api/v1/vm/metrics'), api('/api/v1/vm/findings'), api('/api/v1/vm/coverage')]);
  const acts = (can('investigate') ? btn('Refresh from scanners', 'vmRefresh', [], '', 'refresh') + btn('Sync tickets', 'ticketSync', [], '') : '') + go('#/cloud', 'Cloud posture', 'btn');
  setMainG(__g, page('Vulnerabilities', 'Rapid7, CrowdStrike, Wiz and Defender findings resolved to one record per asset and CVE, prioritised on exploitability and exposure.', acts,
    `<div class="grid g-kpi">${kpi('Open findings', nf(m.open))}${kpi('CISA KEV', nf(m.kev_open), 'known exploited', m.kev_open > 0)}
      ${kpi('Internet-exposed', nf(m.internet_exposed_open))}${kpi('Past SLA', nf(m.sla_breached), '', m.sla_breached > 0)}${kpi('Asset match rate', pct(m.asset_match_rate, 1), 'across scanners')}</div>
    <div class="grid g-3 mt">
      ${card('Open by priority', donut(m.by_priority, CHART_COLOR), {sub: 'exploitability, exposure, criticality'})}
      ${card('Open findings by team', hbars(Object.entries(m.per_team || {}).filter(([, v]) => v.open).sort((a, b) => b[1].open - a[1].open)
        .map(([t, v]) => ({label: t, values: {'past SLA': v.sla_breached || 0, 'within SLA': (v.open || 0) - (v.sla_breached || 0)}})), ['past SLA', 'within SLA'],
        {label: 'open findings by team', empty: 'No open findings'}))}
      ${card('Age of open findings', columns(['0-7', '8-30', '31-90', '90+'].map((k, i) => ({label: k + ' d', value: (m.ageing || {})[k] || 0,
        color: ['var(--c-low)', 'var(--c-medium)', 'var(--c-high)', 'var(--c-critical)'][i]})), {label: 'open findings by age'}), {sub: 'days since first seen'})}
    </div>
    <div class="grid g-2 mt">
      ${card('Ask about exposure', `<div class="inline"><input class="input" style="flex:1;min-width:260px" id="vq" data-enter="vmAsk" placeholder="e.g. which internet-facing hosts have KEV vulnerabilities?">${btn('Query', 'vmAsk', [], 'primary')}</div><div id="vqa"></div>`)}
      ${card('Coverage gaps', `<dl class="kv"><dt>No EDR</dt><dd>${names(cov.missing_edr)}</dd><dt>Not in CMDB</dt><dd>${names(cov.not_in_cmdb)}</dd><dt>Resolution queue</dt><dd>${nf(cov.unresolved_queue)}</dd></dl>`)}
    </div>
    <div class="mt">${card(`Findings <span class="muted">(${f.length})</span>`, table(['Priority', 'CVE', 'Asset', 'Owner', 'SLA due', 'Seen by', 'Status', ''], f.map(x => `<tr>
      <td>${pchip(x.priority)}</td><td class="mono"><a href="#/vulnerabilities/${encodeURIComponent(x.id)}" title="Details: CVE, priority, scanners, fix">${esc(x.cve)}</a></td>
      <td><div class="t-title">${x.asset_id ? entLink(x.asset_id, x.asset) : esc(x.asset)}</div>${x.internet_exposed ? '<div class="t-sub">internet-exposed</div>' : ''}</td>
      <td class="small">${esc(x.team || 'unknown')}</td><td class="mono small">${day(x.sla_due)}</td><td class="small muted">${esc(Object.keys(x.sources).join(', '))}</td><td>${esc(cap(x.status))}</td>
      <td>${x.campaign_id ? '<span class="muted small">In campaign</span>' : can('request_action') ? btn('Start campaign', 'campaign', [x.cve], 'sm') : ''}</td></tr>`), {empty: 'No findings - refresh from scanners.'}), {flush: true})}</div>`));
}
async function vmRefresh() { toast('Refreshing from scanners…'); await post('/api/v1/vm/refresh'); toast('Vulnerability data refreshed'); Vulnerabilities(); }
async function ticketSync() { const r = await post('/api/v1/vm/tickets/sync'); toast(`Tickets checked ${r.checked} · verified ${r.verified} · false closures ${r.false_closures}`); }
async function campaign(cve) { const r = await post('/api/v1/vm/campaigns', {cve, notify_via: 'ticket'}); toast(`Campaign created for ${cve}; notifications await approval`); Vulnerabilities(...route().params); return r; }
// how each input moved the priority score (the components are computed by the platform and add up to the score)
const PRIORITY_INPUTS = [['cvss_component', 'CVSS base score', f => f.cvss], ['epss_component', 'Exploit likelihood (EPSS)', f => f.epss != null ? pct(f.epss, 1) : null],
  ['kev_component', 'Known exploited (CISA KEV)', f => f.kev ? 'yes' : 'no'], ['exposure_component', 'Internet-exposed', f => f.internet_exposed ? 'yes' : 'no'],
  ['criticality_component', 'Asset criticality', f => f.asset_criticality], ['ransomware_component', 'Used in ransomware', f => f.ransomware_use ? 'yes' : 'no']];
// the official pages behind the figures: NVD (description, CVSS), CISA's KEV catalogue, FIRST's EPSS score -
// built from a well-formed CVE id only
const cveSources = (cve, i) => {
  if (!/^CVE-\d{4}-\d{4,7}$/.test(cve || '')) return '';
  const a = (href, label) => `<a target="_blank" rel="noopener noreferrer" href="${esc(href)}">${esc(label)}</a>`;
  return `<div class="small strong mt-s">Sources</div><div class="inline small" style="flex-wrap:wrap;gap:6px 14px">
    ${a(`https://nvd.nist.gov/vuln/detail/${cve}`, 'NVD record (description, CVSS)')}
    ${i.kev ? a(`https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${cve}`, 'CISA KEV catalogue') : ''}
    ${a(`https://api.first.org/data/v1/epss?cve=${cve}`, 'FIRST EPSS score')}
    ${a(`https://www.cve.org/CVERecord?id=${cve}`, 'CVE.org record')}</div>`;
};
async function VulnDetail(id) {
  const __g = GEN;
  const f = await api('/api/v1/vm/findings/' + encodeURIComponent(id));
  const i = f.intel || {}, fx = f.factors || {};
  const overdue = f.sla_due && f.status !== 'closed' && new Date(f.sla_due) < new Date();
  const inputs = PRIORITY_INPUTS.filter(([k]) => fx[k] != null).map(([k, label, v]) => `<tr><td>${esc(label)}</td><td class="mono">${esc(v(fx) ?? '–')}</td><td class="num mono">+${esc(Number(fx[k]).toFixed(3))}</td></tr>`);
  const others = Object.entries(fx).filter(([k, v]) => k.endsWith('_component') && !PRIORITY_INPUTS.some(([p]) => p === k) && v != null)
    .map(([k, v]) => `<tr><td>${esc(cap(k.replace(/_component$/, '').replace(/_/g, ' ')))}</td><td></td><td class="num mono">+${esc(Number(v).toFixed(3))}</td></tr>`);
  const seen = Object.entries(f.sources || {}).map(([t, d]) => `<tr><td><span class="tag">${esc(t)}</span></td><td>${esc(cap(d.status || '–'))}</td>
    <td class="mono small">${dt(d.last_seen)}</td><td class="mono small">${esc(d.cvss ?? '–')}</td><td class="small">${esc(d.product || '–')}${d.tool_exception ? '<div class="t-sub">exception held in the tool</div>' : ''}</td>
    <td>${d.deep_link ? `<a target="_blank" rel="noopener noreferrer" href="${esc(safeUrl(d.deep_link))}">open in tool</a>` : ''}</td></tr>`);
  const acts = f.campaign ? '' : can('request_action') && f.status !== 'closed' ? btn('Start campaign', 'campaign', [f.cve], 'primary') : '';
  setMainG(__g, `<div class="page-head"><div class="ph-main"><div class="inline" style="margin-bottom:8px">${pchip(f.priority)}${i.kev ? chip('known exploited', 'critical') : ''}${f.internet_exposed ? chip('internet-exposed', 'high plain') : ''}<span class="tag">${esc(cap(f.status))}</span></div>
      <h1 class="mono">${esc(f.cve)}</h1><p>${esc(f.title || f.product || '')}${f.title && f.product ? ' · ' + esc(f.product) : ''} on ${f.asset_id ? entLink(f.asset_id, f.asset) : esc(f.asset)}</p></div>
      ${acts ? `<div class="actions">${acts}</div>` : ''}</div>
    <div class="grid g-kpi">${kpi('Priority score', Number(f.score).toFixed(3), esc(f.priority) + ' · computed below')}${kpi('CVSS', i.cvss ?? '–', esc(cap(i.severity || '')))}
      ${kpi('Exploit likelihood', i.epss != null ? pct(i.epss, 1) : '–', i.epss_percentile != null ? 'EPSS, ' + pct(i.epss_percentile, 0) + ' percentile' : 'EPSS')}
      ${kpi('CISA KEV', i.kev ? 'Listed' : 'Not listed', i.kev ? `added ${esc(i.kev_date_added || '–')}${i.kev_due ? ' · federal due ' + esc(i.kev_due) : ''}` : '', !!i.kev)}
      ${kpi('SLA due', day(f.sla_due), overdue ? 'past due' : f.sla_due ? 'open' : '', overdue)}</div>
    <div class="grid g-2 mt"><div class="stack">
      ${card('About this vulnerability', `<div class="prose">${esc(i.description || 'No description from NVD yet.')}</div>${i.ransomware_use ? '<div class="t-sub" style="color:var(--high);margin-top:6px">Known to be used in ransomware campaigns (CISA KEV).</div>' : ''}
        ${cveSources(f.cve, i)}
        ${(i.exploit_refs || []).length ? `<div class="small strong mt-s">Public exploit references <span class="muted" style="font-weight:400">(links NVD tags “Exploit”)</span></div>${moreList(i.exploit_refs.map(u => `<a target="_blank" rel="noopener noreferrer" style="overflow-wrap:anywhere" href="${esc(safeUrl(u))}">${esc(u)}</a>`), 3)}` : ''}`,
        {sub: i.fetched_at ? 'NVD, EPSS and CISA KEV · fetched ' + dt(i.fetched_at) : 'NVD, EPSS and CISA KEV'})}
      ${card('Why this priority', table(['Input', 'Value', 'Adds'], [...inputs, ...others, `<tr><td class="strong">Priority score</td><td>${pchip(f.priority)}</td><td class="num mono strong">${esc(Number(f.score).toFixed(3))}</td></tr>`]), {flush: true, sub: 'computed by the platform, not the model'})}
      ${card('Seen by', table(['Scanner', 'Status', 'Last seen', 'CVSS', 'Product', ''], seen, {empty: 'No scanner record'}), {flush: true, sub: 'one finding, consolidated from every tool that reports it'})}
    </div><div class="stack">
      ${card('Fix', `<div class="prose">${esc(f.remediation || 'No fix published by the scanners yet - apply the vendor fix or upgrade.')}</div>
        <div class="t-sub mt-s">${f.campaign ? `In remediation campaign “${esc(f.campaign.title)}” · ${esc(cap(f.campaign.status))}${f.campaign.target_date ? ' · target ' + day(f.campaign.target_date) : ''}` : 'Not in a remediation campaign yet.'}</div>`)}
      ${card('Ownership', `<dl class="kv"><dt>Owner</dt><dd>${esc(f.owner || 'unknown')}</dd><dt>Team</dt><dd>${esc(f.team || 'unknown')}</dd><dt>Environment</dt><dd>${esc(f.environment || '–')}</dd>
        <dt>Criticality</dt><dd>${esc(f.criticality || '–')}</dd><dt>Location</dt><dd>${esc(f.location || '–')}</dd></dl>`)}
      ${card('History', `<dl class="kv"><dt>First seen</dt><dd>${dt(f.first_seen)}</dd><dt>Last seen</dt><dd>${dt(f.last_seen)}</dd><dt>Reopened</dt><dd>${nf(f.reopened_count)} time(s)</dd>${f.closed_at ? `<dt>Closed</dt><dd>${dt(f.closed_at)}</dd>` : ''}</dl>
        ${f.validations.length ? `<div class="small strong mt-s">Fix validations</div>` + f.validations.map(v => `<div class="list-row small"><span class="grow">${esc(cap(v.result))}${v.false_closure ? ' - <b>false closure</b> (ticket closed, scanners still see it)' : ''}</span><span class="muted">${dt(v.checked_at)}</span></div>`).join('') : ''}
        ${f.exceptions.length ? `<div class="small strong mt-s">Exceptions</div>` + f.exceptions.map(e => `<div class="list-row small"><span class="grow">${esc(cap(e.status))}: ${esc(e.justification)}<div class="t-sub">${esc(e.requested_by)}${e.approver ? ' · approved by ' + esc(e.approver) : ''} · until ${day(e.expires_at)}</div></span></div>`).join('') : ''}`)}
      ${card(`Same CVE on other assets <span class="muted">(${f.other_assets.length})</span>`, f.other_assets.map(o => `<div class="list-row">${pchip(o.priority)}<span class="grow"><a href="#/vulnerabilities/${encodeURIComponent(o.id)}">${esc(o.asset)}</a><div class="t-sub">${esc(o.team || 'unknown team')}</div></span><span class="small muted">${esc(cap(o.status))}</span></div>`).join('') || empty('Only this asset'))}
    </div></div>`);
}
async function vmAsk() {
  const q = $('#vq').value.trim(); if (!q) return;
  const r = await post('/api/v1/vm/query', {question: q});
  $('#vqa').innerHTML = `<div class="divider"></div><div>${esc(r.answer)}</div><div class="small muted mt">Filter used: <code>${esc(JSON.stringify(r.generated_filter))}</code></div>
    <div class="mt">${table(['CVE', 'Asset', 'Priority', 'Owner'], r.records.slice(0, 20).map(x => `<tr><td class="mono">${esc(x.cve)}</td><td>${esc(x.asset)}</td><td>${pchip(x.priority)}</td><td class="small">${esc(x.team || '')}</td></tr>`), {empty: 'No matching records'})}</div>`;
}

async function Cloud() {
  const __g = GEN;
  const [r, own] = await Promise.all([api('/api/v1/vm/misconfigurations'), api('/api/v1/ownership')]), m = r.metrics;
  setMainG(__g, page('Cloud posture', 'Wiz misconfigurations run through the remediation lifecycle: owner, SLA, ticket, and closure validated against Wiz.',
    can('request_action') ? btn('Route to owners', 'misRoute', [], 'primary') : '',
    `<div class="grid g-kpi">${kpi('Open', nf(m.open))}${kpi('Past SLA', nf(m.overdue), '', m.overdue > 0)}${kpi('False closures', nf(m.false_closures), 'fix claimed, Wiz still reports it', m.false_closures > 0)}
      ${kpi('Teams involved', nf(Object.keys(m.by_team).length))}</div>
    <div class="grid g-2 mt">
      ${card('Open by severity', donut(r.items.reduce((a, x) => (a[x.severity] = (a[x.severity] || 0) + 1, a), {})))}
      ${card('Open by owner', hbars(Object.entries(r.items.reduce((a, x) => { const k = x.owner || 'unassigned'; a[k] = a[k] || {overdue: 0, 'on time': 0};
          a[k][x.sla_due && new Date(x.sla_due) < new Date() ? 'overdue' : 'on time'] += 1; return a; }, {})).map(([k, v]) => ({label: k, values: v})),
        ['overdue', 'on time'], {label: 'misconfigurations by owner', empty: 'No open misconfiguration'}))}
    </div>
    <div class="mt">${card('Misconfigurations', table(['Severity', 'Rule', 'Resource', 'Owner', 'Status', 'SLA due', ''], r.items.map(x => `<tr>
      <td>${chip(x.severity)}</td><td class="small">${esc(x.rule)}</td><td><div class="t-title">${esc(x.resource)}</div><div class="t-sub">${esc(x.resource_type)} · ${esc(x.cloud)} ${esc(x.subscription)}</div></td>
      <td class="small">${esc(x.platform_team || 'Unknown owner')}</td><td class="nowrap">${esc(cap(x.status))}${x.reopened ? ` ${chip('reopened ' + x.reopened, 'high plain')}` : ''}</td>
      <td class="mono small nowrap" style="${x.overdue ? 'color:var(--crit)' : ''}">${day(x.sla_due)}</td>
      <td><div class="inline">${can('investigate') ? btn('Mark fixed', 'misVerb', [x.id, 'fixed'], 'sm') + btn('Validate', 'misVerb', [x.id, 'validate'], 'sm') : ''}</div></td></tr>`), {empty: 'No misconfigurations'}), {flush: true})}</div>
    <div class="mt">${ownershipCard(own, r.items.filter(x => !x.platform_team).length)}</div>`));
}
function ownershipCard(o, unowned) {
  const manage = can('manage_ownership'), SHOW = 200;
  const head = o.count ? `Version ${nf(o.version)} · ${nf(o.count)} row(s) from ${esc(o.filename || 'an upload')} · by ${esc(o.set_by)} on ${day(o.set_at)}${o.note ? ` - ${esc(o.note)}` : ''}`
    : 'No mapping uploaded - owners come only from the CMDB connectors.';
  const rows = table(['Resource / host', 'Subscription / account', 'Cloud · type', 'Team', 'Owner', 'Env · criticality'], o.rows.slice(0, SHOW).map(x => `<tr>
      <td class="mono small" style="overflow-wrap:anywhere;max-width:240px">${esc(x.name || '-')}</td><td class="mono small" style="overflow-wrap:anywhere;max-width:200px">${esc(x.subscription || '-')}</td>
      <td class="small">${esc([x.cloud, x.resource_type].filter(Boolean).join(' · ') || 'any')}</td><td class="small strong">${esc(x.team)}</td>
      <td class="small">${esc(x.owner || '')}</td><td class="small">${esc([x.environment, x.criticality].filter(Boolean).join(' · '))}</td></tr>`), {empty: 'No rows.'})
    + (o.count > SHOW ? `<div class="t-sub" style="padding:8px 16px">The first ${nf(SHOW)} of ${nf(o.count)} are shown - export the mapping for all of them.</div>` : '');
  const form = manage ? `<div class="stack" style="gap:10px;padding:12px 16px">
      <input type="file" id="own-file" class="input" style="padding:5px" aria-label="Excel or CSV ownership file" accept=".xlsx,.csv,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,text/csv">
      <input class="input" id="own-note" maxlength="500" aria-label="Why" placeholder="Why (kept in the audit log)">
      <div class="inline" style="gap:8px">${btn('Preview', 'ownUpload', [true], '')}${btn('Upload and apply', 'ownUpload', [false], 'primary')}${o.count ? btn('Clear the mapping', 'ownClear', [], 'ghost') : ''}</div>
      <div class="t-sub">Excel (.xlsx - every sheet) or CSV, up to ${nf(o.max_rows)} rows; an upload replaces the mapping (the history is kept). A header row names the columns:
        <b>Resource</b> / <b>Hostname</b> (wildcards <span class="mono">*</span> <span class="mono">?</span> allowed) and/or <b>Subscription</b> / <b>Account</b> / <b>Project</b>, the <b>Team</b> (required),
        and optionally <b>Owner</b>, <b>Environment</b>, <b>Criticality</b> (critical, high, medium, low), <b>Cloud</b> and <b>Resource type</b> to narrow a row.
        An exact name beats a pattern, a pattern beats a subscription. It fills the gaps the CMDB leaves and never overrides it.</div>
      <div id="own-out"></div></div>` : '';
  return card(`Ownership mapping <span class="muted">(${nf(o.count)})</span>`,
    `<div class="small muted" style="padding:12px 16px 4px">${head}${unowned ? ` · <b>${nf(unowned)}</b> open misconfiguration(s) have no owner` : ''}</div>${form}${rows}`,
    {flush: true, sub: 'which team owns which cloud resources and hosts - for what the CMDB does not hold (Wiz resources)',
     right: btn('Export CSV', 'dl', ['/api/v1/ownership/export'], 'sm', 'download')});
}
async function ownUpload(dry) {
  const f = ($('#own-file') || {}).files?.[0];
  if (!f) { toast('Choose an Excel or CSV file first', true); return; }
  if (f.size > 5e6) { toast('The file is larger than 5 MB - split it', true); return; }
  if (!dry && !confirm(`Replace the ownership mapping with ${f.name}? The previous version stays in the history.`)) return;
  const bytes = new Uint8Array(await f.arrayBuffer()); let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  const r = await post('/api/v1/ownership/upload', {content_b64: btoa(bin), filename: f.name, note: $('#own-note').value.trim(), dry_run: !!dry});
  const c = r.coverage || {};
  const html = `<div class="callout ${r.problem_count ? '' : 'info'}"><div><b>${dry ? 'Preview - nothing has changed yet' : 'Uploaded and applied'}.</b>
      ${nf(r.rows)} row(s) for ${nf(Object.keys(r.by_team).length)} team(s): ${nf(r.added)} new, ${nf(r.removed)} no longer in the file.
      ${c.misconfigurations_without_owner != null ? `It gives an owner to ${nf(c.misconfigurations_covered)} of ${nf(c.misconfigurations_without_owner)} unowned misconfiguration(s) and ${nf(c.findings_covered)} of ${nf(c.findings_without_owner)} unowned finding(s).` : ''}
      ${(c.still_without_owner || []).length ? `<div class="small mt">Still without an owner: <span class="mono">${c.still_without_owner.map(esc).join(', ')}</span></div>` : ''}
      ${r.problem_count ? `<div class="small strong mt">${nf(r.problem_count)} row(s) cannot be used:</div><ul class="small" style="margin:4px 0;padding-left:18px">${r.problems.slice(0, 50).map(p => `<li>${esc(p.where || '')}: <span class="mono">${esc(p.value)}</span> - ${esc(p.problem)}</li>`).join('')}</ul>` : ''}</div></div>`;
  if (!dry) { toast('Ownership mapping updated - owners re-applied'); await Cloud(); }
  const out = $('#own-out'); if (out) out.innerHTML = html;
}
async function ownClear() {
  const why = prompt('Clear the ownership mapping? Owners then come only from the CMDB. Why?');
  if (why === null) return;
  await post('/api/v1/ownership/clear', {reason: why});
  toast('Ownership mapping cleared'); Cloud();
}
async function misRoute() { const r = await post('/api/v1/vm/misconfigurations/route'); toast(Object.keys(r.routed).length ? `Routed to ${Object.keys(r.routed).join(', ')} - tickets await approval` : 'Nothing new to route'); Cloud(); }
async function misVerb(id, verb) { const r = await post(`/api/v1/vm/misconfigurations/${id}/${verb}`); toast(r.result ? `Validation: ${cap(r.result)}${r.false_closure ? ' (false closure - reopened)' : ''}` : `Marked ${cap(r.status)}`); Cloud(); }

// ================================================================= Coverage & Shadow IT
async function Coverage() {
  const __g = GEN;
  const c = await api('/api/v1/dashboard/attack-coverage'), s = c.summary;
  setMainG(__g, page('ATT&CK coverage', `What the enabled tools can detect, and what has actually fired. Tools: ${esc(c.enabled_detection_tools.join(', '))}.`, '',
    `<div class="grid g-kpi">${kpi('Weighted coverage', s.weighted_coverage_pct + '%', `${s.covered} of ${s.techniques} techniques`)}${kpi('Priority blind spots', nf(s.priority_blind_spots), 'no enabled tool detects these', s.priority_blind_spots > 0)}
      ${kpi('Single-source', nf(s.single_source_priority), 'one tool down = blind')}${kpi('Firing', nf(s.firing), 'observed in alerts and cases')}</div>
    <div class="mt">${card('Matrix', `<div class="legend" style="margin:0 0 12px"><span><i style="background:var(--low-bd)"></i>Full</span><span><i style="background:var(--med-bd)"></i>Partial</span><span><i style="background:var(--crit-bd)"></i>Priority blind spot</span><span>● times observed · hover for tools</span></div>
      <div class="matrix">${c.tactics.map(t => `<div class="tactic"><div class="col-h">${esc(t.name)}<small>${t.coverage_pct}%</small></div>
        ${t.techniques.map(x => `<div class="tech ${x.coverage === 'full' ? 'full' : x.coverage === 'partial' ? 'partial' : x.priority ? 'blind' : ''}" title="${esc(`${x.technique} ${x.name}\nDetected by: ${Object.entries(x.detected_by).map(([k, v]) => k + ' (' + v + ')').join(', ') || 'nothing enabled'}\nObserved: ${x.observed}`)}">
          ${x.observed ? `<span class="fired">●${x.observed}</span>` : ''}<b>${esc(x.technique)}</b>${esc(x.name)}</div>`).join('')}</div>`).join('')}</div>`)}</div>
    ${c.priority_blind_spots.length ? `<div class="mt">${card('Blind spots to close', c.priority_blind_spots.map(b => `<div class="list-row"><span class="tag">${esc(b.technique)}</span><span class="grow">${esc(b.name)}</span></div>`).join(''))}</div>` : ''}`));
}

async function ShadowIt() {
  const __g = GEN;
  const r = await api('/api/v1/dashboard/shadow-it?since=-7days');
  if (!r.available) { setMainG(__g, page('Shadow IT', esc(r.reason), '', '')); return; }
  const s = r.summary;
  setMainG(__g, page('Shadow IT', `Unsanctioned services and risky destinations from Umbrella DNS activity over the last ${esc(String(r.window).replace(/^-/, '').replace('days', ' days').replace('hours', ' hours'))}. Sanctioned services live in <code>config/sanctioned_services.yaml</code>; rows are aggregated, not stored.`, '',
    `<div class="grid g-kpi">${kpi('Unsanctioned services', nf(s.unsanctioned_services))}${kpi('High-risk services', nf(s.high_risk_services), '', s.high_risk_services > 0)}
      ${kpi('Users involved', nf(s.users_on_unsanctioned_services))}${kpi('Risky sites reached', nf(s.risky_destinations_reached), '', s.risky_destinations_reached > 0)}</div>
    <div class="grid g-2 mt">
      ${card('Unsanctioned services', table(['Service', 'Categories', 'Risk', {h: 'Users', num: 1}, {h: 'Requests', num: 1}, {h: 'Blocked', num: 1}], r.unsanctioned_services.map(x => `<tr>
        <td class="t-title">${esc(x.service)}</td><td class="small muted">${esc(x.categories.join(', '))}</td><td>${chip(x.risk)}</td><td class="num" title="${esc(x.user_list.join(', '))}">${x.users}</td><td class="num">${x.requests}</td><td class="num">${x.blocked}</td></tr>`)), {flush: true})}
      ${card('By category', Object.entries(r.by_category).map(([k, v]) => `<div class="list-row"><span class="grow">${esc(cap(k).replace(/\bai\b/i, 'AI').replace(/\bvpn\b/i, 'VPN'))}</span><span class="score">${v}</span></div>`).join('') || empty('None'), {sub: 'DNS requests'})}
    </div>
    <div class="mt">${card('Risky destinations', table(['Domain', 'Categories', 'Outcome', 'Users', 'Hosts'], r.risky_destinations.map(x => `<tr><td class="mono small">${esc(x.domain)}</td><td class="small">${esc(x.categories.join(', '))}</td>
      <td>${x.status === 'reached' ? status('critical', 'Reached') : status('ok', 'Blocked')}</td><td class="small">${esc(x.users.join(', '))}</td><td class="small">${esc(x.hosts.join(', '))}</td></tr>`)), {flush: true})}</div>`));
}

// ================================================================= Integrations
const STAGE_HELP = {fake: 'Sample data, no credentials', record: 'Live reads; responses saved (sanitised) as test fixtures; no actions',
  read: 'Live reads; recommendations appear as manual steps', recommend: 'Actions offered; a person approves every one (never above L2)',
  automate: 'Actions follow the automation policy'};
const STAGE_K = {fake: 'info', record: 'medium', read: 'medium', recommend: 'ok', automate: 'ok'};
const PF_K = {ok: 'ok', info: 'info', warning: 'medium', error: 'high', skipped: 'info'};
const fmtVal = v => v === null || v === undefined || v === '' ? '–' : typeof v === 'object' ? JSON.stringify(v) : String(v);
async function Integrations() {
  const __g = GEN;
  const canCheck = can('read_audit') && window.ME.domains.includes('*');
  const [cs, jr, sc, nt, cfg] = await Promise.all([api('/api/v1/dashboard/connectors'), api('/api/v1/jobs?limit=200'),
    canCheck ? api('/api/v1/admin/self-check') : Promise.resolve(null),
    canCheck ? api('/api/v1/admin/notifications') : Promise.resolve(null),
    can('read_audit') ? api('/api/v1/config/connectors') : Promise.resolve(null)]);
  window.__cfg = cfg;
  const byName = cfg ? Object.fromEntries(cfg.connectors.map(c => [c.name, c])) : {};
  const last = {}; jr.runs.forEach(r => { if (!last[r.job]) last[r.job] = r; });
  const stc = {healthy: 'ok', on_demand: 'info', stale: 'medium', error: 'high', misconfigured: 'high', disabled: 'info'};
  const jst = {ok: 'ok', error: 'high', dead_letter: 'critical'};
  const manage = can('manage_connectors');
  const pfCell = c => { const p = (byName[c.name] || {}).last_preflight; return p ? `<div class="t-sub">Preflight: ${status(p.ok ? (p.warnings ? 'medium' : 'ok') : 'high', cap(p.verdict))} <span class="muted">${dt(p.ran_at)}</span></div>` : ''; };
  const fileProblems = cfg && cfg.file_problems.length ? `<div class="callout danger mb"><div><b>Configuration file problems</b> - these entries are ignored until fixed (<span class="mono">python -m soc_platform config check</span> lists them all):
      ${cfg.file_problems.map(p => `<div class="small">${esc(p.where)}: ${esc(p.message)}${p.fix ? ' - ' + esc(p.fix) : ''}</div>`).join('')}</div></div>` : '';
  const pending = cfg && cfg.pending.length ? `<div class="mb">${card('Configuration changes awaiting approval', cfg.pending.map(v => pendingRow(v)).join(''), {sub: 'proposed by one person, approved by another; a newer approved change makes older proposals stale'})}</div>` : '';
  setMainG(__g, page('Integrations', 'Connect, roll out and monitor every security tool: stage, preflight checks, data freshness and scheduled jobs.',
    cfg ? `<span class="status-pill"><span class="dot"></span>Configuration version ${esc(cfg.active_version || 'file only')}</span>` : '',
    `${fileProblems}${pending}<div id="cfgpanel"></div>
    ${sc ? `<div class="mb">${card('Platform self-check', `<div class="inline" style="margin-bottom:${sc.ok ? 0 : 10}px">${status(sc.ok ? 'ok' : 'high', sc.ok ? 'Consistent' : 'Attention')}<span class="small">${sc.passed} of ${sc.total} checks pass - the same figures agree on every screen, report and answer; every stored reference resolves; nothing is duplicated; the audit chain verifies.</span></div>` +
      sc.checks.filter(c => !c.ok).map(c => `<div class="list-row small"><span class="grow"><b>${esc(c.check)}</b></span><span class="mono muted">${esc(JSON.stringify(c.detail)).slice(0, 160)}</span></div>`).join(''), {sub: 'runs hourly; a failure raises a finding'})}</div>` : ''}
    ${card(`Connectors <span class="muted">(${cs.filter(c => c.enabled).length} enabled)</span>`, table(['Tool', 'Stage', 'State', 'Streams · age / expected', ''], cs.map(c => `<tr>
      <td><div class="t-title">${esc(c.tool)}</div><div class="t-sub">${esc(c.name)} · ${esc(c.category)}</div></td>
      <td>${c.enabled ? `<span class="chip plain ${STAGE_K[c.stage] || ''}" title="${esc(STAGE_HELP[c.stage] || '')}">${esc(c.stage_label || c.stage || '')}</span>` : '<span class="muted small">Off</span>'}</td>
      <td>${status(stc[c.state] || 'info', cap(c.state))}${c.config_problems.map(p => `<div class="t-sub" style="color:var(--high)">${esc(p)}</div>`).join('')}${pfCell(c)}</td>
      <td class="small">${c.streams.map(s => `<div>${esc(s.stream)}: <span class="mono">${s.age_hours == null ? 'never' : hours(s.age_hours)}</span> <span class="muted">/ within ${s.expected_within_hours} h</span>${s.fresh ? '' : ' ' + chip('stale', 'medium plain')}${s.last_error ? `<div class="t-sub" style="color:var(--crit)">${esc(s.last_error)}</div>` : ''}</div>`).join('') || '<span class="muted">queried on demand during investigations</span>'}</td>
      <td><div class="inline" style="gap:6px;flex-wrap:wrap">${manage ? btn('Preflight', 'preflight', [c.name], 'sm') : ''}${manage && cfg ? btn('Configure', 'configure', [c.name], 'sm') : ''}${manage && cfg && c.enabled ? btn('Pause', 'pauseConn', [c.name], 'sm danger') : ''}</div></td></tr>`)), {flush: true, sub: 'Preflight checks sign-in, every permission, parsing, data freshness and volume before a tool is trusted'})}
    ${cfg ? `<div class="mt">${card('Configuration', configBody(cfg), {sub: 'file + approved console changes; secrets are never stored here'})}</div>` : ''}
    ${nt ? `<div class="mt">${card('Notifications', (nt.channels.length
        ? `<div class="small" style="margin-bottom:8px">Findings rated <b>${esc(nt.min_severity)}</b> or higher are sent to ${nt.channels.map(c => `<span class="tag">${esc(c)}</span>`).join(' ')} - once per channel, again if a finding escalates.</div>`
        : `<div class="small muted" style="margin-bottom:8px">No channels configured. Set <span class="mono">SOC_NOTIFY_WEBHOOKS</span> (Teams, Slack or JSON webhooks) to be told about important findings.</div>`) +
      (nt.recent.length ? table(['When', 'Channel', 'Severity', 'Outcome'], nt.recent.map(r => `<tr><td class="mono small muted">${dt(r.at)}</td><td class="small">${esc(r.channel)}</td><td>${chip(r.severity)}</td>
        <td>${status(r.status === 'sent' ? 'ok' : 'high', cap(r.status))}${r.error ? `<div class="t-sub" style="color:var(--high)">${esc(r.error.slice(0, 140))} · attempt ${r.attempts} of ${nt.max_attempts}</div>` : ''}</td></tr>`), {flush: true}) : '') +
      (nt.channels.length && manage ? `<div class="mt">${btn('Send test message', 'notifyTest', [])}</div>` : ''),
      {sub: 'sent by the notify job every minute'})}</div>` : ''}
    <div class="mt">${card('Scheduled jobs', table(['Job', 'Last run', 'Outcome', {h: 'Duration', num: 1}, 'Detail', ''], Object.keys(jr.jobs).map(j => { const r = last[j]; return `<tr>
      <td class="t-title">${esc(cap(j))}</td><td class="mono small muted">${r ? dt(r.started_at) : 'never'}</td>
      <td>${r ? status(jst[r.status], cap(r.status)) + `${r.attempts > 1 ? `<div class="t-sub">${r.attempts} attempts</div>` : ''}` : ''}</td>
      <td class="num small">${r && r.duration_s != null ? r.duration_s + ' s' : ''}</td><td class="small muted wrap">${r ? esc((r.error || JSON.stringify(r.summary)).slice(0, 140)) : ''}</td>
      <td>${manage ? btn('Run now', 'runJob', [j], 'sm') : ''}</td></tr>`; })), {flush: true, sub: 'retried with backoff; dead-lettered after 3 failed runs'})}</div>`));
}
function changeList(chs) {
  return chs.length ? table(['Tool', 'Setting', 'From', 'To'], chs.map(c => `<tr><td class="small">${esc(c.connector)}</td><td class="mono small">${esc(c.field)}</td>
    <td class="mono small muted wrap">${esc(fmtVal(c.from))}</td><td class="mono small wrap">${esc(fmtVal(c.to))}</td></tr>`), {flush: true}) : empty('No changes');
}
function pendingRow(v) {
  const mine = v.proposed_by === window.ME.id;
  const pf = Object.entries(v.preflight || {}).map(([n, p]) => `<span class="tag">${esc(n)}: ${esc(p.verdict)}${p.warnings ? ` (${p.warnings} warning${p.warnings > 1 ? 's' : ''})` : ''}</span>`).join(' ');
  return `<div class="list-row" style="display:block"><div class="inline" style="justify-content:space-between;flex-wrap:wrap;gap:8px">
      <div class="small"><b>#${esc(v.id)}</b> ${esc(cap(v.kind))} by ${esc(v.proposed_by)} <span class="muted">${dt(v.created_at)}</span>${v.note ? `<div class="t-sub">${esc(v.note)}</div>` : ''}${pf ? `<div class="t-sub">Preflight: ${pf}</div>` : ''}</div>
      <div class="inline" style="gap:6px">${can('approve_policy') && !mine ? btn('Approve', 'approveConfig', [v.id], 'sm primary') : ''}${can('approve_policy') && !mine ? btn('Reject', 'rejectConfig', [v.id], 'sm') : ''}${mine ? btn('Withdraw', 'rejectConfig', [v.id], 'sm') : ''}</div></div>
    <div class="mt">${changeList(v.changes)}</div></div>`;
}
function configBody(cfg) {
  const manage = can('manage_connectors');
  return `<div class="inline" style="flex-wrap:wrap;gap:8px;margin-bottom:10px">${btn('Export configuration', 'dl', ['/api/v1/config/export'], '', 'download')}
      ${manage ? btn('Import…', 'showImport', [], '') : ''}${btn('History', 'showHistory', [], '')}${btn('Suppliers & sanctioned services', 'showLists', [], '')}
      <span class="small muted">Stages: ${cfg.stages.map(s => `<span class="tag" title="${esc(STAGE_HELP[s.id])}">${esc(s.label)}</span>`).join(' ')}</span></div><div id="cfgextra"></div>`;
}
async function showHistory() {
  const h = await api('/api/v1/config/history?limit=30');
  $('#cfgextra').innerHTML = h.length ? table(['Version', 'Kind', 'Status', 'By', 'Approved by', 'Changes', ''], h.map(v => `<tr><td class="mono">#${esc(v.id)}</td><td class="small">${esc(cap(v.kind))}</td>
      <td>${status(v.status === 'active' ? 'ok' : v.status === 'proposed' ? 'medium' : 'info', cap(v.status))}</td><td class="small">${esc(v.proposed_by)}<div class="t-sub">${dt(v.created_at)}</div></td>
      <td class="small">${esc(v.approved_by || '–')}</td><td class="small">${moreList(v.changes.map(c => `<div><span class="mono">${esc(c.connector)}.${esc(c.field)}</span> → ${esc(fmtVal(c.to))}</div>`), 3, '')}</td>
      <td>${can('manage_connectors') && ['active', 'superseded'].includes(v.status) ? btn('Restore', 'restoreConfig', [v.id], 'sm') : ''}</td></tr>`), {flush: true}) : empty('No console changes yet - the file alone is in force.');
}
function showLists() {
  const L = window.__cfg.lists, manage = can('manage_connectors');
  const sup = L.suppliers.items.map(s => `${s.name} | ${s.domains.join(', ')} | ${s.criticality}`).join('\n');
  $('#cfgextra').innerHTML = `<div class="grid g-2e">
    <div class="stack" style="gap:6px"><label class="small" for="lsup"><b>Key suppliers</b> (vendor e-mail compromise) · from ${esc(L.suppliers.source)} · one per line: <span class="mono">Name | domain1, domain2 | low/medium/high</span></label>
      <textarea id="lsup" rows="10" class="mono" spellcheck="false"${manage ? '' : ' readonly'}>${esc(sup)}</textarea></div>
    <div class="stack" style="gap:6px"><label class="small" for="lsan"><b>Sanctioned services</b> (shadow IT) · from ${esc(L.sanctioned.source)} · one domain per line</label>
      <textarea id="lsan" rows="10" class="mono" spellcheck="false"${manage ? '' : ' readonly'}>${esc(L.sanctioned.items.join('\n'))}</textarea></div></div>
    ${manage ? `<div class="form-row mt"><input class="input" id="lnote" aria-label="Why" placeholder="Why (shown to the approver)">${btn('Propose lists', 'proposeLists', [], 'primary')}</div>` : ''}<div id="lout"></div>`;
}
async function proposeLists() {
  const suppliers = $('#lsup').value.split('\n').map(l => l.trim()).filter(Boolean).map(l => {
    const [name, doms, crit] = l.split('|').map(x => (x || '').trim());
    return {name, domains: (doms || '').split(',').map(d => d.trim()).filter(Boolean), criticality: (crit || 'medium').toLowerCase()};
  });
  const sanctioned = $('#lsan').value.split('\n').map(l => l.trim()).filter(Boolean);
  try {
    const v = await api('/api/v1/config/proposals', {method: 'POST', body: JSON.stringify({changes: {}, lists: {suppliers, sanctioned}, note: $('#lnote').value.trim()})});
    toast(`Proposed as version ${v.id} - another person approves it`); Integrations();
  } catch (e) { $('#lout').innerHTML = rejected(e); }
}
function showImport() {
  $('#cfgextra').innerHTML = `<div class="stack" style="gap:8px"><label class="small" for="cfgimp">Paste an exported configuration (YAML). It becomes one proposal; tools not in it are switched off.</label>
    <textarea id="cfgimp" rows="10" class="mono" spellcheck="false"></textarea><input class="input" id="cfgimpnote" aria-label="Why" placeholder="Why (shown to the approver)">
    <div>${btn('Propose import', 'importConfig', [], 'primary')}</div><div id="cfgimpout"></div></div>`;
}
async function importConfig() {
  try {
    const v = await api('/api/v1/config/import', {method: 'POST', body: JSON.stringify({yaml: $('#cfgimp').value, note: $('#cfgimpnote').value.trim()})});
    toast(`Proposed as version ${v.id} - another person approves it`); Integrations();
  } catch (e) { $('#cfgimpout').innerHTML = rejected(e); }
}
async function restoreConfig(id) {
  try { const v = await post(`/api/v1/config/versions/${id}/restore`, {reason: `restore version ${id}`}); toast(`Restore proposed as version ${v.id}`); Integrations(); }
  catch (e) { $('#cfgextra').innerHTML = rejected(e); }
}
function rejected(e) {
  let d; try { d = JSON.parse(e.message).detail; } catch (x) { d = null; }
  if (!d || typeof d !== 'object') return '';
  return `<div class="callout danger mt"><div><b>${esc(d.message)}</b>${(d.problems || []).map(p => `<div class="small">${esc(p.where)}: ${esc(p.message)}${p.fix ? ' - ' + esc(p.fix) : ''}</div>`).join('')}</div></div>${d.preflight && d.preflight.checks ? preflightHtml(d.preflight) : ''}`;
}
function preflightHtml(r) {
  return `<div class="mt">${card(`Preflight · ${esc(r.tool)} · ${esc(r.stage_label || r.stage)}`, `<div class="inline" style="margin-bottom:8px">${status(r.ok ? (r.warnings ? 'medium' : 'ok') : 'high', cap(r.verdict))}<span class="small muted">${esc(r.errors)} error(s), ${esc(r.warnings)} warning(s) · ${esc(r.duration_ms)} ms · ${dt(r.ran_at)}</span></div>` +
    r.checks.map(c => `<div class="list-row" style="display:block"><div class="inline">${status(PF_K[c.status] || 'info', c.check)}<span class="small">${esc(c.detail)}</span></div>
      ${c.fix ? `<div class="t-sub">Fix: ${esc(c.fix)}</div>` : ''}${(c.streams || []).map(s => `<div class="small" style="margin-left:18px">${status(PF_K[s.status] || 'info', s.stream)} ${s.records != null ? `<span class="muted">${esc(s.records)} record(s) · ${esc(s.latency_ms)} ms${s.volume ? ' · ' + esc(s.volume) : ''}</span>` : ''}
        ${(s.notes || []).map(n => `<div class="t-sub">${esc(n)}</div>`).join('')}${s.fix ? `<div class="t-sub">Fix: ${esc(s.fix)}</div>` : ''}</div>`).join('')}</div>`).join(''), {sub: 'nothing is written to the tool or the context store'})}</div>`;
}
async function preflight(name) {
  toast(`Preflight of ${name} running…`);
  try { const r = await post(`/api/v1/config/connectors/${encodeURIComponent(name)}/preflight`); $('#cfgpanel').innerHTML = preflightHtml(r); $('#cfgpanel').scrollIntoView({behavior: 'smooth'}); toast(`${name}: ${r.verdict}`, !r.ok); }
  catch (e) { $('#cfgpanel').innerHTML = rejected(e); }
}
async function pauseConn(name) {
  const reason = window.prompt(`Pause ${name} now? It stops syncing and offering actions at once (switching it back on needs an approved change).\nReason:`);
  if (!reason || reason.trim().length < 3) { toast('Not paused: a reason is required', true); return; }
  await post(`/api/v1/config/connectors/${encodeURIComponent(name)}/pause`, {reason: reason.trim()});
  toast(`${name} paused`); Integrations();
}
function fieldInput(c, f) {
  const id = `cf-${f.name}`, lab = `aria-label="${esc(f.name)}"`;
  if (f.kind === 'secret') return `<div class="small"><span class="mono">${esc(f.env_var)}</span> ${f.set === true ? status('ok', 'Set') : f.set === false ? status('high', 'Not set') : '<span class="muted">not needed in the Fixtures stage</span>'}${f.rotated_at ? ` <span class="muted">· file changed ${dt(f.rotated_at)}</span>` : ''}</div>`;
  const v = f.value == null ? '' : typeof f.value === 'object' ? JSON.stringify(f.value) : String(f.value);
  if (f.kind === 'choice' || f.kind === 'bool') {
    const opts = f.kind === 'bool' ? ['true', 'false'] : f.choices;
    return `<select id="${id}" ${lab} data-orig="${esc(v)}"><option value="">(default)</option>${opts.map(o => `<option value="${esc(o)}"${String(v).toLowerCase() === String(o) ? ' selected' : ''}>${esc(o)}</option>`).join('')}</select>`;
  }
  const ph = f.env_var && f.value == null ? `from \${${f.env_var}}${f.resolved ? ' = ' + f.resolved : ''}` : (f.required ? 'required' : 'optional');
  return `<input class="input wide" id="${id}" ${lab} data-orig="${esc(v)}" value="${esc(v)}" placeholder="${esc(ph)}">`;
}
function configure(name) {
  const c = (window.__cfg.connectors || []).find(x => x.name === name); if (!c) return;
  const rows = f => `<tr><td><div class="t-title mono small">${esc(f.name)}${f.required ? ' *' : ''}</div><div class="t-sub">${esc(f.description)}</div><div class="t-sub muted">${esc(f.source)}</div></td><td>${fieldInput(c, f)}</td></tr>`;
  const secrets = c.config.filter(f => f.secret), plain = c.config.filter(f => !f.secret && !f.common), adv = c.config.filter(f => !f.secret && f.common);
  $('#cfgpanel').innerHTML = `<div class="mb">${card(`Configure ${esc(c.tool)}`, `
    ${c.problems.length ? `<div class="callout danger mb"><div>${c.problems.map(p => `<div class="small"><b>${esc(p.where)}</b>: ${esc(p.message)}${p.fix ? ' - ' + esc(p.fix) : ''}</div>`).join('')}</div></div>` : ''}
    <ol class="small" style="margin-top:0;padding-left:18px"><li><b>Secrets</b> go in the vault or environment under the names below - never typed here.</li><li><b>Settings</b> and <b>stage</b> are set here.</li>
      <li><b>Propose</b>: a live stage runs the preflight on your proposal first; another person approves it; it applies within seconds, no restart.</li></ol>
    ${secrets.length ? `<h3 class="section-h" style="margin-top:4px">1 · Secrets</h3>${table(['Secret', 'Where it comes from'], secrets.map(rows), {flush: true})}` : ''}
    <h3 class="section-h">2 · Settings</h3>${plain.length ? table(['Setting', 'Value'], plain.map(rows), {flush: true}) : empty('No settings')}
    <details class="mt"><summary class="small">Advanced</summary>${table(['Setting', 'Value'], adv.map(rows), {flush: true})}</details>
    <h3 class="section-h">3 · Stage</h3><div class="form-row"><select id="cf-stage" aria-label="Stage">${window.__cfg.stages.map(s => `<option value="${esc(s.id)}"${s.id === c.stage ? ' selected' : ''}>${esc(s.label)} - ${esc(STAGE_HELP[s.id])}</option>`).join('')}</select>
      <label class="inline small" style="flex:0 0 auto"><input type="checkbox" id="cf-enabled"${c.enabled ? ' checked' : ''}> Switched on</label></div>
    <h3 class="section-h">4 · Propose</h3><div class="form-row"><input class="input" id="cf-note" aria-label="Why" placeholder="Why (shown to the approver)">${btn('Propose change', 'proposeConfig', [name], 'primary')}${btn('Cancel', 'closePanel', [], '')}</div>
    <div id="cfout"></div>`, {sub: `${esc(c.vendor)} · ${esc(c.category)} · currently ${esc(c.stage_label)}${c.enabled ? '' : ' (off)'}`})}</div>`;
  $('#cfgpanel').scrollIntoView({behavior: 'smooth'});
}
function closePanel() { $('#cfgpanel').innerHTML = ''; }
async function proposeConfig(name) {
  const c = window.__cfg.connectors.find(x => x.name === name);
  const ch = {}, settings = {};
  c.config.filter(f => !f.secret).forEach(f => { const el = $(`#cf-${f.name}`); if (el && el.value !== el.dataset.orig) settings[f.name] = el.value === '' ? null : el.value; });
  if (Object.keys(settings).length) ch.settings = settings;
  const st = $('#cf-stage').value, on = $('#cf-enabled').checked;
  if (st !== c.stage) ch.stage = st;
  if (on !== c.enabled) ch.enabled = on;
  if (!Object.keys(ch).length) { toast('Nothing changed', true); return; }
  $('#cfout').innerHTML = `<div class="small muted mt">Checking${ch.stage && ch.stage !== 'fake' || on ? ' and running the preflight' : ''}…</div>`;
  try {
    const v = await api('/api/v1/config/proposals', {method: 'POST', body: JSON.stringify({changes: {[name]: ch}, note: $('#cf-note').value.trim()})});
    toast(`Proposed as version ${v.id} - another person approves it in this screen`); Integrations();
  } catch (e) { $('#cfout').innerHTML = rejected(e); }
}
async function approveConfig(id) {
  try { await post(`/api/v1/config/proposals/${id}/approve`); toast(`Configuration version ${id} is in force`); Integrations(); }
  catch (e) { const h = rejected(e); if (h) $('#cfgpanel').innerHTML = h; }
}
async function rejectConfig(id) { await post(`/api/v1/config/proposals/${id}/reject`, {reason: ''}); toast(`Version ${id} withdrawn or rejected`); Integrations(); }
async function notifyTest() {
  const r = await post('/api/v1/admin/notifications/test');
  const bad = r.results.filter(x => !x.ok);
  toast(bad.length ? `Failed: ${bad.map(x => `${x.channel} (${x.error})`).join('; ')}` : `Test message sent to ${r.results.map(x => x.channel).join(', ')}`, bad.length > 0);
}
async function testConn(name) { return preflight(name); }
async function runJob(name) { toast(`Running ${name}…`); const r = await post(`/api/v1/jobs/${name}/run`); toast(`${name}: ${r.status}${r.error ? ' - ' + r.error : ''}`, r.status !== 'ok'); Integrations(); }

// ================================================================= AI usage
const llmNotice = r => r && r.llm_notice ? `<div class="callout info mt"><div class="small">${esc(r.llm_notice)}</div></div>` : '';
const ADV_K = {'try small': 'ok', 'use large': 'high', keep: 'info', 'not enough data': 'info'};
const tok = n => n == null ? '–' : n >= 1e6 ? (n / 1e6).toFixed(1) + 'M' : n >= 1e3 ? Math.round(n / 1e3) + 'k' : String(n);
const usd = x => x == null ? '–' : '$' + (x < 1 ? x.toFixed(4) : x.toFixed(2));
async function AiUsage() {
  const __g = GEN;
  const [u, pol] = await Promise.all([api('/api/v1/admin/llm/usage?days=30'), api('/api/v1/admin/llm/policy')]);
  window.__llmpol = pol;
  const edit = can('manage_access'), P = pol.policy, b = u.budget;
  const bar = (used, cap) => cap ? `${meter(Math.min(100, 100 * used / cap))}<div class="small muted">${tok(used)} of ${tok(cap)} tokens (${Math.round(100 * used / cap)} %)</div>` : `<div class="small muted">${tok(used)} tokens · no cap</div>`;
  const wf = f => { const r = (P.workflows || {})[f.workflow] || {};
    return `<tr><td><div class="t-title mono small">${esc(f.workflow)}</div><div class="t-sub">${esc(f.description)} · ${esc(f.triggered_by === 'person' ? 'asked by a person' : 'scheduled')}</div></td>
      <td class="num small">${nf(f.calls)}${f.refused ? `<div class="t-sub">${nf(f.refused)} refused by limits</div>` : ''}${f.failed ? `<div class="t-sub" style="color:var(--high)">${nf(f.failed)} not answered (endpoint down / slow)</div>` : ''}</td><td class="num small">${tok(f.mean_in)} / ${tok(f.mean_out)}</td>
      <td class="num small">${usd(f.cost)}${f.alternative ? `<div class="t-sub">${usd(f.cost_on_alternative)} on ${esc(f.alternative)}</div>` : ''}</td>
      <td class="num small">${f.usable_rate == null ? '–' : pct(f.usable_rate)}${f.claims_dropped_rate == null ? '' : `<div class="t-sub">${pct(f.claims_dropped_rate)} statements dropped</div>`}</td>
      <td class="num small">${f.p95_ms == null ? '–' : (f.p95_ms / 1000).toFixed(1) + ' s'}</td>
      <td>${status(ADV_K[f.advice] || 'info', cap(f.advice))}<div class="t-sub">${esc(f.why)}</div></td>
      <td>${edit ? `<select id="wt-${esc(f.workflow)}" aria-label="Model for ${esc(f.workflow)}"><option value="">${esc(f.default_model)} (default)</option>${pol.models.map(m => `<option value="${esc(m.name)}"${r.model === m.name ? ' selected' : ''}>${esc(m.name)}</option>`).join('')}</select>
        <input class="input" style="width:90px;margin-top:4px" id="wm-${esc(f.workflow)}" aria-label="Output cap for ${esc(f.workflow)}" placeholder="cap ${esc(P.max_output_tokens[f.tier] || '')}" value="${esc(r.max_output_tokens || '')}">
        <label class="inline small" style="margin-top:4px"><input type="checkbox" id="we-${esc(f.workflow)}"${r.enabled === false ? '' : ' checked'}> on</label>`
        : `<span class="tag" style="white-space:nowrap">${esc(f.model)}</span>${f.enabled ? '' : ' ' + chip('off', 'medium plain')}`}</td></tr>`; };
  const lim = (id, v, ph, label) => `<input class="input" style="width:100%;max-width:130px" id="${id}" aria-label="${esc(label || id)}" value="${v == null ? '' : esc(v)}" placeholder="${esc(ph || '')}"${edit ? '' : ' readonly'}>`;
  const roleRows = pol.roles.map(r => { const v = (P.roles || {})[r] || {}; return `<tr><td class="small">${esc(cap(r))}</td><td>${lim('rh-' + r, v.hourly_tokens, 'everyone', cap(r) + ' per hour')}</td><td>${lim('rd-' + r, v.daily_tokens, 'everyone', cap(r) + ' per day')}</td></tr>`; });
  const row2 = (label, a, b) => `<tr><td class="small">${label}</td><td>${a}</td><td>${b || ''}</td></tr>`;
  const userOver = Object.entries(P.users || {}).map(([k, v]) => `${k} | ${v.hourly_tokens ?? ''} | ${v.daily_tokens ?? ''}`).join('\n');
  setMainG(__g, page('AI usage & limits', 'Who and what uses the model, what it costs, and the limits that apply. Over any limit the platform answers from the same evidence without the model - nothing fails.', '',
    `<div class="grid g-3">
      ${card('This month', bar(b.month_used, b.monthly_tokens), {sub: 'platform cap'})}
      ${card('Today', bar(b.today_used, b.daily_tokens), {sub: 'resets at midnight UTC'})}
      ${kpi('Cost, last 30 days', usd(u.cost_total), 'at the prices set below')}
    </div>
    <div class="mt">${card('By feature - which model each uses, and whether it should', table(['Feature', {h: 'Calls', num: 1}, {h: 'Tokens in / out', num: 1}, {h: 'Cost', num: 1}, {h: 'Usable', num: 1}, {h: 'p95', num: 1}, 'Advice', 'Model · cap · on'], u.features.map(wf)),
      {flush: true, sub: 'advice is computed from these figures: usable answers, statements the evidence check removed, answer length'})}</div>
    <div class="grid g-2e mt">
      ${card('Budgets', table(['', 'Value', ''], [
          row2('Monthly tokens', lim('lp-month', P.monthly_tokens, '', 'Monthly tokens')),
          row2('Daily tokens', lim('lp-day', P.daily_tokens, '', 'Daily tokens')),
          row2('Warn at (fraction of the month)', lim('lp-alert', P.alert_at, '', 'Warn at')),
          row2('Longest answer: smaller / larger models', lim('lp-cs', P.max_output_tokens.small, '', 'Longest answer, smaller models'), lim('lp-cl', P.max_output_tokens.large, '', 'Longest answer, larger models'))]), {flush: true, sub: 'tokens; 0 = no cap'})}
      ${card('Limits per person', `<div class="small muted" style="margin-bottom:6px">Questions, deep analysis and reports a person asks for. Scheduled work counts only against the budgets. 0 = no model text for them.</div>
        ${table(['Who', 'Per hour', 'Per day'], [row2('<b>Everyone</b>', lim('lu-h', P.user_default.hourly_tokens, '', 'Everyone per hour'), lim('lu-d', P.user_default.daily_tokens, '', 'Everyone per day')), ...roleRows], {flush: true})}
        <label class="small" style="display:block;margin-top:10px" for="lusers">Per person (overrides the role), one per line: <span class="mono">name@company.com | per hour | per day</span></label>
        <textarea id="lusers" rows="4" class="mono" style="width:100%"${edit ? '' : ' readonly'}>${esc(userOver)}</textarea>`, {sub: 'tokens; a role overrides everyone'})}
    </div>
    <div class="mt">
      ${card('Models', `<div class="small muted" style="margin-bottom:6px">The models a feature can use - the ones deployed on your endpoint (<span class="mono">SOC_LLM_MODELS</span> adds more). Prices are USD per million tokens and only drive the cost figures.</div>
        ${table(['Model', 'Size', {h: '$ in / M', num: 1}, {h: '$ out / M', num: 1}, 'Answers?'], pol.models.map((m, i) => { const pr = P.prices[m.name] || {input: 0, output: 0};
          return `<tr><td class="mono small">${esc(m.name)}${m.deployment !== m.name ? `<div class="t-sub">deployment ${esc(m.deployment)}</div>` : ''}${Object.values(pol.default_models).includes(m.name) ? `<div class="t-sub">default for ${esc(Object.entries(pol.default_models).filter(([, v]) => v === m.name).map(([k]) => k === 'small' ? 'routine narrative' : 'summaries and reports').join(', '))}</div>` : ''}</td>
            <td class="small">${esc(m.size === 'small' ? 'smaller' : 'larger')}</td><td class="num">${lim('mpi-' + i, pr.input, '', m.name + ' input price')}</td><td class="num">${lim('mpo-' + i, pr.output, '', m.name + ' output price')}</td>
            <td class="small" id="mchk-${i}">–</td></tr>`; }), {flush: true})}
        ${edit ? `<div class="mt">${btn('Check which models answer', 'checkModels', [], 'sm')}</div>` : ''}`, {sub: 'a feature set to a model your endpoint does not serve falls back to the platform\'s own text'})}
    </div>
    ${edit ? `<div class="form-row mt"><input class="input" id="lp-note" aria-label="Why" placeholder="Why (kept in the history and the audit log)">${btn('Save limits and model choices', 'saveLlmPolicy', [], 'primary')}</div><div id="lpout"></div>` : `<div class="small muted mt">Only an administrator changes these.</div>`}
    <div class="grid g-2e mt">
      ${card('Who used it (last 30 days)', table(['Person', {h: 'Last hour', num: 1}, {h: 'Today', num: 1}, {h: '30 days', num: 1}, {h: 'Calls', num: 1}], u.users.map(x => `<tr><td class="small">${esc(x.user)}</td><td class="num small">${tok(x.hour)}</td><td class="num small">${tok(x.today)}</td><td class="num small">${tok(x.period)}</td><td class="num small">${nf(x.calls)}</td></tr>`), {flush: true, empty: 'No one has asked the model for anything yet.'}))}
      ${card('Recent model calls', `<div class="form-row" style="margin-bottom:8px"><select id="lc-wf" aria-label="Feature"><option value="">Every feature</option>${Object.keys(pol.workflows).map(w => `<option>${esc(w)}</option>`).join('')}</select>
        <select id="lc-st" aria-label="Outcome"><option value="">Every outcome</option>${['ok', 'error', 'unparseable', 'user_limit', 'daily_budget_exceeded', 'budget_exceeded', 'disabled_by_policy', 'circuit_open'].map(s => `<option>${s}</option>`).join('')}</select>${btn('Show', 'loadCalls', [], 'sm')}</div><div id="lcalls"></div>`, {sub: 'open one to see its prompt, answer and what the evidence check removed'})}
      ${card('History', table(['Version', 'By', 'When', 'Why'], pol.history.map(h => `<tr><td class="mono">#${esc(h.id)}</td><td class="small">${esc(h.set_by)}</td><td class="mono small muted">${dt(h.created_at)}</td><td class="small">${esc(h.note || '')}</td></tr>`), {flush: true, empty: 'Defaults in force - nothing changed yet.'}))}
    </div>`));
}
async function loadCalls() {
  const q = new URLSearchParams({limit: '50'}); if ($('#lc-wf').value) q.set('workflow', $('#lc-wf').value); if ($('#lc-st').value) q.set('status', $('#lc-st').value);
  const xs = await api('/api/v1/admin/llm/calls?' + q.toString());
  $('#lcalls').innerHTML = table(['When', 'Feature', 'Outcome', {h: 'Tokens', num: 1}, ''], xs.map(c => `<tr><td class="mono small">${dt(c.ts)}</td><td class="mono small">${esc(c.workflow)}<div class="t-sub">${esc(c.actor || 'scheduled')} · ${esc(c.requested_model || c.tier || '')}</div></td>
    <td>${status(c.status === 'ok' ? 'ok' : 'medium', c.status)}${c.claims_dropped ? `<div class="t-sub">${nf(c.claims_dropped)} removed</div>` : ''}</td><td class="num small">${nf((c.prompt_tokens || 0) + (c.completion_tokens || 0))}</td>
    <td>${c.trace_id ? `<a href="#/trace/${encodeURIComponent(c.trace_id)}">Trace</a>` : ''}</td></tr>`), {flush: true, empty: 'No model calls match'});
}
async function checkModels() {
  const r = await post('/api/v1/admin/llm/models/check', {});
  window.__llmpol.models.forEach((m, i) => { const x = r.results.find(y => y.model === m.name), el = $('#mchk-' + i); if (!el || !x) return;
    el.innerHTML = x.ok ? `${status('ok', 'Yes')}<div class="t-sub">${nf(x.latency_ms)} ms${x.answered_by ? ' · ' + esc(x.answered_by) : ''}</div>` : `${status('high', 'No')}<div class="t-sub" style="white-space:normal">${esc(x.detail || '')}</div>`; });
  toast(`${r.results.filter(x => x.ok).length} of ${r.results.length} models answered`);
}
async function saveLlmPolicy() {
  const pol = window.__llmpol, P = JSON.parse(JSON.stringify(pol.policy));
  const num = (id, fl) => { const v = ($('#' + id).value || '').trim(); if (v === '') return null; const n = fl ? parseFloat(v) : parseInt(v, 10); return Number.isNaN(n) ? v : n; };
  P.monthly_tokens = num('lp-month') ?? 0; P.daily_tokens = num('lp-day') ?? 0; P.alert_at = num('lp-alert', true) ?? 0.8;
  P.max_output_tokens = {small: num('lp-cs'), large: num('lp-cl')};
  P.prices = {}; pol.models.forEach((m, i) => { P.prices[m.name] = {input: num('mpi-' + i, true) ?? 0, output: num('mpo-' + i, true) ?? 0}; });
  delete P.models; delete P.default_models;
  P.user_default = {hourly_tokens: num('lu-h') ?? 0, daily_tokens: num('lu-d') ?? 0};
  P.roles = {}; pol.roles.forEach(r => { const h = num('rh-' + r), d = num('rd-' + r); if (h != null || d != null) P.roles[r] = {...(h != null ? {hourly_tokens: h} : {}), ...(d != null ? {daily_tokens: d} : {})}; });
  P.users = {}; ($('#lusers').value || '').split('\n').map(l => l.trim()).filter(Boolean).forEach(l => { const [who, h, d] = l.split('|').map(x => (x || '').trim()); const o = {}; if (h !== '') o.hourly_tokens = parseInt(h, 10); if (d !== '' && d !== undefined) o.daily_tokens = parseInt(d, 10); P.users[who] = o; });
  P.workflows = {}; Object.keys(pol.workflows).forEach(w => { const t = $(`[id="wt-${w}"]`), m = $(`[id="wm-${w}"]`), e = $(`[id="we-${w}"]`); if (!t) return; const r = {};
    if (t.value) r.model = t.value; if ((m.value || '').trim()) r.max_output_tokens = parseInt(m.value, 10); if (!e.checked) r.enabled = false; if (Object.keys(r).length) P.workflows[w] = r; });
  try { await post('/api/v1/admin/llm/policy', {policy: P, note: $('#lp-note').value.trim()}); toast('AI usage policy saved - in force for the next model call'); AiUsage(); }
  catch (e) { let d; try { d = JSON.parse(e.message).detail; } catch (x) { d = null; } if (d) $('#lpout').innerHTML = `<div class="callout danger mt"><div class="small">${esc(d)}</div></div>`; }
}

// ================================================================= Policy
async function Policy() {
  const __g = GEN;
  const [p, cat, h] = await Promise.all([api('/api/v1/policy'), api('/api/v1/actions/catalog'), api('/health')]);
  setMainG(__g, page('Automation policy', `Versioned autonomy policy (active version ${esc(p.active_version || 'default')}). L0 observe · L1 enrich · L2 recommend · L3 approve · L4 autonomous. Destructive actions are never autonomous.`, '',
    `<div class="grid g-2">
      ${card('Actions', table(['Action', 'Executes via', 'Level', 'Properties'], cat.map(a => `<tr><td class="mono small">${esc(a.action_type)}</td><td class="small muted">${esc(a.tool)}</td>
        <td><span class="chip plain ${a.level >= 4 ? 'high' : a.level === 3 ? 'medium' : ''}">L${a.level}</span></td><td class="small">${a.destructive ? chip('destructive', 'high plain') : ''} ${a.reversible ? chip('reversible', 'ok plain') : ''}</td></tr>`)), {flush: true})}
      <div class="stack">
        ${card('Kill switch', `<p class="small" style="margin-top:0">Halts every automated action on all replicas immediately. Stored durably; survives restarts.</p>
          <div class="inline">${h.kill_switch ? status('critical', 'Automation halted') : status('ok', 'Automation active')}</div>
          ${can('kill_switch') ? `<div class="inline mt">${h.kill_switch ? btn('Release', 'kill', [false]) : btn('Engage kill switch', 'kill', [true], 'danger')}</div>` : ''}`)}
        ${card('Pending policy changes', p.proposals.map(x => `<div class="list-row"><div class="grow small">#${esc(x.id)} by ${esc(x.proposed_by)}<div class="t-sub">${esc(x.note)}</div></div>${can('approve_policy') ? btn('Approve', 'approvePolicy', [x.id], 'sm primary') : ''}</div>`).join('') || empty('No proposals'), {sub: 'proposer cannot approve'})}
      </div>
    </div>`));
}
async function kill(on) { await post('/api/v1/kill-switch?on=' + on); toast(on ? 'Kill switch engaged - all automated actions halted' : 'Kill switch released'); refreshStatus(); Policy(); }
async function approvePolicy(id) { await post(`/api/v1/policy/proposals/${id}/approve`); toast('Policy version activated'); Policy(); }

// ================================================================= Reports
async function Reports() {
  const __g = GEN;
  const [tp, llmSt, cases, rs] = await Promise.all([api('/api/v1/reports/templates'), api('/api/v1/llm/status'), api('/api/v1/cases'), api('/api/v1/reports/style')]);
  window.__rcases = cases.filter(c => c.status !== 'closed' && ['critical', 'high'].includes(c.severity));
  const kinds = [['daily_exposure', 'Daily exposure report', 'Word · VM-F13', 'vulnerability'], ['weekly_vm', 'Weekly vulnerability report', 'Word · VM-F13', 'vulnerability'],
    ['weekly_mgmt', 'Management deck', 'PowerPoint · all domains', '*']];
  const writer = llmSt.configured ? `Narrative is written by the approved LLM (${esc(llmSt.provider)}) from computed figures; every sentence must cite a figure or it is removed.`
    : 'No LLM is configured, so narrative uses deterministic templates. Configure an approved LLM endpoint for richer prose; the figures are identical either way.';
  const tcard = t => card(esc(t.title), `<p class="small muted" style="margin-top:0">${esc(t.description || '')}</p>
      <div class="small" style="margin-bottom:10px"><span class="tag">${t.format === 'pptx' ? 'PowerPoint' : 'Word'}</span><span class="tag">${esc(t.audience)}</span><span class="tag">last ${esc(t.days)} day(s)</span><span class="tag">${t.sections.length} section(s)</span></div>
      ${t.needs_case ? caseSelect('rc-' + t.id) : ''}${btn('Generate', 'buildTemplate', [t.id], 'primary', 'download')}`, {sub: t.standard ? 'standard' : 'saved · ' + esc(t.created_by || '')});
  setMainG(__g, page('Reports', 'Standard reports are preconfigured; any other report can be described in words. Figures are always computed in code from the platform records.', '',
    `<div class="callout info">${writer}</div>
    ${card('Describe a report', `<div class="stack" style="gap:10px"><textarea id="rq" rows="3" placeholder="e.g. A one-page board brief on phishing and supplier risk this quarter, as slides"></textarea>
      <div class="inline">${btn('Plan report', 'reportPlan', [], 'primary')}<span class="small muted">You review the plan before anything is generated. Sections come only from the data catalogue (${tp.sources.length} sources).</span></div></div><div id="rplan"></div>`)}
    <div id="rout"></div>
    <h2 class="section-h">Standard reports</h2><div class="grid g-3">${tp.templates.filter(t => t.standard).map(tcard).join('')}</div>
    ${tp.templates.some(t => !t.standard) ? `<h2 class="section-h">Saved reports</h2><div class="grid g-3">${tp.templates.filter(t => !t.standard).map(tcard).join('')}</div>` : ''}
    <h2 class="section-h">Exports</h2><div class="grid g-3">${kinds.filter(([, , , d]) => d === '*' ? window.ME.domains.includes('*') : inDomain(d)).map(([k, t, s]) => card(t, `<p class="small muted" style="margin-top:0">${esc(s)}</p>${btn('Generate', 'report', [k], '', 'download')}`)).join('')}
      ${can('export_evidence') ? card('Compliance evidence pack', `<p class="small muted" style="margin-top:0">Control tests, evidence JSON, chained audit export and summary (ZIP) · U17</p>${btn('Generate pack', 'compliancePack', [], '', 'download')}<div id="comp"></div>`) : ''}
      ${can('export_evidence') ? card('Audit export', `<p class="small muted" style="margin-top:0">Full hash-chained audit log as JSON Lines with verification, for archiving or SIEM. More formats and filters on the Audit log screen.</p>${btn('Export', 'dl', ['/api/v1/audit/export'], '', 'download')}`) : ''}
    </div>
    <h2 class="section-h">Report style</h2>${styleCard(rs)}`));
}
function styleCard(rs) {
  const S = rs.style, F = S.files || {}, manage = can('manage_report_style');
  const sw = c => `<span style="display:inline-block;width:14px;height:14px;border-radius:3px;vertical-align:-2px;background:#${esc(c)};border:1px solid var(--border)"></span>`;
  const part = (slot, label) => { const f = F[slot]; return `<div class="list-row"><div class="grow"><div class="t-title">${esc(label)}</div>
      <div class="t-sub">${f ? `${esc(f.name)} · ${esc(f.detail)} · ${esc(f.by)} ${dt(f.at)}` : 'house style'}</div></div>${manage && f ? btn('Remove', 'styleRemove', [slot], 'sm ghost') : ''}</div>`; };
  const field = (id, label, v, ph, extra = '') => `<label class="small" for="${id}">${label}</label><input class="input" id="${id}" value="${esc(v || '')}" placeholder="${esc(ph || '')}"${manage ? '' : ' readonly'}${extra}>`;
  return `<div class="stack">
    ${card('What every report looks like', `<p class="small muted" style="margin-top:0">Applied to every Word report and PowerPoint deck - standard, described and scheduled - and the audit trail report. Figures and citations never change; only the look and, for model-written text, the wording.</p>
      ${part('word', 'Word template')}${part('deck', 'PowerPoint template (16:9)')}${part('logo', 'Logo')}
      <div class="list-row"><div class="grow"><div class="t-title">Writing guide</div><div class="t-sub">${S.guide ? `${nf(S.guide.length)} characters - used when the model writes report narrative` : 'none - the model writes in plain report English'}</div></div>${manage && S.guide ? btn('Remove', 'styleRemove', ['guide'], 'sm ghost') : ''}</div>
      <div class="list-row"><div class="grow"><div class="t-title">Brand</div><div class="t-sub">${esc(S.organisation || 'Agentic SOC')} · ${sw(S.primary)} ${sw(S.accent)} · ${esc(S.font)} · ${esc(S.classification)}</div></div></div>
      <div class="inline mt" style="gap:8px;flex-wrap:wrap">${btn('Preview in Word', 'dl', ['/api/v1/reports/style/preview?format=docx'], '', 'download')}${btn('Preview as slides', 'dl', ['/api/v1/reports/style/preview?format=pptx'], '', 'download')}${manage && rs.custom ? btn('Back to the house style', 'styleReset', [], 'ghost') : ''}</div>`,
      {sub: rs.version ? `version ${esc(rs.version)}` : 'house style'})}
    ${manage ? card('Customise', `<div class="stack" style="gap:10px">
      <label class="small" for="st-file"><b>Upload</b> a Word template (.docx / .dotx), a PowerPoint template (.pptx / .potx), a logo (.png / .jpg), a writing guide or skill (.md / .txt), brand settings (brand.json / .yaml) - or a <b>.zip style pack</b> with any of them.</label>
      <input type="file" id="st-file" class="input" style="padding:5px" accept=".docx,.dotx,.pptx,.potx,.png,.jpg,.jpeg,.md,.markdown,.txt,.json,.yaml,.yml,.zip">
      <div class="inline" style="gap:8px">${btn('Upload', 'styleUpload', [], 'primary')}<span class="small muted">Checked before use: macros, document-type declarations and oversized files are refused; a deck template must be 16:9.</span></div>
      <div id="st-out"></div>
      <div class="grid g-2" style="gap:10px">
        <div class="stack" style="gap:4px">${field('st-org', 'Organisation name (header and footer)', S.organisation, 'Agentic SOC', ' maxlength="80"')}</div>
        <div class="stack" style="gap:4px">${field('st-cls', 'Classification line', S.classification, '', ' maxlength="80"')}</div>
        <div class="stack" style="gap:4px">${field('st-pri', 'Primary colour (hex)', S.primary, '1F2A44', ' maxlength="7"')}</div>
        <div class="stack" style="gap:4px">${field('st-acc', 'Accent colour (hex)', S.accent, '2563EB', ' maxlength="7"')}</div>
        <div class="stack" style="gap:4px">${field('st-font', 'Font', S.font, 'Calibri', ' maxlength="40"')}</div>
        <div class="stack" style="gap:4px">${field('st-foot', 'Footer text', S.footer, 'The house footer', ' maxlength="160"')}</div>
      </div>
      <label class="small" for="st-guide">Writing guide - tone, terms and wording for model-written narrative (it cannot change a fact, a figure or a citation)</label>
      <textarea id="st-guide" rows="5" maxlength="8000" placeholder="e.g. Write for executives. British English. Say 'incident', never 'breach', unless confirmed. Lead with the business impact.">${esc(S.guide || '')}</textarea>
      <div class="form-row"><input class="input" id="st-note" maxlength="500" aria-label="Why" placeholder="Why (kept in the history and the audit log)">${btn('Save', 'styleSave', [], 'primary')}</div></div>`, {sub: 'leads and administrators · every change is versioned and audited'}) : ''}
  </div>`;
}
async function styleUpload() {
  const f = $('#st-file').files[0]; if (!f) { toast('Choose a file first', true); return; }
  if (f.size > 15e6) { toast('The file is larger than 15 MB', true); return; }
  const bytes = new Uint8Array(await f.arrayBuffer()); let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  const r = await post('/api/v1/reports/style/upload', {content_b64: btoa(bin), filename: f.name, note: $('#st-note').value.trim()});
  toast('Report style updated');
  await Reports();
  const out = $('#st-out'); if (out) out.innerHTML = `<div class="callout info"><div class="small">Applied: ${r.applied.map(a => `<b>${esc(a.slot)}</b> from ${esc(a.file)} (${esc(a.detail)})`).join('; ')}. Use <i>Preview</i> to see it.</div></div>`;
}
async function styleSave() {
  const v = id => $('#' + id).value.trim();
  await post('/api/v1/reports/style', {organisation: v('st-org'), classification: v('st-cls'), primary: v('st-pri'), accent: v('st-acc'),
    font: v('st-font'), footer: v('st-foot'), guide: $('#st-guide').value, note: v('st-note')});
  toast('Report style saved'); Reports();
}
async function styleRemove(slot) { await post('/api/v1/reports/style/remove', {slot}); toast('Removed - the house style applies to that part'); Reports(); }
async function styleReset() {
  if (!confirm('Go back to the house style? Templates, logo, brand and writing guide stop applying (the history keeps them).')) return;
  await post('/api/v1/reports/style/reset', {}); toast('Back to the house style'); Reports();
}
function caseSelect(id) {
  const cs = window.__rcases || [];
  if (!cs.length) return '<p class="small muted">No open critical or high case to report on.</p>';
  return `<select id="${esc(id)}" style="width:100%;margin-bottom:10px" aria-label="Case">${cs.map(c => `<option value="${esc(c.id)}">${esc(cap(c.severity))} · ${esc(c.title)}</option>`).join('')}</select>`;
}
async function reportPlan() {
  const q = ($('#rq').value || '').trim();
  if (q.length < 3) { toast('Describe the report first', true); return; }
  $('#rplan').innerHTML = '<div class="skeleton" style="margin-top:12px"></div>';
  const sp = await post('/api/v1/reports/plan', {request: q});
  window.__plan = sp;
  $('#rplan').innerHTML = `<div class="plan-box"><div class="t-title">${esc(sp.title)}</div>
      <div class="t-sub">${esc(sp.audience)} · ${sp.format === 'pptx' ? 'PowerPoint' : 'Word'} · last ${esc(sp.days)} day(s) · planned by ${sp.planner === 'llm' ? 'the LLM (catalogue sources only)' : 'keyword rules (no LLM)'}</div>
    <ol class="plan-secs">${sp.sections.map(x => `<li><b>${esc(x.title)}</b> <span class="tag">${esc(x.source)}</span><div class="small muted">${esc(x.instruction)}</div></li>`).join('')}</ol>
    <div class="inline">${btn('Generate', 'buildPlanned', [], 'primary', 'download')}${btn('Save as template', 'savePlanned', [])}</div></div>${llmNotice(sp)}`;
}
async function buildPlanned() { if (window.__plan) await runBuild({spec: window.__plan}); }
async function savePlanned() {
  if (!window.__plan) return;
  await post('/api/v1/reports/templates', {spec: window.__plan});
  toast('Saved to your reports');
  render();
}
async function buildTemplate(id) {
  const sel = $('#rc-' + id);
  await runBuild({template_id: id, case_id: sel ? sel.value : null});
}
async function runBuild(body) {
  toast('Generating…');
  $('#rout').innerHTML = card('Generating report', '<div class="skeleton"></div><div class="skeleton"></div>');
  let r;
  try { r = await post('/api/v1/reports/build', body); } catch (e) { $('#rout').innerHTML = ''; throw e; }
  $('#rout').innerHTML = card(esc(r.title), `${llmNotice(r)}<div class="small muted" style="margin-bottom:10px">Narrative: ${esc(r.writer)}${r.skipped.length ? ` · skipped: ${r.skipped.map(x => esc(x.source + ' (' + x.reason + ')')).join(', ')}` : ''}</div>
    ${r.sections.map(x => `<div class="rep-sec"><h3>${esc(x.title)} <span class="tag">${esc(x.writer)}</span></h3><p>${esc(x.narrative)}</p>
      <details><summary class="small">Figures (${x.facts.length})</summary><dl class="kv">${x.facts.map(([k, v], i) => `<dt>F${i + 1} · ${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}</dl></details></div>`).join('')}`,
    {right: btn('Download ' + (r.format === 'pptx' ? 'PowerPoint' : 'Word'), 'dl', ['/api/v1/reports/' + r.id + '/download'], 'primary', 'download')});
  $('#rout').scrollIntoView({behavior: 'smooth', block: 'start'});
}
async function report(kind) { toast('Generating…'); const r = await post('/api/v1/reports/' + kind); await dl('/api/v1/reports/' + r.id + '/download'); }
async function compliancePack() {
  toast('Building evidence pack…');
  const r = await post('/api/v1/reports/compliance');
  $('#comp').innerHTML = `<div class="callout ${r.summary.failed ? '' : 'info'}">${r.summary.passed} of ${r.summary.tests} control tests passed${r.summary.failed ? ` · ${r.summary.failed} need attention` : ''}.</div>`;
  await dl('/api/v1/reports/' + r.id + '/download');
}

// ================================================================= Access
async function Access() {
  const __g = GEN;
  const me = window.ME;
  const mine = card('Your access', `<dl class="kv"><dt>Signed in as</dt><dd>${esc(me.name)}</dd><dt>Roles</dt><dd>${esc(me.roles.join(', ') || 'none')}</dd>
    <dt>Data scope</dt><dd>${esc(me.domains.includes('*') ? 'All domains' : me.domains.join(', '))}</dd><dt>MFA</dt><dd>${me.mfa ? 'Yes' : 'No - approvals are disabled'}</dd>
    <dt>Permissions</dt><dd>${me.permissions.map(p => `<span class="tag">${esc(p)}</span>`).join('')}</dd></dl>`);
  if (!can('manage_access')) { setMainG(__g, page('Access', 'Access management requires the administrator role with MFA.', '', mine)); return; }
  const [grants, keys, perms] = await Promise.all([api('/api/v1/admin/roles'), api('/api/v1/admin/api-keys'), api('/api/v1/admin/permissions')]);
  setMainG(__g, page('Access', 'Time-bound, domain-scoped role grants on top of Entra roles; service-account keys for integrations. Nobody can change their own access; lead, admin and automation admin grants need a second administrator and at most 90 days.', '',
    `<div class="grid g-2e">
      ${card('Role assignments', table(['Principal', 'Role', 'Scope', 'Expires', ''], grants.map(g => `<tr><td><div class="t-title">${esc(g.principal_id)}</div><div class="t-sub">${esc(g.reason)} · by ${esc(g.granted_by)}</div></td>
        <td>${esc(cap(g.role))}</td><td class="small">${esc(g.domains.includes('*') ? 'All domains' : g.domains.join(', '))}</td><td class="mono small">${day(g.expires_at) === '–' ? 'never' : day(g.expires_at)}</td><td>${g.status === 'proposed' ? `<span class="tag">Awaiting a second admin</span>${g.granted_by !== me.id ? btn('Approve', 'approveGrant', [g.id], 'sm primary') : ''}` : ''}${btn('Revoke', 'revokeGrant', [g.id], 'sm danger')}</td></tr>`), {empty: 'No platform grants - roles come from Entra.'}) +
        `<div class="card-b" style="border-top:1px solid var(--border)"><div class="form-row">
          <input class="input" id="gp" placeholder="user@company.com"><select id="gr">${['analyst', 'lead', 'auditor', 'automation_admin', 'admin'].map(r => `<option value="${r}">${cap(r)}</option>`).join('')}</select>
          <select id="gd"><option value="*">All domains</option><option value="phishing">Phishing</option><option value="incident">Incident</option><option value="vulnerability">Vulnerability</option></select>
          <input class="input" id="gdays" placeholder="Days (blank = none)" style="flex:0 1 150px"></div><div class="form-row" style="margin-top:8px"><input class="input" style="flex:1" id="greason" placeholder="Justification (required)">${btn('Grant', 'grant', [], 'primary')}</div></div>`, {flush: true})}
      ${card('Service accounts', table(['Name', 'Roles', 'Expires', 'Last used', ''], keys.map(k => `<tr><td class="t-title">${esc(k.name)}</td><td class="small">${esc(k.roles.map(cap).join(', '))}<div class="t-sub">${esc(k.domains.includes('*') ? 'All domains' : k.domains.join(', '))}</div></td>
        <td class="mono small">${day(k.expires_at)}</td><td class="mono small muted">${dt(k.last_used_at)}</td><td>${k.active ? btn('Revoke', 'revokeKey', [k.id], 'sm danger') : '<span class="muted small">Inactive</span>'}</td></tr>`), {empty: 'No service accounts'}) +
        `<div class="card-b" style="border-top:1px solid var(--border)"><div class="inline"><input class="input" style="flex:1" id="kn" placeholder="Name, e.g. prometheus"><select id="kr"><option value="auditor">Auditor</option><option value="analyst">Analyst</option><option value="automation_admin">Automation admin</option></select>${btn('Create key', 'newKey', [], 'primary')}</div><div id="kout"></div></div>`, {flush: true, sub: 'can never approve actions'})}
    </div>
    <div class="grid g-2e mt">${mine}${card('Role permissions', table(['Role', 'Permissions'], Object.entries(perms).map(([r, ps]) => `<tr><td class="t-title">${r.startsWith('_') ? '<span style="color:var(--crit)">Never granted to service accounts</span>' : esc(cap(r))}</td><td>${ps.map(p => `<span class="tag">${esc(p)}</span>`).join('')}</td></tr>`)), {flush: true})}</div>`));
}
async function grant() {
  await post('/api/v1/admin/roles', {principal_id: $('#gp').value.trim(), role: $('#gr').value, domains: [$('#gd').value], days: parseInt($('#gdays').value, 10) || null, reason: $('#greason').value.trim()});
  toast(['lead', 'admin', 'automation_admin'].includes($('#gr').value) ? 'Grant proposed - a second administrator must approve it' : 'Access granted'); Access();
}
async function approveGrant(id) { await post('/api/v1/admin/roles/' + id + '/approve', {note: ''}); toast('Grant approved'); Access(); }
async function revokeGrant(id) { await api('/api/v1/admin/roles/' + id, {method: 'DELETE'}); toast('Grant revoked'); Access(); }
async function revokeKey(id) { await api('/api/v1/admin/api-keys/' + id, {method: 'DELETE'}); toast('Key revoked'); Access(); }
async function newKey() {
  const r = await post('/api/v1/admin/api-keys', {name: $('#kn').value.trim() || 'service', roles: [$('#kr').value], days: 90});
  await Access();
  $('#kout').innerHTML = `<div class="callout">Copy this key now - it is shown only once.&nbsp;<code style="word-break:break-all">${esc(r.api_key)}</code></div>`;
}

// ================================================================= Audit
async function Audit() {
  const __g = GEN;
  const all = window.ME.domains.includes('*');
  const [v, xs, info] = await Promise.all([api('/api/v1/audit/verify'), api('/api/v1/audit?limit=300'), api('/api/v1/audit/info')]);
  const lv = info.last_full_verification;
  const every = s => s % 3600 ? `${Math.round(s / 60)} minutes` : s === 3600 ? 'hour' : `${s / 3600} hours`;
  const about = card('About this audit log', `<dl class="kv">
      <dt>Records</dt><dd>${nf(info.records)}${info.first_ts ? ` · ${dt(info.first_ts)} to ${dt(info.last_ts)} UTC` : ''}</dd>
      <dt>Recorded by</dt><dd>${Object.entries(info.by_actor_type).map(([k, n]) => `${esc(cap(k))} ${nf(n)}`).join(' · ') || '–'}</dd>
      <dt>Last full check</dt><dd>${lv ? (lv.ok ? `Verified up to #${esc(lv.seq)} at ${dt(lv.at)} UTC` : `<b>Broken</b> at #${esc(lv.first_bad_seq)}`) : 'not run yet'}${info.self_check_seconds ? ` · runs every ${every(info.self_check_seconds)} with the self-check; the health check verifies newer records` : ''}</dd>
      <dt>Retention</dt><dd>${esc(cap(info.retention.audit))}.</dd>
      <dt>Who can see it</dt><dd>Read: ${info.access.read.map(r => esc(cap(r))).join(', ')} · export: ${info.access.export.map(r => esc(cap(r))).join(', ')}<div class="t-sub">${esc(cap(info.access.scope))}.</div></dd>
    </dl>
    <h3 class="small strong" style="margin:14px 0 6px">What it records</h3>${info.by_category.map(c => `<span class="tag">${esc(c.category)} ${nf(c.records)}</span>`).join(' ') || empty('Nothing yet')}
    <h3 class="small strong" style="margin:14px 0 6px">How it is protected</h3><ul class="small" style="margin:0;padding-left:18px">${info.protection.map(x => `<li>${esc(x)}</li>`).join('')}</ul>
    <h3 class="small strong" style="margin:14px 0 6px">How long other data is kept</h3>
    ${table(['Data', {h: 'Kept (days)', num: 1}, 'Note'], info.retention.other.map(r => `<tr><td class="small" style="white-space:normal">${esc(r.data)}</td><td class="num">${r.days == null ? 'always' : nf(r.days)}</td><td class="small muted" style="white-space:normal">${esc(r.note)}</td></tr>`))}
    <div class="t-sub">The retention job runs every ${every(info.retention.job_seconds || 86400)}; every run is recorded in this log.</div>`, {sub: 'read from the log and the settings in force'});
  const exp = can('export_evidence') && all ? card('Export the audit trail', `<div class="stack" style="gap:10px">
      <label class="small" for="ax-f">Format</label><select id="ax-f">${info.formats.map(f => `<option value="${esc(f.format)}">${esc(f.label)}</option>`).join('')}</select>
      <div class="inline" style="gap:10px;flex-wrap:wrap"><label class="small">From (UTC) <input type="date" class="input" id="ax-from"></label><label class="small">To, inclusive <input type="date" class="input" id="ax-to"></label></div>
      <input class="input" id="ax-ev" maxlength="64" aria-label="Event type" placeholder="Event type (optional), e.g. action.approved or case.*">
      <input class="input" id="ax-actor" maxlength="256" aria-label="Actor" placeholder="Actor (optional), e.g. lena@acme-demo.com">
      <div>${btn('Download', 'auditExport', [], 'primary', 'download')}</div>
      <div class="t-sub">Leave the filters empty for the whole log. Every format but Word carries each record's hash, so an unfiltered export can be re-verified outside the platform; Word is a readable report with the first ${nf(info.docx_max_rows)} records. Each export is itself recorded here.</div></div>`)
    : card('Export the audit trail', empty(all ? 'Exports need the export_evidence permission (lead, administrator or auditor).' : 'Exports need all-domain access: the whole chain is needed to verify it.'));
  setMainG(__g, page('Audit log', 'Append-only and hash-chained: every retrieval, inference, recommendation, approval and action, attributed to an agent or a person.',
    v.ok ? `<span class="status-pill"><span class="dot"></span>Chain verified · ${nf(v.records)} records in the full log${all ? '' : ' (you see those about your domains)'}</span>` : `<span class="status-pill halt"><span class="dot"></span>Chain broken at #${esc(v.first_bad_seq)}</span>`,
    `<div class="grid g-2 mb">${about}${exp}</div>` + card('Latest records',table([{h: '#', num: 1}, 'Time', 'Actor', 'Event', 'Subject', 'Trace'], xs.map(x => `<tr><td class="num mono small muted">${x.seq}</td><td class="mono small">${dt(x.ts)}</td>
      <td class="small">${esc(x.actor_type)} · ${esc(x.actor_id)}</td><td class="mono small">${esc(x.event_type)}</td><td class="small muted">${esc(x.subject_type)} ${esc(x.subject_id)}</td>
      <td class="mono small">${x.trace_id && window.ME.domains.includes('*') ? `<a href="#/trace/${encodeURIComponent(x.trace_id)}" title="Everything this request or job did">${esc(x.trace_id.slice(0, 14))}…</a>` : ''}</td></tr>`)), {flush: true, sub: 'the newest 300 · a trace links every record one request or job run caused'})));
}
function auditExport() {
  const q = new URLSearchParams({format: $('#ax-f').value});
  [['start', '#ax-from'], ['end', '#ax-to'], ['event_type', '#ax-ev'], ['actor_id', '#ax-actor']].forEach(([k, s]) => { const x = $(s).value.trim(); if (x) q.set(k, x); });
  return dl('/api/v1/audit/export?' + q);
}

// ================================================================= Watch lists
const WL = {block: 'Block list', exception: 'Exception list'};
const wlBadges = ls => (ls || []).map(l => ` <span class="chip ${l === 'block' ? 'critical' : 'ok'}" style="margin-left:4px">${esc(WL[l] || l)}</span>`).join('');
function wlCallout(ms) {
  if (!(ms || []).length) return '';
  return ['block', 'exception'].map(k => [k, ms.filter(m => m.list === k)]).filter(([, xs]) => xs.length).map(([k, xs]) =>
    `<div class="callout ${k === 'block' ? 'danger' : 'info'}" style="margin-bottom:12px"><div><b>${k === 'block' ? 'On the block list' : 'On the exception list'}</b> - this case involves ${xs.length === 1 ? 'an entry' : `${xs.length} entries`} on the organisation's ${esc(WL[k].toLowerCase())}:
      <ul class="small" style="margin:6px 0 4px;padding-left:18px">${xs.map(m => `<li><b>${m.kind === 'asset' || m.kind === 'identity' ? entLink(m.entity_id, m.name) : esc(m.name)}</b> (${esc(m.role)}) · matched on ${esc(m.matched_on)} · entry <span class="mono">${esc(m.entry.written || m.entry.value)}</span> (${esc(m.entry.kind_label)})${m.entry.note ? ` - “${esc(m.entry.note)}”` : ''} · added by ${esc(m.entry.added_by)} on ${day(m.entry.added_at)}</li>`).join('')}</ul>
      <div class="t-sub">Context only: it does not change the severity, verdict or recommended actions.${k === 'exception' ? ' An exception does not clear the case - judge it on the evidence.' : ''}</div></div></div>`).join('');
}
async function Watchlists() {
  const __g = GEN;
  const r = await api('/api/v1/watchlists');
  const manage = can('manage_watchlists'), SHOW = 300;
  const what = {block: 'Users, hosts, addresses and indicators the SOC wants called out wherever they appear - a case involving one says so in red.',
    exception: 'Known exceptions - test accounts, scanners, approved tools. A case involving one says so, so the analyst knows; it is still investigated in full.'};
  const listCard = l => card(`${esc(l.label)} <span class="muted">(${nf(l.count)})</span>`,
    `<div class="small muted" style="padding:12px 16px 4px">${esc(what[l.name])}${Object.keys(l.by_kind).length ? ` · ${Object.entries(l.by_kind).map(([k, n]) => `${nf(n)} ${esc(r.kinds[k] || k)}`).join(', ')}` : ''}</div>` +
    table(['Value', 'Type', 'Note', 'From', 'Added', ''], l.entries.slice(0, SHOW).map(e => `<tr><td class="mono small" style="overflow-wrap:anywhere;max-width:280px">${esc(e.value)}</td><td class="small">${esc(e.kind_label)}</td>
      <td class="small" style="white-space:normal">${esc(e.note)}</td><td class="small muted" style="white-space:normal">${esc(e.source)}</td><td class="small muted">${esc(e.added_by)}<br>${day(e.added_at)}</td>
      <td>${manage ? btn('Remove', 'wlRemove', [e.id, e.value], 'sm ghost') : ''}</td></tr>`), {empty: 'Nothing on this list yet.'}) +
    (l.count > SHOW ? `<div class="t-sub" style="padding:8px 16px">The first ${nf(SHOW)} of ${nf(l.count)} are shown - export the list for all of them.</div>` : ''),
    {flush: true, right: btn('Export CSV', 'dl', [`/api/v1/watchlists/${l.name}/export`], 'sm', 'download')});
  const up = manage ? card('Upload a list', `<div class="stack" style="gap:10px">
      <div class="inline" style="gap:10px;flex-wrap:wrap"><select id="wl-list" aria-label="List">${Object.entries(WL).map(([k, v]) => `<option value="${k}">${v}</option>`).join('')}</select>
        <select id="wl-mode" aria-label="How"><option value="add">Add the file's entries to the list</option><option value="replace">Replace the list with the file</option></select></div>
      <input type="file" id="wl-file" class="input" style="padding:5px" aria-label="Excel or CSV file" accept=".xlsx,.csv,.txt,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,text/csv">
      <input class="input" id="wl-note" maxlength="500" aria-label="Why" placeholder="Why (kept in the audit log; the note for rows that have none)">
      <div class="inline" style="gap:8px">${btn('Preview', 'wlUpload', [true], '')}${btn('Upload', 'wlUpload', [false], 'primary')}</div>
      <div class="t-sub">Excel (.xlsx - every sheet is read) or CSV, up to ${nf(r.max_file_mb)} MB and ${nf(r.max_entries)} entries a list. A header row names the columns:
        <b>Username</b>, <b>Email</b>, <b>Hostname</b>, <b>IP address</b>, <b>Domain</b>, <b>URL</b>, <b>Hash</b> - or <b>Value</b> with a <b>Type</b> column - and optionally <b>Note</b> or <b>Reason</b>.
        Without a header the first column is read and its type recognised. Preview shows what would change and every value that cannot be read, changing nothing.</div>
      <div id="wl-out"></div></div>`, {sub: 'leads · every change is audited'}) : '';
  setMainG(__g, page('Watch lists', 'Block and exception lists of users, hosts, IP addresses, domains, URLs and file hashes. Cases are checked against them whenever they are shown, so a change applies to every case at once; a match is shown on the case and in the case list, and never changes a severity, verdict or action.', '',
    `${up ? `<div class="mb">${up}</div>` : ''}<div class="stack">${r.lists.map(listCard).join('')}</div>`));
}
async function wlUpload(dry) {
  const f = $('#wl-file').files[0]; if (!f) { toast('Choose an Excel or CSV file first', true); return; }
  if (f.size > 5e6) { toast('The file is larger than 5 MB - split it', true); return; }
  const list = $('#wl-list').value, mode = $('#wl-mode').value, note = $('#wl-note').value.trim();
  if (!dry && mode === 'replace' && !confirm(`Replace the whole ${WL[list].toLowerCase()} with ${f.name}? Entries not in the file are removed (kept in the history).`)) return;
  const bytes = new Uint8Array(await f.arrayBuffer()); let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  const r = await post(`/api/v1/watchlists/${list}/upload`, {content_b64: btoa(bin), filename: f.name, mode, note, dry_run: !!dry});
  const kinds = Object.entries(r.added_by_kind).map(([k, n]) => `${nf(n)} ${esc(k)}`).join(', ');
  const html = `<div class="callout ${r.problems.length ? '' : 'info'}"><div><b>${dry ? 'Preview - nothing has changed yet' : 'Uploaded'}.</b> ${esc(r.label)}: ${nf(r.added.length)} to add${kinds ? ` (${kinds})` : ''}, ${nf(r.already_listed)} already listed, ${nf(r.removed.length)} to remove - it will hold ${nf(r.count_after)}.
      ${r.added.length ? `<details class="mt"><summary class="small">Entries to add</summary><div class="small mono" style="white-space:normal">${r.added.slice(0, 200).map(a => esc(`${a.value} (${a.kind})`)).join(', ')}${r.added.length > 200 ? ' …' : ''}</div></details>` : ''}
      ${r.removed.length ? `<details class="mt"><summary class="small">Entries to remove</summary><div class="small mono" style="white-space:normal">${r.removed.slice(0, 200).map(esc).join(', ')}</div></details>` : ''}
      ${r.problems.length ? `<div class="small strong mt">${nf(r.problems.length)} value(s) cannot be listed:</div><ul class="small" style="margin:4px 0;padding-left:18px">${r.problems.slice(0, 50).map(p => `<li>${p.where ? esc(p.where) + ': ' : ''}<span class="mono">${esc(p.value)}</span> - ${esc(p.problem)}</li>`).join('')}</ul>` : ''}</div></div>`;
  if (!dry) { toast(`${WL[list]} updated`); await Watchlists(); }
  const out = $('#wl-out'); if (out) out.innerHTML = html;
}
async function wlRemove(id, value) {
  const reason = prompt(`Remove ${value} from the list? Say why (kept in the audit log).`);
  if (reason === null) return;
  await api(`/api/v1/watchlists/entries/${encodeURIComponent(id)}?reason=${encodeURIComponent(reason)}`, {method: 'DELETE'});
  toast('Removed'); Watchlists();
}

// ================================================================= Trace (diagnostics)
async function Trace(id) {
  const __g = GEN;
  const t = await api('/api/v1/admin/trace/' + encodeURIComponent(id));
  const call = c => `<div class="list-row" style="display:block"><div class="inline" style="flex-wrap:wrap;gap:8px">${status(c.status === 'ok' ? 'ok' : ['user_limit', 'budget_exceeded', 'daily_budget_exceeded', 'disabled_by_policy'].includes(c.status) ? 'medium' : 'high', c.status)}
      <span class="mono small">${esc(c.workflow)}</span><span class="tag">${esc(c.tier || '')}</span><span class="small muted">${nf(c.prompt_tokens)} in · ${nf(c.completion_tokens)} out · ${c.latency_ms == null ? '–' : c.latency_ms + ' ms'} · ${esc(c.model)}</span>
      ${c.claims_kept != null ? `<span class="small">${nf(c.claims_kept)} statement(s) kept, ${nf(c.claims_dropped)} removed by the evidence check</span>` : ''}</div>
    ${(c.guardrail && c.guardrail.dropped || []).map(d => `<div class="t-sub" style="color:var(--high)">Removed: “${esc(d.text)}” - ${esc(d.reason)}</div>`).join('')}
    <details class="mt"><summary class="small">Prompt as sent (identities pseudonymised) and answer</summary><pre class="mono small wrap" style="white-space:pre-wrap;max-height:320px;overflow:auto">${esc(c.prompt)}</pre><pre class="mono small wrap" style="white-space:pre-wrap;max-height:320px;overflow:auto">${esc(c.response)}</pre></details></div>`;
  setMainG(__g, page('Trace', `Everything request or job <span class="mono">${esc(t.trace_id)}</span> did - in order.`, '',
    `${t.job_run ? `<div class="mb">${card('Job run', `<dl class="kv"><dt>Job</dt><dd>${esc(t.job_run.job)}</dd><dt>Outcome</dt><dd>${status(t.job_run.status === 'ok' ? 'ok' : 'high', cap(t.job_run.status))} after ${esc(t.job_run.attempts)} attempt(s)</dd><dt>Started</dt><dd class="mono">${dt(t.job_run.started_at)}</dd><dt>Trigger</dt><dd>${esc(t.job_run.trigger)}</dd>${t.job_run.error ? `<dt>Error</dt><dd class="mono small wrap">${esc(t.job_run.error.slice(0, 600))}</dd>` : ''}</dl>`)}</div>` : ''}
    ${t.requests.length ? `<div class="mb">${card('Request', table(['Time', 'Who', 'Request', 'Status', {h: 'ms', num: 1}], t.requests.map(r => `<tr><td class="mono small">${dt(r.ts)}</td><td class="small">${esc(r.principal || 'anonymous')}</td><td class="mono small" style="white-space:normal;overflow-wrap:anywhere">${esc(r.method)} ${esc(r.path)}</td><td>${status(r.status < 400 ? 'ok' : 'high', String(r.status))}</td><td class="num small">${nf(r.latency_ms)}</td></tr>`)), {flush: true})}</div>` : ''}
    <div class="mb">${card(`Audit events <span class="muted">(${t.audit.length})</span>`, table([{h: '#', num: 1}, 'Time', 'Actor', 'Event', 'Subject', 'Detail'], t.audit.map(x => `<tr><td class="num mono small muted">${x.seq}</td><td class="mono small">${dt(x.ts)}</td><td class="small">${esc(x.actor_type)} · ${esc(x.actor_id)}</td>
      <td class="mono small">${esc(x.event_type)}</td><td class="small muted">${esc(x.subject_type)} ${esc(x.subject_id)}</td><td class="mono small muted" style="white-space:normal;overflow-wrap:anywhere;min-width:180px">${esc(JSON.stringify(x.payload).slice(0, 220))}</td></tr>`), {empty: 'No audit events'}), {flush: true, sub: 'hash-chained'})}</div>
    ${card(`Model calls <span class="muted">(${t.llm_calls.length})</span>`, t.llm_calls.map(call).join('') || empty('No model calls'), {sub: 'what each agent asked the model, what it answered, what the evidence check removed'})}`));
}


// ================================================================= Attack story
const HCLS = {rejected: 'ok', unlikely: 'medium', plausible: 'high', cannot_assess: 'info'};
const HLBL = {rejected: 'Rejected', unlikely: 'Unlikely', plausible: 'Still plausible', cannot_assess: 'Cannot assess'};
const NODE = {identity: 'var(--c-critical)', asset: 'var(--c-high)', secret: 'var(--c-vulnerability)', indicator: 'var(--c-other)',
  recipient: 'var(--c-phishing)', case: 'var(--text-3)', campaign: 'var(--c-phishing)'};

function blastGraph(b) {
  // grouped reach, not a force graph: at real-tenant size a graph of every indicator is unreadable
  const by = k => b.nodes.filter(n => n.kind === k);
  const short = (s, n = 46) => { s = String(s || ''); return s.length > n ? s.slice(0, n - 1) + '…' : s; };
  const dot = k => `<i class="bdot" style="background:${NODE[k] || 'var(--c-other)'}"></i>`;
  const sec = (title, n, body) => n ? `<div class="bsec"><div class="small strong">${title} <span class="muted">(${nf(n)})</span></div>${body}</div>` : '';
  const principals = b.nodes.filter(n => n.principal);
  const people = principals.map(n => `<div class="brow">${dot(n.kind)}<span class="strong">${['asset', 'identity'].includes(n.kind) ? entLink(n.id, n.label) : esc(n.label)}</span><span class="tag">${n.kind === 'asset' ? 'host' : 'user'}</span></div>`).join('');
  const secrets = by('secret').map(n => `<div class="brow">${dot('secret')}<span>${esc(n.label)}</span><span class="t-sub">accessed after compromise</span></div>`).join('');
  const rec = by('recipient');
  const recips = `<div class="bchips">${rec.map(n => `<span class="chip plain${n.interacted ? ' high' : ''}" title="${esc(n.label)}${n.interacted ? ' - interacted' : ''}">${esc(short(n.label, 28))}</span>`).join('')}</div>
    <div class="t-sub">${nf(rec.filter(n => n.interacted).length)} of ${nf(rec.length)} other recipients interacted (highlighted)</div>`;
  const cases = by('case').map(n => `<div class="brow">${chip(n.severity || 'info')}<span title="${esc(n.label)}">${caseLink(n.id.replace(/^case:/, ''), short(n.label, 60))}</span><span class="t-sub">${esc(cap(n.domain || ''))}</span></div>`).join('');
  const groups = {};
  by('indicator').forEach(n => { const [t, ...v] = String(n.label).split(':'); (groups[v.length ? t : 'other'] = groups[v.length ? t : 'other'] || []).push(v.length ? v.join(':') : n.label); });
  const IND = {domain: 'Domains', url: 'URLs', ip: 'IP addresses', email: 'Sender addresses', sha256: 'File hashes', other: 'Other'};
  const inds = Object.entries(groups).sort((a, z) => z[1].length - a[1].length).map(([t, vs]) => `<div class="bind"><div class="t-sub strong">${esc(IND[t] || cap(t))} · ${nf(vs.length)}</div>${
    moreList(vs.map(v => `<div class="mono small" title="${esc(v)}">${esc(short(v, 52))}</div>`), 5, '', k => `and ${nf(k)} more`)}</div>`).join('');
  return `<div class="blast">${sec('At the centre', principals.length, people)}${sec('Privileged secrets', by('secret').length, secrets)}
    ${sec('Also received the phishing e-mail', rec.length, recips)}${sec('Related cases', by('case').length, cases)}
    ${sec('Indicators involved', by('indicator').length, `<div class="binds">${inds}</div>`)}</div>`;
}

async function Story(id) {
  const __g = GEN;
  const [st, llmSt] = await Promise.all([api('/api/v1/cases/' + encodeURIComponent(id) + '/story'), api('/api/v1/llm/status')]);
  const a = st.assessment, b = st.blast_radius.stats;
  const evById = Object.fromEntries(st.events.map(e => [e.ref, e]));
  const refs = rs => rs.map(r => { const e = evById[r]; const tip = e ? `${e.tool} · ${e.ts ? dt(e.ts) : 'time not reported'} · ${e.title}` : r;
    return `<abbr class="cite" tabindex="0" data-tip="${esc(tip)}" aria-label="${esc(r + ': ' + tip)}">${esc(r)}</abbr>`; }).join('');
  const kc = st.kill_chain.map(k => `<div class="stg ${esc(k.state)}" title="${esc(k.name)}: ${esc(cap(k.state))}"><b>${esc(k.name)}</b>${
    {observed: 'Observed', blocked: 'Blocked', no_evidence: 'Checked - none', blind_spot: 'Blind spot', before_scope: '-'}[k.state] || esc(k.state)}</div>`).join('');
  const steps = st.steps.map(s => `<div class="stp ${s.outcome === 'blocked' ? 'blocked' : ''}">
      <div class="when">${s.start ? esc(dt(s.start)) : 'time not reported by the tool'} · step ${s.n}</div>
      <div class="ttl">${esc(s.stage_name)}: ${esc(s.title)}</div>
      ${s.narrative !== s.title ? `<div class="small" style="color:var(--text-2)">${esc(s.narrative)}</div>` : ''}
      <div class="meta">${s.outcome === 'blocked' ? chip('blocked', 'ok plain') : chip('succeeded', 'critical plain')}
        ${s.techniques.map(t => `<span class="tag" title="${esc(t.name)}">${esc(t.id)}</span>`).join('')}
        ${s.tools.map(t => `<span class="tag">${esc(t)}</span>`).join('')}
        <span class="small muted">confidence ${esc(s.confidence)} (${esc(s.confidence_reason)})</span> ${refs(s.evidence)}</div></div>`).join('');
  const hyps = st.hypotheses.map(h => `<div class="hyp"><div class="inline" style="justify-content:space-between"><span class="strong small">${esc(h.hypothesis)}</span>
      ${status(HCLS[h.status] || 'info', HLBL[h.status] || h.status)}</div><div class="small" style="color:var(--text-2);margin-top:3px">${esc(h.reasoning)} ${refs(h.evidence)}</div></div>`).join('');
  const gaps = st.gaps.map(g => `<div class="list-row small">${status(g.status === 'blind_spot' ? 'critical' : 'info', g.status === 'blind_spot' ? 'Blind spot' : 'No evidence')}<span class="grow">${esc(g.text)}</span></div>`).join('');
  const plan = st.response_plan.map(ph => `<div class="small strong" style="margin:12px 0 2px">${esc(ph.label)}</div>` + ph.actions.map(x => `
      <div class="plan-item">${x.approvable && can('approve_action') ? `<input type="checkbox" class="plan-cb" value="${esc(x.id)}" ${ph.phase === 'contain' || ph.phase === 'preserve' ? 'checked' : ''} aria-label="select">` : `<span style="width:13px"></span>`}
        <div class="grow"><div class="mono small strong">${esc(x.action_type)}</div><div class="small" style="color:var(--text-2)">${esc(x.rationale)}</div>
        <div class="t-sub">${esc(x.targets.join(', '))}${(x.duplicate_ids || []).length ? ` · ×${x.duplicate_ids.length + 1} (one per related case, approved together)` : ''}${x.four_eyes ? ' · four-eyes: two different people approve' : ''}</div></div>
        ${status(x.status === 'executed' ? 'ok' : x.approvable ? 'medium' : 'info', cap(x.status))}</div>`).join('')).join('');
  const da = st.deep_analysis;
  const deepPanel = !llmSt.configured
    ? `<div class="callout info"><span>No LLM is configured, so the deep analysis is unavailable. The story above is complete and deterministic: every step, gap and explanation is computed from stored records. To enable a deep analysis, set an approved endpoint (<code>SOC_LLM_PROVIDER</code>); internal identities are pseudonymised before any call.</span></div>`
    : `<div id="deep">${da ? deepHtml(da, evById) : `<p class="small muted" style="margin-top:0">A principal-responder review of this story by <b>${esc(llmSt.provider)}</b>. Only the evidence above is sent (internal identities pseudonymised); every statement must cite it or it is removed.</p>`}</div>
       ${can('investigate') ? `<div class="inline mt">${btn(da ? 'Re-run deep analysis' : 'Run deep analysis', 'runDeep', [id, !!da], 'primary', 'intel')}</div>` : ''}`;
  setMainG(__g, `<div class="page-head"><div>
      <div class="inline" style="margin-bottom:8px"><a href="#/cases/${encodeURIComponent(id)}" class="small" aria-label="Back to the case" title="Back to the case">${icon('back')}</a><span class="verdict ${esc(a.verdict)}">${esc(a.label)}</span>
        <span class="small muted">${esc(a.confidence)} confidence · ${esc(a.reason)}</span></div>
      <h1>Attack story</h1><p>${esc(st.title)} · reconstructed from ${st.generated_from.length} case(s), ${st.tools.length} tools${st.span_minutes != null ? ` · ${st.span_minutes} min from first to last step` : ''}</p></div></div>
    ${card(null, `<div class="prose" style="font-size:14px">${esc(st.summary)}</div>`)}
    <div class="grid g-kpi mt">${kpi('Kill-chain stages', st.stages_observed.length, (() => { const r = new Set(st.steps.filter(s => s.outcome !== 'blocked').map(s => s.stage)); const b = new Set(st.steps.filter(s => s.outcome === 'blocked' && !r.has(s.stage)).map(s => s.stage)); return `${r.size} reached · ${b.size} blocked`; })())}${kpi('Steps', st.steps.length, `${st.steps.filter(s => s.outcome === 'blocked').length} blocked`)}
      ${kpi('Users reached', b.users_received ? `${b.users_interacted} / ${b.users_received}` : '0', 'interacted / received')}${kpi('Hosts', b.hosts)}
      ${kpi('Privileged secrets', b.privileged_secrets, esc(st.blast_radius.secrets.join(', ')), b.privileged_secrets > 0)}${kpi('Gaps checked', st.gaps.length, `${st.gaps.filter(g => g.status === 'blind_spot').length} blind spot(s)`)}</div>
    <div class="mt">${card('Kill chain', `<div class="chain">${kc}</div>`, {sub: 'MITRE ATT&CK tactics - observed, blocked, checked without evidence, or blind'})}</div>
    <div class="grid g-2 mt">
      <div class="stack">
        ${card('What happened', st.steps.length ? `<div class="steps">${steps}</div>` : empty('No attack step found in any connected tool.'), {sub: 'every step cites the events it rests on - hover a reference'})}
        ${card('Response plan', plan ? plan + (can('approve_action') ? `<div class="inline mt">${btn('Approve selected', 'approveBundle', [id], 'primary')}<span class="small muted">Each action still passes policy and four-eyes checks.</span></div>` : '') : empty('No actions for this story'), {sub: 'phased: contain, preserve, eradicate, recover, communicate'})}
      </div>
      <div class="stack">
        ${card('Blast radius', blastGraph(st.blast_radius))}
        ${card('Benign explanations tested', hyps || empty('None applicable'), {sub: 'what else could explain this'})}
        ${card('Gaps', gaps || empty('Every stage after the first step has evidence'), {sub: 'what we looked for and did not find'})}
        ${st.exposure.length ? card('Exposure on affected assets', st.exposure.slice(0, 6).map(x => `<div class="list-row small">${chip(x.severity || 'info')}<span class="grow">${esc(x.title)}</span><span class="tag">${esc(x.tool)}</span></div>`).join('')) : ''}
      </div>
    </div>
    <div class="mt">${card('Deep analysis', deepPanel, {sub: 'optional LLM review, bound to the evidence above'})}</div>`);
}

function deepHtml(d, evById) {
  if (!d.ok) return `<div class="callout">${esc(d.reason || 'Deep analysis unavailable')}</div>`;
  const cite = ids => (ids || []).map(r => { const tip = evById[r] ? `${evById[r].tool} · ${evById[r].title}` : r;
    return `<abbr class="cite" tabindex="0" data-tip="${esc(tip)}" aria-label="${esc(r + ': ' + tip)}">${esc(r)}</abbr>`; }).join('');
  return `${d.disagreement ? `<div class="callout danger">${esc(d.disagreement)}</div>` : ''}
    <div class="inline" style="margin-bottom:8px">${chip(d.confidence === 'high' ? 'critical' : d.confidence === 'medium' ? 'medium' : 'info', 'plain')}<span class="small">model confidence <b>${esc(d.confidence)}</b> · ${esc(d.provider)} ${esc(d.model || '')} · ${esc(dt(d.generated_at))}${d.cached ? ' · cached' : ''}</span>
      ${d.dropped_statements ? `<span class="small" style="color:var(--high)">${d.dropped_statements} unsupported statement(s) removed</span>` : '<span class="small muted">every statement cited</span>'}</div>
    <div class="prose">${esc(d.assessment)}</div>
    ${d.attacker_objective ? `<p class="small"><b>Likely objective:</b> ${esc(d.attacker_objective.text)} ${cite(d.attacker_objective.evidence_ids)}</p>` : ''}
    <div class="grid g-2e mt">
      <div><div class="small strong">Key findings</div>${d.key_findings.map(f => `<div class="${f.kind === 'fact' ? 'fact' : 'inf'} small">${esc(f.text)} ${cite(f.evidence_ids)}</div>`).join('') || empty('None')}</div>
      <div><div class="small strong">Alternative explanations</div>${d.alternative_explanations.map(h => `<div class="hyp small"><b>${esc(h.hypothesis)}</b> ${status(HCLS[h.status] || 'info', HLBL[h.status] || h.status)}<div style="color:var(--text-2)">${esc(h.reasoning)} ${cite(h.evidence_ids)}</div></div>`).join('') || empty('None')}</div>
    </div>
    <div class="grid g-2e mt">
      <div><div class="small strong">Priorities</div>${d.priorities.map((p, i) => `<div class="list-row small"><span class="score">${i + 1}</span><div class="grow">${esc(p.text)} <span class="tag">${esc(p.action_ref)}</span><div class="t-sub">${esc(p.why)} ${cite(p.evidence_ids)}</div></div></div>`).join('') || empty('None')}</div>
      <div><div class="small strong">Open questions</div>${d.open_questions.map(q => `<div class="list-row small"><div class="grow">${esc(q.question)}<div class="t-sub">${esc(q.why)} ${cite(q.evidence_ids)}</div></div></div>`).join('') || empty('None')}</div>
    </div>`;
}
async function runDeep(id, force) {
  const el = $('#deep'); if (el) el.innerHTML = '<div class="inline muted"><span class="spin"></span> Analysing the evidence…</div>';
  const r = await post(`/api/v1/cases/${id}/deep-analysis`, {force});
  if (r.available === false) { toast(r.llm_notice || r.reason, true); return; }
  toast(r.llm_notice || (r.ok ? 'Deep analysis complete' : r.reason), !r.ok || !!r.llm_notice);
  Story(id);
}
async function approveBundle(id) {
  const ids = [...document.querySelectorAll('.plan-cb:checked')].map(x => x.value);
  if (!ids.length) { toast('Select at least one action', true); return; }
  const r = await post(`/api/v1/cases/${id}/story/approve`, {action_ids: ids});
  const failed = r.results.filter(x => !x.ok);
  const second = r.results.filter(x => x.ok && x.awaiting_second_approval).length;
  toast(`${r.approved - second} approved${second ? ` · ${second} need a second lead (first approval recorded)` : ''}${failed.length ? ` · ${failed.length} not approved: ${failed[0].error}` : ''}`, failed.length > 0);
  refreshStatus(); Story(id);
}

// ================================================================= registry
window.VIEWS = {trace: Trace, search: Search, story: Story, overview: Overview, intelligence: Intelligence, cases: Cases, entity: Entity, approvals: Approvals, phishing: Phishing,
  suppliers: Suppliers, vulnerabilities: Vulnerabilities, cloud: Cloud, coverage: Coverage, 'shadow-it': ShadowIt, integrations: Integrations, 'ai-usage': AiUsage,
  policy: Policy, reports: Reports, access: Access, audit: Audit, watchlists: Watchlists};
Object.assign(ALLOWED, {saveValueInput, casePage, approvalPage, actDetail, showMore, notifyTest, assignCase, addNote, ownerFilter, reportPlan, buildPlanned, savePlanned, buildTemplate, runDeep, approveBundle, approvalFilter, intelAll, askIntel, refreshIntel, insightAct, intelFilter, caseFilter, runInc, runPh, act, decide, upload, vmRefresh, ticketSync,
  campaign, vmAsk, misRoute, misVerb, ownUpload, ownClear, testConn, runJob, preflight, configure, pauseConn, proposeConfig, approveConfig,
  rejectConfig, closePanel, showHistory, showImport, importConfig, restoreConfig, showLists, proposeLists, saveLlmPolicy, checkModels, loadCalls, kill, approvePolicy, report, compliancePack, grant, approveGrant, revokeGrant, revokeKey, newKey, auditExport, wlUpload, wlRemove, styleUpload, styleSave, styleRemove, styleReset});
