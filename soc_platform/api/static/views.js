// Agentic SOC console - pages. Each view renders into #main; every figure comes from the API.
'use strict';

const dot = k => `<span class="dot-i ${esc(k)}"></span>`;
const status = (k, label) => `<span class="status">${dot(k)}${esc(label)}</span>`;
const hours = h => h == null ? '–' : h < 1 ? Math.max(1, Math.round(h * 60)) + ' min' : h < 48 ? h.toFixed(1) + ' h' : (h / 24).toFixed(1) + ' d';
const PBAND = {P1: 'critical', P2: 'high', P3: 'medium', P4: 'low'};
const pchip = p => `<span class="chip ${PBAND[p] || ''}">${esc(p)}</span>`;
const entLink = (id, name) => `<a href="#/entity/${encodeURIComponent(id)}">${esc(name)}</a>`;
const caseLink = (id, name) => `<a href="#/cases/${encodeURIComponent(id)}">${esc(name)}</a>`;

// ================================================================= Overview
async function Overview() {
  const __g = GEN;
  const [o, conns, dr, top] = await Promise.all([api('/api/v1/dashboard/overview?days=14'), api('/api/v1/dashboard/connectors'),
    api('/api/v1/metrics/drift'), inDomain('*') ? api('/api/v1/intelligence/risk/top?limit=6') : Promise.resolve([])]);
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
    <div class="grid g-2 mt">
      ${card('New cases per day', stackedBars(o.trend, ['phishing', 'incident', 'vulnerability']), {sub: 'by domain'})}
      ${card('Open cases by severity', donut(c.open_by_severity))}
    </div>
    <div class="grid g-2 mt">
      ${card('Highest-priority insights', o.insights.top.map(i => `<div class="list-row">${chip(i.severity)}<div class="grow"><div class="t-title">${esc(i.title)}</div><div class="t-sub">${esc(cap(i.rule))}</div></div></div>`).join('') || empty('No open insights'),
        {right: go('#/intelligence', 'All insights', 'small')})}
      ${card('Riskiest users and hosts', top.map(p => `<div class="list-row"><div class="grow"><div class="t-title">${entLink(p.entity_id, p.name)}</div><div class="t-sub">${esc(p.dimensions.join(' · '))}</div></div>
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
        ${card('Situation brief', `<div class="prose">${esc(b.summary)}</div>`, {right: chip(b.source === 'llm' ? 'LLM narrative' : 'Deterministic', 'plain')})}
        ${card('Ask the analyst', `<div class="inline"><input class="input" style="flex:1;min-width:260px" id="iq" data-enter="askIntel" placeholder="e.g. Is jane.doe@cci-demo.com compromised and what should we do first?">
          ${btn('Ask', 'askIntel', [], 'primary')}</div><div id="ia"></div>`)}
        ${card(`Correlated findings <span class="muted">(${ins.length})</span>`, shown.map(i => `
          <div class="list-row" style="align-items:flex-start;padding:14px 0">
            <div>${chip(i.severity)}</div>
            <div class="grow"><div class="t-title">${esc(i.title)}</div>
              <div class="t-sub">${esc(cap(i.rule))} · ${esc((i.requirements || []).join(', '))} · last seen ${dt(i.last_seen)}</div>
              ${i.narrative ? `<p class="small clamp" style="margin:8px 0 6px;color:var(--text-2)" title="${esc(i.narrative)}">${esc(i.narrative)}</p>` : ''}
              ${(i.next_steps || []).length ? `<div class="small"><span class="strong">Next steps</span><ol style="margin:4px 0 0 18px;padding:0">${i.next_steps.map(n => `<li>${esc(n)}</li>`).join('')}</ol></div>` : ''}
              <details class="mt" style="margin-top:8px"><summary>Evidence (${(i.evidence || []).length})</summary>${(i.evidence || []).map(e => `<div class="ev"><span class="ref">${esc(e.source || '')}</span><span class="small">${esc(e.summary || e.signal || '')} <span class="muted">${esc(e.when ? dt(e.when) : '')}</span></span></div>`).join('')}</details>
            </div>
            <div class="inline">${can('investigate') ? btn('Acknowledge', 'insightAct', [i.id, 'acknowledge'], 'sm') + btn('Dismiss', 'insightAct', [i.id, 'dismiss'], 'sm ghost') : ''}</div>
          </div>`).join('') + (filtered.length > shown.length ? `<div style="padding-top:12px">${btn(`Show all ${filtered.length}`, 'intelAll', [], 'sm')}</div>` : '') || empty('No findings for this filter'),
          {right: `<div class="seg">${['all', 'critical', 'high', 'medium'].map(f => `<button class="${f === INTEL_FILTER ? 'on' : ''}" data-fn="intelFilter" data-args="${arg(f)}">${cap(f)}</button>`).join('')}</div>`})}
      </div>
      ${card('Risk by user and host', top.map(p => `<div class="list-row"><div class="grow"><div class="t-title">${entLink(p.entity_id, p.name)}</div><div class="t-sub">${esc(p.kind)} · ${esc(p.dimensions.join(', '))}</div>
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
    <div class="small muted mt">How this was answered: ${esc(r.planner)} planner · ${r.tool_calls.map(t => `<span class="tag">${esc(t.tool)}</span>`).join('')}</div>`;
}
async function refreshIntel() { await post('/api/v1/intelligence/refresh'); toast('Correlation refreshed'); Intelligence(); }
async function insightAct(id, verb) { await post(`/api/v1/intelligence/insights/${id}/${verb}`); toast(`Insight ${verb}d`); Intelligence(); }
function intelFilter(f) { INTEL_FILTER = f; INTEL_ALL = false; Intelligence(); }
function intelAll() { INTEL_ALL = true; Intelligence(); }

// ================================================================= Cases
let CASE_FILTER = 'all';
async function Cases(id) {
  const __g = GEN;
  if (id) return CaseDetail(id);
  const cs = await api('/api/v1/cases');
  const rows = (CASE_FILTER === 'all' ? cs : cs.filter(c => c.domain === CASE_FILTER)).map(c => `
    <tr class="click" data-fn="goTo" data-args="${arg('#/cases/' + c.id)}"><td>${chip(c.severity)}</td>
      <td><div class="t-title">${esc(c.title)}</div><div class="t-sub">${esc(cap(c.domain))}</div></td>
      <td>${esc(cap(c.verdict || 'pending'))}</td><td class="num">${c.confidence != null ? pct(c.confidence) : '–'}</td>
      <td>${esc(cap(c.status))}</td><td class="muted">${dt(c.created_at)}</td></tr>`);
  const actions = (can('investigate') && inDomain('incident') ? btn('Run incident pipeline', 'runInc', [], '', 'play') : '') +
    (can('investigate') && inDomain('phishing') ? btn('Pull reported email', 'runPh', [], '', 'phishing') : '');
  setMainG(__g, page('Cases', 'Investigations across all domains. Open a case for the evidence, reasoning and recommended actions.', actions,
    card(null, `<div style="padding:12px 14px;border-bottom:1px solid var(--border)"><div class="seg">${['all', 'phishing', 'incident', 'vulnerability'].map(f =>
      `<button class="${f === CASE_FILTER ? 'on' : ''}" data-fn="caseFilter" data-args="${arg(f)}">${cap(f)}${f !== 'all' ? ` <span class="muted">${cs.filter(c => c.domain === f).length}</span>` : ''}</button>`).join('')}</div></div>` +
      table([{h: 'Severity'}, {h: 'Case'}, {h: 'Verdict'}, {h: 'Confidence', num: 1}, {h: 'Status'}, {h: 'Opened'}], rows, {empty: 'No cases yet - run a pipeline to ingest alerts and reported email.'}), {flush: true})));
}
function caseFilter(f) { CASE_FILTER = f; Cases(); }
async function runInc() { toast('Running incident pipeline…'); const r = await post('/api/v1/incidents/run'); toast(`${r.new_incidents} new incident(s), ${r.investigated.length} investigated`); render(); }
async function runPh() { toast('Pulling reported email…'); const r = await post('/api/v1/phishing/ingest'); toast(`${(r.processed || []).length} message(s) analysed`); render(); }

async function CaseDetail(id) {
  const __g = GEN;
  const v = await api('/api/v1/cases/' + encodeURIComponent(id));
  const c = v.case, a = v.assessment || {};
  const un = (v.completeness && v.completeness.unavailable) || [];
  const acts = [...v.actions].sort((x, y) => (x.priority || 99) - (y.priority || 99));
  const astat = x => status(x.status === 'executed' ? 'ok' : ['rejected', 'rolled_back'].includes(x.status) ? 'info' : x.status === 'failed' ? 'critical' : 'medium', cap(x.status));
  const actRow = x => `<tr><td class="num muted">${esc(x.priority ?? '')}</td>
    <td style="min-width:320px"><div class="t-title mono">${esc(x.action_type)}</div><div class="small" style="margin-top:3px;color:var(--text-2)">${esc(x.rationale)}</div>
      <div class="t-sub">L${esc(x.level)}${x.blast_radius ? ' · blast radius: ' + esc(x.blast_radius) : ''}${x.reversible === false ? ' · not reversible' : ''}</div>
      ${(x.policy_reasons || []).slice(1).map(r => `<div class="t-sub">${esc(r)}</div>`).join('')}</td>
    <td class="small wrap">${x.targets.slice(0, 3).map(t => esc(t.id)).join('<br>')}${x.targets.length > 3 ? `<br><span class="muted">+${x.targets.length - 3} more</span>` : ''}</td>
    <td>${astat(x)}${x.approver ? `<div class="t-sub">${esc(x.approver)}</div>` : ''}</td>
    <td><div class="inline" style="flex-wrap:nowrap">${['recommended', 'pending_approval'].includes(x.status) && can('approve_action') ? btn('Approve', 'act', [x.id, 'approve', id], 'sm primary') + btn('Reject', 'act', [x.id, 'reject', id], 'sm') :
      x.status === 'executed' && can('rollback_action') ? btn('Roll back', 'act', [x.id, 'rollback', id], 'sm') : ''}</div></td></tr>`;
  const intel = v.intelligence || {};
  setMainG(__g, `<div class="page-head"><div>
      <div class="inline" style="margin-bottom:8px"><a href="#/cases" class="small">${icon('back', '')}</a>${chip(c.severity)}${chip(c.verdict || 'pending', 'plain')}<span class="muted small">${esc(cap(c.domain))} · ${esc(cap(c.status))} · opened ${dt(c.created_at)}</span></div>
      <h1>${esc(c.title)}</h1><p>Confidence ${pct(c.confidence)} · automation mode ${esc(cap(c.autonomy_mode || 'recommend'))}</p></div>
      <div class="actions">${btn('Investigation record', 'dl', [`/api/v1/cases/${id}/report`], '', 'download')}</div></div>
    ${un.length ? `<div class="callout"><b>Incomplete picture.</b>&nbsp;Unavailable sources: ${un.map(u => esc(u.source)).join(', ')}. Conclusions below exclude them.</div>` : ''}
    <div class="grid g-2">
      <div class="stack">
        ${card('Assessment', `<div class="prose">${esc(c.summary)}</div>
          ${(a.facts || []).length ? `<h3 class="small strong" style="margin:16px 0 4px">Facts</h3>${a.facts.map(x => `<div class="fact small">${esc(x.text)} ${cite(x)}</div>`).join('')}` : ''}
          ${(a.inferences || []).length ? `<h3 class="small strong" style="margin:16px 0 4px">Inferences</h3>${a.inferences.map(x => `<div class="inf small">${esc(x.text)} ${cite(x)}</div>`).join('')}` : ''}
          ${(a.mitre || []).length ? `<h3 class="small strong" style="margin:16px 0 6px">MITRE ATT&amp;CK</h3>${a.mitre.map(m => `<span class="tag">${esc(m.technique)} ${esc(m.name || '')}</span>`).join('')}` : ''}`,
          {sub: 'hover a reference to see the evidence it cites'})}
        ${card(`Recommended actions <span class="muted">(${acts.length})</span>`, table(['#', 'Action and rationale', 'Targets', 'Status', ''], acts.map(actRow), {empty: 'No actions recommended'}), {flush: true})}
        ${card('Evidence', Object.entries(v.evidence).map(([d, items]) => `<div class="small strong" style="margin:10px 0 2px;text-transform:capitalize">${esc(cap(d))}</div>` +
          items.map(i => `<div class="ev"><span class="ref">${esc(i.ref || '')}</span><div class="grow small"><span class="muted">${esc(i.source)}</span> · ${esc(i.summary)}
            ${i.type !== 'fact' ? chip('inference', 'plain') : ''} ${i.deep_link ? `<a target="_blank" rel="noopener noreferrer" href="${esc(safeUrl(i.deep_link))}">open in tool</a>` : ''}</div></div>`).join('')).join('') || empty('No evidence'))}
      </div>
      <div class="stack">
        ${(intel.entity_risk || []).length || (intel.insights || []).length ? card('Cross-domain context',
          (intel.entity_risk || []).map(r => `<div class="list-row"><span class="grow">${entLink(r.entity_id, r.name)}</span><div style="width:70px">${meter(r.score)}</div><span class="score">${Math.round(r.score)}</span></div>`).join('') +
          (intel.insights || []).map(i => `<div class="list-row" style="align-items:flex-start">${chip(i.severity)}<div class="grow small">${esc(i.title)}</div></div>`).join('')) : ''}
        ${card('Entities', v.entities.map(e => `<div class="list-row"><span class="tag">${esc(e.kind)}</span><div class="grow"><div class="t-title">${['asset', 'identity'].includes(e.kind) ? entLink(e.id, e.name) : esc(e.name)}</div>
          <div class="t-sub">${esc(e.role)} · seen by ${esc(e.seen_by.join(', ') || '–')}</div></div></div>`).join('') || empty('No entities'))}
        ${can('investigate') ? card('Analyst decision', `<div class="stack" style="gap:10px"><select id="dv">${['true_positive', 'malicious', 'suspicious', 'false_positive', 'benign'].map(o => `<option value="${o}">${cap(o)}</option>`).join('')}</select>
          <textarea id="dr" rows="3" placeholder="Reasoning (used as feedback for tuning)"></textarea>${btn('Record decision', 'decide', [id], 'primary')}</div>
          ${v.dispositions.map(d => `<div class="list-row small"><span class="grow">${esc(d.analyst)}: <b>${esc(cap(d.verdict))}</b> - ${esc(d.reasoning)}</span><span class="muted">${dt(d.at)}</span></div>`).join('')}`) : ''}
        ${card('Timeline', v.timeline.slice(-30).reverse().map(t => `<div class="list-row small"><span class="mono muted" style="min-width:110px">${dt(t.ts)}</span><span class="grow">${esc(t.title)}</span><span class="tag">${esc(t.tool || '')}</span></div>`).join('') || empty('No events'))}
        ${card('Audit trail', `<details><summary>${v.audit.length} audited events</summary>${v.audit.map(x => `<div class="list-row small"><span class="mono muted">#${x.seq}</span><span class="grow">${esc(x.event)}</span><span class="muted">${esc(x.actor)}</span></div>`).join('')}</details>`)}
      </div>
    </div>`);
}
async function act(aid, verb, cid) { await post(`/api/v1/actions/${aid}/${verb}`, {note: 'via console'}); toast(`Action ${verb === 'approve' ? 'approved' : verb === 'reject' ? 'rejected' : 'rolled back'}`); refreshStatus(); cid ? CaseDetail(cid) : Approvals(); }
async function decide(id) { await post(`/api/v1/cases/${id}/disposition`, {verdict: $('#dv').value, reasoning: $('#dr').value}); toast('Decision recorded'); CaseDetail(id); }

// ================================================================= Entity 360
async function Entity(id) {
  const __g = GEN;
  const e = await api('/api/v1/entities/' + encodeURIComponent(id) + '/360');
  const r = e.risk;
  setMainG(__g, `<div class="page-head"><div><div class="inline" style="margin-bottom:8px"><span class="tag">${esc(e.kind)}</span>${r && r.score > 0 ? chip(r.band) : chip('no risk signals', 'plain')}</div>
      <h1>${esc(e.name)}</h1><p>Seen by ${esc(e.seen_by.join(', ') || '–')}</p></div>
      ${r ? `<div class="actions"><div class="card kpi" style="min-width:160px"><div class="label">Risk score</div><div class="value">${Math.round(r.score)}<span class="muted" style="font-size:14px">/100</span></div><div class="foot">${esc(r.dimensions.join(' · '))}</div></div></div>` : ''}</div>
    <div class="grid g-2">
      <div class="stack">
        ${card('Why this score', (r && r.factors.length) ? r.factors.map(f => `<div class="list-row" style="align-items:flex-start"><span class="score mono" style="min-width:42px">+${Math.round(f.decayed)}</span>
          <div class="grow"><div class="t-title">${esc(cap(f.signal))}</div><div class="t-sub">${esc(f.detail)}</div></div><span class="tag">${esc(f.source)}</span><span class="muted small">${dt(f.when)}</span></div>`).join('') : empty('No risk factors in the window'),
          {sub: 'weights decay with age'})}
        ${card('Timeline across tools', e.timeline.slice(-40).reverse().map(t => `<div class="list-row small"><span class="mono muted" style="min-width:110px">${dt(t.ts)}</span><span class="grow">${esc(t.title)}</span><span class="tag">${esc(t.tool || '')}</span></div>`).join('') || empty('No events'))}
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
async function Approvals() {
  const __g = GEN;
  const all = await api('/api/v1/actions?status=recommended,pending_approval');
  const doms = [...new Set(all.map(x => x.domain))].sort();
  const xs = APPROVAL_FILTER === 'all' ? all : all.filter(x => x.domain === APPROVAL_FILTER);
  setMainG(__g, page('Approvals', 'Actions the platform recommends. Nothing here runs until someone with the right role approves it; four-eyes actions need a second person.', '',
    card(null, `<div style="padding:12px 14px;border-bottom:1px solid var(--border)"><div class="seg">${['all', ...doms].map(f =>
      `<button class="${f === APPROVAL_FILTER ? 'on' : ''}" data-fn="approvalFilter" data-args="${arg(f)}">${esc(cap(f))} <span class="muted">${f === 'all' ? all.length : all.filter(x => x.domain === f).length}</span></button>`).join('')}</div></div>` +
      table(['Action', 'Targets', 'Rationale', 'Policy', ''], xs.map(x => `<tr>
      <td class="nowrap"><div class="t-title mono">${esc(x.action_type)}</div><div class="t-sub">${esc(cap(x.domain))} · L${esc(x.level)}</div></td>
      <td class="small wrap">${x.targets.slice(0, 3).map(t => esc(t.id)).join('<br>') || '<span class="muted">-</span>'}</td><td class="small">${esc(x.rationale)}</td>
      <td class="small muted">${(x.policy_reasons || []).slice(1).map(esc).join('<br>') || 'recommend (L2)'}</td>
      <td><div class="inline" style="flex-wrap:nowrap">${can('approve_action') ? btn('Approve', 'act', [x.id, 'approve'], 'sm primary') + btn('Reject', 'act', [x.id, 'reject'], 'sm') : ''}${x.case_id ? `<a class="btn sm ghost" href="#/cases/${encodeURIComponent(x.case_id)}">Case</a>` : ''}</div></td></tr>`),
      {empty: 'Nothing is waiting for approval.'}), {flush: true})));
}
function approvalFilter(f) { APPROVAL_FILTER = f; Approvals(); }

// ================================================================= Phishing
async function Phishing() {
  const __g = GEN;
  const m = await api('/api/v1/phishing/metrics');
  const clickers = Object.entries(m.clickers || {}).sort((a, b) => b[1] - a[1]);
  setMainG(__g, page('Phishing', 'User-reported email: analysis, campaign scope, who clicked, endpoint and identity impact, gated remediation.',
    (can('investigate') ? btn('Pull reporting mailbox', 'runPh', [], '', 'refresh') : '') + go('#/suppliers', 'Supplier risk', 'btn'),
    `<div class="grid g-kpi">${kpi('Reported', nf(m.reported))}${kpi('Auto-closed', nf(m.auto_closed), `${nf(m.sampled_for_qa)} sampled for QA`)}
      ${kpi('Campaigns', nf(m.campaigns))}${kpi('Repeat clickers', nf((m.repeat_clickers || []).length), '', (m.repeat_clickers || []).length > 0)}
      ${kpi('Time to containment', m.time_to_containment_minutes && m.time_to_containment_minutes.median != null ? m.time_to_containment_minutes.median + ' min' : '–', 'median')}</div>
    <div class="grid g-3 mt">
      ${card('Verdict mix', donut(m.verdict_mix, {malicious: 'var(--c-critical)', suspicious: 'var(--c-high)', spam: 'var(--c-medium)', safe: 'var(--c-low)'}))}
      ${card('Users who clicked', clickers.map(([u, n]) => `<div class="list-row"><span class="grow">${esc(u)}</span>${n >= 2 ? chip('repeat', 'plain') : ''}<span class="score">${n}</span></div>`).join('') || empty('No clicks recorded'))}
      ${can('investigate') ? card('Analyse a message', `<div class="stack" style="gap:10px"><input type="file" id="eml" accept=".eml,message/rfc822" class="input" style="padding:5px">
        ${btn('Analyse', 'upload', [], 'primary')}<div class="small muted">The original is stored encrypted; the verdict, evidence and recommended actions open as a case.</div></div>`) : ''}
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
async function Vulnerabilities() {
  const __g = GEN;
  const [m, f, cov] = await Promise.all([api('/api/v1/vm/metrics'), api('/api/v1/vm/findings'), api('/api/v1/vm/coverage')]);
  const acts = (can('investigate') ? btn('Refresh from scanners', 'vmRefresh', [], '', 'refresh') + btn('Sync tickets', 'ticketSync', [], '') : '') + go('#/cloud', 'Cloud posture', 'btn');
  setMainG(__g, page('Vulnerabilities', 'Rapid7, CrowdStrike, Wiz and Defender findings resolved to one record per asset and CVE, prioritised on exploitability and exposure.', acts,
    `<div class="grid g-kpi">${kpi('Open findings', nf(m.open))}${kpi('CISA KEV', nf(m.kev_open), 'known exploited', m.kev_open > 0)}
      ${kpi('Internet-exposed', nf(m.internet_exposed_open))}${kpi('Past SLA', nf(m.sla_breached), '', m.sla_breached > 0)}${kpi('Asset match rate', pct(m.asset_match_rate, 1), 'across scanners')}</div>
    <div class="grid g-2 mt">
      ${card('Ask about exposure', `<div class="inline"><input class="input" style="flex:1;min-width:260px" id="vq" data-enter="vmAsk" placeholder="e.g. which internet-facing hosts have KEV vulnerabilities?">${btn('Query', 'vmAsk', [], 'primary')}</div><div id="vqa"></div>`)}
      ${card('Coverage gaps', `<dl class="kv"><dt>No EDR</dt><dd>${esc(cov.missing_edr.join(', ') || 'none')}</dd><dt>Not in CMDB</dt><dd>${esc(cov.not_in_cmdb.join(', ') || 'none')}</dd><dt>Resolution queue</dt><dd>${nf(cov.unresolved_queue)}</dd></dl>`)}
    </div>
    <div class="mt">${card(`Findings <span class="muted">(${f.length})</span>`, table(['Priority', 'CVE', 'Asset', 'Owner', 'SLA due', 'Seen by', 'Status', ''], f.map(x => `<tr>
      <td>${pchip(x.priority)}</td><td class="mono">${esc(x.cve)}</td><td><div class="t-title">${esc(x.asset)}</div>${x.internet_exposed ? '<div class="t-sub">internet-exposed</div>' : ''}</td>
      <td class="small">${esc(x.team || 'unknown')}</td><td class="mono small">${day(x.sla_due)}</td><td class="small muted">${esc(Object.keys(x.sources).join(', '))}</td><td>${esc(cap(x.status))}</td>
      <td>${x.campaign_id ? '<span class="muted small">In campaign</span>' : can('request_action') ? btn('Start campaign', 'campaign', [x.cve], 'sm') : ''}</td></tr>`), {empty: 'No findings - refresh from scanners.'}), {flush: true})}</div>`));
}
async function vmRefresh() { toast('Refreshing from scanners…'); await post('/api/v1/vm/refresh'); toast('Vulnerability data refreshed'); Vulnerabilities(); }
async function ticketSync() { const r = await post('/api/v1/vm/tickets/sync'); toast(`Tickets checked ${r.checked} · verified ${r.verified} · false closures ${r.false_closures}`); }
async function campaign(cve) { const r = await post('/api/v1/vm/campaigns', {cve, notify_via: 'ticket'}); toast(`Campaign created for ${cve}; notifications await approval`); Vulnerabilities(); return r; }
async function vmAsk() {
  const q = $('#vq').value.trim(); if (!q) return;
  const r = await post('/api/v1/vm/query', {question: q});
  $('#vqa').innerHTML = `<div class="divider"></div><div>${esc(r.answer)}</div><div class="small muted mt">Filter used: <code>${esc(JSON.stringify(r.generated_filter))}</code></div>
    <div class="mt">${table(['CVE', 'Asset', 'Priority', 'Owner'], r.records.slice(0, 20).map(x => `<tr><td class="mono">${esc(x.cve)}</td><td>${esc(x.asset)}</td><td>${pchip(x.priority)}</td><td class="small">${esc(x.team || '')}</td></tr>`), {empty: 'No matching records'})}</div>`;
}

async function Cloud() {
  const __g = GEN;
  const r = await api('/api/v1/vm/misconfigurations'), m = r.metrics;
  setMainG(__g, page('Cloud posture', 'Wiz misconfigurations run through the remediation lifecycle: owner, SLA, ticket, and closure validated against Wiz.',
    can('request_action') ? btn('Route to owners', 'misRoute', [], 'primary') : '',
    `<div class="grid g-kpi">${kpi('Open', nf(m.open))}${kpi('Past SLA', nf(m.overdue), '', m.overdue > 0)}${kpi('False closures', nf(m.false_closures), 'fix claimed, Wiz still reports it', m.false_closures > 0)}
      ${kpi('Teams involved', nf(Object.keys(m.by_team).length))}</div>
    <div class="mt">${card('Misconfigurations', table(['Severity', 'Rule', 'Resource', 'Owner', 'Status', 'SLA due', ''], r.items.map(x => `<tr>
      <td>${chip(x.severity)}</td><td class="small">${esc(x.rule)}</td><td><div class="t-title">${esc(x.resource)}</div><div class="t-sub">${esc(x.resource_type)} · ${esc(x.cloud)} ${esc(x.subscription)}</div></td>
      <td class="small">${esc(x.platform_team || 'Unknown owner')}</td><td class="nowrap">${esc(cap(x.status))}${x.reopened ? ` ${chip('reopened ' + x.reopened, 'high plain')}` : ''}</td>
      <td class="mono small nowrap" style="${x.overdue ? 'color:var(--crit)' : ''}">${day(x.sla_due)}</td>
      <td><div class="inline">${can('investigate') ? btn('Mark fixed', 'misVerb', [x.id, 'fixed'], 'sm') + btn('Validate', 'misVerb', [x.id, 'validate'], 'sm') : ''}</div></td></tr>`), {empty: 'No misconfigurations'}), {flush: true})}</div>`));
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
      <div class="matrix" style="grid-template-columns:repeat(${c.tactics.length},minmax(112px,1fr))">${c.tactics.map(t => `<div><div class="col-h">${esc(t.name)}<small>${t.coverage_pct}%</small></div>
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
      ${card('By category', Object.entries(r.by_category).map(([k, v]) => `<div class="list-row"><span class="grow">${esc(cap(k))}</span><span class="score">${v}</span></div>`).join('') || empty('None'))}
    </div>
    <div class="mt">${card('Risky destinations', table(['Domain', 'Categories', 'Outcome', 'Users', 'Hosts'], r.risky_destinations.map(x => `<tr><td class="mono small">${esc(x.domain)}</td><td class="small">${esc(x.categories.join(', '))}</td>
      <td>${x.status === 'reached' ? status('critical', 'Reached') : status('ok', 'Blocked')}</td><td class="small">${esc(x.users.join(', '))}</td><td class="small">${esc(x.hosts.join(', '))}</td></tr>`)), {flush: true})}</div>`));
}

// ================================================================= Integrations
async function Integrations() {
  const __g = GEN;
  const [cs, jr] = await Promise.all([api('/api/v1/dashboard/connectors'), api('/api/v1/jobs?limit=200')]);
  const last = {}; jr.runs.forEach(r => { if (!last[r.job]) last[r.job] = r; });
  const stc = {healthy: 'ok', on_demand: 'info', stale: 'medium', error: 'high', misconfigured: 'high', disabled: 'info'};
  const jst = {ok: 'ok', error: 'high', dead_letter: 'critical'};
  setMainG(__g, page('Integrations', 'Connector health, data freshness against each stream\'s expected cadence, and scheduled job runs.', '',
    `${card(`Connectors <span class="muted">(${cs.filter(c => c.enabled).length} enabled)</span>`, table(['Tool', 'State', 'Mode', 'Streams · age / expected', ''], cs.map(c => `<tr>
      <td><div class="t-title">${esc(c.tool)}</div><div class="t-sub">${esc(c.name)} · ${esc(c.category)}</div></td>
      <td>${status(stc[c.state] || 'info', cap(c.state))}${c.config_problems.map(p => `<div class="t-sub" style="color:var(--high)">${esc(p)}</div>`).join('')}</td>
      <td><span class="tag">${esc(c.mode || '')}</span></td>
      <td class="small">${c.streams.map(s => `<div>${esc(s.stream)}: <span class="mono">${s.age_hours == null ? 'never' : hours(s.age_hours)}</span> <span class="muted">/ within ${s.expected_within_hours} h</span>${s.fresh ? '' : ' ' + chip('stale', 'medium plain')}${s.last_error ? `<div class="t-sub" style="color:var(--crit)">${esc(s.last_error)}</div>` : ''}</div>`).join('') || '<span class="muted">queried on demand during investigations</span>'}</td>
      <td>${c.enabled && can('manage_connectors') ? btn('Test', 'testConn', [c.name], 'sm') : ''}</td></tr>`)), {flush: true})}
    <div class="mt">${card('Scheduled jobs', table(['Job', 'Last run', 'Outcome', {h: 'Duration', num: 1}, 'Detail', ''], Object.keys(jr.jobs).map(j => { const r = last[j]; return `<tr>
      <td class="t-title">${esc(cap(j))}</td><td class="mono small muted">${r ? dt(r.started_at) : 'never'}</td>
      <td>${r ? status(jst[r.status], cap(r.status)) + `${r.attempts > 1 ? `<div class="t-sub">${r.attempts} attempts</div>` : ''}` : ''}</td>
      <td class="num small">${r && r.duration_s != null ? r.duration_s + ' s' : ''}</td><td class="small muted">${r ? esc((r.error || JSON.stringify(r.summary)).slice(0, 140)) : ''}</td>
      <td>${can('manage_connectors') ? btn('Run now', 'runJob', [j], 'sm') : ''}</td></tr>`; })), {flush: true, sub: 'retried with backoff; dead-lettered after 3 failed runs'})}</div>`));
}
async function testConn(name) { const r = await post(`/api/v1/connectors/${name}/test`); toast(r.ok ? `${name}: connected (${r.latency_ms} ms, ${r.sample_records ?? 0} records)` : `${name}: ${r.error}`, !r.ok); }
async function runJob(name) { toast(`Running ${name}…`); const r = await post(`/api/v1/jobs/${name}/run`); toast(`${name}: ${r.status}${r.error ? ' - ' + r.error : ''}`, r.status !== 'ok'); Integrations(); }

// ================================================================= Policy
async function Policy() {
  const __g = GEN;
  const [p, cat, h] = await Promise.all([api('/api/v1/policy'), api('/api/v1/actions/catalog'), (await fetch('/health')).json()]);
  setMainG(__g, page('Automation policy', `Versioned autonomy policy (active version ${esc(p.active_version || 'default')}). L0 observe · L1 notify · L2 recommend · L3 approve · L4 autonomous. Destructive actions are never autonomous.`, '',
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
  const kinds = [['daily_exposure', 'Daily exposure report', 'Word · VM-F13', 'vulnerability'], ['weekly_vm', 'Weekly vulnerability report', 'Word · VM-F13', 'vulnerability'],
    ['weekly_mgmt', 'Management deck', 'PowerPoint · all domains', '*']];
  setMainG(__g, page('Reports', 'Generated from one validated dataset; figures are computed in code, commentary is grounded on them. CCI templates plug in.', '',
    `<div class="grid g-3">${kinds.filter(([, , , d]) => d === '*' ? window.ME.domains.includes('*') : inDomain(d)).map(([k, t, s]) => card(t, `<p class="small muted" style="margin-top:0">${esc(s)}</p>${btn('Generate', 'report', [k], 'primary', 'download')}`)).join('')}
      ${can('export_evidence') ? card('Compliance evidence pack', `<p class="small muted" style="margin-top:0">Control tests, evidence JSON, chained audit export and summary (ZIP) · U17</p>${btn('Generate pack', 'compliancePack', [], 'primary', 'download')}<div id="comp"></div>`) : ''}
      ${can('export_evidence') ? card('Audit export', `<p class="small muted" style="margin-top:0">Full hash-chained audit log as JSON Lines with verification, for archiving or SIEM.</p>${btn('Export', 'dl', ['/api/v1/audit/export'], '', 'download')}`) : ''}
    </div>`));
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
  setMainG(__g, page('Access', 'Time-bound, domain-scoped role grants on top of Entra roles; service-account keys for integrations. Nobody can change their own access.', '',
    `<div class="grid g-2e">
      ${card('Role assignments', table(['Principal', 'Role', 'Scope', 'Expires', ''], grants.map(g => `<tr><td><div class="t-title">${esc(g.principal_id)}</div><div class="t-sub">${esc(g.reason)} · by ${esc(g.granted_by)}</div></td>
        <td>${esc(cap(g.role))}</td><td class="small">${esc(g.domains.includes('*') ? 'All domains' : g.domains.join(', '))}</td><td class="mono small">${day(g.expires_at) === '–' ? 'never' : day(g.expires_at)}</td><td>${btn('Revoke', 'revokeGrant', [g.id], 'sm danger')}</td></tr>`), {empty: 'No platform grants - roles come from Entra.'}) +
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
  toast('Access granted'); Access();
}
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
  const [v, xs] = await Promise.all([api('/api/v1/audit/verify'), api('/api/v1/audit?limit=300')]);
  setMainG(__g, page('Audit log', 'Append-only and hash-chained: every retrieval, inference, recommendation, approval and action, attributed to an agent or a person.',
    v.ok ? `<span class="status-pill"><span class="dot"></span>Chain verified · ${nf(v.records)} records</span>` : `<span class="status-pill halt"><span class="dot"></span>Chain broken at #${esc(v.first_bad_seq)}</span>`,
    card(null, table([{h: '#', num: 1}, 'Time', 'Actor', 'Event', 'Subject'], xs.map(x => `<tr><td class="num mono small muted">${x.seq}</td><td class="mono small">${dt(x.ts)}</td>
      <td class="small">${esc(x.actor_type)} · ${esc(x.actor_id)}</td><td class="mono small">${esc(x.event_type)}</td><td class="small muted">${esc(x.subject_type)} ${esc(x.subject_id)}</td></tr>`)), {flush: true})));
}

// ================================================================= registry
window.VIEWS = {overview: Overview, intelligence: Intelligence, cases: Cases, entity: Entity, approvals: Approvals, phishing: Phishing,
  suppliers: Suppliers, vulnerabilities: Vulnerabilities, cloud: Cloud, coverage: Coverage, 'shadow-it': ShadowIt, integrations: Integrations,
  policy: Policy, reports: Reports, access: Access, audit: Audit};
Object.assign(ALLOWED, {approvalFilter, intelAll, askIntel, refreshIntel, insightAct, intelFilter, caseFilter, runInc, runPh, act, decide, upload, vmRefresh, ticketSync,
  campaign, vmAsk, misRoute, misVerb, testConn, runJob, kill, approvePolicy, report, compliancePack, grant, revokeGrant, revokeKey, newKey});
