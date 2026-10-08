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
        ${card('Ask the analyst', `<div class="inline"><input class="input" style="flex:1;min-width:260px" id="iq" data-enter="askIntel" placeholder="e.g. Is jane.doe@acme-demo.com compromised and what should we do first?">
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
    <div class="small muted mt">How this was answered: ${esc(r.planner)} planner · ${r.tool_calls.map(t => `<span class="tag">${esc(t.tool)}</span>`).join('')}</div>${llmNotice(r)}`;
}
async function refreshIntel() { await post('/api/v1/intelligence/refresh'); toast('Correlation refreshed'); Intelligence(); }
async function insightAct(id, verb) { await post(`/api/v1/intelligence/insights/${id}/${verb}`); toast(`Insight ${verb}d`); Intelligence(); }
function intelFilter(f) { INTEL_FILTER = f; INTEL_ALL = false; Intelligence(); }
function intelAll() { INTEL_ALL = true; Intelligence(); }

// ================================================================= Cases
let CASE_FILTER = 'all';
let OWNER_FILTER = 'all';
async function Cases(id) {
  const __g = GEN;
  if (id) return CaseDetail(id);
  const qs = new URLSearchParams();
  if (CASE_FILTER !== 'all') qs.set('domain', CASE_FILTER);
  if (OWNER_FILTER !== 'all') qs.set('assignee', OWNER_FILTER);
  const [cs, csum] = await Promise.all([api('/api/v1/cases' + (qs.toString() ? '?' + qs : '')), api('/api/v1/cases/summary')]);
  const shown = OWNER_FILTER !== 'all' ? csum[OWNER_FILTER === 'me' ? 'mine' : 'unassigned']
    : CASE_FILTER === 'all' ? csum.total : (csum.by_domain[CASE_FILTER] || 0);
  const rows = cs.map(c => `
    <tr class="click" data-fn="goTo" data-args="${arg('#/cases/' + c.id)}"><td>${chip(c.severity)}</td>
      <td><div class="t-title">${esc(c.title)}</div><div class="t-sub">${esc(cap(c.domain))}</div></td>
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
      (cs.length < shown ? `<div class="small muted" style="padding:10px 14px">Showing the ${cs.length} most recent of ${shown} cases.</div>` : ''), {flush: true})));
}
function caseFilter(f) { CASE_FILTER = f; Cases(); }
function ownerFilter(f) { OWNER_FILTER = f; Cases(); }
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
    <td style="min-width:190px"><div class="t-title mono" style="overflow-wrap:anywhere">${esc(x.action_type)}</div><div class="small" style="margin-top:3px;color:var(--text-2);overflow-wrap:anywhere">${esc(x.rationale)}</div>
      <div class="t-sub">L${esc(x.level)}${x.blast_radius ? ' · blast radius: ' + esc(x.blast_radius) : ''}${x.reversible === false ? ' · not reversible' : ''}</div>
      ${(x.policy_reasons || []).slice(1).map(r => `<div class="t-sub">${esc(r)}</div>`).join('')}</td>
    <td class="small wrap" style="min-width:110px">${x.targets.slice(0, 3).map(t => esc(t.name || t.recipient || t.id)).join('<br>')}${x.targets.length > 3 ? `<br><span class="muted">+${x.targets.length - 3} more</span>` : ''}</td>
    <td>${astat(x)}${x.approver ? `<div class="t-sub">${esc(x.approver)}</div>` : ''}</td>
    <td><div class="inline" style="flex-wrap:wrap;gap:6px">${['recommended', 'pending_approval'].includes(x.status) && can('approve_action') ? btn('Approve', 'act', [x.id, 'approve', id], 'sm primary') + btn('Reject', 'act', [x.id, 'reject', id], 'sm') :
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
  setMainG(__g, `<div class="page-head"><div>
      <div class="inline" style="margin-bottom:8px"><a href="#/cases" class="small" aria-label="Back to cases" title="Back to cases">${icon('back', '')}</a>${chip(c.severity)}${chip(c.verdict || 'pending', 'plain')}<span class="muted small">${esc(cap(c.domain))} · ${esc(cap(c.status))} · opened ${dt(c.created_at)}</span></div>
      <h1>${esc(c.title)}</h1><p>Confidence ${pct(c.confidence)} · automation mode ${esc(cap(c.autonomy_mode || 'recommend'))} ·
        owner <b>${c.assignee ? esc(c.assignee) : 'unassigned'}</b>
        ${can('investigate') && c.assignee !== ME.id.toLowerCase() ? btn('Take case', 'assignCase', [id, 'me'], 'sm') : ''}
        ${can('investigate') && c.assignee && (c.assignee === ME.id.toLowerCase() || can('approve_high_impact')) ? btn('Unassign', 'assignCase', [id, ''], 'sm ghost') : ''}</p></div>
      <div class="actions"><a class="btn primary" href="#/story/${encodeURIComponent(id)}">${icon('intel')}Attack story</a>${btn('Investigation record', 'dl', [`/api/v1/cases/${encodeURIComponent(id)}/report`], '', 'download')}</div></div>
    ${un.length ? `<div class="callout"><b>Incomplete picture.</b>&nbsp;Unavailable sources: ${un.map(u => esc(u.source)).join(', ')}. Conclusions below exclude them.</div>` : ''}
    <div class="grid g-2">
      <div class="stack">
        ${card('Assessment', `<div class="prose">${esc(c.summary)}</div>${a.narration_pending ? '<div class="t-sub" style="margin-top:6px">The written explanation is being prepared; the verdict, evidence and recommendations below are final. Refresh in a moment.</div>' : ''}
          ${(a.facts || []).length ? `<h3 class="small strong" style="margin:16px 0 4px">Facts</h3>${a.facts.map(x => `<div class="fact small">${esc(x.text)} ${cite(x)}</div>`).join('')}` : ''}
          ${(a.inferences || []).length ? `<h3 class="small strong" style="margin:16px 0 4px">Inferences</h3>${a.inferences.map(x => `<div class="inf small">${esc(x.text)} ${cite(x)}</div>`).join('')}` : ''}
          ${(a.mitre || []).length ? `<h3 class="small strong" style="margin:16px 0 6px">MITRE ATT&amp;CK</h3>${a.mitre.map(m => `<span class="tag">${esc(m.technique)} ${esc(m.name || '')}</span>`).join('')}` : ''}`,
          {sub: 'hover a reference to see the evidence it cites'})}
        ${analysisCard}
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
async function act(aid, verb, cid) { await post(`/api/v1/actions/${aid}/${verb}`, {note: 'via console'}); toast(`Action ${verb === 'approve' ? 'approved' : verb === 'reject' ? 'rejected' : 'rolled back'}`); refreshStatus(); cid ? CaseDetail(cid) : Approvals(); }
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
  setMainG(__g, `<div class="page-head"><div><div class="inline" style="margin-bottom:8px"><span class="tag">${esc(e.kind)}</span>${r && r.score > 0 ? chip(r.band) : chip('no risk signals', 'plain')}</div>
      <h1>${esc(e.name)}</h1><p>Seen by ${esc(e.seen_by.join(', ') || '–')}</p></div>
      ${r ? `<div class="actions"><div class="card kpi" style="min-width:160px"><div class="label">Risk score</div><div class="value">${Math.round(r.score)}<span class="muted" style="font-size:14px">/100</span></div><div class="foot">${esc(r.dimensions.join(' · '))}</div></div></div>` : ''}</div>
    <div class="grid g-2">
      <div class="stack">
        ${card('Why this score', (r && r.factors.length) ? r.factors.map(f => `<div class="list-row" style="align-items:flex-start"><span class="score mono" style="min-width:42px">+${Math.round(f.decayed)}</span>
          <div class="grow"><div class="t-title">${esc(cap(f.signal))}</div><div class="t-sub">${esc(f.detail)}</div></div><span class="tag">${esc(f.source)}</span><span class="muted small">${dt(f.when)}</span></div>`).join('') : empty('No risk factors in the window'),
          {sub: 'weights decay with age'})}
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
async function Approvals() {
  const __g = GEN;
  const [xs, sm] = await Promise.all([api('/api/v1/actions?status=recommended,pending_approval' + (APPROVAL_FILTER === 'all' ? '' : '&domain=' + encodeURIComponent(APPROVAL_FILTER))),
    api('/api/v1/actions/summary?status=recommended,pending_approval')]);
  const doms = Object.keys(sm.by_domain).sort();
  const total = APPROVAL_FILTER === 'all' ? sm.total : (sm.by_domain[APPROVAL_FILTER] || 0);
  setMainG(__g, page('Approvals', 'Actions the platform recommends. Nothing here runs until someone with the right role approves it; four-eyes actions need a second person.', '',
    card(null, `<div style="padding:12px 14px;border-bottom:1px solid var(--border)"><div class="seg">${['all', ...doms].map(f =>
      `<button class="${f === APPROVAL_FILTER ? 'on' : ''}" data-fn="approvalFilter" data-args="${arg(f)}">${esc(cap(f))} <span class="muted">${f === 'all' ? sm.total : (sm.by_domain[f] || 0)}</span></button>`).join('')}</div></div>` +
      table(['Action', 'Targets', 'Rationale', 'Policy', ''], xs.map(x => `<tr>
      <td class="nowrap"><div class="t-title mono">${esc(x.action_type)}</div><div class="t-sub">${esc(cap(x.domain))} · L${esc(x.level)}</div></td>
      <td class="small wrap">${x.targets.slice(0, 3).map(t => esc(t.name || t.recipient || t.id)).join('<br>') || '<span class="muted">-</span>'}</td><td class="small wrap">${esc(x.rationale)}</td>
      <td class="small muted">${(x.policy_reasons || []).slice(1).map(esc).join('<br>') || 'recommend (L2)'}</td>
      <td><div class="inline" style="flex-wrap:wrap;gap:6px">${can('approve_action') ? btn('Approve', 'act', [x.id, 'approve'], 'sm primary') + btn('Reject', 'act', [x.id, 'reject'], 'sm') : ''}${x.case_id ? `<a class="btn sm ghost" href="#/cases/${encodeURIComponent(x.case_id)}">Case</a>` : ''}</div></td></tr>`),
      {empty: 'Nothing is waiting for approval.'}) +
      (xs.length < total ? `<div class="small muted" style="padding:10px 14px">Showing the ${xs.length} most recent of ${total} actions.</div>` : ''), {flush: true})));
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
      ${kpi('Time to containment', m.time_to_containment_minutes && m.time_to_containment_minutes.median != null ? Math.round(m.time_to_containment_minutes.median) + ' min' : '–', m.time_to_containment_minutes && m.time_to_containment_minutes.median != null ? 'median, report to first containment' : 'no containment executed yet')}</div>
    <div class="grid g-3 mt">
      ${card('Verdict mix', donut(m.verdict_mix, {malicious: 'var(--c-critical)', suspicious: 'var(--c-high)', spam: 'var(--c-medium)', safe: 'var(--c-low)'}))}
      ${card('Users who clicked', clickers.map(([u, n]) => `<div class="list-row"><span class="grow">${esc(u)}</span>${n >= 2 ? chip('repeat', 'plain') : ''}<span class="score">${n}</span></div>`).join('') || empty('No clicks recorded'))}
      ${can('investigate') ? card('Analyse a message', `<div class="stack" style="gap:10px"><input type="file" id="eml" aria-label="Email file to analyse (.eml)" accept=".eml,message/rfc822" class="input" style="padding:5px">
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
      <td class="small">${esc(v.approved_by || '–')}</td><td class="small">${v.changes.slice(0, 3).map(c => `<div><span class="mono">${esc(c.connector)}.${esc(c.field)}</span> → ${esc(fmtVal(c.to))}</div>`).join('')}${v.changes.length > 3 ? `<div class="muted">+${v.changes.length - 3} more</div>` : ''}</td>
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
      <td class="num small">${nf(f.calls)}${f.refused ? `<div class="t-sub">${nf(f.refused)} refused</div>` : ''}</td><td class="num small">${tok(f.mean_in)} / ${tok(f.mean_out)}</td>
      <td class="num small">${usd(f.cost)}<div class="t-sub">${usd(f.cost_on_other_tier)} on ${esc(f.other_tier)}</div></td>
      <td class="num small">${f.usable_rate == null ? '–' : pct(f.usable_rate)}${f.claims_dropped_rate == null ? '' : `<div class="t-sub">${pct(f.claims_dropped_rate)} statements dropped</div>`}</td>
      <td class="num small">${f.p95_ms == null ? '–' : (f.p95_ms / 1000).toFixed(1) + ' s'}</td>
      <td>${status(ADV_K[f.advice] || 'info', cap(f.advice))}<div class="t-sub">${esc(f.why)}</div></td>
      <td>${edit ? `<select id="wt-${esc(f.workflow)}" aria-label="Tier for ${esc(f.workflow)}" data-orig="${esc(r.tier || '')}"><option value="">${esc(f.code_default_tier)} (default)</option>${pol.tiers.map(t => `<option value="${t}"${r.tier === t ? ' selected' : ''}>${t}</option>`).join('')}</select>
        <input class="input" style="width:90px;margin-top:4px" id="wm-${esc(f.workflow)}" aria-label="Output cap for ${esc(f.workflow)}" placeholder="cap ${esc(P.max_output_tokens[f.tier] || '')}" value="${esc(r.max_output_tokens || '')}">
        <label class="inline small" style="margin-top:4px"><input type="checkbox" id="we-${esc(f.workflow)}"${r.enabled === false ? '' : ' checked'}> on</label>`
        : `<span class="tag">${esc(f.tier)}</span>${f.enabled ? '' : ' ' + chip('off', 'medium plain')}`}</td></tr>`; };
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
    <div class="mt">${card('By feature - which model each uses, and whether it should', table(['Feature', {h: 'Calls', num: 1}, {h: 'Tokens in / out', num: 1}, {h: 'Cost', num: 1}, {h: 'Usable', num: 1}, {h: 'p95', num: 1}, 'Advice', 'Tier · cap · on'], u.features.map(wf)),
      {flush: true, sub: 'advice is computed from these figures: usable answers, statements the evidence check removed, answer length'})}</div>
    <div class="grid g-2e mt">
      ${card('Budgets', table(['', 'Value', ''], [
          row2('Monthly tokens', lim('lp-month', P.monthly_tokens, '', 'Monthly tokens')),
          row2('Daily tokens', lim('lp-day', P.daily_tokens, '', 'Daily tokens')),
          row2('Warn at (fraction of the month)', lim('lp-alert', P.alert_at, '', 'Warn at')),
          row2('Longest answer: small / large tier', lim('lp-cs', P.max_output_tokens.small, '', 'Small tier longest answer'), lim('lp-cl', P.max_output_tokens.large, '', 'Large tier longest answer')),
          row2('Small tier $ per million: in / out', lim('lp-psi', P.prices.small.input, '', 'Small tier input price'), lim('lp-pso', P.prices.small.output, '', 'Small tier output price')),
          row2('Large tier $ per million: in / out', lim('lp-pli', P.prices.large.input, '', 'Large tier input price'), lim('lp-plo', P.prices.large.output, '', 'Large tier output price'))]), {flush: true, sub: 'tokens; 0 = no cap'})}
      ${card('Limits per person', `<div class="small muted" style="margin-bottom:6px">Questions, deep analysis and reports a person asks for. Scheduled work counts only against the budgets. 0 = no model text for them.</div>
        ${table(['Who', 'Per hour', 'Per day'], [row2('<b>Everyone</b>', lim('lu-h', P.user_default.hourly_tokens, '', 'Everyone per hour'), lim('lu-d', P.user_default.daily_tokens, '', 'Everyone per day')), ...roleRows], {flush: true})}
        <label class="small" style="display:block;margin-top:10px" for="lusers">Per person (overrides the role), one per line: <span class="mono">name@company.com | per hour | per day</span></label>
        <textarea id="lusers" rows="4" class="mono" style="width:100%"${edit ? '' : ' readonly'}>${esc(userOver)}</textarea>`, {sub: 'tokens; a role overrides everyone'})}
    </div>
    ${edit ? `<div class="form-row mt"><input class="input" id="lp-note" aria-label="Why" placeholder="Why (kept in the history and the audit log)">${btn('Save limits and model choices', 'saveLlmPolicy', [], 'primary')}</div><div id="lpout"></div>` : `<div class="small muted mt">Only an administrator changes these.</div>`}
    <div class="grid g-2e mt">
      ${card('Who used it (last 30 days)', table(['Person', {h: 'Last hour', num: 1}, {h: 'Today', num: 1}, {h: '30 days', num: 1}, {h: 'Calls', num: 1}], u.users.map(x => `<tr><td class="small">${esc(x.user)}</td><td class="num small">${tok(x.hour)}</td><td class="num small">${tok(x.today)}</td><td class="num small">${tok(x.period)}</td><td class="num small">${nf(x.calls)}</td></tr>`), {flush: true, empty: 'No one has asked the model for anything yet.'}))}
      ${card('History', table(['Version', 'By', 'When', 'Why'], pol.history.map(h => `<tr><td class="mono">#${esc(h.id)}</td><td class="small">${esc(h.set_by)}</td><td class="mono small muted">${dt(h.created_at)}</td><td class="small">${esc(h.note || '')}</td></tr>`), {flush: true, empty: 'Defaults in force - nothing changed yet.'}))}
    </div>`));
}
async function saveLlmPolicy() {
  const pol = window.__llmpol, P = JSON.parse(JSON.stringify(pol.policy));
  const num = (id, fl) => { const v = ($('#' + id).value || '').trim(); if (v === '') return null; const n = fl ? parseFloat(v) : parseInt(v, 10); return Number.isNaN(n) ? v : n; };
  P.monthly_tokens = num('lp-month') ?? 0; P.daily_tokens = num('lp-day') ?? 0; P.alert_at = num('lp-alert', true) ?? 0.8;
  P.max_output_tokens = {small: num('lp-cs'), large: num('lp-cl')};
  P.prices = {small: {input: num('lp-psi', true), output: num('lp-pso', true)}, large: {input: num('lp-pli', true), output: num('lp-plo', true)}};
  P.user_default = {hourly_tokens: num('lu-h') ?? 0, daily_tokens: num('lu-d') ?? 0};
  P.roles = {}; pol.roles.forEach(r => { const h = num('rh-' + r), d = num('rd-' + r); if (h != null || d != null) P.roles[r] = {...(h != null ? {hourly_tokens: h} : {}), ...(d != null ? {daily_tokens: d} : {})}; });
  P.users = {}; ($('#lusers').value || '').split('\n').map(l => l.trim()).filter(Boolean).forEach(l => { const [who, h, d] = l.split('|').map(x => (x || '').trim()); const o = {}; if (h !== '') o.hourly_tokens = parseInt(h, 10); if (d !== '' && d !== undefined) o.daily_tokens = parseInt(d, 10); P.users[who] = o; });
  P.workflows = {}; Object.keys(pol.workflows).forEach(w => { const t = $(`[id="wt-${w}"]`), m = $(`[id="wm-${w}"]`), e = $(`[id="we-${w}"]`); if (!t) return; const r = {};
    if (t.value) r.tier = t.value; if ((m.value || '').trim()) r.max_output_tokens = parseInt(m.value, 10); if (!e.checked) r.enabled = false; if (Object.keys(r).length) P.workflows[w] = r; });
  try { await post('/api/v1/admin/llm/policy', {policy: P, note: $('#lp-note').value.trim()}); toast('AI usage policy saved - in force for the next model call'); AiUsage(); }
  catch (e) { let d; try { d = JSON.parse(e.message).detail; } catch (x) { d = null; } if (d) $('#lpout').innerHTML = `<div class="callout danger mt"><div class="small">${esc(d)}</div></div>`; }
}

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
  const [tp, llmSt, cases] = await Promise.all([api('/api/v1/reports/templates'), api('/api/v1/llm/status'), api('/api/v1/cases')]);
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
      ${can('export_evidence') ? card('Audit export', `<p class="small muted" style="margin-top:0">Full hash-chained audit log as JSON Lines with verification, for archiving or SIEM.</p>${btn('Export', 'dl', ['/api/v1/audit/export'], '', 'download')}`) : ''}
    </div>`));
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
    v.ok ? `<span class="status-pill"><span class="dot"></span>Chain verified · ${nf(v.records)} records in the full log${window.ME.domains.includes('*') ? '' : ' (you see those about your domains)'}</span>` : `<span class="status-pill halt"><span class="dot"></span>Chain broken at #${esc(v.first_bad_seq)}</span>`,
    card(null, table([{h: '#', num: 1}, 'Time', 'Actor', 'Event', 'Subject'], xs.map(x => `<tr><td class="num mono small muted">${x.seq}</td><td class="mono small">${dt(x.ts)}</td>
      <td class="small">${esc(x.actor_type)} · ${esc(x.actor_id)}</td><td class="mono small">${esc(x.event_type)}</td><td class="small muted">${esc(x.subject_type)} ${esc(x.subject_id)}</td></tr>`)), {flush: true})));
}


// ================================================================= Attack story
const HCLS = {rejected: 'ok', unlikely: 'medium', plausible: 'high', cannot_assess: 'info'};
const HLBL = {rejected: 'Rejected', unlikely: 'Unlikely', plausible: 'Still plausible', cannot_assess: 'Cannot assess'};
const NODE = {identity: 'var(--c-critical)', asset: 'var(--c-high)', secret: 'var(--c-vulnerability)', indicator: 'var(--c-other)',
  recipient: 'var(--c-phishing)', case: 'var(--text-3)', campaign: 'var(--c-phishing)'};

function blastGraph(b) {
  const W = 640, H = 440, cx = W / 2, cy = H / 2;
  const center = b.nodes.filter(n => n.principal), ring1 = b.nodes.filter(n => !n.principal && ['secret', 'case', 'campaign'].includes(n.kind)),
    ring2 = b.nodes.filter(n => !n.principal && ['indicator', 'recipient'].includes(n.kind));
  const pos = {};
  center.forEach((n, i) => { pos[n.id] = [cx + (center.length > 1 ? (i - (center.length - 1) / 2) * 110 : 0), cy]; });
  const place = (arr, r) => arr.forEach((n, i) => { const a = (i / Math.max(arr.length, 1)) * 2 * Math.PI - Math.PI / 2 + (r > 150 ? 0.25 : 0);
    pos[n.id] = [cx + r * 1.35 * Math.cos(a), cy + r * Math.sin(a)]; });
  place(ring1, 105); place(ring2, 178);
  const short = s => { s = String(s || ''); return s.length > 24 ? s.slice(0, 22) + '…' : s; };
  let g = '';
  b.edges.forEach(e => { const a = pos[e.from], c = pos[e.to]; if (a && c) g += `<line x1="${a[0]}" y1="${a[1]}" x2="${c[0]}" y2="${c[1]}"/>`; });
  // campaign hub links principals to recipients
  if (pos.campaign) center.filter(n => n.kind === 'identity').forEach(n => { const a = pos[n.id], c = pos.campaign; g += `<line x1="${a[0]}" y1="${a[1]}" x2="${c[0]}" y2="${c[1]}"/>`; });
  b.nodes.forEach(n => {
    const p = pos[n.id]; if (!p) return;
    const r = n.principal ? 13 : n.kind === 'recipient' ? 6 : 8;
    const fill = n.kind === 'recipient' && !n.interacted ? 'var(--surface)' : (NODE[n.kind] || 'var(--c-other)');
    g += `<g><title>${esc(n.kind)}: ${esc(n.label)}${n.interacted ? ' (interacted)' : ''}</title><circle cx="${p[0]}" cy="${p[1]}" r="${r}" style="fill:${fill};stroke:${NODE[n.kind] || 'var(--c-other)'};stroke-width:2"/>
      <text x="${p[0]}" y="${p[1] + r + 12}" text-anchor="middle" style="${n.principal ? 'font-weight:650;fill:var(--text)' : ''}">${esc(short(n.label))}</text></g>`;
  });
  return `<svg class="graph" viewBox="0 0 ${W} ${H}" role="img" aria-label="blast radius">${g}</svg>
    <div class="legend">${[['identity', 'User'], ['asset', 'Host'], ['secret', 'Privileged secret'], ['indicator', 'Indicator'], ['recipient', 'Recipient (filled = interacted)'], ['case', 'Related case']]
      .map(([k, l]) => `<span><i style="background:${NODE[k]}"></i>${l}</span>`).join('')}</div>`;
}

async function Story(id) {
  const __g = GEN;
  const [st, llmSt] = await Promise.all([api('/api/v1/cases/' + encodeURIComponent(id) + '/story'), api('/api/v1/llm/status')]);
  const a = st.assessment, b = st.blast_radius.stats;
  const evById = Object.fromEntries(st.events.map(e => [e.ref, e]));
  const refs = rs => rs.map(r => { const e = evById[r]; return `<abbr class="cite" title="${esc(e ? `${e.tool} · ${e.ts || 'time not reported'} · ${e.title}` : r)}">${esc(r)}</abbr>`; }).join('');
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
        <div class="t-sub">${esc(x.targets.join(', '))}${(x.duplicate_ids || []).length ? ` · ×${x.duplicate_ids.length + 1} (one per related case, approved together)` : ''}${x.four_eyes ? ' · four-eyes: needs a second approver' : ''}</div></div>
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
  const cite = ids => (ids || []).map(r => `<abbr class="cite" title="${esc(evById[r] ? evById[r].title : r)}">${esc(r)}</abbr>`).join('');
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
  toast(`${r.approved} approved${failed.length ? ` · ${failed.length} not approved: ${failed[0].error}` : ''}`, failed.length > 0);
  refreshStatus(); Story(id);
}

// ================================================================= registry
window.VIEWS = {search: Search, story: Story, overview: Overview, intelligence: Intelligence, cases: Cases, entity: Entity, approvals: Approvals, phishing: Phishing,
  suppliers: Suppliers, vulnerabilities: Vulnerabilities, cloud: Cloud, coverage: Coverage, 'shadow-it': ShadowIt, integrations: Integrations, 'ai-usage': AiUsage,
  policy: Policy, reports: Reports, access: Access, audit: Audit};
Object.assign(ALLOWED, {notifyTest, assignCase, addNote, ownerFilter, reportPlan, buildPlanned, savePlanned, buildTemplate, runDeep, approveBundle, approvalFilter, intelAll, askIntel, refreshIntel, insightAct, intelFilter, caseFilter, runInc, runPh, act, decide, upload, vmRefresh, ticketSync,
  campaign, vmAsk, misRoute, misVerb, testConn, runJob, preflight, configure, pauseConn, proposeConfig, approveConfig,
  rejectConfig, closePanel, showHistory, showImport, importConfig, restoreConfig, showLists, proposeLists, saveLlmPolicy, kill, approvePolicy, report, compliancePack, grant, revokeGrant, revokeKey, newKey});
