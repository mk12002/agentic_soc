const safeUrl=u=>/^https?:\/\//i.test(String(u||''))?String(u):'#';
let TOKEN=localStorage.getItem('soc_token')||'';const TABS=['Intelligence','Cases','Approvals','Vulnerabilities','Phishing','Connectors','Policy','Audit'];let tab='Intelligence';
const $=s=>document.querySelector(s);const esc=v=>String(v??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
async function api(p,o={}){const r=await fetch(p,{...o,headers:{'Authorization':'Bearer '+TOKEN,'Content-Type':'application/json',...(o.headers||{})}});
 if(!r.ok){const t=await r.text();alert(r.status+': '+t);throw new Error(t)}return r.headers.get('content-type')?.includes('json')?r.json():r}
async function login(){const r=await fetch(`/api/v1/dev/token?user=${encodeURIComponent($('#user').value)}&roles=${$('#role').value}`);if(!r.ok){alert('dev tokens disabled');return}
 TOKEN=(await r.json()).token;localStorage.setItem('soc_token',TOKEN);boot()}
async function boot(){if(!TOKEN)return;const me=await api('/api/v1/me');$('#who').textContent=me.name+' ('+me.roles.join(',')+')';
 $('#nav').innerHTML=TABS.map(t=>`<button class="${t==tab?'on':''}" data-fn="show" data-args="[&quot;${esc(t)}&quot;]">${t}</button>`).join('');show(tab)}
function show(t){tab=t;document.querySelectorAll('#nav button').forEach(b=>b.classList.toggle('on',b.textContent==t));({Intelligence,Cases,Approvals,Vulnerabilities,Phishing,Connectors,Policy,Audit})[t]()}
const sev=s=>`<span class="pill ${esc(s)}">${esc(s)}</span>`;

async function Cases(){const cs=await api('/api/v1/cases');$('#main').innerHTML=`<div class="card"><h2>Cases</h2>
 <button class="b" data-fn="runInc" data-args="[]">Run incident pipeline</button> <button class="b" data-fn="runPh" data-args="[]">Pull reported emails</button>
 <table><tr><th>Domain</th><th>Title</th><th>Severity</th><th>Verdict</th><th>Status</th><th>Opened</th></tr>${cs.map(c=>`<tr class="click" data-fn="caseView" data-args="[&quot;${esc(c.id)}&quot;]">
 <td>${esc(c.domain)}</td><td>${esc(c.title)}</td><td>${sev(c.severity)}</td><td>${esc(c.verdict)}</td><td>${esc(c.status)}</td><td class="muted">${esc(c.created_at.slice(0,16))}</td></tr>`).join('')}</table></div>`}
async function runInc(){await api('/api/v1/incidents/run',{method:'POST'});Cases()}
async function runPh(){await api('/api/v1/phishing/ingest',{method:'POST'});Cases()}
async function caseView(id){const v=await api('/api/v1/cases/'+id);const c=v.case,a=v.assessment||{};
 const inc=v.completeness&&v.completeness.unavailable&&v.completeness.unavailable.length?`<div class="warn">Incomplete: unavailable sources ${v.completeness.unavailable.map(u=>esc(u.source)).join(', ')}</div>`:'';
 $('#main').innerHTML=`<div class="card"><h2>${esc(c.title)} ${sev(c.severity)}</h2><div class="muted">${esc(c.domain)} · ${esc(c.status)} · verdict <b>${esc(c.verdict)}</b> · confidence ${esc(c.confidence)} · mode ${esc(c.autonomy_mode)}</div>${inc}
 <p>${esc(c.summary)}</p><h3>Facts</h3>${(a.facts||[]).map(x=>`<div class="fact">${esc(x.text)} <span class="muted">[${x.evidence_ids.join(', ')}]</span></div>`).join('')}
 ${(a.inferences||[]).length?'<h3>Inferences</h3>'+a.inferences.map(x=>`<div class="inf">${esc(x.text)} [${x.evidence_ids.join(', ')}]</div>`).join(''):''}
 <h3>MITRE ATT&CK</h3>${(a.mitre||[]).map(m=>`<span class="pill">${esc(m.technique)} ${esc(m.name||'')}</span> `).join('')}
 <p><a href="#" data-fn="dl" data-args="[&quot;/api/v1/cases/${esc(id)}/report&quot;]">Download investigation record (.docx)</a></p></div>
 ${intelPanel(v.intelligence)}
 <div class="row"><div class="card"><h2>Recommended actions</h2><table><tr><th>#</th><th>Action</th><th>Targets</th><th>Status</th><th>Why / blast radius</th><th></th></tr>
 ${v.actions.sort((x,y)=>(x.priority||99)-(y.priority||99)).map(x=>`<tr><td>${esc(x.priority)}</td><td><b>${esc(x.action_type)}</b><br><span class="muted">L${x.level}</span></td><td>${x.targets.map(t=>esc(t.id)).slice(0,4).join('<br>')}${x.targets.length>4?'<br>+'+(x.targets.length-4):''}</td>
 <td>${esc(x.status)}${x.approver?'<br><span class="muted">by '+esc(x.approver)+'</span>':''}</td><td>${esc(x.rationale)}<br><span class="muted">${esc(x.blast_radius||'')} ${x.reversible===false?'· not reversible':''}</span><br><span class="muted">${(x.policy_reasons||[]).slice(1).map(esc).join('; ')}</span></td>
 <td>${['recommended','pending_approval'].includes(x.status)?`<button class="b" data-fn="act" data-args="[&quot;${esc(x.id)}&quot;,&quot;approve&quot;,&quot;${esc(id)}&quot;]">Approve</button> <button class="g b" data-fn="act" data-args="[&quot;${esc(x.id)}&quot;,&quot;reject&quot;,&quot;${esc(id)}&quot;]">Reject</button>`:x.status=='executed'?`<button class="g b" data-fn="act" data-args="[&quot;${esc(x.id)}&quot;,&quot;rollback&quot;,&quot;${esc(id)}&quot;]">Rollback</button>`:''}</td></tr>`).join('')}</table></div></div>
 <div class="row"><div class="card"><h2>Entities</h2><table>${v.entities.map(e=>`<tr><td>${esc(e.kind)}</td><td>${esc(e.role)}</td><td>${esc(e.name)}</td><td class="muted">${e.seen_by.join(', ')}</td></tr>`).join('')}</table></div>
 <div class="card"><h2>Timeline</h2><table>${v.timeline.map(t=>`<tr><td class="muted">${esc(t.ts.slice(0,19))}</td><td>${esc(t.tool)}</td><td>${esc(t.title)}</td></tr>`).join('')}</table></div></div>
 <div class="card"><h2>Evidence by dimension</h2>${Object.entries(v.evidence).map(([d,items])=>`<h3>${esc(d)}</h3>${items.map(i=>`<div class="${i.type=='fact'?'fact':'inf'}">${esc(i.source)}: ${esc(i.summary)} ${i.deep_link?`<a target=_blank rel="noopener noreferrer" href="${esc(safeUrl(i.deep_link))}">open</a>`:''}</div>`).join('')}`).join('')}</div>
 <div class="card"><h2>Analyst decision</h2><select id="dv"><option>true_positive</option><option>malicious</option><option>false_positive</option><option>benign</option></select>
 <input id="dr" size="60" placeholder="reasoning"> <button class="b" data-fn="decide" data-args="[&quot;${esc(id)}&quot;]">Record decision</button>
 ${v.dispositions.map(d=>`<div class="muted">${esc(d.at.slice(0,16))} ${esc(d.analyst)}: ${esc(d.verdict)} - ${esc(d.reasoning)}</div>`).join('')}</div>
 <div class="card"><h2>Audit</h2>${v.audit.map(x=>`<div class="muted">#${x.seq} ${esc(x.ts.slice(0,19))} ${esc(x.actor)} ${esc(x.event)}</div>`).join('')}</div>`}
async function act(aid,verb,cid){await api(`/api/v1/actions/${aid}/${verb}`,{method:'POST',body:JSON.stringify({note:'via console'})});cid?caseView(cid):Approvals()}
async function decide(id){await api(`/api/v1/cases/${id}/disposition`,{method:'POST',body:JSON.stringify({verdict:$('#dv').value,reasoning:$('#dr').value})});caseView(id)}
async function dl(p){const r=await api(p);const b=await r.blob();const u=URL.createObjectURL(b);const a=document.createElement('a');a.href=u;a.download=(r.headers.get('content-disposition')||'').split('filename=')[1]?.replace(/"/g,'')||'report';a.click()}
async function Approvals(){const xs=await api('/api/v1/actions?status=recommended,pending_approval');$('#main').innerHTML=`<div class="card"><h2>Awaiting approval (${xs.length})</h2><table><tr><th>Action</th><th>Domain</th><th>Targets</th><th>Rationale</th><th>Policy</th><th></th></tr>
 ${xs.map(x=>`<tr><td><b>${esc(x.action_type)}</b><br><span class="muted">L${x.level} · ${esc(x.requested_by)}</span></td><td>${esc(x.domain)}</td><td>${x.targets.map(t=>esc(t.id)).slice(0,3).join('<br>')}</td><td>${esc(x.rationale)}</td><td class="muted">${x.policy_reasons.map(esc).join('<br>')}</td>
 <td><button class="b" data-fn="act" data-args="[&quot;${esc(x.id)}&quot;,&quot;approve&quot;]">Approve</button> <button class="b g" data-fn="act" data-args="[&quot;${esc(x.id)}&quot;,&quot;reject&quot;]">Reject</button> ${x.case_id?`<a href="#" data-fn="caseView" data-args="[&quot;${esc(x.case_id)}&quot;]">case</a>`:''}</td></tr>`).join('')}</table></div>`}
async function Vulnerabilities(){const [m,f,cov]=await Promise.all([api('/api/v1/vm/metrics'),api('/api/v1/vm/findings'),api('/api/v1/vm/coverage')]);
 $('#main').innerHTML=`<div class="row">${[['Open',m.open],['KEV open',m.kev_open],['Internet-exposed',m.internet_exposed_open],['Past SLA',m.sla_breached],['Asset match rate',((m.asset_match_rate||0)*100).toFixed(1)+'%']].map(([k,v])=>`<div class="card"><div class="muted">${k}</div><div class="kpi">${v}</div></div>`).join('')}</div>
 <div class="card"><button class="b" data-fn="vmRefresh" data-args="[]">Refresh from scanners</button> <button class="b g" data-fn="rep" data-args="[&quot;daily_exposure&quot;]">Daily exposure report</button> <button class="b g" data-fn="rep" data-args="[&quot;weekly_vm&quot;]">Weekly VM report</button> <button class="b g" data-fn="rep" data-args="[&quot;weekly_mgmt&quot;]">Management deck</button>
 <h3>Ask</h3><input id="q" size="70" placeholder="e.g. which KEV vulnerabilities are internet exposed?"> <button class="b" data-fn="ask" data-args="[]">Query</button><div id="qa"></div></div>
 <div class="card"><h2>Findings</h2><table><tr><th>P</th><th>CVE</th><th>Asset</th><th>Team</th><th>SLA due</th><th>Seen by</th><th>Status</th><th></th></tr>${f.map(x=>`<tr><td>${esc(x.priority)}</td><td>${esc(x.cve)}</td><td>${esc(x.asset)}${x.internet_exposed?' 🌐':''}</td><td>${esc(x.team)}</td><td>${esc((x.sla_due||'').slice(0,10))}</td><td class="muted">${Object.keys(x.sources).join(', ')}</td><td>${esc(x.status)}</td><td>${x.campaign_id?'<span class="muted">in campaign</span>':`<button class="b" data-fn="camp" data-args="[&quot;${esc(x.cve)}&quot;]">Campaign</button>`}</td></tr>`).join('')}</table></div>
 <div class="card"><h2>Coverage</h2><div>Missing EDR: ${esc(cov.missing_edr.join(', ')||'none')}</div><div>Not in CMDB: ${esc(cov.not_in_cmdb.join(', ')||'none')}</div><div>Unresolved identity queue: ${cov.unresolved_queue}</div></div>`}
async function vmRefresh(){await api('/api/v1/vm/refresh',{method:'POST'});Vulnerabilities()}
async function camp(cve){const r=await api('/api/v1/vm/campaigns',{method:'POST',body:JSON.stringify({cve,notify_via:'ticket'})});alert('Campaign '+r.campaign_id+' created; notifications await approval');Vulnerabilities()}
async function ask(){const r=await api('/api/v1/vm/query',{method:'POST',body:JSON.stringify({question:$('#q').value})});$('#qa').innerHTML=`<p>${esc(r.answer)} <span class="muted">filter: <code>${esc(JSON.stringify(r.generated_filter))}</code></span></p>
 <table>${r.records.map(x=>`<tr><td>${esc(x.cve)}</td><td>${esc(x.asset)}</td><td>${esc(x.priority)}</td><td>${esc(x.team)}</td><td class="muted">${x.sources.join(', ')}</td></tr>`).join('')}</table>`}
async function rep(k){const r=await api('/api/v1/reports/'+k,{method:'POST'});dl('/api/v1/reports/'+r.id+'/download')}
async function Phishing(){const m=await api('/api/v1/phishing/metrics');$('#main').innerHTML=`<div class="row">${[['Reported',m.reported],['Auto-closed',m.auto_closed],['QA-sampled',m.sampled_for_qa],['Campaigns',m.campaigns],['Repeat clickers',m.repeat_clickers.length]].map(([k,v])=>`<div class="card"><div class="muted">${k}</div><div class="kpi">${v}</div></div>`).join('')}</div>
 <div class="card"><h2>Submit a reported email (.eml)</h2><input type="file" id="f" accept=".eml"> <button class="b" data-fn="upl" data-args="[]">Analyse</button><button class="b g" data-fn="runPh" data-args="[]">Pull reporting mailbox</button>
 <h3>Verdict mix</h3><pre>${esc(JSON.stringify(m.verdict_mix,null,1))}</pre><h3>Clickers</h3><pre>${esc(JSON.stringify(m.clickers,null,1))}</pre></div>`}
async function upl(){const fd=new FormData();fd.append('file',$('#f').files[0]);const r=await fetch('/api/v1/phishing/submit',{method:'POST',headers:{'Authorization':'Bearer '+TOKEN},body:fd});if(!r.ok){alert(await r.text());return}const v=await r.json();caseView(v.case.id)}
async function Connectors(){const cs=await api('/api/v1/connectors');$('#main').innerHTML=`<div class="card"><h2>Connectors (${cs.filter(c=>c.enabled).length} enabled)</h2><table><tr><th>Tool</th><th>Category</th><th>Mode</th><th>Health</th><th>Streams / lookups</th><th>Confidence</th><th>To confirm</th></tr>
 ${cs.map(c=>`<tr><td><b>${esc(c.tool)}</b><br><span class="muted">${esc(c.name)}</span></td><td>${esc(c.category)}</td><td>${c.enabled?esc(c.mode):'<span class="muted">disabled</span>'}</td><td>${c.health?(c.health.ok?'ok':'<span style="color:var(--crit)">'+esc(c.health.error)+'</span>'):''}${(c.config_problems||[]).map(p=>'<div style="color:var(--high)">'+esc(p)+'</div>').join('')}</td>
 <td class="muted">${(c.streams||[]).join(', ')}<br>${(c.lookups||[]).join(', ')}</td><td>${esc(c.confidence)}</td><td class="muted">${esc(c.to_confirm)}</td></tr>`).join('')}</table></div>`}
async function Policy(){const [p,cat]=await Promise.all([api('/api/v1/policy'),api('/api/v1/actions/catalog')]);$('#main').innerHTML=`<div class="card"><h2>Autonomy policy (version ${esc(p.active_version||'default')})</h2>
 <button class="b r" data-fn="kill" data-args="[true]">Engage kill switch</button> <button class="b g" data-fn="kill" data-args="[false]">Release kill switch</button>
 <table><tr><th>Action type</th><th>Tool(s)</th><th>Level</th><th>Destructive</th><th>Reversible</th></tr>${cat.map(a=>`<tr><td>${esc(a.action_type)}</td><td class="muted">${esc(a.tool)}</td><td>L${a.level}</td><td>${a.destructive?'yes':''}</td><td>${a.reversible?'yes':''}</td></tr>`).join('')}</table>
 <h3>Pending proposals</h3>${p.proposals.map(x=>`<div>#${x.id} by ${esc(x.proposed_by)}: ${esc(x.note)} <button class="b" data-fn="apol" data-args="[${esc(x.id)}]">Approve</button></div>`).join('')||'<span class="muted">none</span>'}</div>`}
async function kill(on){await api('/api/v1/kill-switch?on='+on,{method:'POST'});Policy()}
async function apol(id){await api(`/api/v1/policy/proposals/${id}/approve`,{method:'POST'});Policy()}
async function Audit(){const [v,xs]=await Promise.all([api('/api/v1/audit/verify'),api('/api/v1/audit?limit=300')]);$('#main').innerHTML=`<div class="card"><h2>Audit log ${v.ok?'<span class="pill low">chain verified</span>':'<span class="pill critical">CHAIN BROKEN at '+v.first_bad_seq+'</span>'}</h2>
 <table><tr><th>#</th><th>Time</th><th>Actor</th><th>Event</th><th>Subject</th></tr>${xs.map(x=>`<tr><td>${x.seq}</td><td class="muted">${esc(x.ts.slice(0,19))}</td><td>${esc(x.actor_type)}:${esc(x.actor_id)}</td><td>${esc(x.event_type)}</td><td class="muted">${esc(x.subject_type)} ${esc(x.subject_id)}</td></tr>`).join('')}</table></div>`}
boot();

function intelPanel(x){if(!x)return'';return `<div class="card"><h2>Cross-domain intelligence</h2>
 ${(x.entity_risk||[]).map(r=>`<span class="pill ${esc(r.band)}">${esc(r.name)} ${Math.round(r.score)}/100</span> `).join('')}
 ${(x.insights||[]).map(i=>`<div class="fact"><b>${sev(i.severity)} ${esc(i.title)}</b><div class="muted">${esc(i.narrative)}</div><div>${(i.next_steps||[]).map(n=>'• '+esc(n)).join('<br>')}</div></div>`).join('')||'<span class="muted">no correlated findings</span>'}</div>`}
async function Intelligence(){const [b,ins,top]=await Promise.all([api('/api/v1/intelligence/brief'),api('/api/v1/intelligence/insights'),api('/api/v1/intelligence/risk/top?limit=10')]);
 $('#main').innerHTML=`<div class="card"><h2>Situation brief <span class="muted">(${esc(b.source)})</span></h2><div style="white-space:pre-wrap">${esc(b.summary)}</div>
 <h3>Ask the analyst</h3><input id="iq" size="80" placeholder="e.g. Is jane.doe@cci-demo.com compromised and what should we do first?"> <button class="b" data-fn="askIntel" data-args="[]">Ask</button> <button class="b g" data-fn="refreshIntel" data-args="[]">Re-correlate</button><div id="ia"></div></div>
 <div class="row"><div class="card" style="flex:2"><h2>Correlated findings (${ins.length})</h2>${ins.map(i=>`<div class="fact"><b>${sev(i.severity)} ${esc(i.title)}</b> <span class="muted">${esc(i.rule)} · ${esc((i.requirements||[]).join(', '))}</span>
  <div class="muted">${esc(i.narrative)}</div><div>${(i.next_steps||[]).map(n=>'• '+esc(n)).join('<br>')}</div>
  <button class="b g" data-fn="insightAct" data-args="[&quot;${esc(i.id)}&quot;,&quot;acknowledge&quot;]">Acknowledge</button> <button class="b g" data-fn="insightAct" data-args="[&quot;${esc(i.id)}&quot;,&quot;dismiss&quot;]">Dismiss</button></div>`).join('')}</div>
 <div class="card"><h2>Highest risk users &amp; hosts</h2><table>${top.map(p=>`<tr><td>${sev(p.band)}</td><td>${esc(p.name)}<br><span class="muted">${esc(p.dimensions.join(', '))}</span></td><td class="kpi" style="font-size:18px">${Math.round(p.score)}</td></tr>`).join('')}</table></div></div>`}
async function askIntel(){const q=$('#iq').value;if(!q)return;$('#ia').innerHTML='<p class="muted">analysing…</p>';const r=await api('/api/v1/intelligence/ask',{method:'POST',body:JSON.stringify({question:q})});
 $('#ia').innerHTML=`<p>${esc(r.answer)}</p>${(r.claims||[]).map(c=>`<div class="${c.kind=='fact'?'fact':'inf'}">${esc(c.text)} <span class="muted">[${c.evidence_ids.map(esc).join(', ')}]</span></div>`).join('')}
 <p class="muted">planner: ${esc(r.planner)} · tools: ${r.tool_calls.map(t=>esc(t.tool)).join(' → ')}</p>`}
async function refreshIntel(){await api('/api/v1/intelligence/refresh',{method:'POST'});Intelligence()}
async function insightAct(id,verb){await api(`/api/v1/intelligence/insights/${id}/${verb}`,{method:'POST'});Intelligence()}
// Delegated click handling: no inline handlers, so the page runs under a strict Content-Security-Policy.
const ALLOWED={act,apol,ask,askIntel,camp,caseView,decide,dl,insightAct,kill,login,refreshIntel,rep,runInc,runPh,show,upl,vmRefresh};
document.addEventListener('click',ev=>{const el=ev.target.closest('[data-fn]');if(!el)return;ev.preventDefault();
 const fn=ALLOWED[el.dataset.fn];if(!fn)return;let args=[];try{args=JSON.parse(el.dataset.args||'[]')}catch(e){return}fn(...args)});
