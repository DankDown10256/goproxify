// Schéma d'architecture : rendu commun de la vue Infrastructure (lecture) et de son mode édition.
// Le modèle (hôtes → rôles → capacités) vient de architecture.json (via _archLoad) ;
// l'état live (/nodes, /nodes/live, /metrics/summary) n'est qu'une surcouche.
// Dépend de pages/architecture-wizard.js (_arch, _ARCH_ICONS, _archBuildPacks, suivi des modifications) et de core/api.js.

window._asLive = {};        // node_name → état temps réel (/nodes/live)
window._asHist = {};        // node_name → échantillons de statut de la session : g ok · o dégradé · r hors ligne · x inconnu
window._asHealthOK = true;
window._asSelKey = null;    // rôle affiché dans le panneau de détail (type:nom, stable entre deux rechargements)
window._asMetrics = null;   // /metrics/summary
window._asRpsHist = [];     // débit total des passerelles à chaque échantillon
window._asContainers = {};  // node_name d'agent → nombre de conteneurs découverts
window._asEvents = {};      // node_name → derniers événements (panneau de détail)
window._asLinks = [];       // liaisons du schéma en flux, tracées après rendu
window._asEdgeWin = {};     // node_name de passerelle → dernier intervalle (/metrics/proxies : p95_ms, error_rate)
window._asListFilter = { f: 'all', q: '' };
window._asArm = null;       // écran tactile : type de rôle choisi dans la palette, en attente d'un hôte
const AS_HIST_LEN = 24;

const _AS_ROLE = {
  edge:  { k: 'var(--purple)', label: 'arch.svc.edge' },
  agent: { k: 'var(--green)', label: 'arch.svc.agent' },
  admin: { k: 'var(--orange, #f97316)', label: 'arch.svc.admin' },
};

function _asKey(svc) { return svc.nodeName || svc.name; }

function _asSelKeyOf(svc) { return svc.type + ':' + _asKey(svc); }

function _asState(svc) {
  if (svc.type === 'admin') return window._asHealthOK ? 'ok' : 'warn';
  if (svc.status === 'online') return 'ok';
  if (svc.status === 'declared') return 'off';
  return 'warn';
}

function _asStTxt(st) {
  return t(st === 'ok' ? 'as.st.online' : st === 'off' ? 'as.st.declared' : 'as.st.offline');
}

function _asAllSvcs(model) {
  return model.hosts.flatMap(h => (h.services || []).map(s => ({ s, h })));
}

function _asGroupOf(model, id) {
  return (model.haGroups || []).find(g => g.members.includes(id)) || null;
}

function _asCaps(model, svc) {
  const c = [];
  if (svc.type === 'edge') {
    if (svc.access) c.push('Access');
    if (_asGroupOf(model, svc.id)) c.push('HA');
    if (svc.domains || svc.acme) c.push('TLS');
  } else if (svc.type === 'agent') {
    if (svc.docker) c.push('Docker');
    if (svc.podman) c.push('Podman');
    if (svc.portainer) c.push('Portainer');
    if (svc.k8s) c.push('K8s');
  }
  return c;
}

function _asLiveNode(svc) {
  return (_arch.nodes || []).find(n => n.role === svc.type &&
    (n.node_name === svc.nodeName || n.node_name === svc.name || n.display_name === svc.name)) || null;
}

/** Une mesure par nœud : appelée au chargement puis à chaque tick du live. */
function asSample(model) {
  for (const { s } of _asAllSvcs(model)) {
    if (s.type === 'admin') continue;
    const st = _asState(s);
    const live = window._asLive[_asKey(s)];
    const ch = st === 'off' ? 'x' : st === 'warn' ? 'r' : (live && live.risk_level && live.risk_level !== 'low' ? 'o' : 'g');
    const h = window._asHist[_asKey(s)] = window._asHist[_asKey(s)] || [];
    h.push(ch);
    if (h.length > AS_HIST_LEN) h.shift();
  }
  window._asRpsHist.push(_asTotalRps(model));
  if (window._asRpsHist.length > AS_HIST_LEN) window._asRpsHist.shift();
}

function _asTotalRps(model) {
  return _asAllSvcs(model).filter(x => x.s.type === 'edge')
    .reduce((n, x) => n + ((window._asLive[_asKey(x.s)] || {}).rps || 0), 0);
}

function _asSpark(key) {
  const h = (window._asHist[key] || []).slice();
  while (h.length < AS_HIST_LEN) h.unshift('x');
  return `<span class="as-spk">${h.map(c => `<i${c === 'g' ? '' : ` data-s="${c}"`}></i>`).join('')}</span>`;
}

function _asPct(key) {
  const h = (window._asHist[key] || []).filter(c => c !== 'x');
  if (!h.length) return null;
  return Math.round(h.filter(c => c === 'g' || c === 'o').length / h.length * 1000) / 10;
}

// ── Formats ──────────────────────────────────────────────────────────────────

function _asNum(v, digits) {
  return Number(v).toLocaleString(typeof gpxBCP47 === 'function' ? gpxBCP47() : undefined, { maximumFractionDigits: digits == null ? 1 : digits });
}

function _asRps(v) { return _asNum(v || 0, (v || 0) < 10 ? 1 : 0); }

/** Date jamais atteinte (0001-01-01) = nœud jamais vu. */
function _asSeen(iso) { return !!iso && !String(iso).startsWith('0001'); }

function _asDur(iso) {
  const m = Math.max(1, Math.round((Date.now() - new Date(iso).getTime()) / 60000));
  if (m < 60) return t('as.dur.min', { n: m });
  const h = Math.round(m / 60);
  if (h < 48) return t('as.dur.h', { n: h });
  return t('as.dur.d', { n: Math.round(h / 24) });
}

/** Heure seule pour aujourd'hui, jour/mois + heure sinon (colonnes étroites du panneau et du journal). */
function _asTime(iso) {
  const d = new Date(iso);
  const opts = { hour: '2-digit', minute: '2-digit' };
  if (new Date().toDateString() !== d.toDateString()) Object.assign(opts, { day: '2-digit', month: '2-digit' });
  if (state.timezone) opts.timeZone = state.timezone;
  return d.toLocaleString(typeof gpxBCP47 === 'function' ? gpxBCP47() : undefined, opts);
}

/** Sous-titre d'un rôle : « Passerelle · leader », « Agent · Docker, Portainer »… */
function _asRoleDetail(model, s, h) {
  if (s.type === 'admin') return t('as.admin_role') + (h ? ' · ' + h.name : '');
  let extra = '';
  if (s.type === 'edge') {
    const g = _asGroupOf(model, s.id);
    if (g) extra = t(g.members[0] === s.id ? 'as.leader' : 'as.follower');
  } else {
    extra = _asCaps(model, s).join(', ');
  }
  return t(_AS_ROLE[s.type].label) + (extra ? ' · ' + extra : '');
}

/** Passerelle à laquelle un agent se connecte (cible déclarée, passerelle du même hôte, sinon la première). */
function _asAgentTarget(model, x) {
  const edges = _asAllSvcs(model).filter(y => y.s.type === 'edge');
  if (x.s.targetEdgeId) {
    const e = edges.find(y => y.s.id === x.s.targetEdgeId);
    if (e) return e;
  }
  const local = edges.find(y => y.h === x.h);
  if (local) return local;
  const node = _asLiveNode(x.s);
  if (node && node.target_edge) {
    const e = edges.find(y => node.target_edge.includes(_asKey(y.s)));
    if (e) return e;
  }
  return edges[0] || null;
}

// ── Nœud (vue « Par hôte » et mode édition « Par rôle ») ───────────────────────

function _asNodeHTML(model, svc, host, o) {
  const role = _AS_ROLE[svc.type];
  const st = _asState(svc);
  const key = _asKey(svc);
  const live = window._asLive[key];
  const caps = _asCaps(model, svc);
  let body = '';
  if (o.edit && svc.type !== 'admin') {
    body = '';
  } else if (svc.type === 'admin') {
    const ne = _asAllSvcs(model).filter(x => x.s.type === 'edge').length;
    const na = _asAllSvcs(model).filter(x => x.s.type === 'agent').length;
    body = `<span class="as-ft" style="margin-top:10px"><span>${esc(t('as.manages_n', { e: ne, a: na }))}</span></span>`;
  } else {
    const pct = _asPct(key);
    const right = svc.type === 'edge' && live ? esc(t('as.req_s', { n: _asRps(live.rps) })) : '';
    body = `${_asSpark(key)}<span class="as-ft"><span>${pct == null ? '—' : `<b>${_asNum(pct)} %</b> · ${esc(t('as.session'))}`}</span><span>${right}</span></span>`;
  }
  const meta = svc.type === 'admin'
    ? `${t('as.admin_role')} · ${host ? host.name : ''}`
    : `${t(role.label)} · ${host ? host.name : ''}`;
  const virtual = svc.virtual ? ' data-virtual' : '';
  return `<button type="button" class="as-node" style="--k:${role.k};--h:${_asHostColor(model, host)}" data-svc="${esc(svc.id)}"${virtual}${o.sel ? ' data-sel' : ''}${st === 'warn' ? ' data-tone="warn"' : ''}
    onclick="asNodeClick('${esc(svc.id)}')">
    <span class="as-hd"><span class="as-ic">${_ARCH_ICONS[svc.type] || ''}</span>
      <span class="as-nm">${esc(svc.name)}<small>${esc(meta)}</small></span>
      <span class="as-st" data-tone="${st}">${esc(_asStTxt(st))}</span></span>
    ${body}
    ${caps.length ? `<span class="as-cs">${caps.map(c => `<span>${esc(c)}</span>`).join('')}</span>` : ''}
  </button>`;
}

/** Mode édition « Par rôle » : tiers Passerelles / Agents. model = { hosts, haGroups } ; o = { edit, selectedId } */
function _asTiersHTML(model, o) {
  o = o || {};
  const all = _asAllSvcs(model);
  const edges = all.filter(x => x.s.type === 'edge');
  const agents = all.filter(x => x.s.type === 'agent');
  let admin = all.find(x => x.s.type === 'admin');
  if (!all.length && !o.edit) return `<div class="as-empty">${esc(t('as.empty'))}</div>`;
  if (!admin) admin = { s: { id: 'admin-virtual', type: 'admin', name: 'Admin', status: 'online', virtual: true }, h: null };
  const node = x => _asNodeHTML(model, x.s, x.h, { sel: o.selectedId === x.s.id, edit: !!o.edit });
  const add = type => o.edit ? `<button type="button" class="as-add" onclick="asAdd('${type}')">${esc(t('as.add'))}</button>` : '';

  const grouped = new Set();
  const groups = (model.haGroups || []).map(g => {
    const members = edges.filter(x => g.members.includes(x.s.id));
    members.forEach(x => grouped.add(x.s.id));
    if (!members.length) return '';
    const leader = members[0].s.name;
    const upN = members.filter(x => _asState(x.s) === 'ok').length;
    return `<div class="as-ha"><span class="as-ha-tag">${esc(t('as.ha_tag', { id: g.id, leader, up: upN, n: members.length }))}</span>
      <div class="as-ha-in">${members.map(node).join('')}</div></div>`;
  }).join('');
  const loose = edges.filter(x => !grouped.has(x.s.id));
  const gateways = `<div style="display:grid;gap:10px;min-width:0">${groups}${loose.length ? `<div class="as-ha-in">${loose.map(node).join('')}</div>` : ''}${!edges.length ? `<div class="as-empty" style="padding:14px 0">${esc(t('as.no_gateway'))}</div>` : ''}</div>`;

  const upE = edges.filter(x => _asState(x.s) === 'ok').length;
  const upA = agents.filter(x => _asState(x.s) === 'ok').length;
  return `<div class="as-tiers">
    <div class="as-net"><span class="as-pill">${_ARCH_ICONS.globe} ${esc(t('as.internet'))}</span></div>
    <div class="as-vl"><span>80 / 443</span></div>
    <div class="as-tier">
      <div class="as-th"><b>${esc(t('as.gateways'))}</b>${add('edge')}<span class="as-th-m">${esc(t('as.tier_online', { up: upE, n: edges.length }))}</span></div>
      <div class="as-row">
        ${gateways}
        <div class="as-hl"><span>${esc(t('as.manages'))}</span></div>
        <div class="as-who"><span class="as-pill">${esc(t('as.administrator'))}</span><div class="as-vl" data-dashed style="height:26px;--c:var(--purple)"></div>${node(admin)}</div>
      </div>
    </div>
    <div class="as-vl" data-up style="--c:var(--green)"><span>${esc(t('as.flow_ws', { n: agents.length }))}</span></div>
    <div class="as-tier">
      <div class="as-th"><b>${esc(t('as.agents'))}</b>${add('agent')}<span class="as-th-m">${esc(t('as.tier_online', { up: upA, n: agents.length }))}</span></div>
      <div class="as-ag">${agents.map(x => `<div>${node(x)}</div>`).join('')}${o.edit ? `<div><button type="button" class="as-slot" onclick="asAdd('agent')">+ ${esc(t('as.add_agent'))}</button></div>` : ''}</div>
      ${!agents.length && !o.edit ? `<div class="as-empty" style="padding:14px 0">${esc(t('as.no_agent'))}</div>` : ''}
    </div>
  </div>`;
}

// ── Vue « Flux » : Internet → passerelles → agents, liaisons tracées après rendu ──

function _asFlowNode(model, x, sel) {
  const { s, h } = x;
  const role = _AS_ROLE[s.type];
  const st = _asState(s);
  const key = _asKey(s);
  const live = window._asLive[key];
  let foot;
  if (s.type === 'admin') {
    const ne = _asAllSvcs(model).filter(y => y.s.type === 'edge').length;
    const na = _asAllSvcs(model).filter(y => y.s.type === 'agent').length;
    foot = `<span class="as-ft"><span>${esc(t('as.manages_n', { e: ne, a: na }))}</span></span>`;
  } else {
    let metric = '';
    const node = _asLiveNode(s);
    if (st === 'warn' && node && _asSeen(node.last_seen_at)) metric = t('as.since', { dur: `<b>${esc(_asDur(node.last_seen_at))}</b>` });
    else if (s.type === 'edge' && live) metric = t('as.req_s', { n: `<b>${_asRps(live.rps)}</b>` });
    else if (s.type === 'agent' && window._asContainers[key] != null) metric = t('as.containers_n', { n: `<b>${window._asContainers[key]}</b>` });
    foot = `<span class="as-ft"><span class="as-hchip"><i style="background:${_asHostColor(model, h)}"></i>${esc(h ? h.name : '—')}</span><span>${metric}</span></span>${_asSpark(key)}`;
  }
  return `<button type="button" class="as-node as-fn" data-lk="${esc(s.id)}" style="--k:${role.k}"${sel ? ' data-sel' : ''}${st === 'warn' ? ' data-tone="warn"' : ''}
    onclick="asNodeClick('${esc(s.id)}')" aria-pressed="${sel ? 'true' : 'false'}">
    <span class="as-hd"><span class="as-ic">${_ARCH_ICONS[s.type] || ''}</span>
      <span class="as-nm">${esc(s.name)}<small>${esc(_asRoleDetail(model, s, h))}</small></span>
      <span class="as-st" data-tone="${st}">${esc(_asStTxt(st))}</span></span>
    ${foot}
  </button>`;
}

function _asFlowHTML(model, o) {
  const all = _asAllSvcs(model);
  const edges = all.filter(x => x.s.type === 'edge');
  const agents = all.filter(x => x.s.type === 'agent');
  const admin = all.find(x => x.s.type === 'admin');
  window._asLinks = [];
  if (!edges.length && !agents.length) return `<div class="as-empty">${esc(t('as.empty'))}</div>`;
  const node = x => _asFlowNode(model, x, o.selectedId === x.s.id);

  const grouped = new Set();
  const groups = (model.haGroups || []).map(g => {
    const members = edges.filter(x => g.members.includes(x.s.id));
    if (!members.length) return '';
    members.forEach(x => grouped.add(x.s.id));
    const up = members.filter(x => _asState(x.s) === 'ok').length;
    return `<div class="as-fl-ha"><span class="as-fl-ha-tag">${esc(t('as.flow.ha', { id: g.id, up, n: members.length }))}</span>${members.map(node).join('')}</div>`;
  }).join('');
  const loose = edges.filter(x => !grouped.has(x.s.id)).map(node).join('');

  const links = edges.map(x => ({ from: 'inet', to: x.s.id, k: 'u' }));
  for (const x of agents) {
    const tgt = _asAgentTarget(model, x);
    if (tgt) links.push({ from: x.s.id, to: tgt.s.id, k: _asState(x.s) === 'ok' ? 'w' : 'x' });
  }
  if (admin && edges.length) links.push({ from: admin.s.id, to: 'gw', k: 'm' });
  window._asLinks = links;

  const upE = edges.filter(x => _asState(x.s) === 'ok').length;
  const upA = agents.filter(x => _asState(x.s) === 'ok').length;
  return `<div class="as-flow">
    <svg class="as-links" aria-hidden="true"></svg>
    ${admin ? `<div class="as-fl-top">${node(admin)}</div>` : ''}
    <div class="as-fl-in"><div class="as-inet" data-lk="inet">${_ARCH_ICONS.globe}<b>${esc(t('as.internet'))}</b><small>80 / 443</small></div></div>
    <div class="as-fl-col" data-col="gw">
      <div class="as-fl-h" data-lk="gw">${esc(t('as.gateways'))} · ${esc(t('as.tier_online', { up: upE, n: edges.length }))}</div>
      ${groups}${loose}${edges.length ? '' : `<div class="as-empty" style="padding:14px 0">${esc(t('as.no_gateway'))}</div>`}
    </div>
    <div class="as-fl-col" data-col="ag">
      <div class="as-fl-h">${esc(t('as.agents'))} · ${esc(t('as.tier_online', { up: upA, n: agents.length }))}</div>
      ${agents.map(node).join('') || `<div class="as-empty" style="padding:14px 0">${esc(t('as.no_agent'))}</div>`}
    </div>
  </div>`;
}

/** Trace les liaisons du schéma en flux à partir de la position réelle des nœuds. */
function asDrawLinks() {
  const flow = document.querySelector('#as-root .as-flow');
  if (!flow) return;
  const svg = flow.querySelector('.as-links');
  if (!svg || getComputedStyle(svg).display === 'none') return;
  const box = flow.getBoundingClientRect();
  const rect = el => {
    const b = el.getBoundingClientRect();
    return { l: b.left - box.left, r: b.right - box.left, t: b.top - box.top, b: b.bottom - box.top,
      cx: (b.left + b.right) / 2 - box.left, cy: (b.top + b.bottom) / 2 - box.top };
  };
  const find = id => flow.querySelector(`[data-lk="${CSS.escape(id)}"]`);
  const curveX = (x1, y1, x2, y2) => { const m = (x1 + x2) / 2; return `M${x1} ${y1} C${m} ${y1} ${m} ${y2} ${x2} ${y2}`; };
  const paths = window._asLinks.map(lk => {
    const a = find(lk.from), b = find(lk.to);
    if (!a || !b) return '';
    const A = rect(a), B = rect(b);
    let d;
    if (lk.k === 'm') { const m = (A.b + B.t) / 2; d = `M${A.cx} ${A.b} C${A.cx} ${m} ${B.cx} ${m} ${B.cx} ${B.t}`; }
    else if (lk.k === 'u') d = curveX(A.r, A.cy, B.l, B.cy);
    else d = curveX(A.l, A.cy, B.r, B.cy);
    return `<path class="as-ln" data-k="${lk.k}" d="${d}"></path>`;
  }).join('');
  const marker = k => `<marker id="as-mk-${k}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path class="as-mk" data-k="${k}" d="M0 0L10 5L0 10z"></path></marker>`;
  svg.setAttribute('viewBox', `0 0 ${box.width} ${box.height}`);
  svg.innerHTML = `<defs>${marker('u')}${marker('w')}${marker('x')}</defs>${paths}`;
}

// ── Bandeau d'indicateurs, « À traiter », panneau de détail ─────────────────────

function _asRpsSpark() {
  const h = window._asRpsHist;
  if (h.length < 2) return '';
  const max = Math.max(...h, 1);
  const pts = h.map((v, i) => `${Math.round(i * 80 / (h.length - 1))},${Math.round(26 - v / max * 22)}`).join(' ');
  return `<svg class="as-kc-sp" width="80" height="28" viewBox="0 0 80 28" aria-hidden="true"><polyline points="${pts}"></polyline></svg>`;
}

function _asKpiStripHTML(model) {
  const all = _asAllSvcs(model);
  const edges = all.filter(x => x.s.type === 'edge');
  const nodes = all.filter(x => x.s.type !== 'admin');
  const up = nodes.filter(x => _asState(x.s) === 'ok').length;
  const down = nodes.filter(x => _asState(x.s) === 'warn').length;
  const grp = (model.haGroups || []).find(g => g.members.length >= 2);
  let quorum = '—';
  let qsub = t('as.kpi.no_ha');
  if (grp) {
    const members = grp.members.map(id => all.find(y => y.s.id === id)).filter(Boolean);
    quorum = `${members.filter(x => _asState(x.s) === 'ok').length} <small>/ ${members.length}</small>`;
    qsub = t('as.kpi.quorum_sub', { id: grp.id, leader: members[0] ? members[0].s.name : '—' });
  }
  const m = window._asMetrics || {};
  const wsA = m.ws ? m.ws.admin_connections : null;
  const wsG = m.ws ? m.ws.agent_connections : null;
  const sync = m.peers ? m.peers.avg_sync_ms : null;
  const cell = (label, value, sub, extra, tone) => `<div class="as-kc"${tone ? ` data-tone="${tone}"` : ''}>
    <div class="as-kc-t"><span class="as-kc-l">${esc(label)}</span><span class="as-kc-v">${value}</span><span class="as-kc-s">${esc(sub)}</span></div>${extra || ''}</div>`;
  return `<section class="as-kstrip" aria-label="${esc(t('as.kpis'))}">
    ${cell(t('as.kpi.traffic'), `${_asRps(_asTotalRps(model))} <small>req/s</small>`, t('as.kpi.traffic_sub', { n: edges.length }), _asRpsSpark())}
    ${cell(t('as.kpi.online'), `${up} <small>/ ${nodes.length}</small>`, down ? t('as.kpi.offline_n', { n: down }) : t('as.kpi.all_online'), '', down ? 'bad' : '')}
    ${cell(t('as.kpi.quorum'), quorum, qsub)}
    ${cell(t('as.kpi.ws'), wsA == null && wsG == null ? '—' : String((wsA || 0) + (wsG || 0)), t('as.kpi.ws_sub', { a: wsA == null ? '—' : wsA, g: wsG == null ? '—' : wsG }))}
    ${cell(t('as.kpi.sync'), sync == null ? '—' : `${Math.round(sync)} <small>ms</small>`, t('as.kpi.sync_sub'))}
  </section>`;
}

const _AS_WARN_ICON = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l10 18H2z"/><path d="M12 10v5M12 18h.01"/></svg>';
const _AS_EDIT_ICON = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 20l4-1 11-11-3-3L5 16z"/></svg>';
const _AS_REDEPLOY_ICON ='<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M20 12a8 8 0 1 1-2.3-5.6L20 9"/><path d="M20 4v5h-5"/></svg>';

/** Écarts déclaré/déployé d'un hôte, hors statut (déjà signalé comme hors ligne). */
function _asHostDrift(h) {
  return (h.services || []).some(s => s.type !== 'admin' && _asLiveNode(s) && _asDriftRows(s, h).slice(1).some(r => r.bad));
}

function _asTodoHTML(model) {
  const items = [];
  const item = (tone, icon, title, sub, btns) => `<div class="as-td"><span class="as-td-ic" data-tone="${tone}">${icon}</span>
    <div class="as-td-tx"><b>${esc(title)}</b><small>${esc(sub)}</small></div>${btns}</div>`;
  const draft = typeof _archDraftRead === 'function' ? _archDraftRead() : null;
  if (draft && draft.n) {
    items.push(item('info', _AS_EDIT_ICON, t('as.todo.draft', { n: draft.n }), t('as.todo.draft_sub', { date: fmtDate(new Date(draft.savedAt).toISOString()) }),
      `<button class="btn btn-ghost btn-sm as-td-no" onclick="asDraftDiscard()">${esc(t('as.edit.discard'))}</button>
       <button class="btn btn-primary btn-sm" onclick="openInfraWizard()">${esc(t('as.todo.draft_resume'))}</button>`));
  }
  for (const n of (_arch.nodes || []).filter(x => x.status === 'pending')) {
    const role = n.role === 'edge' ? t('arch.svc.edge') : n.role === 'agent' ? t('arch.svc.agent') : n.role;
    items.push(item('warn', _ARCH_ICONS[n.role] || '', t('as.todo.pending', { name: n.display_name || n.node_name || n.id }),
      `${role} · ${n.endpoint || n.remote_addr || '—'}`,
      `<button class="btn btn-ghost btn-sm as-td-no" onclick="rejectNode('${esc(n.id)}')">${esc(t('infra.reject'))}</button>
       <button class="btn btn-primary btn-sm" onclick="acceptNode('${esc(n.id)}')">${esc(t('infra.accept'))}</button>`));
  }
  for (const { s, h } of _asAllSvcs(model)) {
    if (s.type === 'admin' || _asState(s) !== 'warn') continue;
    const node = _asLiveNode(s);
    const seen = node && _asSeen(node.last_seen_at);
    items.push(item('bad', _AS_WARN_ICON,
      seen ? t('as.todo.offline', { name: s.name, dur: _asDur(node.last_seen_at) }) : t('as.todo.offline_nodur', { name: s.name }),
      (h ? h.name : '—') + (seen ? ' · ' + t('as.todo.last_seen', { time: _asTime(node.last_seen_at) }) : ''),
      `<button class="btn btn-secondary btn-sm" onclick="asSelect('${esc(s.id)}',true)">${esc(t('as.todo.inspect'))}</button>`));
  }
  for (const h of model.hosts) {
    if (!_asHostDrift(h)) continue;
    items.push(item('warn', _AS_REDEPLOY_ICON, t('as.todo.drift', { host: h.name }), t('as.todo.drift_sub'),
      `<button class="btn btn-secondary btn-sm" onclick="asOpenConfig('${h.id}','e')">${esc(t('as.todo.see_drift'))}</button>`));
  }
  for (const dn of (window._excludedDeclaredNodes ? window._excludedDeclaredNodes.values() : [])) {
    items.push(item('warn', _ARCH_ICONS.agent, t('as.todo.excluded', { name: dn.name }), t('as.todo.excluded_sub'),
      `<button class="btn btn-ghost btn-sm as-td-no" onclick="confirmAgentRemoval('${esc(dn.id)}','${esc(dn.name)}','${esc(dn.name)}')">${esc(t('infra.excluded.confirm_btn'))}</button>`));
  }
  if (!items.length) return '';
  return `<section class="as-todo" aria-label="${esc(t('as.todo.label'))}">
    <div class="as-todo-h">${esc(t('as.todo.title', { n: items.length }))}</div>
    <div class="as-todo-list">${items.join('')}</div>
  </section>`;
}

/** Rôle mis en avant par défaut : un nœud en panne, sinon la première passerelle. */
function _asDefaultSel(model) {
  const all = _asAllSvcs(model);
  const x = all.find(y => y.s.type !== 'admin' && _asState(y.s) === 'warn')
    || all.find(y => y.s.type === 'edge') || all.find(y => y.s.type === 'agent') || all[0];
  return x ? _asSelKeyOf(x.s) : null;
}

function _asSelected(model) {
  const all = _asAllSvcs(model);
  let x = all.find(y => _asSelKeyOf(y.s) === window._asSelKey);
  if (!x) {
    window._asSelKey = _asDefaultSel(model);
    x = all.find(y => _asSelKeyOf(y.s) === window._asSelKey);
  }
  return x || null;
}

const _AS_EV = {
  scale_up: ['as.ev.scale_up', 'ok'], scale_down: ['as.ev.scale_down', 'warn'],
  health_escalation: ['as.ev.health', 'bad'], health_critical: ['as.ev.health', 'bad'],
  health_watch_started: ['as.ev.watch', ''], agent_online: ['as.ev.online', 'ok'], new_digest: ['as.ev.digest', ''],
  start: ['as.ev.start', 'ok'], stop: ['as.ev.stop', 'warn'], destroy: ['as.ev.destroy', 'bad'],
};

/** Catégorie d'un événement pour les filtres du journal complet. */
function _asEvCat(type) {
  if (/^scale_/.test(type)) return 'scale';
  if (/^health_/.test(type)) return 'health';
  if (/online|offline|connect/.test(type)) return 'conn';
  return 'other';
}

function _asEvLabel(type) {
  const e = _AS_EV[type];
  return e ? { label: t(e[0]), tone: e[1] } : { label: type || '—', tone: '' };
}

function _asPanelHTML(model) {
  const x = _asSelected(model);
  if (!x) return `<div class="as-pn-empty">${esc(t('as.panel.empty'))}</div>`;
  const { s, h } = x;
  const role = _AS_ROLE[s.type];
  const st = _asState(s);
  const key = _asKey(s);
  const node = _asLiveNode(s);
  const live = window._asLive[key] || null;
  const all = _asAllSvcs(model);
  const g = _asGroupOf(model, s.id);

  let sub;
  if (s.type === 'edge') sub = g ? t(g.members[0] === s.id ? 'as.panel.leader_of' : 'as.panel.member_of', { id: g.id }) : t('as.panel.standalone');
  else if (s.type === 'agent') { const tg = _asAgentTarget(model, x); sub = tg ? t('as.panel.agent_to', { edge: tg.s.name }) : t('arch.svc.agent'); }
  else sub = t('as.admin_role');

  const hostLine = h ? `<div class="as-pn-host"><span class="as-hd-dot" style="--h:${_asHostColor(model, h)}"></span>${esc(h.name)}${h.region ? ' · ' + esc(h.region) : ''}
    <span class="as-zt" data-p="${h.internet ? 0 : 1}">${esc(h.internet ? t('arch.host.internet') : t('arch.host.private'))}</span></div>` : '';

  const pct = _asPct(key);
  const stat = (v, l) => `<div class="as-pn-stat"><b>${v}</b><small>${esc(l)}</small></div>`;
  let stats;
  if (s.type === 'edge') {
    const win = window._asEdgeWin[key];
    stats = stat(live ? _asRps(live.rps) : '—', t('as.stat.rps'))
      + stat(win && win.p95_ms > 0 ? _asNum(win.p95_ms, 0) + ' ms' : '—', t('as.stat.p95'))
      + stat(pct == null ? '—' : _asNum(pct) + ' %', t('as.stat.avail'));
  } else if (s.type === 'agent') {
    const cpu = live && live.cpu_pct != null ? live.cpu_pct : (node && node.cpu_pct != null ? node.cpu_pct : null);
    stats = stat(window._asContainers[key] != null ? window._asContainers[key] : '—', t('as.stat.containers'))
      + stat(cpu == null ? '—' : _asNum(cpu, 0) + ' %', t('as.stat.cpu'))
      + stat(pct == null ? '—' : _asNum(pct) + ' %', t('as.stat.avail'));
  } else {
    const m = window._asMetrics || {};
    stats = stat(all.filter(y => y.s.type === 'edge').length, t('as.stat.gw'))
      + stat(all.filter(y => y.s.type === 'agent').length, t('as.stat.agents'))
      + stat(m.ws && m.ws.admin_connections != null ? m.ws.admin_connections : '—', t('as.stat.sessions'));
  }

  const caps = _asCaps(model, s);
  const dl = [];
  const row = (k, v, tone) => { if (v) dl.push(`<dt>${esc(k)}</dt><dd${tone ? ` data-tone="${tone}"` : ''}>${v}</dd>`); };
  if (s.type === 'edge') {
    row(t('as.panel.reach'), (s.reachable || (node && node.endpoint)) ? `<span class="as-mono">${esc(s.reachable || node.endpoint)}</span>` : '');
    if (live && !live.low_traffic) row(t('as.panel.err'), `${_asNum(live.error_pct)} %`, live.error_pct >= 5 ? 'warn' : '');
  }
  if (s.type !== 'admin') row(t('as.panel.version'), node && node.version ? esc(node.version) : '—');
  if (s.type !== 'admin' && h) {
    if (!node) row(t('as.config'), esc(t('as.drift.not_connected')));
    else if (_asDriftRows(s, h).slice(1).some(r => r.bad)) row(t('as.config'), `<a href="#" onclick="event.preventDefault();asOpenConfig('${h.id}','e')">${esc(t('as.drift.bad'))}</a>`, 'warn');
    else row(t('as.config'), esc(t('as.drift.ok')), 'ok');
  }
  if (g) {
    const peers = g.members.filter(id => id !== s.id).map(id => all.find(y => y.s.id === id)).filter(Boolean).map(y => y.s.name);
    row(t('as.panel.peers'), esc(peers.join(', ') || '—'));
  }
  if (s.type === 'agent' && node && (node.container_runtimes || []).length) row(t('as.drift.runtime'), esc(node.container_runtimes.join(', ')));
  if (st === 'warn' && node && _asSeen(node.last_seen_at)) row(t('as.panel.last_seen'), esc(fmtDate(node.last_seen_at)));

  const b = (kind, label, cls) => `<button type="button" class="btn ${cls || 'btn-secondary'} btn-sm" onclick="asAct('${kind}','${esc(s.id)}')">${esc(label)}</button>`;
  let main = '';
  let more = '';
  if (s.type === 'edge' && node) {
    main = b('traffic', t('infra.title.traffic'), 'btn-primary') + b('settings', t('as.act.settings')) + b('config', t('as.config'));
    more = b('update', t('as.act.update'), 'btn-ghost') + b('rollback', t('infra.title.rollback'), 'btn-ghost');
  } else if (s.type === 'agent' && node) {
    main = b('containers', t('as.act.containers'), 'btn-primary') + b('events', t('as.act.events')) + b('config', t('as.config'));
    more = b('rescan', t('as.act.rescan'), 'btn-ghost') + b('agent_update', t('as.act.update'), 'btn-ghost') + b('agent_cfg', t('as.act.agent_cfg'), 'btn-ghost');
  } else if (h) {
    main = b('config', t('as.config'), 'btn-primary');
  }
  if (s.type !== 'admin') more += `<button type="button" class="btn btn-ghost btn-sm as-pn-del" onclick="asAct('delete','${esc(s.id)}')">${esc(t('as.act.delete'))}</button>`;

  let events = '';
  if (s.type !== 'admin') {
    const evs = window._asEvents[key];
    if (evs === undefined) _asLoadNodeEvents(key);
    const rows = evs == null
      ? `<div class="as-pn-empty">${esc(t('common.loading'))}</div>`
      : evs.length
        ? evs.map(e => { const l = _asEvLabel(e.event_type); return `<div class="as-pn-evr"><span>${esc(_asTime(e.created_at))}</span><span>${esc(l.label)}${e.detail ? `<small>${esc(e.detail)}</small>` : ''}</span></div>`; }).join('')
        : `<div class="as-pn-empty">${esc(t('as.panel.no_events'))}</div>`;
    events = `<div class="as-pn-ev"><span class="as-pn-k">${esc(t('as.panel.events'))}</span>${rows}</div>`;
  }

  return `<div class="as-pn-top">
      <span class="as-pn-k">${esc(t('as.panel.sel.' + s.type))}</span>
      <div class="as-pn-hd" style="--k:${role.k}"><span class="as-ic">${_ARCH_ICONS[s.type] || ''}</span>
        <div class="as-pn-nm"><b>${esc(s.name)}</b><small>${esc(sub)}</small></div>
        <span class="as-st" data-tone="${st}">${esc(_asStTxt(st))}</span></div>
      ${hostLine}
    </div>
    <div class="as-pn-stats">${stats}</div>
    ${s.type !== 'admin' ? `<div class="as-pn-spk">${_asSpark(key)}<div class="as-pn-cap"><span>${esc(t('as.panel.hist'))}</span><span>${esc(t('as.panel.now'))}</span></div></div>` : ''}
    ${caps.length ? `<div><span class="as-pn-k">${esc(t('as.caps'))}</span><span class="as-cs">${caps.map(c => `<span>${esc(c)}</span>`).join('')}</span></div>` : ''}
    ${dl.length ? `<dl class="as-pn-dl">${dl.join('')}</dl>` : ''}
    ${main || more ? `<div class="as-pn-acts">${main ? `<div>${main}</div>` : ''}${more ? `<div>${more}</div>` : ''}</div>` : ''}
    ${events}`;
}

async function _asLoadNodeEvents(nodeName) {
  window._asEvents[nodeName] = null;
  const evs = await api('GET', `/node-events?node=${encodeURIComponent(nodeName)}&limit=4`).catch(() => []);
  window._asEvents[nodeName] = Array.isArray(evs) ? evs : [];
  const x = _asSelected(_arch);
  if (x && _asKey(x.s) === nodeName) {
    const p = document.getElementById('as-panel');
    if (p) p.innerHTML = _asPanelHTML(_arch);
  }
}

function _asTopoHeadHTML() {
  const b = (m, k) => `<button type="button"${window._asMode === m ? ' data-on aria-pressed="true"' : ' aria-pressed="false"'} onclick="asSetMode('${m}')">${esc(t(k))}</button>`;
  let extra = '';
  if (window._asMode === 'role') {
    extra = `<div class="as-lg">
      <span style="--c:var(--blue)">${esc(t('as.legend.users'))}</span>
      <span style="--c:var(--green)">${esc(t('as.legend.ws'))}</span>
      <span style="--c:var(--purple)" data-dashed>${esc(t('as.legend.admin'))}</span></div>`;
  } else if (window._asMode === 'list') {
    extra = _asListFiltersHTML();
  }
  return `<h2>${esc(t('as.topology'))}</h2><div class="as-seg" role="group" aria-label="${esc(t('as.layout'))}">${b('role', 'as.view.flow')}${b('host', 'as.by_host')}${b('list', 'as.view.list')}</div>${extra}`;
}

/** En-tête du schéma : rendu au chargement et au changement de disposition seulement (la recherche garde le focus). */
function asRenderHead() {
  const el = document.getElementById('as-topo-h');
  if (el) el.innerHTML = _asTopoHeadHTML();
}

/** Vue lecture : redessine indicateurs, « À traiter », schéma et panneau (chargement puis tick du live). */
function asRenderLive() {
  const set = (id, html) => { const el = document.getElementById(id); if (el) el.innerHTML = html; };
  const x = _asSelected(_arch);
  set('as-kpis', _asKpiStripHTML(_arch));
  set('as-todo', _asTodoHTML(_arch));
  if (!document.querySelector('#as-topo-h h2')) asRenderHead();
  _asListCountsUpdate();
  set('as-root', asSchemaHTML(_arch, { selectedId: x ? x.s.id : null }));
  set('as-panel', _asPanelHTML(_arch));
  requestAnimationFrame(asDrawLinks);
}

function asSelect(id, scroll) {
  const x = _asAllSvcs(_arch).find(y => y.s.id === id);
  if (!x) return;
  window._asSelKey = _asSelKeyOf(x.s);
  asRenderLive();
  const p = document.getElementById('as-panel');
  if (p && (scroll || window.innerWidth <= 1180)) p.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// ── Hôtes : chaque hôte porte un ou plusieurs rôles (passerelle, agent, Admin) ; un agent porte une ou plusieurs plateformes ──

const _AS_HOST_COLORS = ['#378ADD', '#D85A30', '#7F77DD', '#1D9E75', '#BA7517', '#D4537E'];

function _asHostColor(model, host) {
  const i = host ? model.hosts.indexOf(host) : -1;
  return i < 0 ? 'var(--border)' : _AS_HOST_COLORS[i % _AS_HOST_COLORS.length];
}

// Disposition de la vue lecture (role = flux, host = par hôte, list = liste) et du mode édition (host = cartes d'hôtes, role = tiers).
window._asMode = (function () {
  try { const m = localStorage.getItem('gpx_as_mode'); return m === 'host' || m === 'list' ? m : 'role'; } catch { return 'role'; }
})();
window._asEditMode = (function () {
  try { return localStorage.getItem('gpx_as_edit_mode') === 'role' ? 'role' : 'host'; } catch { return 'host'; }
})();
window._asMenu = null;

function _asRerender() {
  if (window._asEdit) { _archRender(); return; }
  asRenderLive();
}

function asSetMode(mode) {
  window._asMode = mode;
  try { localStorage.setItem('gpx_as_mode', mode); } catch {}
  asRenderHead();
  _asRerender();
}

function asSetEditMode(mode) {
  window._asEditMode = mode;
  try { localStorage.setItem('gpx_as_edit_mode', mode); } catch {}
  _archRender();
}

function asToggleMenu(hostId) {
  window._asMenu = window._asMenu === hostId ? null : hostId;
  _asRerender();
}

function asAddTo(hostId, type) {
  window._asMenu = null;
  const host = _arch.hosts.find(h => h.id === hostId);
  if (host && type === 'edge' && !(host.services || []).length) host.internet = true;
  _archAddService(hostId, type);
}

function asAddHost() {
  const h = _archEmptyHost(_arch.hosts.length + 1);
  _arch.hosts.push(h);
  _arch.selectedHostId = h.id;
  _arch.selectedSvcId = null;
  _archRender();
}

/** Plateformes portées par les agents d'un hôte (Docker ou Podman, Portainer, K8s : cumulables sauf Docker/Podman). */
function _asPlatforms(h) {
  const set = new Set();
  for (const s of h.services || []) {
    if (s.type !== 'agent') continue;
    if (s.docker) set.add('Docker');
    if (s.podman) set.add('Podman');
    if (s.portainer) set.add('Portainer');
    if (s.k8s) set.add('K8s');
  }
  return [...set];
}

function _asHasAdmin(model) {
  return _asAllSvcs(model).some(x => x.s.type === 'admin' && !x.s.virtual);
}

function _asAddMenu(model, h) {
  if (window._asMenu !== h.id) return '';
  const item = (type, desc, off) => `<button type="button" class="as-mi" ${off ? 'disabled' : ''} onclick="event.stopPropagation();asAddTo('${h.id}','${type}')"><span>${esc(t(_AS_ROLE[type].label))}</span><small>${esc(desc)}</small></button>`;
  return `<div class="as-menu">${item('edge', t('arch.role.edge_desc'))}${item('agent', t('arch.role.agent_desc'))}${item('admin', t('arch.role.admin_desc'), _asHasAdmin(model))}</div>`;
}

function _asHostHead(model, h, o) {
  const inet = !!h.internet;
  const zone = o.edit
    ? `<button type="button" class="as-zt" data-p="${inet ? 0 : 1}" onclick="event.stopPropagation();_archSetHostInternet('${h.id}',${!inet})" title="${esc(t('arch.host.internet_hint'))}">${esc(inet ? t('arch.host.internet') : t('arch.host.private'))}</button>`
    : `<span class="as-zt" data-p="${inet ? 0 : 1}">${esc(inet ? t('arch.host.internet') : t('arch.host.private'))}</span>`;
  return `<div class="as-hh"><span class="as-hd-dot"></span><b>${esc(h.name)}</b>${zone}</div>
    ${h.region ? `<small class="as-hsub">${esc(h.region)}</small>` : ''}`;
}

/** Mode édition « Par rôle » : une carte par hôte + « Ajouter un hôte », au-dessus des tiers. */
function _asHostStripHTML(model, o) {
  const cards = model.hosts.map(h => {
    const sel = o.selectedHostId === h.id && !o.selectedId;
    const roles = (h.services || []).map(s => `<span class="as-hrole" style="--k:${_AS_ROLE[s.type].k}" onclick="event.stopPropagation();asNodeClick('${esc(s.id)}')">${esc(s.name)}</span>`).join('');
    const plats = _asPlatforms(h).map(p => `<span class="as-hplat">${esc(p)}</span>`).join('');
    return `<div class="as-hcard"${sel ? ' data-sel' : ''} style="--h:${_asHostColor(model, h)}" onclick="asHostTap('${h.id}')"${window._asArm ? ' data-arm' : ''}>
      ${_asHostHead(model, h, o)}
      <div class="as-hroles">${roles || `<span class="as-hempty">${esc(t('as.host_empty'))}</span>`}</div>
      ${plats ? `<div class="as-hroles">${plats}</div>` : ''}
      <button type="button" class="as-add" onclick="event.stopPropagation();asToggleMenu('${h.id}')">${esc(t('as.add_element'))}</button>
      ${_asAddMenu(model, h)}
    </div>`;
  }).join('');
  return `<div class="as-hosts">${cards}<button type="button" class="as-hcard as-hnew" onclick="asAddHost()">+ ${esc(t('as.add_host'))}</button></div>`;
}

/** Vue lecture « Par hôte » : chaque hôte est un cadre qui contient ses rôles. */
function _asByHostHTML(model, o) {
  if (!_asAllSvcs(model).length) return `<div class="as-empty">${esc(t('as.empty'))}</div>`;
  const boxes = model.hosts.map(h => {
    const svcs = (h.services || []).map(s => _asNodeHTML(model, s, h, { sel: o.selectedId === s.id })).join('');
    const plats = _asPlatforms(h).map(p => `<span class="as-hplat">${esc(p)}</span>`).join('');
    return `<section class="as-hostbox" style="--h:${_asHostColor(model, h)}">
      ${_asHostHead(model, h, o)}
      ${plats ? `<div class="as-hroles">${plats}</div>` : ''}
      <div class="as-hostgrid">${svcs || `<span class="as-hempty">${esc(t('as.host_empty'))}</span>`}</div>
    </section>`;
  }).join('');
  return `<div class="as-byhost">${boxes}</div>`;
}

// ── Vue lecture « Liste » : inventaire groupé par hôte, filtres et recherche ──

const _AS_LIST_F = [['all', 'as.list.f.all'], ['edge', 'as.list.f.edge'], ['agent', 'as.list.f.agent'], ['down', 'as.list.f.down'], ['drift', 'as.list.f.drift']];

function _asListMatch(model, x, f, q) {
  const { s, h } = x;
  if (f === 'edge' && s.type !== 'edge') return false;
  if (f === 'agent' && s.type !== 'agent') return false;
  if (f === 'down' && (s.type === 'admin' || _asState(s) !== 'warn')) return false;
  if (f === 'drift' && !(s.type !== 'admin' && h && _asLiveNode(s) && _asDriftRows(s, h).slice(1).some(r => r.bad))) return false;
  if (!q) return true;
  return [s.name, h ? h.name : '', (h && h.region) || '', t(_AS_ROLE[s.type].label), ..._asCaps(model, s)].join(' ').toLowerCase().includes(q);
}

function _asListCount(model, f) {
  return _asAllSvcs(model).filter(x => _asListMatch(model, x, f, '')).length;
}

function _asListCountsUpdate() {
  for (const [f] of _AS_LIST_F) {
    const el = document.getElementById('as-lc-' + f);
    if (el) el.textContent = _asListCount(_arch, f);
  }
}

function _asListFiltersHTML() {
  const lf = window._asListFilter;
  return `<div class="as-lf">
    <label class="as-lf-q">${'<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="M20 20l-4-4"/></svg>'}
      <input type="search" value="${esc(lf.q)}" placeholder="${esc(t('as.list.search_ph'))}" aria-label="${esc(t('as.list.search'))}" oninput="asListSearch(this.value)"></label>
    ${_AS_LIST_F.map(([f, k]) => `<button type="button" class="as-lf-c"${lf.f === f ? ' data-on aria-pressed="true"' : ' aria-pressed="false"'} onclick="asListFilter('${f}')">${esc(t(k))} <span id="as-lc-${f}">${_asListCount(_arch, f)}</span></button>`).join('')}
  </div>`;
}

function asListFilter(f) {
  window._asListFilter.f = f;
  asRenderHead();
  asRenderLive();
}

function asListSearch(q) {
  window._asListFilter.q = q;
  const x = _asSelected(_arch);
  const root = document.getElementById('as-root');
  if (root) root.innerHTML = asSchemaHTML(_arch, { selectedId: x ? x.s.id : null });
}

function _asListRowHTML(model, x, sel) {
  const { s } = x;
  const st = _asState(s);
  const key = _asKey(s);
  const node = _asLiveNode(s);
  const live = window._asLive[key];
  const pct = _asPct(key);
  let load = '—';
  if (s.type === 'edge' && live) load = t('as.req_s', { n: `<b>${_asRps(live.rps)}</b>` });
  else if (s.type === 'agent' && st === 'warn' && node && _asSeen(node.last_seen_at)) load = esc(t('as.since', { dur: _asDur(node.last_seen_at) }));
  else if (s.type === 'agent' && window._asContainers[key] != null) load = t('as.containers_n', { n: `<b>${window._asContainers[key]}</b>` });
  else if (s.type === 'admin' && window._asMetrics && window._asMetrics.ws && window._asMetrics.ws.admin_connections != null) load = esc(t('as.list.sessions', { n: window._asMetrics.ws.admin_connections }));
  const caps = _asCaps(model, s);
  return `<button type="button" class="as-lr" style="--k:${_AS_ROLE[s.type].k}"${sel ? ' data-sel aria-pressed="true"' : ' aria-pressed="false"'}${st === 'warn' ? ' data-tone="warn"' : ''} onclick="asSelect('${esc(s.id)}')">
    <span class="as-lr-n"><span class="as-ic">${_ARCH_ICONS[s.type] || ''}</span><span class="as-nm">${esc(s.name)}<small>${esc(t(_AS_ROLE[s.type].label))}</small></span></span>
    <span><span class="as-st" data-tone="${st}">${esc(_asStTxt(st))}</span></span>
    <span class="as-lr-av">${s.type === 'admin' ? '—' : `${_asSpark(key)}<span>${pct == null ? '—' : _asNum(pct) + ' %'}</span>`}</span>
    <span class="as-lr-ld">${load}</span>
    <span>${node && node.version ? esc(node.version) : '—'}</span>
    <span class="as-cs">${caps.map(c => `<span>${esc(c)}</span>`).join('')}</span>
  </button>`;
}

function _asListHostHTML(model, h) {
  const svcs = h.services || [];
  const connected = svcs.some(s => s.type !== 'admin' && _asLiveNode(s));
  const tone = _asHostDrift(h) ? 'warn' : connected ? 'ok' : 'off';
  const label = tone === 'warn' ? t('as.drift.bad') : tone === 'ok' ? t('as.drift.ok') : t('as.drift.not_connected');
  return `<div class="as-lh" style="--h:${_asHostColor(model, h)}">
    <span class="as-hd-dot"></span><b>${esc(h.name)}</b>
    <span class="as-zt" data-p="${h.internet ? 0 : 1}">${esc(h.internet ? t('arch.host.internet') : t('arch.host.private'))}</span>
    <small>${esc([h.region, t('as.list.roles', { n: svcs.length })].filter(Boolean).join(' · '))}</small>
    <span class="as-lh-st" data-tone="${tone}">${esc(label)}</span>
    <button type="button" class="btn btn-ghost btn-sm" onclick="asOpenConfig('${h.id}')">${esc(t('as.config'))}</button>
  </div>`;
}

function _asListHTML(model, o) {
  if (!_asAllSvcs(model).length) return `<div class="as-empty">${esc(t('as.empty'))}</div>`;
  const lf = window._asListFilter;
  const q = (lf.q || '').trim().toLowerCase();
  const body = model.hosts.map(h => {
    const rows = (h.services || []).map(s => ({ s, h })).filter(x => _asListMatch(model, x, lf.f, q));
    return rows.length ? _asListHostHTML(model, h) + rows.map(x => _asListRowHTML(model, x, o.selectedId === x.s.id)).join('') : '';
  }).join('');
  return `<div class="as-list">
    <div class="as-lr as-lr-h" aria-hidden="true"><span>${esc(t('as.list.col.node'))}</span><span>${esc(t('as.drift.status'))}</span><span>${esc(t('as.list.col.avail'))}</span><span>${esc(t('as.list.col.load'))}</span><span>${esc(t('as.panel.version'))}</span><span>${esc(t('as.caps'))}</span></div>
    ${body || `<div class="as-empty">${esc(t('as.list.none'))}</div>`}
  </div>`;
}

// ── Mode édition « Par hôte » : cartes d'hôtes, rôles glissables, modifications repérées ──

function _asEditRoleHTML(model, s, h, sel) {
  const chg = _archChangeOf(s.id);
  const diff = _archCapDiff(s);
  const caps = _asCaps(model, s).map(c => diff.add.includes(c) ? `<span data-chg="add">+ ${esc(c)}</span>` : `<span>${esc(c)}</span>`)
    .concat(diff.del.map(c => `<span data-chg="del">${esc(c)}</span>`)).join('');
  const badge = chg ? `<span class="as-bd" data-k="${chg.kind === 'add' ? 'new' : 'mod'}">${esc(t(chg.kind === 'add' ? 'as.edit.new' : 'as.edit.modified'))}</span>` : '';
  return `<button type="button" class="as-rb" draggable="true" data-arch-svc="${esc(s.id)}" ondragstart="_archDragStart(event)" style="--k:${_AS_ROLE[s.type].k}"${sel ? ' data-sel' : ''}${chg && chg.kind === 'add' ? ' data-new' : ''}
    onclick="event.stopPropagation();asRoleTap('${esc(s.id)}','${h.id}')">
    <span class="as-hd"><span class="as-ic">${_ARCH_ICONS[s.type] || ''}</span><span class="as-nm">${esc(s.name)}<small>${esc(_asRoleDetail(model, s, h))}</small></span>${badge}</span>
    ${caps ? `<span class="as-cs">${caps}</span>` : ''}
  </button>`;
}

function _asEditGhostHTML(s) {
  return `<div class="as-rb" data-removed style="--k:${_AS_ROLE[s.type].k}">
    <span class="as-hd"><span class="as-ic">${_ARCH_ICONS[s.type] || ''}</span><span class="as-nm"><s>${esc(s.name)}</s><small>${esc(t(_AS_ROLE[s.type].label))}</small></span><span class="as-bd" data-k="del">${esc(t('as.edit.removed'))}</span></span>
    <button type="button" class="as-restore" onclick="event.stopPropagation();asRestoreSvc('${esc(s.id)}')">${esc(t('as.edit.restore'))}</button>
  </div>`;
}

function _asEditHostsHTML(model, o) {
  const ha = (model.haGroups || []).filter(g => g.members.length).map(g => {
    const names = g.members.map((id, i) => {
      const s = _archFindSvc(id);
      return s ? esc(s.name) + (i === 0 ? ` <small>(${esc(t('as.leader'))})</small>` : '') : '';
    }).filter(Boolean).join(' · ');
    return `<div class="as-hastrip"><span class="as-hastrip-t">${esc(t('as.edit.ha_strip', { id: g.id }))}</span><span>${names}</span></div>`;
  }).join('');
  const cards = model.hosts.map(h => {
    const sel = o.selectedHostId === h.id && !o.selectedId;
    const isNew = _archIsNewHost(h.id);
    const roles = (h.services || []).map(s => _asEditRoleHTML(model, s, h, o.selectedId === s.id)).join('');
    const ghosts = _archRemovedOn(h.id).map(_asEditGhostHTML).join('');
    const empty = !(h.services || []).length;
    return `<section class="as-hc"${sel ? ' data-sel' : ''}${isNew ? ' data-new' : ''} style="--h:${_asHostColor(model, h)}" aria-label="${esc(t('as.host'))} ${esc(h.name)}"
      ${window._asArm ? ' data-arm' : ''} onclick="asHostTap('${h.id}')" ondragover="asDragOver(event,this)" ondragleave="this.removeAttribute('data-drop')" ondrop="asDropOn(event,this,'${h.id}')">
      <div class="as-hh"><span class="as-hd-dot"></span><b>${esc(h.name)}</b>${isNew ? `<span class="as-bd" data-k="new">${esc(t('as.edit.new'))}</span>` : ''}
        <button type="button" class="as-zt" data-p="${h.internet ? 0 : 1}" onclick="event.stopPropagation();_archSetHostInternet('${h.id}',${!h.internet})" title="${esc(t('arch.host.internet_hint'))}">${esc(h.internet ? t('arch.host.internet') : t('arch.host.private'))}</button></div>
      ${h.region ? `<small class="as-hsub">${esc(h.region)}</small>` : ''}
      ${roles}${ghosts}
      ${empty ? `<span class="as-hc-note">${esc(t('as.edit.host_empty_note'))}</span>` : ''}
      <div class="as-hostadd"><button type="button" class="as-slot as-hc-add" onclick="event.stopPropagation();asToggleMenu('${h.id}')">${esc(t('as.edit.add_role'))}</button>${_asAddMenu(model, h)}</div>
    </section>`;
  }).join('');
  return `<div class="as-edit-canvas">
    ${ha ? `<div class="as-hastrips">${ha}</div>` : ''}
    <div class="as-hcs">${cards}<button type="button" class="as-slot as-hc-new" onclick="asAddHost()">+ ${esc(t('as.add_host'))}</button></div>
  </div>`;
}

function asDragOver(ev, el) {
  ev.preventDefault();
  el.setAttribute('data-drop', '');
}

function asDropOn(ev, el, hostId) {
  el.removeAttribute('data-drop');
  _archDrop(ev, hostId);
}

// Écran tactile : le glisser-déposer HTML n'y fonctionne pas ; on touche un élément de la palette, puis l'hôte.
function _asCoarse() {
  return !!(window.matchMedia && window.matchMedia('(pointer: coarse)').matches);
}

function asPalettePick(type) {
  if (!_asCoarse()) { asAdd(type); return; }
  window._asArm = window._asArm === type ? null : type;
  _archRender();
}

function asDisarm() {
  window._asArm = null;
  _archRender();
}

function asHostTap(hostId) {
  const type = window._asArm;
  if (!type) { _archSelectHost(hostId); return; }
  window._asArm = null;
  asAddTo(hostId, type);
}

function asRoleTap(svcId, hostId) {
  if (window._asArm) asHostTap(hostId);
  else _archSelectSvc(svcId);
}

function _asEditToolbarHTML(model) {
  const pal = (type, label, off) => `<button type="button" class="as-pal" data-t="${type}" draggable="${off ? 'false' : 'true'}" data-arch-type="${type}"
    ondragstart="_archDragStart(event)" onclick="asPalettePick('${type}')"${window._asArm === type ? ' aria-pressed="true"' : ''}${off ? ` disabled title="${esc(t('as.edit.admin_single'))}"` : ''}>${_ARCH_ICONS[type]}${esc(label)}</button>`;
  const seg = (m, k) => `<button type="button"${window._asEditMode === m ? ' data-on aria-pressed="true"' : ' aria-pressed="false"'} onclick="asSetEditMode('${m}')">${esc(t(k))}</button>`;
  return `<div class="as-etb">
    <span class="as-etb-l">${esc(t('as.edit.add'))}</span>
    <button type="button" class="as-pal" onclick="asAddHost()">${_ARCH_ICONS.host}${esc(t('as.host'))}</button>
    ${pal('edge', t('arch.svc.edge'))}${pal('agent', t('arch.svc.agent'))}${pal('admin', t('arch.svc.admin'), _asHasAdmin(model))}
    <span class="as-etb-h">${esc(t(_asCoarse() ? 'as.edit.tap_hint' : 'as.edit.drag_hint'))}</span>
    <div class="as-seg" role="group" aria-label="${esc(t('as.layout'))}">${seg('host', 'as.by_host')}${seg('role', 'as.by_role')}</div>
    ${window._asArm ? `<div class="as-arm" role="status"><span>${esc(t('as.edit.arm', { role: t(_AS_ROLE[window._asArm].label) }))}</span>
      <button type="button" class="btn btn-ghost btn-sm" onclick="asDisarm()">${esc(t('common.cancel'))}</button></div>` : ''}
  </div>`;
}

/** model = { hosts, haGroups } ; o = { edit, selectedId, selectedHostId } */
function asSchemaHTML(model, o) {
  o = o || {};
  if (o.edit) {
    return `<div class="as">${window._asEditMode === 'role'
      ? _asHostStripHTML(model, o) + _asTiersHTML(model, o)
      : _asEditHostsHTML(model, o)}</div>`;
  }
  const view = window._asMode === 'host' ? _asByHostHTML : window._asMode === 'list' ? _asListHTML : _asFlowHTML;
  return `<div class="as">${view(model, o)}</div>`;
}

function asNodeClick(id) {
  if (id === 'admin-virtual') return;
  if (window._asEdit) { _archSelectSvc(id); return; }
  asSelect(id);
}

/** Édition : ajoute un nœud à l'hôte sélectionné, sinon sur un hôte libre (ou un nouvel hôte). */
function asAdd(type) {
  let host = _arch.hosts.find(h => h.id === _arch.selectedHostId)
    || _arch.hosts.find(h => !(h.services || []).length);
  if (!host) { host = _archEmptyHost(_arch.hosts.length + 1); _arch.hosts.push(host); }
  if (type === 'edge' && !(host.services || []).length) host.internet = true;
  _archAddService(host.id, type);
}

function asMoveSvc(svcId, toHostId) {
  if (toHostId === 'new') {
    const h = _archEmptyHost(_arch.hosts.length + 1);
    _arch.hosts.push(h);
    toHostId = h.id;
  }
  _archMoveSvc(svcId, toHostId);
}

/** Inspecteur du mode édition : rôle sélectionné, sinon hôte sélectionné. */
function asInspectorHTML() {
  const svc = _arch.selectedSvcId ? _archFindSvc(_arch.selectedSvcId) : null;
  if (svc) return `<div class="as-ins">${_archInspectRole(svc)}</div>`;
  const h = _arch.selectedHostId ? _arch.hosts.find(x => x.id === _arch.selectedHostId) : null;
  if (!h) return `<div class="as-ins"><div class="as-ins-empty">${esc(t('arch.inspector_empty'))}</div></div>`;
  const roles = (h.services || []).map(s => `<button class="arch-addrole" style="--arch-accent:${_archRoleAccent(s.type)};display:block;width:100%;text-align:left;margin-bottom:5px;" onclick="_archSelectSvc('${s.id}')">${esc(t(_ARCH_ROLES[s.type].label))} · ${esc(s.name)}</button>`).join('');
  return `<div class="as-ins">
    <div class="as-ins-h"><span class="as-ins-k">${esc(t('as.host'))}</span>
      <div class="as-ins-n"><b>${esc(h.name)}</b>${_archIsNewHost(h.id) ? `<span class="as-bd" data-k="new">${esc(t('as.edit.new'))}</span>` : ''}</div>
      <div class="as-ins-note">${esc(t('as.host_note'))}</div></div>
    <div class="as-ins-b">
      ${_archGroup(t('arch.group.identity'),
        _archField(t('arch.host.name'), `<input class="arch-input" value="${esc(h.name)}" onchange="_archRenameHost('${h.id}',this.value);_archRender()">`) +
        _archField(t('arch.host.region'), `<input class="arch-input" value="${esc(h.region || '')}" placeholder="eu-west-1" onchange="_archSetHostRegion('${h.id}',this.value)">`) +
        _archCapRow(!!h.internet, t('arch.host.internet'), t('arch.host.internet_hint'), `_archSetHostInternet('${h.id}',this.checked)`))}
      ${_archGroup(t('as.host_elements'), roles || `<div class="arch-cap-desc">${esc(t('as.host_empty'))}</div>`)}
    </div>
    <div class="as-ins-f">
      <button class="btn btn-secondary btn-sm" onclick="asOpenConfig('${h.id}')">${esc(t('as.config'))}</button>
      ${_arch.hosts.length > 1 ? `<button class="btn btn-ghost btn-sm" style="margin-left:auto;color:var(--red)" onclick="_archRemoveHost('${h.id}')">${esc(t('arch.host.remove'))}</button>` : ''}
    </div>
  </div>`;
}

// ── Actions d'exploitation (panneau de détail) ──────────────────────────────

const _asM = { hostId: null, tab: 'f', fmt: 'compose', versions: null, current: null, verName: null, verData: null, ticket: null };

function _asOverlay(html) {
  let ov = document.getElementById('as-overlay');
  if (!ov) {
    ov = document.createElement('div');
    ov.id = 'as-overlay';
    ov.className = 'as-ov';
    ov.onclick = e => { if (e.target === ov) asCloseModal(); };
    document.body.appendChild(ov);
    document.addEventListener('keydown', _asEsc);
  }
  ov.innerHTML = `<div class="as-md" role="dialog" aria-modal="true">${html}</div>`;
}

function _asEsc(e) { if (e.key === 'Escape') asCloseModal(); }

function asCloseModal() {
  const ov = document.getElementById('as-overlay');
  if (ov) ov.remove();
  document.removeEventListener('keydown', _asEsc);
}

function asAct(kind, id) {
  const x = _asAllSvcs(_arch).find(y => y.s.id === id);
  if (!x) return;
  const s = x.s;
  const node = _asLiveNode(s);
  const name = s.name;
  const nn = node ? node.node_name : (s.nodeName || s.name);
  if (kind === 'config') { if (x.h) asOpenConfig(x.h.id); return; }
  asCloseModal();
  switch (kind) {
    case 'traffic': selectEdge(node, 'edge-trafic'); break;
    case 'settings': selectEdge(node, 'edge-general'); break;
    case 'update': nodeAction(nn, 'update'); break;
    case 'rollback': nodeAction(nn, 'rollback'); break;
    case 'rescan': agentRescan(nn); break;
    case 'agent_update': agentUpdate(nn); break;
    case 'containers': agentContainers(nn, name); break;
    case 'events': agentEvents(nn, name); break;
    case 'agent_cfg': agentConfigure(nn, node); break;
    case 'delete': {
      if (node) { deleteActiveNode(s.type === 'agent' ? nn : node.id, name, s.type); break; }
      const dn = (_arch.declaredNodes || []).find(n => n.role === s.type && n.name === (s.nodeName || s.name));
      if (dn) deleteDeclaredNode(dn.id);
      break;
    }
  }
}

// ── Modale Configuration : formats · écarts · versions ──────────────────────

function asOpenConfig(hostId, tab) {
  Object.assign(_asM, { hostId: hostId || null, tab: tab || (hostId ? 'f' : 'v'), fmt: 'compose', verName: null, verData: null, ticket: null });
  asRenderConfig();
}

function _asStable(v) {
  if (Array.isArray(v)) return '[' + v.map(_asStable).join(',') + ']';
  if (v && typeof v === 'object') return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + _asStable(v[k])).join(',') + '}';
  return JSON.stringify(v === undefined ? null : v);
}

function _asCfgOf(n) {
  const c = n && n.config;
  if (!c) return {};
  if (typeof c === 'string') { try { return JSON.parse(c); } catch { return {}; } }
  return c;
}

/** Valeur de config comparée : absente, vide, false ou « none » reviennent au même réglage par défaut. */
function _asCfgVal(v) {
  return v === undefined || v === null || v === false || v === '' || v === 'none' ? null : v;
}

/** Différences entre deux versions du fichier d'architecture. */
function asDiffArch(oldA, newA) {
  const key = n => n.role + ':' + n.name;
  const om = new Map((oldA.nodes || []).map(n => [key(n), n]));
  const nm = new Map((newA.nodes || []).map(n => [key(n), n]));
  const out = [];
  for (const [k, n] of nm) {
    if (!om.has(k)) { out.push({ kind: 'add', text: n.name }); continue; }
    const a = _asCfgOf(om.get(k)), b = _asCfgOf(n);
    const keys = [...new Set([...Object.keys(a), ...Object.keys(b)])]
      .filter(x => x !== 'env_vars' && x !== 'arch_bootstrap' && _asStable(_asCfgVal(a[x])) !== _asStable(_asCfgVal(b[x])));
    if ((om.get(k).region || '') !== (n.region || '')) keys.unshift('region');
    if (keys.length) out.push({ kind: 'mod', text: n.name + ' · ' + keys.join(', ') });
  }
  for (const [k, n] of om) if (!nm.has(k)) out.push({ kind: 'del', text: n.name });
  return out;
}

function _asFormatFlows(host) {
  const flows = (typeof _archNetworkFlows === 'function' ? _archNetworkFlows() : []);
  const mine = flows.filter(f => String(f.from).includes(host.name) || String(f.to).includes(host.name));
  return (mine.length ? mine : flows).map(f => `${f.from} → ${f.to}  [${f.dir}]  ${f.why}`).join('\n') || '—';
}

function _asDriftRows(s, host) {
  const node = _asLiveNode(s);
  const rows = [];
  const decSt = t('as.st.declared');
  rows.push({ p: t('as.drift.status'), d: decSt, l: node ? (node.status || '—') : t('as.drift.not_connected'), bad: !!node && node.status !== 'online' });
  if (node && node.region && host.region && host.region !== node.region) rows.push({ p: t('arch.host.region'), d: host.region || '—', l: node.region || '—', bad: true });
  if (s.type === 'agent' && node) {
    const rts = (node.container_runtimes || []).map(r => String(r).toLowerCase());
    const dec = s.podman ? 'podman' : s.docker ? 'docker' : '—';
    if (rts.length) rows.push({ p: t('as.drift.runtime'), d: dec, l: rts.join(', '), bad: dec !== '—' && !rts.some(r => r.includes(dec)) });
    const pl = node._agent_config && node._agent_config.portainer;
    if (pl && pl.enabled !== undefined) rows.push({ p: 'Portainer', d: s.portainer ? 'on' : 'off', l: pl.enabled ? 'on' : 'off', bad: !!s.portainer !== !!pl.enabled });
  }
  if (s.type === 'edge' && node) {
    const ep = node.endpoint || node.node_endpoint || '';
    if (s.reachable || ep) rows.push({ p: t('arch.opt.reachable'), d: s.reachable || '—', l: ep || '—', bad: !!s.reachable && !!ep && !ep.includes(s.reachable) });
  }
  return rows;
}

const _AS_FMTS = [['compose', 'as.fmt.compose'], ['env', 'as.fmt.env'], ['cli', 'as.fmt.cli'], ['flows', 'as.fmt.flows'], ['declared', 'as.fmt.declared'], ['ticket', 'as.fmt.ticket']];

function _asFormatsHTML(host) {
  const pack = _archBuildPacks().find(p => p.hostId === host.id);
  let text = '';
  if (_asM.fmt === 'compose') text = pack ? pack.composeText : '';
  else if (_asM.fmt === 'env') text = pack ? pack.envText : '';
  else if (_asM.fmt === 'cli') text = pack ? pack.cliText : '';
  else if (_asM.fmt === 'flows') text = _asFormatFlows(host);
  else if (_asM.fmt === 'declared') {
    const names = new Set(host.services.map(s => s.type + ':' + (s.nodeName || s.name)));
    text = JSON.stringify({ nodes: (_arch.declaredNodes || []).filter(n => names.has(n.role + ':' + n.name)) }, null, 2);
  }
  const pills = `<div class="as-pills">${_AS_FMTS.map(([id, k]) => `<button type="button"${_asM.fmt === id ? ' data-on' : ''} onclick="_asM.fmt='${id}';asRenderConfig()">${esc(t(k))}</button>`).join('')}</div>`;
  if (_asM.fmt === 'ticket') {
    const tk = _asM.ticket;
    return pills + (tk
      ? `<div class="arch-field-label">${esc(t('arch.install_label'))}</div><pre class="as-code">${esc(tk.installCmd || '')}</pre>
         <div class="arch-field-label" style="margin-top:10px">${esc(t('arch.bootstrap_label'))}</div><pre class="as-code">${esc(tk.url || '')}</pre>
         ${tk.qr ? `<img src="${esc(tk.qr)}" alt="QR" width="140" height="140" style="background:#fff;padding:8px;margin-top:10px">` : ''}`
      : `<p style="font-size:12.5px;color:var(--text2);margin:0 0 10px">${esc(t('as.ticket.hint'))}</p>
         <button class="btn btn-primary btn-sm" ${pack ? '' : 'disabled'} onclick="asMakeTicket('${host.id}')">${esc(t('as.ticket.generate'))}</button>`);
  }
  if (!text) return pills + `<div class="as-empty">${esc(t(_asM.fmt === 'env' && pack ? 'as.env_inline' : 'as.no_config'))}</div>`;
  return `${pills}<pre class="as-code" id="as-code">${esc(text)}</pre>
    <div class="as-acts"><button class="btn btn-secondary btn-sm" onclick="asCopy()">${esc(t('as.copy'))}</button>
    <button class="btn btn-secondary btn-sm" onclick="asDownload('${host.name.replace(/[^a-z0-9_-]/gi, '_')}-${_asM.fmt}.txt')">${esc(t('as.download'))}</button></div>`;
}

function _asDriftHTML(host) {
  const rows = host.services.filter(s => s.type !== 'admin').flatMap(s => _asDriftRows(s, host).map(r => ({ ...r, p: `${s.name} · ${r.p}` })));
  return `<table class="as-diff"><tr><th>${esc(t('as.drift.col.param'))}</th><th>${esc(t('as.drift.col.declared'))}</th><th>${esc(t('as.drift.col.live'))}</th></tr>
    ${rows.map(r => `<tr${r.bad ? ' data-bad' : ''}><td>${esc(r.p)}</td><td>${esc(r.d)}</td><td>${esc(r.l)}</td></tr>`).join('')}</table>`;
}

function _asVersionsHTML() {
  if (!_asM.versions) return `<p style="color:var(--text2)">${esc(t('common.loading'))}</p>`;
  const rows = _asM.versions.map(v => {
    const on = _asM.verName === v.name;
    return `<div class="as-ver"${on ? ' data-on' : ''}><div><b>${esc(new Date(v.saved_at).toLocaleString())}</b><small>${esc(v.name)}</small></div>
      <div class="as-ver-b"><button class="btn btn-secondary btn-sm" onclick="asViewVersion('${esc(v.name)}')">${esc(t('as.ver.view'))}</button>
      <button class="btn btn-ghost btn-sm" onclick="asRestoreVersion('${esc(v.name)}')">${esc(t('as.ver.restore'))}</button></div></div>`;
  }).join('');
  let detail = '';
  if (_asM.verData && _asM.current) {
    const d = asDiffArch(_asM.verData, _asM.current);
    const sym = { add: '+', del: '−', mod: '~' };
    detail = `<div style="margin-top:12px"><div class="arch-field-label">${esc(t('as.ver.diff_title'))}</div>
      ${d.length ? `<table class="as-diff">${d.map(x => `<tr><td style="width:24px">${sym[x.kind]}</td><td>${esc(x.text)}</td><td style="color:var(--text2)">${esc(t('as.ver.' + x.kind))}</td></tr>`).join('')}</table>` : `<div class="as-empty" style="padding:10px 0">${esc(t('as.ver.same'))}</div>`}
      <details style="margin-top:8px"><summary style="cursor:pointer;font-size:12px;color:var(--text2)">${esc(t('as.ver.content'))}</summary><pre class="as-code" style="margin-top:6px">${esc(JSON.stringify(_asM.verData, null, 2))}</pre></details></div>`;
  }
  return `${rows || `<div class="as-empty">${esc(t('as.ver.none'))}</div>`}${detail}`;
}

function asRenderConfig() {
  const host = _asM.hostId ? _arch.hosts.find(h => h.id === _asM.hostId) : null;
  if (_asM.tab !== 'v' && !host) _asM.tab = 'v';
  const tabs = [host ? ['f', 'as.tab.formats'] : null, host ? ['e', 'as.tab.drift'] : null, ['v', 'as.tab.versions']].filter(Boolean);
  let body = '';
  if (_asM.tab === 'f') body = _asFormatsHTML(host);
  else if (_asM.tab === 'e') body = _asDriftHTML(host);
  else {
    body = _asVersionsHTML();
    if (!_asM.versions) asLoadVersions();
  }
  const drift = host ? host.services.filter(s => s.type !== 'admin').some(s => _asDriftRows(s, host).some(r => r.bad)) : false;
  _asOverlay(`<div class="as-mh"><b>${esc(host ? t('as.cfg.title', { name: host.name }) : t('as.history'))}</b>
      ${host ? `<span class="as-st" data-tone="${drift ? 'warn' : 'ok'}">${esc(drift ? t('as.drift.bad') : t('as.drift.ok'))}</span>` : ''}
      <button class="btn btn-ghost btn-sm" style="margin-left:auto" onclick="asCloseModal()" aria-label="${esc(t('common.close'))}">×</button></div>
    <div class="as-tabs">${tabs.map(([id, k]) => `<button type="button"${_asM.tab === id ? ' data-on' : ''} onclick="_asM.tab='${id}';asRenderConfig()">${esc(t(k))}</button>`).join('')}</div>
    ${body}`);
}

async function asLoadVersions() {
  const [list, cur] = await Promise.all([
    api('GET', '/architecture/versions').catch(() => []),
    api('GET', '/architecture').catch(() => null),
  ]);
  _asM.versions = Array.isArray(list) ? list : [];
  _asM.current = cur;
  if (document.getElementById('as-overlay')) asRenderConfig();
}

async function asViewVersion(name) {
  _asM.verName = name;
  _asM.verData = await api('GET', '/architecture/versions/' + encodeURIComponent(name)).catch(() => null);
  asRenderConfig();
}

function asRestoreVersion(name) {
  confirm_(t('as.ver.confirm'), async () => {
    try {
      await api('POST', '/architecture/restore', { name });
      toast(t('as.ver.restored'), 'success');
      asCloseModal();
      navigate(state.page === 'architecture' ? 'architecture' : 'infrastructure');
      if (state.page === 'architecture') { _arch.loading = true; _archLoad(); }
    } catch (e) {
      toast(t('common.error_msg', { msg: e.message }), 'error');
    }
  });
}

async function asMakeTicket(hostId) {
  const pack = _archBuildPacks().find(p => p.hostId === hostId);
  if (!pack) return;
  await _archCreateTickets([pack]);
  _asM.ticket = { installCmd: pack.installCmd, url: pack.bootstrapUrl, qr: pack.qrCode };
  asRenderConfig();
}

function asCopy() {
  const el = document.getElementById('as-code');
  if (el) navigator.clipboard.writeText(el.textContent).then(() => toast(t('common.copied') || 'Copié', 'success'));
}

function asDownload(filename) {
  const el = document.getElementById('as-code');
  if (!el) return;
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([el.textContent], { type: 'text/plain' }));
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}
