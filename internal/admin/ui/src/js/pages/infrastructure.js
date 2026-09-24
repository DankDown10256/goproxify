// ── PAGE: Infrastructure (topologie, wizard, cartes, drawer) ───────────
// Extrait de pages-all.js — phase 2.
// Dépend de shared/infra-config.js et shared/fmt.js.

// ── PAGE: Topology ─────────────────────────────────────────────────────────
pages.infrastructure = async function() {
  const content = document.getElementById('content');
  content.innerHTML = '<p style="color:var(--text2)">' + t('common.loading') + '</p>';
  try {
    const [nodes, health, declaredAll, infraMetrics] = await Promise.all([
      api('GET','/nodes'),
      api('GET','/health').catch(()=>null),
      api('GET','/declared-nodes').catch(()=>[]),
      api('GET','/internal/v1/metrics/summary').catch(()=>null),
    ]);
    const allNodes   = nodes || [];
    // Build excluded map: nodeName → declared-node entry
    window._excludedDeclaredNodes = new Map();
    for (const dn of (declaredAll || [])) {
      try { if (JSON.parse(dn.config || '{}').excluded) window._excludedDeclaredNodes.set(dn.name, dn); } catch {}
    }
    const pendingNodes = allNodes.filter(n => n.status === 'pending');
    const coreNodes  = allNodes.filter(n => n.role === 'core' && n.status !== 'pending');
    const agentNodes = allNodes.filter(n => n.role === 'agent' && n.status !== 'pending');
    const adminNode  = { node_name: 'Admin', role: 'admin', status: health?.status === 'ok' ? 'online' : 'offline', version: health?.version || '', cpu_pct: null, mem_pct: null, container_runtimes: [] };

    window._coreNodes = coreNodes;
    window.openCore = function(i, page) { selectCore(window._coreNodes[i], page); };
    if (typeof refreshNavCores === 'function') refreshNavCores();
    window._infraNodes = [...allNodes, adminNode];
    window._topoSelection = new Set();
    _closeDetails();


    const pendingSection = pendingNodes.length
      ? `<div style="margin-bottom:8px;font-size:11px;font-weight:600;letter-spacing:.07em;text-transform:uppercase;color:var(--orange,#f97316);opacity:.9;">${t('infra.section.pending_accept', { n: pendingNodes.length })}</div>
         <div class="node-grid" style="margin-bottom:24px;">${pendingNodes.map(n => infraPendingCard(n)).join('')}</div>`
      : '';
    const coresSection = coreNodes.length
      ? `<div style="margin-bottom:8px;font-size:11px;font-weight:600;letter-spacing:.07em;text-transform:uppercase;color:var(--text2);opacity:.7;">${t('infra.section.cores', { n: coreNodes.length })}</div>
         <div class="node-grid" style="margin-bottom:24px;">${coreNodes.map((n,i) => infraCoreCard(n, i)).join('')}</div>`
      : '';
    const agentsSection = agentNodes.length
      ? `<div style="margin-bottom:8px;font-size:11px;font-weight:600;letter-spacing:.07em;text-transform:uppercase;color:var(--text2);opacity:.7;">${t('infra.section.agents', { n: agentNodes.length })}</div>
         <div class="node-grid">${agentNodes.map(n => infraAgentCard(n)).join('')}</div>`
      : '';
    const topoPending = pendingNodes.length ? t('infra.topology_pending_suffix', { n: pendingNodes.length }) : '';

    const wsAdminConns = infraMetrics?.ws?.admin_connections ?? null;
    const wsAgentConns = infraMetrics?.ws?.agent_connections ?? null;
    const peerSyncAvg = infraMetrics?.peers?.avg_sync_ms ?? null;
    const clusterMetricsBand = (wsAdminConns != null || wsAgentConns != null || peerSyncAvg != null) ? `
      <div style="display:flex;gap:20px;flex-wrap:wrap;padding:10px 16px;margin-bottom:16px;background:var(--bg2);border:1px solid var(--border);border-radius:8px;font-size:12px">
        ${wsAdminConns!=null?`<span style="opacity:.7">WS Admin : <b>${wsAdminConns}</b></span>`:''}
        ${wsAgentConns!=null?`<span style="opacity:.7">WS Agent : <b>${wsAgentConns}</b></span>`:''}
        ${peerSyncAvg!=null?`<span style="opacity:.7">Sync pair (moy.) : <b>${Math.round(peerSyncAvg)} ms</b></span>`:''}
      </div>` : '';

    content.innerHTML = `
      ${clusterMetricsBand}
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:8px;">
        <h2 style="font-family:var(--font-heading);font-size:16px;font-weight:600;margin:0;">${t('page.infrastructure')}</h2>
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
          <button type="button" class="btn btn-secondary btn-sm" onclick="openDockerLabelsModal()">${t('infra.labels')}</button>
          <button type="button" class="btn btn-primary btn-sm" onclick="openInfraWizard()">${t('infra.add')}</button>
        </div>
      </div>
      <div class="card blueprint" style="margin-bottom:24px;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <div class="card-header">
          <span class="card-title">${t('infra.topology')}</span>
          <span style="font-size:11px;color:var(--text2)">${t('infra.topology_meta', { cores: coreNodes.length, agents: agentNodes.length, pending: topoPending })}</span>
          <span id="topo-live-meta" style="font-size:11px;color:var(--text2)"></span>
        </div>
        <div id="topology-container" style="overflow-x:auto;padding:8px 0"></div>
        <div id="topo-details" class="topo-details" style="display:none;"></div>
      </div>
      <div style="margin-bottom:8px;font-size:11px;font-weight:600;letter-spacing:.07em;text-transform:uppercase;color:var(--text2);opacity:.7;">${t('nav.section.Administration')}</div>
      <div style="margin-bottom:24px;">${infraAdminCard(adminNode, health)}</div>
      ${pendingSection}
      ${coresSection}
      ${agentsSection}
    `;
    renderTopology(allNodes.filter(n => n.status !== 'pending'), health);
    startTopologyLive(content);

    // Événements scaling & santé
    const events = await api('GET','/node-events?limit=30').catch(() => []);
    const scaleEvents = (events||[]).filter(e => e.event_type.startsWith('scale_') || e.event_type === 'health_escalation');
    if (scaleEvents.length) {
      const evDiv = document.createElement('div');
      evDiv.style.cssText = 'margin-top:24px';
      evDiv.innerHTML = `
        <div class="card blueprint">
          <div class="card-header"><span class="card-title">${t('infra.scale_events')}</span></div>
          <div class="table-wrap"><table>
            <thead><tr><th>${t('infra.col.node')}</th><th>${t('trafic.type')}</th><th>${t('infra.col.container')}</th><th>${t('infra.col.detail')}</th><th>${t('common.date')}</th></tr></thead>
            <tbody>${scaleEvents.map(e => `<tr>
              <td style="font-weight:600">${esc(e.node_name)}</td>
              <td><span class="tag ${e.event_type.startsWith('scale_up')?'tag-green':e.event_type.startsWith('scale_down')?'tag-yellow':'tag-red'}">${esc(e.event_type)}</span></td>
              <td class="mono" style="font-size:11px">${esc(e.container_id||'—')}</td>
              <td style="font-size:12px;color:var(--text2)">${esc(e.detail||'—')}</td>
              <td style="font-size:11px">${fmtDate(e.created_at)}</td>
            </tr>`).join('')}</tbody>
          </table></div>
        </div>`;
      content.appendChild(evDiv);
    }
  } catch(e) { content.innerHTML = `<p style="color:var(--red)">${esc(e.message)}</p>`; }
};

// ── WIZARD : Ajout d'un nœud Infrastructure ───────────────────────────────

function _genSecret() {
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2,'0')).join('');
}

const _wiz = {
  coreList: [],
  declaredNodes: [],
  pairingSecret: '',
};

/** Endpoint Admin→Core à partir d'un hôte saisi (évite :8000 en double). */
function _wizCoreEndpoint(host) {
  const h = (host || '').trim();
  if (!h) return '';
  if (h.includes('://')) return h;
  if (h.includes(':')) return 'http://' + h;
  return 'http://' + h + ':8000';
}

/** Fusionne nœuds Core et tokens pour listes Agent / cluster Raft. */
function _wizLoadCoreList(nodes, tokens) {
  const byName = new Map();
  for (const n of (nodes || []).filter(x => x.role === 'core')) {
    const key = (n.node_name || n.display_name || n.id || '').trim();
    if (!key) continue;
    byName.set(key, { ...n, node_name: n.node_name || key });
  }
  for (const t of (tokens || []).filter(x => x.role === 'core' && !x.revoked && x.node_endpoint)) {
    const key = (t.node_name || '').trim();
    if (!key) continue;
    const existing = byName.get(key) || { node_name: key, display_name: key, role: 'core', status: 'online' };
    existing.node_endpoint = t.node_endpoint;
    byName.set(key, existing);
  }
  return [...byName.values()];
}

/** Options Core pour stack unifié (déclaré ou valeurs par défaut du nœud). */
function _wizCoreOptsFromExisting(core) {
  if (!core) return null;
  const name = (core.node_name || core.display_name || 'goproxify-core').trim();
  const declared = (_wiz.declaredNodes || []).find(n => n.role === 'core' && n.name === name);
  let cfg = {};
  if (declared) {
    try {
      cfg = typeof declared.config === 'string' ? JSON.parse(declared.config) : (declared.config || {});
    } catch (_) { cfg = {}; }
  }
  if (cfg.env_vars && cfg.image) {
    const ports = ['80:80', '443:443'];
    if (cfg.http3) ports.push('443:443/udp');
    ports.push('8000:8000');
    if (cfg.cluster) ports.push('8002:8002');
    return {
      name,
      svcName: name,
      image: cfg.image,
      envVars: cfg.env_vars,
      ports,
      volumes: [`${name}_data:/etc/goproxify`],
      netBlock: `\nnetworks:\n  goproxify-net:\n    driver: bridge`,
      restart: cfg.restart || 'unless-stopped',
    };
  }
  return _buildCoreOpts({
    wc_name: name,
    wc_restart: cfg.restart || 'unless-stopped',
    wc_log: cfg.log_level || 'info',
    wc_cluster: !!cfg.cluster,
    wc_raft_leader: cfg.raft_leader || '',
    wc_http3: !!cfg.http3,
  });
}


/** Entrée unique : page Composer la topologie. */
function openInfraWizard() {
  if (typeof openArchWizard === 'function') {
    openArchWizard();
    return;
  }
  toast(t('common.error') || 'Error', 'error');
}


function infraPendingCard(n) {
  const name = n.display_name || n.node_name || n.id;
  const role = n.role === 'core' ? 'Core' : (n.role === 'agent' ? 'Agent' : n.role);
  return `<div class="card blueprint" style="padding:18px 20px;display:flex;flex-direction:column;gap:0;border-color:color-mix(in srgb,var(--orange,#f97316) 40%,var(--border));">
    <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
    <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px;margin-bottom:8px;">
      <div style="min-width:0;">
        <div class="card-kicker">${esc(role)} · ${t('infra.pending_kicker')}</div>
        <div style="font-weight:700;font-size:15px;margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${esc(name)}</div>
        <div style="font-size:10.5px;opacity:.45;margin-top:2px;font-family:monospace;">${esc(n.endpoint||n.remote_addr||'—')}</div>
      </div>
      <span class="tag" style="background:color-mix(in srgb,var(--orange,#f97316) 16%,transparent);color:var(--orange,#f97316);">○ ${t('infra.pending')}</span>
    </div>
    <div style="display:flex;gap:8px;margin-top:14px;">
      <button class="btn btn-ghost btn-sm" style="flex:1;justify-content:center;border:1px solid var(--border);font-size:11px;color:var(--red);" onclick="rejectNode('${esc(n.id)}')">${t('infra.reject')}</button>
      <button class="btn btn-primary btn-sm" style="flex:1;justify-content:center;" onclick="acceptNode('${esc(n.id)}')">${t('infra.accept')}</button>
    </div>
  </div>`;
}

function infraAdminCard(node, health) {
  const online = node.status === 'online';
  return `<div class="card blueprint" style="padding:18px 20px;display:flex;align-items:center;gap:20px;flex-wrap:wrap;">
    <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
    <div style="flex:1;min-width:200px;">
      <div class="card-kicker">${t('infra.control_plane')}</div>
      <div style="font-weight:700;font-size:15px;margin-top:2px;">Admin</div>
      <div style="font-size:10.5px;opacity:.45;margin-top:2px;font-family:monospace;">localhost · SQLite</div>
    </div>
    <div style="display:flex;flex-direction:column;gap:4px;min-width:120px;">
      ${statusBadge(online)}
      <span style="font-size:11px;color:var(--text2);font-family:monospace;">v${esc(node.version || '—')}</span>
    </div>
    <div style="flex:none;display:flex;gap:8px;flex-wrap:wrap;">
      <button class="btn btn-secondary btn-sm" onclick="navigate('settings')">${t('page.settings')}</button>
      <button class="btn btn-secondary btn-sm" onclick="navigate('users')">${t('page.users')}</button>
    </div>
  </div>`;
}

function infraCoreCard(n, idx) {
  const declared = n.status === 'declared';
  const online = n.status === 'online';
  const cpu  = n.cpu_pct  ?? 0;
  const mem  = n.mem_pct  ?? 0;
  const name = n.display_name || n.node_name;
  const meterCol = v => v > 80 ? 'var(--red)' : v > 60 ? 'var(--yellow)' : 'var(--green)';
  const meterBar = (label, val) => `<div style="margin-top:6px;">
    <div style="display:flex;justify-content:space-between;font-size:11px;color:var(--text2);margin-bottom:3px;"><span>${label}</span><span>${val.toFixed(0)}%</span></div>
    <div style="height:4px;background:var(--bg3);"><div style="height:100%;width:${Math.min(val,100)}%;background:${meterCol(val)};transition:width .3s;"></div></div>
  </div>`;
  const rts = (n.container_runtimes || []);
  const kicker = [t('infra.data_plane'), n.region, n.environment].filter(Boolean).join(' · ');
  const cardStyle = declared ? 'padding:18px 20px;display:flex;flex-direction:column;gap:0;opacity:.55;filter:grayscale(.5);' : 'padding:18px 20px;display:flex;flex-direction:column;gap:0;';
  const iconConfig = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>`;
  const iconTrash  = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/></svg>`;
  const actions = declared
    ? `<div style="display:flex;gap:6px;margin-top:14px;align-items:center;">
        <button class="btn-icon" title="${t('infra.view_config')}" onclick="showDeclaredNodeConfig('${n.id}')">${iconConfig}</button>
        <button class="btn-icon" title="${t('common.delete')}" style="color:var(--red);margin-left:auto;" onclick="deleteDeclaredNode('${n.id}')">${iconTrash}</button>
      </div>`
    : `<div style="display:flex;gap:6px;margin-top:14px;align-items:center;">
        <button class="btn-icon" title="${t('infra.title.traffic')}" onclick="openCore(${idx},'core-trafic')">
          <svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
        </button>
        <button class="btn-icon" title="${t('infra.title.general_settings')}" onclick="openCore(${idx},'core-general')">
          <svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/></svg>
        </button>
        <button class="btn-icon" title="${t('infra.title.update')}" onclick="nodeAction('${esc(n.node_name)}','update')">
          <svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="16 16 12 12 8 16"/><line x1="12" y1="12" x2="12" y2="21"/><path d="M20.39 18.39A5 5 0 0018 9h-1.26A8 8 0 103 16.3"/></svg>
        </button>
        <button class="btn-icon" title="${t('infra.title.rollback')}" onclick="nodeAction('${esc(n.node_name)}','rollback')">
          <svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 102.13-9.36L1 10"/></svg>
        </button>
        ${_infraPendingDeploy(name) ? `<button class="btn-icon" title="${t('infra.mark_deployed')}" onclick="archMarkDeployed('${esc(name)}')">
          <svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></svg>
        </button>` : ''}
        <button class="btn-icon" title="${t('infra.title.delete_node')}" style="color:var(--red);margin-left:auto;" onclick="deleteActiveNode('${esc(n.id)}','${esc(name)}','core')">
          <svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4h6v2"/></svg>
        </button>
      </div>`;
  return `<div class="card blueprint" style="${cardStyle}">
    <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
    <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px;margin-bottom:8px;">
      <div style="min-width:0;">
        <div class="card-kicker">${esc(kicker)}</div>
        <div style="font-weight:700;font-size:15px;margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${esc(name)}</div>
        <div style="font-size:10.5px;opacity:.45;margin-top:2px;font-family:monospace;">${declared ? t('infra.waiting_connection') : esc(n.endpoint||n.node_endpoint||'—')}</div>
        ${rts.length ? `<div style="margin-top:6px;display:flex;gap:4px;flex-wrap:wrap;">${rts.map(rt=>`<span class="tag tag-neutral" style="font-size:10px;">${esc(rt)}</span>`).join('')}</div>` : ''}
      </div>
      <div style="flex:none;display:flex;flex-direction:column;align-items:flex-end;gap:4px;">
        ${statusBadge(online, declared)}
        ${_infraPendingDeploy(name) ? `<span class="tag" style="font-size:10px;background:rgba(249,115,22,.15);color:var(--orange,#f97316);border:1px solid rgba(249,115,22,.35);padding:2px 6px;border-radius:4px;">${t('infra.redeploy_required')}</span>` : ''}
        <span style="font-size:10px;opacity:.45;font-family:monospace;">v${esc(n.version || '—')}</span>
      </div>
    </div>
    ${!declared ? meterBar('CPU', cpu) + meterBar('RAM', mem) : ''}
    ${actions}
  </div>`;
}

function infraAgentCard(n) {
  const declared = n.status === 'declared';
  const online = n.status === 'online';
  const name = n.display_name || n.node_name;
  const nodeName = n.node_name;
  const rts = (n.container_runtimes || []);
  const kicker = ['Agent', n.region, n.environment].filter(Boolean).join(' · ');
  const dnExcluded = window._excludedDeclaredNodes?.get(nodeName);
  const excluded = !!dnExcluded;
  const dnId = dnExcluded ? dnExcluded.id : '';
  const cardStyle = declared
    ? 'padding:18px 20px;display:flex;flex-direction:column;gap:0;opacity:.55;filter:grayscale(.5);'
    : excluded
      ? 'padding:18px 20px;display:flex;flex-direction:column;gap:0;border-color:rgba(239,68,68,.4);'
      : 'padding:18px 20px;display:flex;flex-direction:column;gap:0;';

  // Icônes SVG inline
  const iconRescan  = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>`;
  const iconUpdate  = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 16 12 12 8 16"/><line x1="12" y1="12" x2="12" y2="21"/><path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3"/></svg>`;
  const iconContainers = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>`;
  const iconEvents  = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>`;
  const iconCfg2    = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/></svg>`;
  const iconTrash   = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/></svg>`;
  const iconConfig  = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>`;

  const activeActions = `<div style="display:flex;gap:6px;margin-top:14px;align-items:center;">
    <button class="btn-icon" title="${t('infra.title.rescan')}" onclick="agentRescan('${esc(nodeName)}')">
      ${iconRescan}
    </button>
    <button class="btn-icon" title="${t('infra.title.update_agent')}" onclick="agentUpdate('${esc(nodeName)}')">
      ${iconUpdate}
    </button>
    <button class="btn-icon" title="${t('infra.title.discovered_containers')}" onclick="agentContainers('${esc(nodeName)}','${esc(name)}')">
      ${iconContainers}
    </button>
    <button class="btn-icon" title="${t('infra.title.events')}" onclick="agentEvents('${esc(nodeName)}','${esc(name)}')">
      ${iconEvents}
    </button>
    <button class="btn-icon" title="${t('infra.configure')}" onclick="agentConfigure('${esc(nodeName)}',${JSON.stringify(n).replace(/</g,'\\u003c').replace(/>/g,'\\u003e').replace(/"/g,'&quot;')})">
      ${iconCfg2}
    </button>
    ${_infraPendingDeploy(name) ? `<button class="btn-icon" title="${t('infra.mark_deployed')}" onclick="archMarkDeployed('${esc(name)}')">
      <svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></svg>
    </button>` : ''}
    ${excluded
      ? `<button class="btn-icon" title="${t('infra.excluded.confirm_btn')}" style="color:var(--red);margin-left:auto;" onclick="confirmAgentRemoval('${esc(dnId)}','${esc(nodeName)}','${esc(name)}')">
           <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
         </button>`
      : `<button class="btn-icon" title="${t('infra.title.delete_node')}" style="color:var(--red);margin-left:auto;" onclick="deleteActiveNode('${esc(nodeName || n.id)}','${esc(name)}','agent')">
           ${iconTrash}
         </button>`}
  </div>`;

  return `<div class="card blueprint" style="${cardStyle}">
    <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
    <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px;margin-bottom:8px;">
      <div style="min-width:0;">
        <div class="card-kicker">${esc(kicker)}</div>
        <div style="font-weight:700;font-size:15px;margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${esc(name)}</div>
        ${declared ? `<div style="font-size:10.5px;opacity:.45;margin-top:2px;font-family:monospace;">${t('infra.waiting_connection')}</div>` : ''}
        ${rts.length ? `<div style="margin-top:6px;display:flex;gap:4px;flex-wrap:wrap;">${rts.map(rt=>`<span class="tag tag-neutral" style="font-size:10px;">${esc(rt)}</span>`).join('')}</div>` : ''}
      </div>
      <div style="flex:none;display:flex;flex-direction:column;align-items:flex-end;gap:4px;">
        ${statusBadge(online, declared)}
        ${excluded ? `<span class="tag" style="font-size:10px;background:rgba(239,68,68,.15);color:var(--red,#ef4444);border:1px solid rgba(239,68,68,.35);padding:2px 6px;border-radius:4px;">${t('infra.excluded_badge')}</span>` : ''}
        ${_infraPendingDeploy(name) ? `<span class="tag" style="font-size:10px;background:rgba(249,115,22,.15);color:var(--orange,#f97316);border:1px solid rgba(249,115,22,.35);padding:2px 6px;border-radius:4px;">${t('infra.redeploy_required')}</span>` : ''}
        <span style="font-size:10px;opacity:.45;font-family:monospace;">v${esc(n.version || '—')}</span>
      </div>
    </div>
    ${!declared ? `<div style="font-size:11px;color:var(--text2);margin-top:4px;">${t('infra.discovery_telemetry')}</div>` : ''}
    ${declared ? `<div style="display:flex;gap:6px;margin-top:14px;align-items:center;">
      <button class="btn-icon" title="${t('infra.view_config')}" onclick="showDeclaredNodeConfig('${n.id}')">${iconConfig}</button>
      <button class="btn-icon" title="${t('common.delete')}" style="color:var(--red);margin-left:auto;" onclick="deleteDeclaredNode('${n.id}')">${iconTrash}</button>
    </div>` : activeActions}
  </div>`;
}


async function deleteActiveNode(id, name, role) {
  const doDelete = async () => {
    try {
      if (role === 'agent') {
        await api('POST', '/agents/' + encodeURIComponent(id) + '/revoke');
        await api('POST', '/declared-nodes', {role: 'agent', name: id, config: {excluded: true}}).catch(() => {});
        toast(t('infra.toast.agent_excluded'), 'success');
        _showAgentStopSnippet(id, name);
      } else {
        await api('DELETE', '/nodes/' + encodeURIComponent(id));
        toast(t('infra.toast.node_deleted'), 'success');
        navigate('infrastructure');
      }
    } catch (e) {
      toast(t('common.error_msg', { msg: e.message }), 'error');
    }
  };

  if (role === 'agent') {
    _confirmCb = doDelete;
    modal(
      t('infra.revoke_agent.title', { name: esc(name) }),
      `<div style="font-size:13.5px;line-height:1.5;color:var(--text1);">
        <p style="margin:0 0 12px;">${t('infra.revoke_agent.lead')}</p>
        <ol style="margin:0;padding-left:1.25rem;color:var(--text2);font-size:13px;line-height:1.55;">
          <li style="margin-bottom:6px;">${t('infra.revoke_agent.step_revoke')}</li>
          <li style="margin-bottom:6px;">${t('infra.revoke_agent.step_docker')}</li>
          <li>${t('infra.revoke_agent.step_colo')}</li>
        </ol>
        <p style="margin:14px 0 0;font-size:12px;color:var(--text2);">${t('infra.revoke_agent.hint')}</p>
      </div>`,
      `<button class="btn btn-secondary" onclick="closeModal()">${t('common.cancel')}</button>
       <button class="btn btn-danger" onclick="closeModal();if(_confirmCb){const f=_confirmCb;_confirmCb=null;f();}">${t('infra.revoke_agent.confirm')}</button>`
    );
    return;
  }

  confirm_(t('infra.confirm.delete_node', { name }), doDelete);
}

function _showAgentStopSnippet(nodeName, displayName) {
  const svcName = nodeName.toLowerCase().replace(/[^a-z0-9_-]/g, '-');
  const snippet = `# Stop and remove the agent container\ndocker compose stop ${svcName}\ndocker compose rm -f ${svcName}\n\n# Or with plain docker:\ndocker stop ${svcName} && docker rm ${svcName}`;
  modal(
    t('infra.excluded.compose_title'),
    `<p style="margin:0 0 10px;font-size:13.5px;">${t('infra.excluded.compose_hint')}</p>
     <pre style="background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:12px;font-size:12px;font-family:monospace;overflow-x:auto;white-space:pre;">${esc(snippet)}</pre>
     <p style="margin:10px 0 0;font-size:12px;color:var(--text2);">${t('infra.excluded.lead')}</p>`,
    `<button class="btn btn-secondary" onclick="closeModal();navigate('infrastructure')">${t('common.close')}</button>`
  );
}

async function confirmAgentRemoval(dnId, nodeName, displayName) {
  const doRemove = async () => {
    try {
      if (dnId) await api('DELETE', '/declared-nodes/' + encodeURIComponent(dnId));
      try { await api('DELETE', '/nodes/' + encodeURIComponent(nodeName)); } catch (_) {}
      toast(t('infra.toast.agent_removal_confirmed'), 'success');
      navigate('infrastructure');
    } catch (e) {
      toast(t('common.error_msg', { msg: e.message }), 'error');
    }
  };
  confirm_(t('infra.confirm.delete_node', { name: displayName }), doRemove);
}


/** Génère les opts Agent (envVars, volumes, image) depuis un formulaire "Ajouter un agent". */
function _buildAddAgentOpts({ name, coreURL, docker, dockerSock, portainer, portainerURL, portainerKey, pairingSecret }) {
  const cat = window._gpxCatalog;
  const image = cat ? cat.image('agent') : 'ghcr.io/vincamok/goproxify/agent:preview';
  const netBlock = cat ? cat.netBlock() : '\nnetworks:\n  goproxify_net:\n    driver: bridge';
  const sockPath = dockerSock || '/var/run/docker.sock';
  const envVars = [
    { k: 'GPX_IDENTITY_AGENT_NODE_NAME',    v: name },
    { k: 'GPX_CONTROL_PLANE_CORE_ENDPOINT', v: coreURL },
    { k: 'GPX_PAIRING_SECRET',              v: pairingSecret || '' },
    docker ? { k: 'GPX_DOCKER_ENABLED',  v: 'true' } : { k: 'GPX_DOCKER_ENABLED', v: 'false' },
    docker ? { k: 'GPX_DOCKER_RUNTIME',  v: 'auto' } : null,
    portainer                 ? { k: 'GPX_PORTAINER_ENABLED',  v: 'true' }         : null,
    portainer && portainerURL ? { k: 'GPX_PORTAINER_URL',      v: portainerURL }    : null,
    portainer && portainerKey ? { k: 'GPX_PORTAINER_API_KEY',  v: portainerKey }    : null,
  ].filter(Boolean);
  const volumes = [];
  if (docker) volumes.push(`${sockPath}:${sockPath}:ro`);
  volumes.push(`${name}_data:/etc/goproxify`);
  return { name, svcName: name, image, envVars, ports: [], volumes, netBlock, restart: 'unless-stopped', command: 'agent' };
}

window.openAddAgentModal = async function() {
  const cores = (window._coreNodes || []).filter(n => n.status === 'online');
  let pairingSecret = _wiz.pairingSecret;
  if (!pairingSecret) {
    const sec = await api('GET', '/pairing-secret').catch(() => null);
    pairingSecret = sec?.secret || '';
    _wiz.pairingSecret = pairingSecret;
  }

  const coreOptions = cores.length
    ? cores.map(c => `<option value="${esc(c.node_name||c.id)}">${esc(c.display_name||c.node_name||c.id)}</option>`).join('')
    : `<option value="">${t('common.none')}</option>`;

  const formHTML = `
    <div style="display:flex;flex-direction:column;gap:12px;">
      <label style="display:flex;flex-direction:column;gap:4px;font-size:12px;color:var(--text2);">${t('infra.add_agent.name')}
        <input id="aa-name" type="text" value="goproxify-agent-1" placeholder="goproxify-agent-1"
          style="background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:6px 10px;font-size:13px;color:var(--text1);">
      </label>
      <label style="display:flex;flex-direction:column;gap:4px;font-size:12px;color:var(--text2);">${t('infra.add_agent.core')}
        <select id="aa-core-select" onchange="document.getElementById('aa-core-url').value=this.value?'':'http://goproxify-core:8000'"
          style="background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:6px 10px;font-size:13px;color:var(--text1);">
          ${coreOptions}
          <option value="__custom__">${t('infra.add_agent.core_url')}</option>
        </select>
        <input id="aa-core-url" type="text" placeholder="http://goproxify-core:8000"
          value="${cores.length ? 'http://' + esc(cores[0].node_name||cores[0].id) + ':8000' : 'http://goproxify-core:8000'}"
          style="background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:6px 10px;font-size:13px;color:var(--text1);margin-top:4px;">
      </label>
      <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--text2);margin-top:4px;">${t('infra.add_agent.docker')}</div>
      <label style="display:flex;align-items:center;gap:8px;font-size:13px;cursor:pointer;">
        <input type="checkbox" id="aa-docker" checked style="accent-color:var(--accent);width:16px;height:16px;">
        ${t('infra.configure.enabled')}
      </label>
      <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--text2);margin-top:4px;">${t('infra.add_agent.portainer')}</div>
      <label style="display:flex;align-items:center;gap:8px;font-size:13px;cursor:pointer;">
        <input type="checkbox" id="aa-portainer" style="accent-color:var(--accent);width:16px;height:16px;">
        ${t('infra.configure.enabled')}
      </label>
      <label style="display:flex;flex-direction:column;gap:4px;font-size:12px;color:var(--text2);">${t('infra.add_agent.portainer_url')}
        <input id="aa-portainer-url" type="url" value="" placeholder="https://portainer:9443"
          style="background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:6px 10px;font-size:13px;color:var(--text1);">
      </label>
      <label style="display:flex;flex-direction:column;gap:4px;font-size:12px;color:var(--text2);">${t('infra.add_agent.portainer_key')}
        <input id="aa-portainer-key" type="password" value="" placeholder="ptr_..."
          style="background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:6px 10px;font-size:13px;color:var(--text1);">
      </label>
    </div>`;

  const footer = `
    <button class="btn btn-secondary" onclick="closeModal()">${t('common.cancel')}</button>
    <button class="btn btn-primary" id="aa-generate-btn" onclick="_submitAddAgent('${esc(pairingSecret)}')">${t('infra.add_agent.step1')}</button>`;

  modal(t('infra.add_agent.title'), formHTML, footer);
};

window._submitAddAgent = async function(pairingSecret) {
  const name   = (document.getElementById('aa-name')?.value || '').trim();
  const coreSelectVal = document.getElementById('aa-core-select')?.value;
  let coreURL = (document.getElementById('aa-core-url')?.value || '').trim();
  if (coreSelectVal && coreSelectVal !== '__custom__') {
    coreURL = `http://${coreSelectVal}:8000`;
  }
  const docker       = document.getElementById('aa-docker')?.checked ?? true;
  const portainer    = document.getElementById('aa-portainer')?.checked ?? false;
  const portainerURL = document.getElementById('aa-portainer-url')?.value || '';
  const portainerKey = document.getElementById('aa-portainer-key')?.value || '';

  if (!name) { toast(t('infra.add_agent.name') + ' requis', 'error'); return; }
  if (!coreURL) { toast(t('infra.add_agent.core_url') + ' requis', 'error'); return; }

  const btn = document.getElementById('aa-generate-btn');
  if (btn) { btn.disabled = true; btn.textContent = t('infra.add_agent.generating'); }

  // 1. Créer le declared_node avec auto_accept
  const agentConfig = {
    docker: { enabled: docker, runtime: docker ? 'auto' : '' },
    portainer: { enabled: portainer, url: portainerURL, api_key: portainerKey },
    core_endpoint: coreURL,
    auto_accept: true,
  };
  try {
    await api('POST', '/declared-nodes', {
      role: 'agent',
      name,
      config: agentConfig,
    });
  } catch(e) {
    if (btn) { btn.disabled = false; btn.textContent = t('infra.add_agent.step1'); }
    toast(t('common.error_msg', { msg: e.message }), 'error');
    return;
  }

  // 2. Générer le snippet docker-compose
  const opts = _buildAddAgentOpts({ name, coreURL, docker, portainer, portainerURL, portainerKey, pairingSecret });
  const composeText = _cfgComposeText(opts, 'inline');
  const envText = opts.envVars.map(({ k, v }) => `${k}=${v}`).join('\n');

  const snippetHTML = `
    <div style="display:flex;flex-direction:column;gap:14px;">
      <p style="margin:0;font-size:13px;color:var(--text2);">${t('infra.add_agent.step2_body')}</p>
      <div>
        <div style="font-size:11px;font-weight:600;letter-spacing:.05em;text-transform:uppercase;color:var(--text2);margin-bottom:6px;">docker-compose.yml</div>
        <div style="position:relative;">
          <button class="btn btn-ghost btn-sm" style="position:absolute;top:6px;right:6px;font-size:11px;z-index:1;"
            onclick="navigator.clipboard.writeText(document.getElementById('aa-compose-pre').textContent).then(()=>toast('Copié','success'))">${t('infra.add_agent.copy_compose')}</button>
          <pre id="aa-compose-pre" style="background:var(--bg2);border-radius:6px;padding:12px 80px 12px 14px;font-size:11px;overflow-x:auto;white-space:pre;color:var(--text1);margin:0;max-height:220px;overflow-y:auto;">${esc(composeText)}</pre>
        </div>
      </div>
      <div>
        <div style="font-size:11px;font-weight:600;letter-spacing:.05em;text-transform:uppercase;color:var(--text2);margin-bottom:6px;">.env</div>
        <div style="position:relative;">
          <button class="btn btn-ghost btn-sm" style="position:absolute;top:6px;right:6px;font-size:11px;z-index:1;"
            onclick="navigator.clipboard.writeText(document.getElementById('aa-env-pre').textContent).then(()=>toast('Copié','success'))">${t('infra.add_agent.copy_env')}</button>
          <pre id="aa-env-pre" style="background:var(--bg2);border-radius:6px;padding:12px 80px 12px 14px;font-size:11px;overflow-x:auto;white-space:pre;color:var(--text1);margin:0;max-height:180px;overflow-y:auto;">${esc(envText)}</pre>
        </div>
      </div>
    </div>`;

  // Remplace le contenu du modal
  const modalBody = document.querySelector('.modal-body');
  const modalFooter = document.querySelector('.modal-footer');
  if (modalBody) modalBody.innerHTML = snippetHTML;
  if (modalFooter) modalFooter.innerHTML = `<button class="btn btn-primary" onclick="closeModal();infraPage()">${t('common.close')}</button>`;
};

async function agentRescan(nodeName) {
  try {
    await api('POST', `/nodes/${encodeURIComponent(nodeName)}/rescan`);
    toast(t('infra.toast.rescan_started'), 'success');
  } catch(e) { toast(t('infra.toast.rescan_failed', { msg: e.message }), 'error'); }
}

function _epCoreRowHTML(epName, coreEndpoint, authToken) {
  const s = 'font-size:11px;padding:4px 6px;border:1px solid var(--border);border-radius:4px;background:var(--bg);color:var(--text1);width:100%;';
  const cores = (window._coreNodes || []).filter(n => n.status !== 'pending');

  const coreURL = c => { const ep = c.endpoint || c.node_endpoint || ''; return ep.startsWith('http') ? ep : 'http://' + ep; };
  const knownMatch = cores.find(c => coreURL(c) === coreEndpoint);
  const isOther = coreEndpoint && !knownMatch;

  const options = [
    `<option value=""${!coreEndpoint ? ' selected' : ''}>${t('infra.configure.ep_core_select_placeholder')}</option>`,
    ...cores.map(c => `<option value="${esc(coreURL(c))}"${c === knownMatch ? ' selected' : ''}>${esc(c.node_name || c.display_name)} — ${esc(coreURL(c))}</option>`),
    `<option value="__other__"${isOther ? ' selected' : ''}>${t('infra.configure.ep_core_other')}</option>`,
  ].join('');

  return `<div style="display:grid;grid-template-columns:1fr 1fr 1fr auto;gap:4px;align-items:start;" class="ep-core-row">
    <input type="text" placeholder="${t('infra.configure.ep_core_name')}" value="${esc(epName)}" style="${s}">
    <div>
      <select class="ep-core-select" onchange="_epCoreSelectChange(this)" style="${s}cursor:pointer;">${options}</select>
      <input type="url" class="ep-core-manual" placeholder="http://core:8000" value="${esc(isOther ? coreEndpoint : '')}"
        style="${s}margin-top:3px;display:${isOther ? 'block' : 'none'};">
    </div>
    <input type="password" placeholder="${t('infra.configure.ep_core_token')}" value="${esc(authToken)}" style="${s}">
    <button type="button" style="padding:4px 8px;font-size:11px;background:var(--red,#e53e3e);color:#fff;border:none;border-radius:4px;cursor:pointer;margin-top:2px;"
      onclick="this.closest('.ep-core-row').remove()">✕</button>
  </div>`;
}

window._epCoreSelectChange = function(sel) {
  const manual = sel.closest('.ep-core-row').querySelector('.ep-core-manual');
  manual.style.display = sel.value === '__other__' ? 'block' : 'none';
};

function _renderEpCoreRows(epCores) {
  return Object.entries(epCores).map(([name, conf]) =>
    _epCoreRowHTML(name, conf.core_endpoint || '', conf.auth_token || '')
  ).join('');
}

window._addEpCoreRow = function() {
  const list = document.getElementById('cfg-ep-cores-list');
  if (!list) return;
  const div = document.createElement('div');
  div.innerHTML = _epCoreRowHTML('', '', '');
  list.appendChild(div.firstElementChild);
};

async function agentConfigure(nodeName, node) {
  const name = (node && (node.display_name || node.node_name)) || nodeName;
  const formId = 'agent-cfg-form-' + nodeName.replace(/[^a-z0-9]/gi,'_');

  const sectionTitle = (label) =>
    `<div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--text2);margin:16px 0 8px;">${label}</div>`;

  const toggle = (id, label, checked) =>
    `<label style="display:flex;align-items:center;gap:8px;font-size:13px;cursor:pointer;">
       <input type="checkbox" id="${id}" ${checked?'checked':''} style="accent-color:var(--accent);width:16px;height:16px;">
       ${label}
     </label>`;

  const field = (id, label, value, type='text', placeholder='') =>
    `<label style="display:flex;flex-direction:column;gap:4px;font-size:12px;color:var(--text2);">${label}
       <input id="${id}" type="${type}" value="${esc(value||'')}" placeholder="${esc(placeholder)}"
         style="background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:6px 10px;font-size:13px;color:var(--text1);font-family:inherit;">
     </label>`;

  // Chercher la declared config (wizard) pour pré-remplir les champs si l'agent est live.
  // Le declared config stocke des champs plats (portainer_url, portainer_key) contrairement
  // à _agent_config qui utilise un objet imbriqué {portainer: {url, api_key, enabled}}.
  let declaredCfg = (node && node._declared_config) || null;
  if (!declaredCfg) {
    const declaredNodes = await api('GET', '/declared-nodes').catch(() => []);
    const dn = (Array.isArray(declaredNodes) ? declaredNodes : [])
      .find(n => n.role === 'agent' && n.name === nodeName);
    declaredCfg = (dn && dn.config) || null;
  }
  const fallback = declaredCfg || {};
  const d = (node && node._agent_config && node._agent_config.docker) || {};
  // Merge live portainer config with wizard-declared fallback field by field,
  // so the modal pre-fills even when the agent hasn't yet pushed its own config.
  const pLive = (node && node._agent_config && node._agent_config.portainer) || {};
  const p = {
    enabled: pLive.enabled !== undefined ? pLive.enabled : !!fallback.portainer,
    url: pLive.url || fallback.portainer_url || '',
    api_key: pLive.api_key || fallback.portainer_key || '',
    poll_interval_s: pLive.poll_interval_s,
    skip_endpoints: pLive.skip_endpoints,
    endpoint_cores: pLive.endpoint_cores,
  };
  const cp = (node && node._agent_config && node._agent_config.control_plane) || {};

  // Sélecteur "Core cible" — liste des Cores connus
  const coreURL = c => { const ep = c.endpoint || c.node_endpoint || ''; return ep.startsWith('http') ? ep : 'http://' + ep; };
  const coreNodes = (window._coreNodes || []).filter(n => n.status !== 'pending');
  const currentCoreEP = cp.core_endpoint || '';
  const knownCoreMatch = coreNodes.find(c => coreURL(c) === currentCoreEP);
  const isCoreOther = currentCoreEP && !knownCoreMatch;
  const coreSelectOpts = [
    `<option value=""${!currentCoreEP ? ' selected' : ''}>${t('infra.configure.ep_core_select_placeholder')}</option>`,
    ...coreNodes.map(c => `<option value="${esc(coreURL(c))}"${c === knownCoreMatch ? ' selected' : ''}>${esc(c.display_name||c.node_name)} — ${esc(coreURL(c))}</option>`),
    `<option value="__other__"${isCoreOther ? ' selected' : ''}>${t('infra.configure.ep_core_other')}</option>`,
  ].join('');
  const selStyle = 'background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:6px 10px;font-size:13px;color:var(--text1);font-family:inherit;width:100%;';
  const coreSelect = `<label style="display:flex;flex-direction:column;gap:4px;font-size:12px;color:var(--text2);">${t('infra.configure.core_target')}
    <select id="cfg-core-ep-select" style="${selStyle}" onchange="(function(s){const m=document.getElementById('cfg-core-ep-manual');if(m)m.style.display=s.value==='__other__'?'block':'none';})(this)">${coreSelectOpts}</select>
    <input id="cfg-core-ep-manual" type="url" value="${esc(isCoreOther ? currentCoreEP : '')}" placeholder="http://core.example.com:8000"
      style="${selStyle}display:${isCoreOther ? 'block' : 'none'};margin-top:4px;">
  </label>`;

  const body = `<form id="${formId}" style="display:flex;flex-direction:column;gap:10px;">
    ${sectionTitle(t('infra.configure.core_section'))}
    ${coreSelect}
    ${sectionTitle(t('infra.configure.docker_section'))}
    ${toggle('cfg-docker-enabled', t('infra.configure.enabled'), d.enabled !== false)}
    ${field('cfg-docker-socket', 'Socket path', d.socket_path, 'text', '/var/run/docker.sock')}
    ${sectionTitle(t('infra.configure.portainer_section'))}
    ${toggle('cfg-portainer-enabled', t('infra.configure.enabled'), !!p.enabled)}
    ${field('cfg-portainer-url', t('infra.configure.url'), p.url, 'url', 'https://portainer:9443')}
    ${field('cfg-portainer-key', t('infra.configure.api_key'), p.api_key, 'password', 'ptr_...')}
    ${field('cfg-portainer-poll', t('infra.configure.poll_interval'), p.poll_interval_s||30, 'number', '30')}
    ${field('cfg-portainer-skip', t('infra.configure.skip_endpoints'), (p.skip_endpoints||[]).join(', '), 'text', 'lucas.vm-docker, prod-server')}
    <div style="margin-top:10px;">
      <div style="font-size:11px;font-weight:600;color:var(--text2);margin-bottom:6px;">${t('infra.configure.endpoint_cores')}</div>
      <div id="cfg-ep-cores-list" style="display:flex;flex-direction:column;gap:6px;margin-bottom:6px;">
        ${_renderEpCoreRows(p.endpoint_cores||{})}
      </div>
      <button type="button" class="btn btn-secondary" style="font-size:11px;padding:4px 10px;" onclick="_addEpCoreRow()">${t('infra.configure.endpoint_cores_add')}</button>
      <p style="margin:4px 0 0;font-size:10px;color:var(--text2);">${t('infra.configure.endpoint_cores_hint')}</p>
    </div>
    <p style="margin:8px 0 0;font-size:11px;color:var(--text2);">${t('infra.configure.restart_notice')}</p>
  </form>`;

  const footer = `
    <button class="btn btn-secondary" onclick="closeModal()">${t('common.cancel')}</button>
    <button class="btn btn-primary" id="cfg-apply-btn" onclick="_submitAgentConfigure('${esc(nodeName)}','${formId}')">${t('common.save')}</button>`;

  modal(t('infra.configure.title', { name: esc(name) }), body, footer);
}
window.agentConfigure = agentConfigure;

window._submitAgentConfigure = async function(nodeName, formId) {
  const btn = document.getElementById('cfg-apply-btn');
  if (btn) { btn.disabled = true; btn.textContent = t('infra.configure.applying'); }

  const cfgCoreSel = document.getElementById('cfg-core-ep-select');
  const cfgCoreEP = cfgCoreSel?.value === '__other__'
    ? document.getElementById('cfg-core-ep-manual')?.value?.trim()
    : cfgCoreSel?.value?.trim();

  const patch = {
    ...(cfgCoreEP ? { control_plane: { core_endpoint: cfgCoreEP } } : {}),
    docker: {
      enabled: document.getElementById('cfg-docker-enabled')?.checked ?? true,
      socket_path: document.getElementById('cfg-docker-socket')?.value || '/var/run/docker.sock',
    },
    portainer: {
      enabled: document.getElementById('cfg-portainer-enabled')?.checked ?? false,
      url: document.getElementById('cfg-portainer-url')?.value || '',
      api_key: document.getElementById('cfg-portainer-key')?.value || '',
      poll_interval_s: parseInt(document.getElementById('cfg-portainer-poll')?.value || '30', 10) || 30,
      skip_endpoints: (document.getElementById('cfg-portainer-skip')?.value || '').split(',').map(s => s.trim()).filter(Boolean),
      endpoint_cores: (() => {
        const result = {};
        document.querySelectorAll('#cfg-ep-cores-list .ep-core-row').forEach(row => {
          const name = row.querySelector('input[type=text]')?.value?.trim();
          const sel  = row.querySelector('.ep-core-select');
          const ep   = (sel?.value === '__other__' || !sel)
            ? row.querySelector('.ep-core-manual')?.value?.trim()
            : sel?.value?.trim();
          const tok  = row.querySelector('input[type=password]')?.value?.trim();
          if (name && ep) result[name] = { core_endpoint: ep, auth_token: tok };
        });
        return result;
      })(),
    },
  };

  try {
    await api('POST', `/nodes/${encodeURIComponent(nodeName)}/configure`, patch);
    closeModal();
    toast(t('infra.configure.applied'), 'success');
  } catch(e) {
    if (btn) { btn.disabled = false; btn.textContent = t('common.save'); }
    toast(t('infra.configure.failed', { msg: e.message }), 'error');
  }
};

async function agentUpdate(nodeName) {
  if (!confirm(t('infra.confirm.update_agent', { name: nodeName }))) return;
  try {
    await api('POST', `/nodes/${encodeURIComponent(nodeName)}/update`, {});
    toast(t('infra.toast.update_started'), 'success');
  } catch(e) { toast(t('common.error_msg', { msg: e.message }), 'error'); }
}

async function agentContainers(nodeName, displayName) {
  let items = [];
  let loadErr = '';
  try {
    const all = await api('GET', '/discovered-containers') || [];
    items = all.filter(c => c.agent_name === nodeName);
  } catch(e) {
    loadErr = e.message || t('prism.load_err');
  }

  const srcLabel = { docker: 'Docker', k8s: 'Kubernetes', portainer: 'Portainer', podman: 'Podman' };
  const srcOrder = ['docker', 'portainer', 'k8s', 'podman'];

  // group by source
  const groups = {};
  for (const c of items) {
    const src = c.source || 'docker';
    if (!groups[src]) groups[src] = [];
    groups[src].push(c);
  }

  const tableFor = (list) => {
    const rows = list.map(c => {
      const backends = (c.backends || []).join(', ') || '—';
      const tls = c.tls ? ' <span class="tag tag-green" style="font-size:10px;">TLS</span>' : '';
      return `<tr>
        <td style="padding:6px 10px;font-size:12px;font-family:monospace;">${esc(c.host || '—')}</td>
        <td style="padding:6px 10px;font-size:11px;color:var(--text2);">${esc(backends)}</td>
        <td style="padding:6px 10px;font-size:11px;color:var(--text2);">${esc(c.core_name || '—')}${tls}</td>
      </tr>`;
    }).join('');
    return `<div style="overflow-x:auto;max-height:280px;overflow-y:auto;margin-bottom:16px;">
      <table style="width:100%;border-collapse:collapse;border:1px solid var(--border);border-radius:6px;overflow:hidden;">
        <thead>
          <tr style="background:var(--bg2);">
            <th style="padding:6px 10px;font-size:11px;font-weight:600;text-align:left;">${t('infra.col.host')}</th>
            <th style="padding:6px 10px;font-size:11px;font-weight:600;text-align:left;">${t('infra.col.backends')}</th>
            <th style="padding:6px 10px;font-size:11px;font-weight:600;text-align:left;">Core</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
  };

  let sections = '';
  const presentSrcs = srcOrder.filter(s => groups[s]);
  const otherSrcs = Object.keys(groups).filter(s => !srcOrder.includes(s));
  for (const src of [...presentSrcs, ...otherSrcs]) {
    const label = srcLabel[src] || src;
    sections += `<h4 style="margin:0 0 8px;font-size:12px;font-weight:600;color:var(--text1);">${esc(label)} <span style="font-weight:400;color:var(--text2);">(${groups[src].length})</span></h4>`;
    sections += tableFor(groups[src]);
  }

  if (!sections) {
    sections = `<p style="font-size:12px;color:var(--text2);text-align:center;">${
      loadErr
        ? t('common.error_msg', { msg: esc(loadErr) })
        : t('infra.containers.empty')
    }</p>`;
  }

  const body = `
    <p style="margin:0 0 16px;font-size:12px;color:var(--text2);">${t('infra.containers.intro', { name: esc(displayName) })}</p>
    ${sections}`;
  modal(t('infra.containers.title'), body,
    `<button class="btn btn-secondary" onclick="agentRescan('${esc(nodeName)}');closeModal()">${t('infra.rescan')}</button>
     <button class="btn btn-primary" onclick="closeModal()" aria-label="${t('common.close')}">${t('common.close')}</button>`);
}

async function agentEvents(nodeName, displayName) {
  let events = [];
  let loadErr = '';
  try {
    events = await api('GET', `/node-events?node=${encodeURIComponent(nodeName)}&limit=50`);
    if (!Array.isArray(events)) events = [];
  } catch(e) {
    loadErr = e.message || t('prism.load_err');
  }

  const typeColor = { scale_up:'var(--green)', scale_down:'var(--yellow)', health_watch_started:'var(--accent)',
    new_digest:'var(--accent)', health_critical:'var(--red)', health_escalation:'var(--red)',
    start:'var(--green)', stop:'var(--yellow)', destroy:'var(--red)', agent_online:'var(--accent)', default:'var(--text2)' };

  const rows = events.length
    ? events.map(ev => {
        const col = typeColor[ev.event_type] || typeColor.default;
        const ts = ev.created_at ? fmtDate(ev.created_at) : '—';
        return `<tr>
          <td style="padding:5px 10px;font-size:11px;color:var(--text2);white-space:nowrap;">${esc(ts)}</td>
          <td style="padding:5px 10px;font-size:11px;font-weight:600;color:${col};">${esc(ev.event_type||'—')}</td>
          <td style="padding:5px 10px;font-size:11px;font-family:monospace;color:var(--text2);">${esc(ev.container_id ? String(ev.container_id).slice(0,12) : '—')}</td>
          <td style="padding:5px 10px;font-size:11px;color:var(--text2);">${esc(ev.detail||'')}</td>
        </tr>`;
      }).join('')
    : `<tr><td colspan="4" style="padding:12px 10px;font-size:12px;color:var(--text2);text-align:center;">${
        loadErr
          ? t('common.error_msg', { msg: esc(loadErr) })
          : t('infra.events.empty')
      }</td></tr>`;

  const body = `
    <p style="margin:0 0 12px;font-size:12px;color:var(--text2);">${t('infra.events.intro', { name: esc(displayName) })}</p>
    <div style="overflow-x:auto;max-height:360px;overflow-y:auto;">
      <table style="width:100%;border-collapse:collapse;border:1px solid var(--border);border-radius:6px;overflow:hidden;">
        <thead>
          <tr style="background:var(--bg2);">
            <th style="padding:5px 10px;font-size:11px;font-weight:600;text-align:left;">${t('common.date')}</th>
            <th style="padding:5px 10px;font-size:11px;font-weight:600;text-align:left;">${t('trafic.type')}</th>
            <th style="padding:5px 10px;font-size:11px;font-weight:600;text-align:left;">${t('infra.col.container')}</th>
            <th style="padding:5px 10px;font-size:11px;font-weight:600;text-align:left;">${t('infra.col.detail')}</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
  modal(t('infra.events.title', { name: esc(displayName) }), body,
    `<button class="btn btn-primary" onclick="closeModal()">${t('common.close')}</button>`);
}

function _infraPendingDeploy(name) {
  try {
    const s = JSON.parse(localStorage.getItem('gpx_pending_deploy') || '{}');
    return !!s[name];
  } catch { return false; }
}

async function deleteDeclaredNode(id) {
  if (!confirm(t('infra.confirm.delete_declared'))) return;
  try {
    await api('DELETE', '/declared-nodes/' + id);
    navigate('infrastructure');
  } catch(e) { alert(t('common.error_msg', { msg: e.message })); }
}

async function showDeclaredNodeConfig(id) {
  try {
    const nodes = await api('GET', '/declared-nodes') || [];
    const node = nodes.find(n => n.id === id);
    if (!node) { modal(t('infra.error'), '<p style="margin:0;">' + t('infra.node_not_found') + '</p>', '<button class="btn btn-primary" onclick="closeModal()">' + t('common.close') + '</button>'); return; }
    const cfg = typeof node.config === 'string' ? JSON.parse(node.config) : (node.config || {});

    // Build opts from stored env_vars+image (new format) or fallback to legacy compose_text/env_text
    let bodyHTML;
    if (cfg.env_vars && cfg.image) {
      const opts = {
        name: node.name,
        svcName: node.name,
        image: cfg.image,
        envVars: cfg.env_vars,
        ports: node.role === 'core' ? (() => {
          const p = ['80:80','443:443'];
          if (cfg.http3) p.push('443:443/udp');
          p.push('8000:8000');
          if (cfg.cluster) p.push('8002:8002');
          return p;
        })() : [],
        volumes: node.role === 'core'
          ? [`${node.name}_data:/etc/goproxify`]
          : (cfg.docker !== false
            ? ['/var/run/docker.sock:/var/run/docker.sock:ro', `${node.name}_data:/etc/goproxify`]
            : [`${node.name}_data:/etc/goproxify`]),
        netBlock: `\nnetworks:\n  goproxify-net:\n    driver: bridge`,
        restart: cfg.restart || 'unless-stopped',
      };
      window._cfgState = { tab: 'compose', inline: false };
      // Agent déclaré : stack unifié seulement si placement colocated (même hôte/compose)
      let coreOpts = null;
      if (node.role === 'agent') {
        const placement = (cfg.placement || '').trim();
        const target = (cfg.target_core || '').trim();
        const hostPart = (target.match(/https?:\/\/([^/:]+)/i) || [])[1] || '';
        const looksInternal = !!hostPart &&
          !/^\d+\.\d+\.\d+\.\d+$/.test(hostPart) &&
          !hostPart.includes('.') &&
          /^https?:\/\/[a-z0-9]([a-z0-9-]*[a-z0-9])?(:\d+)?$/i.test(target);
        const useUnified = placement === 'colocated' || (!placement && looksInternal);
        if (useUnified) {
          const coreNode = nodes.find(n => {
            if (n.role !== 'core') return false;
            if (target && (target.includes(n.name) || target === n.name)) return true;
            return false;
          }) || nodes.find(n => n.role === 'core');
          if (coreNode) {
            _wiz.declaredNodes = nodes;
            coreOpts = _wizCoreOptsFromExisting({ node_name: coreNode.name, display_name: coreNode.name });
            if (coreOpts) {
              const internalURL = `http://${coreOpts.name}:8000`;
              opts.envVars = (opts.envVars || [])
                .filter(e => e.k !== 'GPX_CONTROL_PLANE_CORE_ENDPOINT' && e.k !== 'GPX_NETWORK_MANAGEMENT_CORE_CONTAINER_NAME')
                .concat([
                  { k: 'GPX_CONTROL_PLANE_CORE_ENDPOINT', v: internalURL },
                  { k: 'GPX_NETWORK_MANAGEMENT_CORE_CONTAINER_NAME', v: coreOpts.name },
                ]);
            }
          }
        }
      }
      bodyHTML = coreOpts ? _renderConfigUI(coreOpts, opts) : _renderConfigUI(opts);
    } else if (cfg.compose_text || cfg.env_text) {
      // Legacy: show static compose_text/env_text
      const copyBtn = (eid, label) =>
        `<button class="btn btn-ghost btn-sm" style="position:absolute;top:8px;right:8px;" onclick="navigator.clipboard.writeText(document.getElementById('${eid}').textContent)">${label}</button>`;
      bodyHTML = `
        <div style="margin-bottom:16px;">
          <div style="font-size:12px;font-weight:600;margin-bottom:6px;">docker-compose.yml</div>
          <div style="position:relative;">
            ${copyBtn('modal-dc-compose', t('dockerlbl.copy'))}
            <pre id="modal-dc-compose" style="background:var(--bg2);border-radius:8px;padding:14px;font-size:11px;overflow-x:auto;white-space:pre;color:var(--text1);margin:0;max-height:260px;">${esc(cfg.compose_text||'')}</pre>
          </div>
        </div>
        <div>
          <div style="font-size:12px;font-weight:600;margin-bottom:6px;">.env</div>
          <div style="position:relative;">
            ${copyBtn('modal-dc-env', t('dockerlbl.copy'))}
            <pre id="modal-dc-env" style="background:var(--bg2);border-radius:8px;padding:14px;font-size:11px;overflow-x:auto;white-space:pre;color:var(--text1);margin:0;max-height:200px;">${esc(cfg.env_text||'')}</pre>
          </div>
        </div>`;
    } else {
      modal(t('infra.config_title', { name: esc(node.name) }),
        `<p style="margin:0 0 12px;font-size:13.5px;opacity:.8;">${t('infra.config_unavailable')}</p>
         <p style="margin:0;font-size:13px;color:var(--text2);">${t('infra.config_regen_hint')}</p>`,
        `<button class="btn btn-ghost btn-sm" onclick="closeModal()">${t('common.cancel')}</button>
         <button class="btn btn-danger btn-sm" onclick="closeModal();deleteDeclaredNode('${id}')">${t('infra.delete_recreate')}</button>`);
      return;
    }

    const pendingDeploy = _infraPendingDeploy(node.name);
    const deployBtn = pendingDeploy
      ? `<button class="btn btn-secondary" onclick="archMarkDeployed('${esc(node.name)}')">${t('infra.mark_deployed')}</button>`
      : '';
    modal(t('infra.config_title', { name: esc(node.name) }), bodyHTML,
      `${deployBtn}<button class="btn btn-primary" onclick="closeModal()">${t('common.close')}</button>`, true);
  } catch(e) {
    modal(t('infra.error'), `<p style="margin:0;font-size:13.5px;opacity:.8;">${t('infra.config_load_fail', { msg: esc(e.message) })}</p>`,
      '<button class="btn btn-primary" onclick="closeModal()">' + t('common.close') + '</button>');
  }
}


// pages.nodes redirige vers infrastructure (entrée nav supprimée).
pages.nodes = () => navigate('infrastructure');

window.nodeAction = async function(name, action) {
  try {
    await api('POST', `/nodes/${encodeURIComponent(name)}/${action}`);
    toast(t('infra.toast.action_started', { action, name }), 'success');
  } catch(e) { toast(e.message, 'error'); }
};

// ── Topology selection & panneau détails ───────────────────────────────────
window._topoSelection = new Set();

function _topoNodeId(n) {
  if (!n) return '';
  if (n.role === 'admin') return 'admin';
  return n.status === 'declared' ? n.id : (n.node_name || n.id);
}

function _topoSelectedNodes() {
  const sel = window._topoSelection;
  const all = window._infraNodes || [];
  return all.filter(n => sel.has(_topoNodeId(n)));
}

function _topoSelect(nodeId) {
  const sel = window._topoSelection;
  if (sel.has(nodeId)) sel.delete(nodeId);
  else sel.add(nodeId);

  document.querySelectorAll('.topo-tile-wrap').forEach(el => {
    el.classList.toggle('selected', sel.has(el.dataset.nodeId));
  });

  _renderDetails();
  _updateActionBar();
}
window._topoSelect = _topoSelect;

function _statusBadgeHTML(n) {
  if (n.status === 'declared')
    return `<span class="tag" style="background:var(--bg3);color:var(--text2);">${t('infra.status.disconnected')}</span>`;
  if (n.status === 'online')
    return `<span class="tag tag-green">${t('infra.status.active')}</span>`;
  if (n.status === 'pending')
    return `<span class="tag" style="background:color-mix(in srgb,var(--orange,#f97316) 16%,transparent);color:var(--orange,#f97316);">○ ${t('infra.pending')}</span>`;
  return `<span class="tag tag-red">${t('infra.status.inactive')}</span>`;
}

function _detailsMeter(label, val) {
  const v = val || 0;
  return `<div style="margin-top:6px;">
    <div style="display:flex;justify-content:space-between;font-size:11px;color:var(--text2);margin-bottom:3px;"><span>${label}</span><span>${v.toFixed(0)}%</span></div>
    <div style="height:4px;background:var(--bg3);"><div style="height:100%;width:${Math.min(v,100)}%;background:${v>80?'var(--red)':v>60?'var(--yellow)':'var(--green)'};"></div></div>
  </div>`;
}

function _detailsCardHTML(n) {
  const name = n.display_name || n.node_name || 'Admin';
  const roleBadge = `<span class="tag tag-neutral" style="font-size:10px;">${esc(n.role||'admin')}</span>`;
  const stBadge = _statusBadgeHTML(n);
  let body = '';

  if (n.status === 'declared') {
    const iconConfig = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>`;
    const iconTrash = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/></svg>`;
    body = `<p style="color:var(--text2);font-size:13px;margin:12px 0;">${t('infra.waiting_connection')}</p>
      <div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap;">
        <button class="btn-icon" title="${t('infra.view_config')}" onclick="showDeclaredNodeConfig('${n.id}')">${iconConfig}</button>
        <button class="btn-icon" title="${t('common.delete')}" style="color:var(--red);" onclick="deleteDeclaredNode('${n.id}')">${iconTrash}</button>
      </div>`;
  } else if (n.role === 'admin') {
    body = `<div style="margin-top:10px;font-size:12px;color:var(--text2);">${t('infra.version')} <strong style="color:var(--text1);">v${esc(n.version||'—')}</strong></div>
      <div style="margin-top:12px;"><button class="btn btn-primary btn-sm" onclick="navigate('settings')">${t('page.settings')}</button></div>`;
  } else if (n.role === 'core') {
    const idx = (window._coreNodes||[]).findIndex(c => (c.node_name||c.id) === (n.node_name||n.id));
    body = `<div style="margin-top:10px;">
      <div style="font-size:11px;color:var(--text2);">${t('infra.endpoint')}</div>
      <div style="font-family:monospace;font-size:12px;">${esc(n.endpoint||n.node_endpoint||'—')}</div>
    </div>
    <div style="margin-top:8px;font-size:12px;color:var(--text2);">${t('infra.version')} <strong style="color:var(--text1);">v${esc(n.version||'—')}</strong></div>
    ${_detailsMeter('CPU', n.cpu_pct||0)}
    ${_detailsMeter('RAM', n.mem_pct||0)}
    <div style="display:flex;gap:6px;margin-top:14px;align-items:center;flex-wrap:wrap;">
      ${idx >= 0 ? `<button class="btn-icon" title="${t('infra.title.traffic')}" onclick="openCore(${idx},'core-trafic')">
        <svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
      </button>
      <button class="btn-icon" title="${t('infra.title.general_settings')}" onclick="openCore(${idx},'core-general')">
        <svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/></svg>
      </button>` : ''}
      <button class="btn-icon" title="${t('infra.title.update')}" onclick="nodeAction('${esc(n.node_name)}','update')">
        <svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="16 16 12 12 8 16"/><line x1="12" y1="12" x2="12" y2="21"/><path d="M20.39 18.39A5 5 0 0018 9h-1.26A8 8 0 103 16.3"/></svg>
      </button>
    </div>`;
  } else if (n.role === 'agent') {
    const rts = (n.container_runtimes||[]);
    const nn = n.node_name || n.id;
    const dn = n.display_name || nn;
    const iconRescan = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>`;
    const iconUpdate = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 16 12 12 8 16"/><line x1="12" y1="12" x2="12" y2="21"/><path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3"/></svg>`;
    const iconContainers = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>`;
    const iconEvents = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>`;
    const iconConfigure = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/></svg>`;
    body = `<div style="margin-top:10px;">
      <div style="font-size:11px;color:var(--text2);">${t('infra.linked_core')}</div>
      <div style="font-family:monospace;font-size:12px;">${esc(n.target_core||'—')}</div>
    </div>
    <div style="margin-top:8px;font-size:12px;color:var(--text2);">${t('infra.version')} <strong style="color:var(--text1);">v${esc(n.version||'—')}</strong></div>
    ${rts.length ? `<div style="margin-top:8px;display:flex;gap:4px;flex-wrap:wrap;">${rts.map(r=>`<span class="tag tag-neutral" style="font-size:10px;">${esc(r)}</span>`).join('')}</div>` : ''}
    <div style="display:flex;gap:6px;margin-top:14px;align-items:center;flex-wrap:wrap;">
      <button class="btn-icon" title="${t('infra.title.discovered_containers')}" onclick="agentContainers('${esc(nn)}','${esc(dn)}')">${iconContainers}</button>
      <button class="btn-icon" title="${t('infra.title.events')}" onclick="agentEvents('${esc(nn)}','${esc(dn)}')">${iconEvents}</button>
      <button class="btn-icon" title="${t('infra.title.rescan')}" onclick="agentRescan('${esc(nn)}')">${iconRescan}</button>
      <button class="btn-icon" title="${t('infra.title.update_agent')}" onclick="agentUpdate('${esc(nn)}')">${iconUpdate}</button>
      <button class="btn-icon" title="${t('infra.configure')}" onclick="agentConfigure('${esc(nn)}',${JSON.stringify(n).replace(/</g,'\\u003c').replace(/>/g,'\\u003e')})">${iconConfigure}</button>
    </div>`;
  }

  return `<div class="topo-details-card">
    <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px;margin-bottom:4px;">
      <div style="font-weight:700;font-size:15px;">${esc(name)}</div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;">${roleBadge}${stBadge}</div>
    </div>
    ${body}
  </div>`;
}

function _detailsRelationActions(nodes) {
  const liveCores  = nodes.filter(n => n.role === 'core' && n.status === 'online');
  const liveAgents = nodes.filter(n => n.role === 'agent' && n.status === 'online');
  const declaredAgents = nodes.filter(n => n.role === 'agent' && n.status === 'declared');
  let actions = [];
  const iconLink = `<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>`;
  const iconRaft = `<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="5" r="2.5"/><circle cx="5" cy="19" r="2.5"/><circle cx="19" cy="19" r="2.5"/><path d="M12 7.5v4M12 11.5l-5.5 5M12 11.5l5.5 5"/></svg>`;
  const iconCompare = `<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="18" rx="1"/><rect x="14" y="3" width="7" height="18" rx="1"/></svg>`;
  const iconDeselect = `<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6L6 18M6 6l12 12"/></svg>`;

  if (liveCores.length === 1 && (liveAgents.length + declaredAgents.length) >= 1) {
    const core = liveCores[0];
    const coreName = core.display_name || core.node_name;
    const nAgents = liveAgents.length + declaredAgents.length;
    actions.push(`<button class="btn-icon" title="${t('infra.link_agents', { core: esc(coreName) })}" onclick="_topoLinkAgentsHint('${esc(coreName)}',${nAgents})">${iconLink}</button>`);
  }
  if (liveCores.length >= 2 && nodes.length === liveCores.length) {
    actions.push(`<button class="btn-icon" title="${t('infra.tag.raft_cluster')}" onclick="_topoRaftHint()">${iconRaft}</button>`);
  }
  if (nodes.length >= 2) {
    actions.push(`<button class="btn-icon" title="${t('infra.compare')}" onclick="_topoCompareHint()">${iconCompare}</button>`);
  }
  return actions.length
    ? `<div class="topo-details-actions">${actions.join('')}<button class="btn-icon" title="${t('infra.deselect')}" onclick="_clearTopoSelection()">${iconDeselect}</button></div>`
    : '';
}

window._topoLinkAgentsHint = function(coreName, nAgents) {
  modal(t('infra.link_agents_title'),
    `<p style="margin:0 0 10px;font-size:13px;color:var(--text2);">${t('infra.link_agents_body', { n: nAgents, core: esc(coreName) })}</p>
     <p style="margin:0;font-size:12px;color:var(--text2);">${t('infra.link_agents_hint')}</p>`,
    `<button class="btn btn-primary" onclick="closeModal()">${t('infra.understood')}</button>`);
};
window._topoRaftHint = function() {
  modal(t('infra.tag.raft_cluster'),
    `<p style="margin:0;font-size:13px;">${t('infra.raft_hint_body')}</p>`,
    `<button class="btn btn-secondary" onclick="closeModal()">${t('common.close')}</button>
     <button class="btn btn-primary" onclick="closeModal();openInfraWizard()">${t('infra.open_wizard')}</button>`);
};
window._topoCompareHint = function() {
  const names = _topoSelectedNodes().map(n => n.display_name || n.node_name || n.role).join(', ');
  modal(t('infra.compare'),
    `<p style="margin:0;font-size:13px;">${t('infra.selection', { names: esc(names) })}</p>
     <p style="margin:10px 0 0;font-size:12px;color:var(--text2);">${t('infra.compare_soon')}</p>`,
    `<button class="btn btn-primary" onclick="closeModal()">${t('common.close')}</button>`);
};

function _renderDetails() {
  const panel = document.getElementById('topo-details');
  if (!panel) return;
  const nodes = _topoSelectedNodes();
  if (!nodes.length) {
    panel.style.display = 'none';
    panel.innerHTML = '';
    return;
  }
  panel.style.display = 'block';
  const header = nodes.length === 1
    ? `<div class="topo-details-header"><span>${t('infra.details')}</span><button class="btn btn-ghost btn-sm" onclick="_clearTopoSelection()" style="font-size:16px;line-height:1;">×</button></div>`
    : `<div class="topo-details-header"><span>${t('infra.details_selected', { n: nodes.length })}</span><button class="btn btn-ghost btn-sm" onclick="_clearTopoSelection()" style="font-size:16px;line-height:1;">×</button></div>`;
  const cards = `<div class="topo-details-grid">${nodes.map(_detailsCardHTML).join('')}</div>`;
  const relation = nodes.length >= 2 ? _detailsRelationActions(nodes) : '';
  panel.innerHTML = header + cards + relation;
}

function _closeDetails() {
  const panel = document.getElementById('topo-details');
  if (panel) { panel.style.display = 'none'; panel.innerHTML = ''; }
}

function _clearTopoSelection() {
  window._topoSelection.clear();
  document.querySelectorAll('.topo-tile-wrap.selected').forEach(el => el.classList.remove('selected'));
  _closeDetails();
  _updateActionBar();
}
window._clearTopoSelection = _clearTopoSelection;




// ── Topologie temps réel : débit, risque, santé ────────────────────────────
// Sonde GET /nodes/live toutes les 5 s et met à jour les tuiles en place (pas de re-rendu de la page).

const TOPO_LIVE_POLL_MS = 5000;
const TOPO_LIVE_HISTORY = 24; // 2 min de débit pour la sparkline

function _topoSparkline(values) {
  if (values.length < 2) return '';
  const w = 60, h = 14, max = Math.max(...values, 1);
  const pts = values.map((v, i) => `${(i / (values.length - 1) * w).toFixed(1)},${(h - 1 - v / max * (h - 2)).toFixed(1)}`).join(' ');
  return `<svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" style="flex:none;opacity:.7"><polyline points="${pts}" fill="none" stroke="var(--accent)" stroke-width="1.5"/></svg>`;
}

function _topoApplyLive(live) {
  const hist = window._topoHist = window._topoHist || {};
  const meta = document.getElementById('topo-live-meta');
  if (meta) meta.textContent = t('infra.live.meta', { sec: live.window_sec, bans: live.bans_active });

  for (const n of live.nodes) {
    const h = hist[n.node_name] = hist[n.node_name] || [];
    h.push(n.rps);
    if (h.length > TOPO_LIVE_HISTORY) h.shift();

    const wrap = document.querySelector(`.topo-tile-wrap[data-node-id="${CSS.escape(n.node_name)}"]`);
    if (!wrap) continue;
    wrap.dataset.risk = n.risk_level;
    let box = wrap.querySelector('.topo-live');
    if (!box) {
      box = document.createElement('div');
      box.className = 'topo-live';
      wrap.appendChild(box);
    }
    const why = n.risk_factor !== 'none' ? ` · ${t('infra.live.factor.' + n.risk_factor)}` : '';
    const traffic = n.role === 'core'
      ? `<span>${t('infra.live.reqs', { rps: n.rps < 10 ? n.rps.toFixed(1) : Math.round(n.rps) })}</span>${_topoSparkline(h)}`
      : '';
    box.innerHTML = `${traffic}<span class="topo-risk topo-risk-${n.risk_level}" title="${esc(t('infra.live.risk', { score: n.risk }) + why)}${n.low_traffic && n.role === 'core' ? ' — ' + esc(t('infra.live.low')) : ''}">${esc(t('infra.live.risk', { score: n.risk }))}</span>`;
  }
}

async function _topoLiveTick(content) {
  if (!content.isConnected || !document.getElementById('topology-container')) return;
  const live = await api('GET', '/nodes/live').catch(() => null);
  if (!live) return;
  // Un nœud apparu ou disparu change la structure du graphe : rechargement complet, une seule fois par changement.
  const sig = live.nodes.map(n => n.node_name).join('|');
  if (window._topoSig !== undefined && window._topoSig !== sig) {
    window._topoSig = sig;
    pages.infrastructure();
    return;
  }
  window._topoSig = sig;
  _topoApplyLive(live);
}

function startTopologyLive(content) {
  if (typeof content._cleanup === 'function') content._cleanup();
  window._topoSig = undefined;
  window._topoHist = {};
  _topoLiveTick(content);
  const timer = setInterval(() => _topoLiveTick(content), TOPO_LIVE_POLL_MS);
  content._cleanup = () => clearInterval(timer);
}
