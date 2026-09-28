// ── PAGE: Infrastructure (schéma d'architecture, ajout de nœuds, actions d'exploitation) ──
// Dépend de shared/infra-config.js, shared/arch-schema.js et shared/fmt.js.

// ── PAGE: Infrastructure : schéma de l'architecture (source : architecture.json) ────
// Le modèle hôtes → rôles → capacités est chargé par _archLoad (architecture-wizard.js) depuis
// GET /architecture ; l'état live (/nodes, /nodes/live, /metrics/summary) n'est qu'une surcouche.
// Mise en page : indicateurs · À traiter · schéma (flux ou par hôte) + journal · panneau du nœud sélectionné.
pages.infrastructure = async function() {
  const content = document.getElementById('content');
  content.innerHTML = '<p style="color:var(--text2)">' + t('common.loading') + '</p>';
  try {
    await _archLoad();
    const [health, live, metrics, containers] = await Promise.all([
      api('GET','/health').catch(()=>null),
      api('GET','/nodes/live').catch(()=>null),
      api('GET','/metrics/summary').catch(()=>null),
      api('GET','/discovered-containers').catch(()=>null),
    ]);
    if (state.page !== 'infrastructure') return;
    const allNodes = _arch.nodes;
    window._excludedDeclaredNodes = new Map();
    for (const dn of _arch.declaredNodes) {
      if (_archParseCfg(dn.config).excluded) window._excludedDeclaredNodes.set(dn.name, dn);
    }
    window._edgeNodes = allNodes.filter(n => n.role === 'edge' && n.status !== 'pending');
    window.openEdge = function(i, page) { selectEdge(window._edgeNodes[i], page); };
    if (typeof refreshNavEdges === 'function') refreshNavEdges();
    window._asEdit = false;
    window._asHealthOK = health?.status === 'ok';
    window._asMetrics = metrics;
    window._asEvents = {};
    window._asContainers = {};
    for (const c of (Array.isArray(containers) ? containers : [])) {
      if (c.agent_name) window._asContainers[c.agent_name] = (window._asContainers[c.agent_name] || 0) + 1;
    }
    asApplyLive(live);
    asSample(_arch);

    const ta = document.getElementById('topbar-actions');
    if (ta) ta.innerHTML = `
      <button type="button" class="btn btn-secondary btn-sm" onclick="openDockerLabelsModal()">${esc(t('infra.labels'))}</button>
      <button type="button" class="btn btn-secondary btn-sm" onclick="asOpenConfig(null,'v')">${esc(t('as.history'))}</button>
      <button type="button" class="btn btn-primary btn-sm" onclick="openInfraWizard()">${esc(t('as.edit_arch'))}</button>`;

    content.innerHTML = `<div class="as-page">
      <div id="as-kpis"></div>
      <div id="as-todo"></div>
      <div class="as-main">
        <div class="as-left">
          <section class="as-card"><div class="as-card-h" id="as-topo-h"></div><div id="as-root"></div></section>
          <section class="as-card" id="as-journal" hidden></section>
        </div>
        <aside class="as-card as-panel" id="as-panel" aria-label="${esc(t('as.panel.label'))}"></aside>
      </div>
    </div>`;
    asRenderLive();
    startTopologyLive(content);
    loadInfraJournal();
  } catch(e) { content.innerHTML = `<p style="color:var(--red)">${esc(e.message)}</p>`; }
};

/** Journal d'infrastructure : événements de scaling et de santé récents. */
async function loadInfraJournal() {
  const events = await api('GET', '/node-events?limit=40').catch(() => []);
  const el = document.getElementById('as-journal');
  if (!el) return;
  const list = (Array.isArray(events) ? events : [])
    .filter(e => /^scale_/.test(e.event_type) || e.event_type === 'health_escalation' || e.event_type === 'health_critical')
    .slice(0, 8);
  el.hidden = !list.length;
  el.innerHTML = `<div class="as-card-h"><h2>${esc(t('as.journal'))}</h2></div>
    ${list.map(e => {
      const l = _asEvLabel(e.event_type);
      return `<div class="as-ev"><span class="as-ev-t">${esc(_asTime(e.created_at))}</span>
        <span class="as-tag"${l.tone ? ` data-tone="${l.tone}"` : ''}>${esc(l.label)}</span>
        <b>${esc(e.node_name || '—')}</b><span class="as-ev-d">${esc(e.detail || e.container_id || '—')}</span></div>`;
    }).join('')}`;
}

// ── WIZARD : Ajout d'un nœud Infrastructure ───────────────────────────────

function _genSecret() {
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2,'0')).join('');
}

const _wiz = {
  edgeList: [],
  declaredNodes: [],
  pairingSecret: '',
};

/** Endpoint Admin→Passerelle à partir d'un hôte saisi (évite :8000 en double). */
function _wizEdgeEndpoint(host) {
  const h = (host || '').trim();
  if (!h) return '';
  if (h.includes('://')) return h;
  if (h.includes(':')) return 'http://' + h;
  return 'http://' + h + ':8000';
}

/** Fusionne nœuds passerelle et tokens pour listes Agent / cluster Raft. */
function _wizLoadEdgeList(nodes, tokens) {
  const byName = new Map();
  for (const n of (nodes || []).filter(x => x.role === 'edge')) {
    const key = (n.node_name || n.display_name || n.id || '').trim();
    if (!key) continue;
    byName.set(key, { ...n, node_name: n.node_name || key });
  }
  for (const t of (tokens || []).filter(x => x.role === 'edge' && !x.revoked && x.node_endpoint)) {
    const key = (t.node_name || '').trim();
    if (!key) continue;
    const existing = byName.get(key) || { node_name: key, display_name: key, role: 'edge', status: 'online' };
    existing.node_endpoint = t.node_endpoint;
    byName.set(key, existing);
  }
  return [...byName.values()];
}

/** Options passerelle pour stack unifié (déclaré ou valeurs par défaut du nœud). */
function _wizEdgeOptsFromExisting(edge) {
  if (!edge) return null;
  const name = (edge.node_name || edge.display_name || 'goproxify-edge').trim();
  const declared = (_wiz.declaredNodes || []).find(n => n.role === 'edge' && n.name === name);
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
  return _buildEdgeOpts({
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
function _buildAddAgentOpts({ name, edgeURL, docker, dockerSock, portainer, portainerURL, portainerKey, pairingSecret }) {
  const cat = window._gpxCatalog;
  const image = cat ? cat.image('agent') : 'ghcr.io/vincamok/goproxify/agent:preview';
  const netBlock = cat ? cat.netBlock() : '\nnetworks:\n  goproxify_net:\n    driver: bridge';
  const sockPath = dockerSock || '/var/run/docker.sock';
  const envVars = [
    { k: 'GPX_IDENTITY_AGENT_NODE_NAME',    v: name },
    { k: 'GPX_CONTROL_PLANE_EDGE_ENDPOINT', v: edgeURL },
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
  const edges = (window._edgeNodes || []).filter(n => n.status === 'online');
  let pairingSecret = _wiz.pairingSecret;
  if (!pairingSecret) {
    const sec = await api('GET', '/pairing-secret').catch(() => null);
    pairingSecret = sec?.secret || '';
    _wiz.pairingSecret = pairingSecret;
  }

  const edgeOptions = edges.length
    ? edges.map(c => `<option value="${esc(c.node_name||c.id)}">${esc(c.display_name||c.node_name||c.id)}</option>`).join('')
    : `<option value="">${t('common.none')}</option>`;

  const formHTML = `
    <div style="display:flex;flex-direction:column;gap:12px;">
      <label style="display:flex;flex-direction:column;gap:4px;font-size:12px;color:var(--text2);">${t('infra.add_agent.name')}
        <input id="aa-name" type="text" value="goproxify-agent-1" placeholder="goproxify-agent-1"
          style="background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:6px 10px;font-size:13px;color:var(--text1);">
      </label>
      <label style="display:flex;flex-direction:column;gap:4px;font-size:12px;color:var(--text2);">${t('infra.add_agent.edge')}
        <select id="aa-edge-select" onchange="document.getElementById('aa-edge-url').value=this.value?'':'http://goproxify-edge:8000'"
          style="background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:6px 10px;font-size:13px;color:var(--text1);">
          ${edgeOptions}
          <option value="__custom__">${t('infra.add_agent.edge_url')}</option>
        </select>
        <input id="aa-edge-url" type="text" placeholder="http://goproxify-edge:8000"
          value="${edges.length ? 'http://' + esc(edges[0].node_name||edges[0].id) + ':8000' : 'http://goproxify-edge:8000'}"
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
  const edgeSelectVal = document.getElementById('aa-edge-select')?.value;
  let edgeURL = (document.getElementById('aa-edge-url')?.value || '').trim();
  if (edgeSelectVal && edgeSelectVal !== '__custom__') {
    edgeURL = `http://${edgeSelectVal}:8000`;
  }
  const docker       = document.getElementById('aa-docker')?.checked ?? true;
  const portainer    = document.getElementById('aa-portainer')?.checked ?? false;
  const portainerURL = document.getElementById('aa-portainer-url')?.value || '';
  const portainerKey = document.getElementById('aa-portainer-key')?.value || '';

  if (!name) { toast(t('infra.add_agent.name') + ' requis', 'error'); return; }
  if (!edgeURL) { toast(t('infra.add_agent.edge_url') + ' requis', 'error'); return; }

  const btn = document.getElementById('aa-generate-btn');
  if (btn) { btn.disabled = true; btn.textContent = t('infra.add_agent.generating'); }

  // 1. Créer le declared_node avec auto_accept
  const agentConfig = {
    docker: { enabled: docker, runtime: docker ? 'auto' : '' },
    portainer: { enabled: portainer, url: portainerURL, api_key: portainerKey },
    edge_endpoint: edgeURL,
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
  const opts = _buildAddAgentOpts({ name, edgeURL, docker, portainer, portainerURL, portainerKey, pairingSecret });
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

function _epEdgeRowHTML(epName, edgeEndpoint, authToken) {
  const s = 'font-size:11px;padding:4px 6px;border:1px solid var(--border);border-radius:4px;background:var(--bg);color:var(--text1);width:100%;';
  const edges = (window._edgeNodes || []).filter(n => n.status !== 'pending');

  const edgeURL = c => { const ep = c.endpoint || c.node_endpoint || ''; return ep.startsWith('http') ? ep : 'http://' + ep; };
  const knownMatch = edges.find(c => edgeURL(c) === edgeEndpoint);
  const isOther = edgeEndpoint && !knownMatch;

  const options = [
    `<option value=""${!edgeEndpoint ? ' selected' : ''}>${t('infra.configure.ep_edge_select_placeholder')}</option>`,
    ...edges.map(c => `<option value="${esc(edgeURL(c))}"${c === knownMatch ? ' selected' : ''}>${esc(c.node_name || c.display_name)} — ${esc(edgeURL(c))}</option>`),
    `<option value="__other__"${isOther ? ' selected' : ''}>${t('infra.configure.ep_edge_other')}</option>`,
  ].join('');

  return `<div style="display:grid;grid-template-columns:1fr 1fr 1fr auto;gap:4px;align-items:start;" class="ep-edge-row">
    <input type="text" placeholder="${t('infra.configure.ep_edge_name')}" value="${esc(epName)}" style="${s}">
    <div>
      <select class="ep-edge-select" onchange="_epEdgeSelectChange(this)" style="${s}cursor:pointer;">${options}</select>
      <input type="url" class="ep-edge-manual" placeholder="http://edge:8000" value="${esc(isOther ? edgeEndpoint : '')}"
        style="${s}margin-top:3px;display:${isOther ? 'block' : 'none'};">
    </div>
    <input type="password" placeholder="${t('infra.configure.ep_edge_token')}" value="${esc(authToken)}" style="${s}">
    <button type="button" style="padding:4px 8px;font-size:11px;background:var(--red,#e53e3e);color:#fff;border:none;border-radius:4px;cursor:pointer;margin-top:2px;"
      onclick="this.closest('.ep-edge-row').remove()">✕</button>
  </div>`;
}

window._epEdgeSelectChange = function(sel) {
  const manual = sel.closest('.ep-edge-row').querySelector('.ep-edge-manual');
  manual.style.display = sel.value === '__other__' ? 'block' : 'none';
};

function _renderEpEdgeRows(epEdges) {
  return Object.entries(epEdges).map(([name, conf]) =>
    _epEdgeRowHTML(name, conf.edge_endpoint || '', conf.auth_token || '')
  ).join('');
}

window._addEpEdgeRow = function() {
  const list = document.getElementById('cfg-ep-edges-list');
  if (!list) return;
  const div = document.createElement('div');
  div.innerHTML = _epEdgeRowHTML('', '', '');
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
    endpoint_edges: pLive.endpoint_edges,
  };
  const cp = (node && node._agent_config && node._agent_config.control_plane) || {};

  // Sélecteur "Passerelle cible" — liste des passerelles connus
  const edgeURL = c => { const ep = c.endpoint || c.node_endpoint || ''; return ep.startsWith('http') ? ep : 'http://' + ep; };
  const edgeNodes = (window._edgeNodes || []).filter(n => n.status !== 'pending');
  const currentEdgeEP = cp.edge_endpoint || '';
  const knownEdgeMatch = edgeNodes.find(c => edgeURL(c) === currentEdgeEP);
  const isEdgeOther = currentEdgeEP && !knownEdgeMatch;
  const edgeSelectOpts = [
    `<option value=""${!currentEdgeEP ? ' selected' : ''}>${t('infra.configure.ep_edge_select_placeholder')}</option>`,
    ...edgeNodes.map(c => `<option value="${esc(edgeURL(c))}"${c === knownEdgeMatch ? ' selected' : ''}>${esc(c.display_name||c.node_name)} — ${esc(edgeURL(c))}</option>`),
    `<option value="__other__"${isEdgeOther ? ' selected' : ''}>${t('infra.configure.ep_edge_other')}</option>`,
  ].join('');
  const selStyle = 'background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:6px 10px;font-size:13px;color:var(--text1);font-family:inherit;width:100%;';
  const edgeSelect = `<label style="display:flex;flex-direction:column;gap:4px;font-size:12px;color:var(--text2);">${t('infra.configure.edge_target')}
    <select id="cfg-edge-ep-select" style="${selStyle}" onchange="(function(s){const m=document.getElementById('cfg-edge-ep-manual');if(m)m.style.display=s.value==='__other__'?'block':'none';})(this)">${edgeSelectOpts}</select>
    <input id="cfg-edge-ep-manual" type="url" value="${esc(isEdgeOther ? currentEdgeEP : '')}" placeholder="http://edge.example.com:8000"
      style="${selStyle}display:${isEdgeOther ? 'block' : 'none'};margin-top:4px;">
  </label>`;

  const body = `<form id="${formId}" style="display:flex;flex-direction:column;gap:10px;">
    ${sectionTitle(t('infra.configure.edge_section'))}
    ${edgeSelect}
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
      <div style="font-size:11px;font-weight:600;color:var(--text2);margin-bottom:6px;">${t('infra.configure.endpoint_edges')}</div>
      <div id="cfg-ep-edges-list" style="display:flex;flex-direction:column;gap:6px;margin-bottom:6px;">
        ${_renderEpEdgeRows(p.endpoint_edges||{})}
      </div>
      <button type="button" class="btn btn-secondary" style="font-size:11px;padding:4px 10px;" onclick="_addEpEdgeRow()">${t('infra.configure.endpoint_edges_add')}</button>
      <p style="margin:4px 0 0;font-size:10px;color:var(--text2);">${t('infra.configure.endpoint_edges_hint')}</p>
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

  const cfgEdgeSel = document.getElementById('cfg-edge-ep-select');
  const cfgEdgeEP = cfgEdgeSel?.value === '__other__'
    ? document.getElementById('cfg-edge-ep-manual')?.value?.trim()
    : cfgEdgeSel?.value?.trim();

  const patch = {
    ...(cfgEdgeEP ? { control_plane: { edge_endpoint: cfgEdgeEP } } : {}),
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
      endpoint_edges: (() => {
        const result = {};
        document.querySelectorAll('#cfg-ep-edges-list .ep-edge-row').forEach(row => {
          const name = row.querySelector('input[type=text]')?.value?.trim();
          const sel  = row.querySelector('.ep-edge-select');
          const ep   = (sel?.value === '__other__' || !sel)
            ? row.querySelector('.ep-edge-manual')?.value?.trim()
            : sel?.value?.trim();
          const tok  = row.querySelector('input[type=password]')?.value?.trim();
          if (name && ep) result[name] = { edge_endpoint: ep, auth_token: tok };
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
        <td style="padding:6px 10px;font-size:11px;color:var(--text2);">${esc(c.edge_name || '—')}${tls}</td>
      </tr>`;
    }).join('');
    return `<div style="overflow-x:auto;max-height:280px;overflow-y:auto;margin-bottom:16px;">
      <table style="width:100%;border-collapse:collapse;border:1px solid var(--border);border-radius:6px;overflow:hidden;">
        <thead>
          <tr style="background:var(--bg2);">
            <th style="padding:6px 10px;font-size:11px;font-weight:600;text-align:left;">${t('infra.col.host')}</th>
            <th style="padding:6px 10px;font-size:11px;font-weight:600;text-align:left;">${t('infra.col.backends')}</th>
            <th style="padding:6px 10px;font-size:11px;font-weight:600;text-align:left;">Passerelle</th>
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

async function deleteDeclaredNode(id) {
  if (!confirm(t('infra.confirm.delete_declared'))) return;
  try {
    await api('DELETE', '/declared-nodes/' + id);
    navigate('infrastructure');
  } catch(e) { alert(t('common.error_msg', { msg: e.message })); }
}

// pages.nodes redirige vers infrastructure (entrée nav supprimée).
pages.nodes = () => navigate('infrastructure');

window.nodeAction = async function(name, action) {
  try {
    await api('POST', `/nodes/${encodeURIComponent(name)}/${action}`);
    toast(t('infra.toast.action_started', { action, name }), 'success');
  } catch(e) { toast(e.message, 'error'); }
};

// ── Schéma temps réel : débit, statut, disponibilité de session ─────────────
// Sonde GET /nodes/live et /metrics/summary toutes les 5 s : met à jour le débit, l'historique de statut
// et les indicateurs, puis redessine la vue. Un nœud apparu, disparu ou dont le statut change modifie
// le modèle : rechargement complet de la page.

const TOPO_LIVE_POLL_MS = 5000;

function asApplyLive(live) {
  const m = {};
  for (const n of (live && live.nodes) || []) m[n.node_name] = n;
  window._asLive = m;
}

async function _topoLiveTick(content) {
  if (!content.isConnected || !document.getElementById('as-root')) return;
  const [live, metrics] = await Promise.all([
    api('GET', '/nodes/live').catch(() => null),
    api('GET', '/metrics/summary').catch(() => null),
  ]);
  if (!live || !content.isConnected || state.page !== 'infrastructure') return;
  const sig = live.nodes.map(n => n.node_name + ':' + n.status).join('|');
  if (window._topoSig !== undefined && window._topoSig !== sig) {
    window._topoSig = sig;
    pages.infrastructure();
    return;
  }
  window._topoSig = sig;
  if (metrics) window._asMetrics = metrics;
  asApplyLive(live);
  asSample(_arch);
  asRenderLive();
}

function startTopologyLive(content) {
  if (typeof content._cleanup === 'function') content._cleanup();
  window._topoSig = undefined;
  _topoLiveTick(content);
  const timer = setInterval(() => _topoLiveTick(content), TOPO_LIVE_POLL_MS);
  // Les liaisons du schéma suivent la position des nœuds (redimensionnement, polices chargées…).
  const root = document.getElementById('as-root');
  const ro = root && typeof ResizeObserver === 'function' ? new ResizeObserver(() => asDrawLinks()) : null;
  if (ro) ro.observe(root);
  content._cleanup = () => { clearInterval(timer); if (ro) ro.disconnect(); };
}
