// ── Shared: UI config docker-compose / Portainer / CLI ─────────────────
// Chargé avant pages/infrastructure.js et le wizard.
// Extrait de pages-all.js — phase 2.

// ── Config UI partagé : onglets docker-compose / Portainer / CLI + toggle inline ──

// State and opts stored per uid so multiple config UIs can coexist on the same page.
window._cfgStates = {};
window._cfgOptsMap = {};
// Legacy single-instance compat (infra modal uses no uid)
window._cfgState = { tab: 'compose', inline: false };

function _cfgPre(id, text) {
  return `<div style="position:relative;margin-bottom:12px;">
    <button class="btn btn-ghost btn-sm" style="position:absolute;top:6px;right:6px;font-size:11px;z-index:1;"
      onclick="navigator.clipboard.writeText(document.getElementById('${id}').textContent).then(()=>toast('Copié','success'))">Copier</button>
    <pre id="${id}" style="background:var(--bg2);border-radius:6px;padding:12px 80px 12px 14px;font-size:11px;overflow-x:auto;white-space:pre;color:var(--text1);margin:0;max-height:300px;overflow-y:auto;">${esc(text)}</pre>
  </div>`;
}

function _cfgLabel(txt) {
  return `<div style="font-size:11px;font-weight:600;letter-spacing:.05em;text-transform:uppercase;color:var(--text2);margin-bottom:6px;">${txt}</div>`;
}

function _cfgComposeSvc(opts, mode) {
  const { name, image, envVars, ports, volumes, restart, svcName, command } = opts;
  const svc = svcName || name;
  let envSection;
  if (mode === 'env_file')           envSection = `    env_file:\n      - .env`;
  else if (mode === 'portainer_vars') envSection = `    environment:` + envVars.map(({k}) => `\n      - ${k}=\${${k}}`).join('');
  else                               envSection = `    environment:` + envVars.map(({k,v}) => `\n      - ${k}=${v}`).join('');
  const portSection = ports.length ? `    ports:\n` + ports.map(p => `      - "${p}"`).join('\n') + '\n' : '';
  const volLines = volumes.map(v => `      - ${v}`).join('\n');
  const volSection = volumes.length ? `    volumes:\n${volLines}\n` : '';
  const cmdSection = command ? `    command: ["${command}"]\n` : '';
  return `  ${svc}:\n    image: ${image}\n    container_name: ${name}\n    restart: ${restart}\n${cmdSection}${portSection}${envSection}\n${volSection}    networks:\n      - goproxify_net`;
}

function _cfgComposeText(opts, mode) {
  const { name, netBlock } = opts;
  return `services:\n${_cfgComposeSvc(opts, mode)}\n\nvolumes:\n  ${name}_data:\n${netBlock}`;
}

function _cfgComposeTextFull(edgeOpts, agentOpts, mode) {
  const edgeSvc  = _cfgComposeSvc(edgeOpts, mode);
  const agentSvc = _cfgComposeSvc(agentOpts, mode).replace(
    '    networks:\n      - goproxify_net',
    `    depends_on:\n      - ${edgeOpts.svcName||edgeOpts.name}\n    networks:\n      - goproxify_net`
  );
  const edgeVol  = `  ${edgeOpts.name}_data:`;
  const agentVol = agentOpts.volumes.filter(v=>!v.includes('docker.sock') && !v.includes('podman.sock')).map(v=>`  ${v.split(':')[0]}:`).join('\n');
  return `services:\n${edgeSvc}\n\n${agentSvc}\n\nvolumes:\n${edgeVol}\n${agentVol}\n${edgeOpts.netBlock}`;
}

function _cfgEnvFileText(opts) {
  return opts.envVars.map(({k,v}) => `${k}=${v}`).join('\n');
}

function _cfgEnvFileTextFull(edgeOpts, agentOpts) {
  const seen = new Set();
  return [...edgeOpts.envVars, ...agentOpts.envVars]
    .filter(({k}) => { if (seen.has(k)) return false; seen.add(k); return true; })
    .map(({k,v}) => `${k}=${v}`).join('\n');
}

function _cfgCliText(opts) {
  const { name, image, envVars, ports, volumes, restart } = opts;
  const pFlags = ports.map(p => `  -p ${p}`).join(' \\\n');
  const eFlags = envVars.map(({k,v}) => `  -e ${k}=${v}`).join(' \\\n');
  const vFlags = volumes.map(v => `  -v ${v}`).join(' \\\n');
  return `docker run -d \\\n  --name ${name} \\\n  --restart ${restart} \\\n`
    + (pFlags ? pFlags + ' \\\n' : '')
    + eFlags + ' \\\n'
    + (vFlags ? vFlags + ' \\\n' : '')
    + `  --network goproxify_net \\\n  ${image}`;
}

function _cfgMode(state) {
  return state.inline ? 'inline' : (state.tab === 'portainer' ? 'portainer_vars' : 'env_file');
}

function _cfgEnvFileName(tab) {
  return tab === 'portainer' ? 'stack.env — Variables à saisir dans Portainer' : '.env';
}

function _cfgContentHTML(opts, uid, adminOpts) {
  const state = window._cfgStates[uid] || window._cfgState;
  const { tab, inline } = state;
  const p = uid ? uid + '-' : '';
  if (tab === 'cli') {
    return _cfgLabel('Commande Docker') + _cfgPre(p + 'cfg-cli', _cfgCliText(opts))
      + (adminOpts ? _cfgLabel('Admin — Commande Docker') + _cfgPre(p + 'cfg-cli-admin', _cfgCliText(adminOpts)) : '');
  }
  const mode = _cfgMode(state);
  const compose = adminOpts ? _cfgComposeTextAdmin(opts, adminOpts, mode) : _cfgComposeText(opts, mode);
  const envText = adminOpts
    ? [...opts.envVars, ...adminOpts.envVars].map(({k,v}) => `${k}=${v}`).join('\n')
    : _cfgEnvFileText(opts);
  return _cfgLabel('docker-compose.yml') + _cfgPre(p + 'cfg-compose', compose)
    + (!inline ? _cfgLabel(_cfgEnvFileName(tab)) + _cfgPre(p + 'cfg-env', envText) : '');
}

function _cfgContentHTMLFull(edgeOpts, agentOpts, uid, adminOpts) {
  const state = window._cfgStates[uid] || window._cfgState;
  const { tab, inline } = state;
  const p = uid ? uid + '-' : '';
  if (tab === 'cli') {
    return _cfgLabel('Passerelle — Commande Docker') + _cfgPre(p + 'cfg-cli-edge', _cfgCliText(edgeOpts))
      + _cfgLabel('Agent — Commande Docker') + _cfgPre(p + 'cfg-cli-agent', _cfgCliText(agentOpts))
      + (adminOpts ? _cfgLabel('Admin — Commande Docker') + _cfgPre(p + 'cfg-cli-admin', _cfgCliText(adminOpts)) : '');
  }
  const mode = _cfgMode(state);
  const compose = adminOpts
    ? _cfgComposeTextFullAdmin(edgeOpts, agentOpts, adminOpts, mode)
    : _cfgComposeTextFull(edgeOpts, agentOpts, mode);
  const envText = adminOpts
    ? _cfgEnvFileTextFull(edgeOpts, agentOpts) + '\n' + adminOpts.envVars.map(({k,v}) => `${k}=${v}`).join('\n')
    : _cfgEnvFileTextFull(edgeOpts, agentOpts);
  return _cfgLabel('docker-compose.yml') + _cfgPre(p + 'cfg-compose', compose)
    + (!inline ? _cfgLabel(_cfgEnvFileName(tab)) + _cfgPre(p + 'cfg-env', envText) : '');
}

function _cfgRender(uid) {
  const p = uid ? uid + '-' : '';
  const state = uid ? (window._cfgStates[uid] || (window._cfgStates[uid] = { tab: 'compose', inline: false })) : window._cfgState;
  const optsEntry = uid ? (window._cfgOptsMap[uid] || {}) : { opts: window._cfgOpts, extra: window._cfgOptsFull, admin: window._cfgOptsAdmin };
  const area = document.getElementById(p + 'cfg-content-area');
  if (!area) return;
  area.innerHTML = optsEntry.extra
    ? _cfgContentHTMLFull(optsEntry.opts, optsEntry.extra, uid, optsEntry.admin)
    : _cfgContentHTML(optsEntry.opts, uid, optsEntry.admin);
  ['compose','portainer','cli'].forEach(t => {
    const btn = document.getElementById(p + 'cfg-tab-' + t);
    if (!btn) return;
    const active = t === state.tab;
    btn.style.borderBottom = active ? '2px solid var(--accent)' : '2px solid transparent';
    btn.style.fontWeight = active ? '700' : '400';
    btn.style.color = active ? 'var(--accent)' : 'var(--text2)';
  });
  const tog = document.getElementById(p + 'cfg-toggle-row');
  if (tog) tog.style.display = state.tab === 'cli' ? 'none' : 'flex';
}

window._cfgTab = function(tab, uid) {
  if (uid) {
    if (!window._cfgStates[uid]) window._cfgStates[uid] = { tab: 'compose', inline: false };
    window._cfgStates[uid].tab = tab;
  } else {
    window._cfgState.tab = tab;
  }
  _cfgRender(uid);
};
window._cfgToggle = function(uid) {
  const p = uid ? uid + '-' : '';
  const cb = document.getElementById(p + 'cfg-inline-cb');
  if (uid) {
    if (!window._cfgStates[uid]) window._cfgStates[uid] = { tab: 'compose', inline: false };
    window._cfgStates[uid].inline = cb ? cb.checked : false;
  } else {
    window._cfgState.inline = cb ? cb.checked : false;
  }
  _cfgRender(uid);
};

function _renderConfigUI(opts, optsExtra, uid, adminOpts) {
  const p = uid ? uid + '-' : '';
  if (uid) {
    if (!window._cfgStates[uid]) window._cfgStates[uid] = { tab: 'compose', inline: false };
    window._cfgOptsMap[uid] = { opts, extra: optsExtra || null, admin: adminOpts || null };
  } else {
    window._cfgOpts = opts;
    window._cfgOptsFull = optsExtra || null;
    window._cfgOptsAdmin = adminOpts || null;
    if (!window._cfgState) window._cfgState = { tab: 'compose', inline: false };
  }
  const state = uid ? window._cfgStates[uid] : window._cfgState;
  const tabBtn = (id, lbl) =>
    `<button id="${p}cfg-tab-${id}" onclick="_cfgTab('${id}'${uid ? ",'" + uid + "'" : ''})" style="padding:8px 14px;background:none;border:none;border-bottom:2px solid ${state.tab===id?'var(--accent)':'transparent'};cursor:pointer;font-size:12px;font-weight:${state.tab===id?700:400};color:${state.tab===id?'var(--accent)':'var(--text2)'};">${lbl}</button>`;
  return `<div>
    <div style="display:flex;border-bottom:1px solid var(--border);margin-bottom:14px;">
      ${tabBtn('compose','docker-compose')}
      ${tabBtn('portainer','Portainer Stack')}
      ${tabBtn('cli','CLI')}
    </div>
    <div id="${p}cfg-toggle-row" style="display:${state.tab==='cli'?'none':'flex'};align-items:center;gap:8px;margin-bottom:12px;">
      <label style="display:flex;align-items:center;gap:7px;font-size:12px;cursor:pointer;color:var(--text1);">
        <input type="checkbox" id="${p}cfg-inline-cb" ${state.inline?'checked':''} onchange="_cfgToggle(${uid ? "'" + uid + "'" : ''})" style="accent-color:var(--accent);width:14px;height:14px;">
        Inliner les valeurs <span style="color:var(--text2);">(sans fichier .env)</span>
      </label>
    </div>
    <div id="${p}cfg-content-area">${optsExtra ? _cfgContentHTMLFull(opts, optsExtra, uid, adminOpts) : _cfgContentHTML(opts, uid, adminOpts)}</div>
  </div>`;
}

// ── Constructeurs d'options ────────────────────────────────────────────────

function _buildEdgeOpts(d) {
  const cat      = window._gpxCatalog;
  const name     = (d.wc_name || 'edge-1').trim();
  const restart  = d.wc_restart || 'unless-stopped';
  const logLevel = d.wc_log || 'info';
  const cluster  = !!d.wc_cluster;
  const portal   = !!d.wc_portal;
  const nodeID   = (d.wc_cluster_node_id || name).trim();
  const group    = (d.wc_cluster_group || 'ha-1').trim();
  const peers    = (d.wc_cluster_peers || '').trim();
  const envVars = [
    { k:'GPX_IDENTITY_EDGE_NODE_NAME', v: name },
    { k:'GPX_PAIRING_SECRET',          v: _wiz.pairingSecret || '' },
    { k:'GPX_ENGINE_LOG_LEVEL',        v: logLevel },
    cluster ? { k:'GPX_CLUSTER_ENABLED',    v: 'true' } : null,
    cluster ? { k:'GPX_CLUSTER_RAFT_PORT',  v: '8002' } : null,
    cluster ? { k:'GPX_CLUSTER_NODE_ID',    v: nodeID } : null,
    cluster ? { k:'GPX_CLUSTER_GROUP_NAME', v: group } : null,
    cluster && peers ? { k:'GPX_CLUSTER_PEERS', v: peers } : null,
    // Compat wizard infra historique (ignoré par passerelle ; peers poussés par Admin sinon)
    cluster && d.wc_raft_leader && !peers ? { k:'GPX_CLUSTER_RAFT_LEADER', v: d.wc_raft_leader } : null,
    portal ? { k:'GPX_PORTAL_ENABLED', v: 'true' } : null,
  ].filter(Boolean);
  const image    = cat ? cat.image('edge') : 'ghcr.io/vincamok/goproxify/edge:preview';
  const netBlock = cat ? cat.netBlock()    : '\nnetworks:\n  goproxify_net:\n    driver: bridge';
  const ports    = cat ? cat.portStrings('edge', { http3: d.wc_http3, cluster, portal }) : (function(){
    const p = ['80:80','443:443'];
    if (d.wc_http3) p.push('443:443/udp');
    p.push('8000:8000');
    if (cluster) p.push('8002:8002');
    if (portal)  { p.push('2222:2222'); p.push('8444:8444'); }
    return p;
  })();
  _wiz.edgeSvcName = name;
  return { name, svcName: name, image, envVars, ports, volumes:[`${name}_data:/etc/goproxify`], netBlock, restart, command: 'edge' };
}

function _buildAgentOpts(d) {
  const cat      = window._gpxCatalog;
  const isFull   = _wiz.scenario === 'full';
  const name     = (d.wa_name || 'agent-1').trim();
  const restart  = d.wa_restart || (isFull ? d.wc_restart : 'unless-stopped') || 'unless-stopped';
  const edgeName = isFull ? (d.wc_name || 'goproxify-edge') : null;
  const edgeURL  = d.wa_edge_url || (edgeName ? `http://${edgeName}:8000` : 'http://goproxify-edge:8000');
  const edgeContainer = d.wa_edge_container_name || edgeName || '';
  const runtime  = d.wa_runtime || (d.wa_podman ? 'podman' : (d.wa_docker !== false ? 'docker' : ''));
  const useContainerRuntime = runtime === 'docker' || runtime === 'podman';
  const sockHost = runtime === 'podman' ? '/run/podman/podman.sock' : '/var/run/docker.sock';
  const adminName = isFull ? (d.wa_admin_name || 'goproxify-admin') : null;
  const adminURL  = d.wa_admin_url || (adminName ? `http://${adminName}:9443` : '');
  const envVars = [
    { k:'GPX_IDENTITY_AGENT_NODE_NAME',          v: name },
    { k:'GPX_CONTROL_PLANE_EDGE_ENDPOINT',       v: edgeURL },
    adminURL ? { k:'GPX_CONTROL_PLANE_ADMIN_ENDPOINT', v: adminURL } : null,
    { k:'GPX_PAIRING_SECRET',                    v: _wiz.pairingSecret || '' },
    d.wa_region ? { k:'GPX_IDENTITY_REGION',  v: d.wa_region } : null,
    useContainerRuntime ? { k:'GPX_DOCKER_ENABLED',  v: 'true' } : null,
    useContainerRuntime ? { k:'GPX_DOCKER_RUNTIME', v: runtime } : null,
    useContainerRuntime && edgeContainer ? { k:'GPX_NETWORK_MANAGEMENT_EDGE_CONTAINER_NAME', v: edgeContainer } : null,
    d.wa_k8s       ? { k:'GPX_KUBERNETES_ENABLED',     v: 'true' } : null,
    d.wa_portainer ? { k:'GPX_PORTAINER_ENABLED',      v: 'true' } : null,
    d.wa_portainer&&d.wa_portainer_url ? { k:'GPX_PORTAINER_URL',     v: d.wa_portainer_url } : null,
    d.wa_portainer&&d.wa_portainer_key ? { k:'GPX_PORTAINER_API_KEY', v: d.wa_portainer_key } : null,
    d.wa_log_fwd   ? { k:'GPX_LOG_FORWARDING_ENABLED', v: 'true' } : null,
  ].filter(Boolean);
  const image    = cat ? cat.image('agent') : 'ghcr.io/vincamok/goproxify/agent:preview';
  const netBlock = cat ? cat.netBlock()     : '\nnetworks:\n  goproxify_net:\n    driver: bridge';
  const volumes  = [];
  if (useContainerRuntime) volumes.push(`${sockHost}:${sockHost}:ro`);
  volumes.push(`${name}_data:/etc/goproxify`);
  return { name, svcName: name, image, envVars, ports: [], volumes, netBlock, restart, command: 'agent' };
}

function _buildAdminOpts(d) {
  const cat      = window._gpxCatalog;
  const name     = 'goproxify-admin';
  const edgeName = (d.wa_edge_name || _wiz.edgeSvcName || 'goproxify-edge').trim();
  const envVars  = [
    { k: 'GPX_SECURITY_JWT_SECRET',     v: d.wa_jwt_secret || '' },
    { k: 'GPX_PAIRING_SECRET',          v: _wiz.pairingSecret || '' },
    { k: 'GPX_FIRST_ADMIN_EMAIL',       v: d.wa_admin_email || 'admin@example.com' },
    { k: 'GPX_FIRST_ADMIN_PASSWORD',    v: d.wa_admin_password || 'CHANGE_ME' },
    { k: 'GPX_IDENTITY_EDGE_NODE_NAME', v: edgeName },
    { k: 'GPX_SERVER_API_PORT',         v: '9443' },
  ];
  const image    = cat ? cat.image('admin') : 'ghcr.io/vincamok/goproxify/admin:preview';
  const netBlock = cat ? cat.netBlock()     : '\nnetworks:\n  goproxify_net:\n    driver: bridge';
  const ports    = cat ? cat.portStrings('admin') : ['9443:9443'];
  return { name, svcName: name, image, envVars, ports, volumes: [`${name}_data:/etc/goproxify`], netBlock, restart: 'unless-stopped', command: 'admin' };
}

function _cfgComposeTextAdmin(edgeOpts, adminOpts, mode) {
  const edgeSvc  = _cfgComposeSvc(edgeOpts, mode);
  const adminSvc = _cfgComposeSvc(adminOpts, mode);
  const edgeVol  = `  ${edgeOpts.name}_data:`;
  const adminVol = `  ${adminOpts.name}_data:`;
  return `services:\n${edgeSvc}\n\n${adminSvc}\n\nvolumes:\n${edgeVol}\n${adminVol}\n${edgeOpts.netBlock}`;
}

function _cfgComposeTextFullAdmin(edgeOpts, agentOpts, adminOpts, mode) {
  const edgeSvc  = _cfgComposeSvc(edgeOpts, mode);
  const agentSvc = _cfgComposeSvc(agentOpts, mode).replace(
    '    networks:\n      - goproxify_net',
    `    depends_on:\n      - ${edgeOpts.svcName||edgeOpts.name}\n    networks:\n      - goproxify_net`
  );
  const adminSvc = _cfgComposeSvc(adminOpts, mode);
  const edgeVol  = `  ${edgeOpts.name}_data:`;
  const agentVol = agentOpts.volumes.filter(v=>!v.includes('docker.sock') && !v.includes('podman.sock')).map(v=>`  ${v.split(':')[0]}:`).join('\n');
  const adminVol = `  ${adminOpts.name}_data:`;
  return `services:\n${edgeSvc}\n\n${agentSvc}\n\n${adminSvc}\n\nvolumes:\n${edgeVol}\n${agentVol}\n${adminVol}\n${edgeOpts.netBlock}`;
}
