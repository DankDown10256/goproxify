// ── Shared: UI config docker-compose / Portainer / CLI ─────────────────
// Chargé avant pages/infrastructure.js et le wizard.
// Extrait de pages-all.js — phase 2.

// ── Config UI partagé : onglets docker-compose / Portainer / CLI + toggle inline ──

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
  const { name, image, envVars, ports, volumes, restart, svcName } = opts;
  const svc = svcName || name;
  let envSection;
  if (mode === 'env_file')       envSection = `    env_file:\n      - .env`;
  else if (mode === 'portainer_vars') envSection = `    environment:` + envVars.map(({k}) => `\n      - ${k}=\${${k}}`).join('');
  else                           envSection = `    environment:` + envVars.map(({k,v}) => `\n      - ${k}=${v}`).join('');
  const portSection = ports.length ? `    ports:\n` + ports.map(p => `      - "${p}"`).join('\n') + '\n' : '';
  const volLines = volumes.map(v => `      - ${v}`).join('\n');
  const volSection = volumes.length ? `    volumes:\n${volLines}\n` : '';
  return `  ${svc}:\n    image: ${image}\n    container_name: ${name}\n    restart: ${restart}\n${portSection}${envSection}\n${volSection}    networks:\n      - goproxify-net`;
}

function _cfgComposeText(opts, mode) {
  const { name, netBlock } = opts;
  return `services:\n${_cfgComposeSvc(opts, mode)}\n\nvolumes:\n  ${name}_data:\n${netBlock}`;
}

function _cfgComposeTextFull(coreOpts, agentOpts, mode) {
  const coreSvc  = _cfgComposeSvc(coreOpts, mode);
  const agentSvc = _cfgComposeSvc(agentOpts, mode).replace(
    '    networks:\n      - goproxify-net',
    `    depends_on:\n      - ${coreOpts.svcName||coreOpts.name}\n    networks:\n      - goproxify-net`
  );
  const coreVol  = `  ${coreOpts.name}_data:`;
  const agentVol = agentOpts.volumes.filter(v=>!v.includes('docker.sock') && !v.includes('podman.sock')).map(v=>`  ${v.split(':')[0]}:`).join('\n');
  return `services:\n${coreSvc}\n\n${agentSvc}\n\nvolumes:\n${coreVol}\n${agentVol}\n${coreOpts.netBlock}`;
}

function _cfgEnvFileText(opts) {
  return opts.envVars.map(({k,v}) => `${k}=${v}`).join('\n');
}

function _cfgEnvFileTextFull(coreOpts, agentOpts) {
  const seen = new Set();
  return [...coreOpts.envVars, ...agentOpts.envVars]
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
    + `  --network goproxify-net \\\n  ${image}`;
}

function _cfgContentHTML(opts) {
  const { tab, inline } = window._cfgState;
  if (tab === 'cli') return _cfgLabel('Commande Docker') + _cfgPre('cfg-cli', _cfgCliText(opts));
  const mode = inline ? 'inline' : (tab === 'portainer' ? 'portainer_vars' : 'env_file');
  const compose = _cfgComposeText(opts, mode);
  const envFileName = tab === 'portainer' ? 'stack.env — Variables à saisir dans Portainer' : '.env';
  return _cfgLabel('docker-compose.yml') + _cfgPre('cfg-compose', compose)
    + (!inline ? _cfgLabel(envFileName) + _cfgPre('cfg-env', _cfgEnvFileText(opts)) : '');
}

function _cfgContentHTMLFull(coreOpts, agentOpts) {
  const { tab, inline } = window._cfgState;
  if (tab === 'cli') {
    return _cfgLabel('Core — Commande Docker') + _cfgPre('cfg-cli-core', _cfgCliText(coreOpts))
      + _cfgLabel('Agent — Commande Docker') + _cfgPre('cfg-cli-agent', _cfgCliText(agentOpts));
  }
  const mode = inline ? 'inline' : (tab === 'portainer' ? 'portainer_vars' : 'env_file');
  const compose = _cfgComposeTextFull(coreOpts, agentOpts, mode);
  const envFileName = tab === 'portainer' ? 'stack.env — Variables à saisir dans Portainer' : '.env';
  return _cfgLabel('docker-compose.yml') + _cfgPre('cfg-compose', compose)
    + (!inline ? _cfgLabel(envFileName) + _cfgPre('cfg-env', _cfgEnvFileTextFull(coreOpts, agentOpts)) : '');
}

function _cfgRender() {
  const area = document.getElementById('cfg-content-area');
  if (!area) return;
  area.innerHTML = window._cfgOptsFull
    ? _cfgContentHTMLFull(window._cfgOpts, window._cfgOptsFull)
    : _cfgContentHTML(window._cfgOpts);
  ['compose','portainer','cli'].forEach(t => {
    const btn = document.getElementById('cfg-tab-' + t);
    if (!btn) return;
    const active = t === window._cfgState.tab;
    btn.style.borderBottom = active ? '2px solid var(--accent)' : '2px solid transparent';
    btn.style.fontWeight = active ? '700' : '400';
    btn.style.color = active ? 'var(--accent)' : 'var(--text2)';
  });
  const tog = document.getElementById('cfg-toggle-row');
  if (tog) tog.style.display = window._cfgState.tab === 'cli' ? 'none' : 'flex';
}

window._cfgTab = function(tab) { window._cfgState.tab = tab; _cfgRender(); };
window._cfgToggle = function() {
  const cb = document.getElementById('cfg-inline-cb');
  window._cfgState.inline = cb ? cb.checked : false;
  _cfgRender();
};

function _renderConfigUI(opts, optsExtra) {
  window._cfgOpts = opts;
  window._cfgOptsFull = optsExtra || null;
  if (!window._cfgState) window._cfgState = { tab: 'compose', inline: false };
  const tabBtn = (id, lbl) =>
    `<button id="cfg-tab-${id}" onclick="_cfgTab('${id}')" style="padding:8px 14px;background:none;border:none;border-bottom:2px solid ${window._cfgState.tab===id?'var(--accent)':'transparent'};cursor:pointer;font-size:12px;font-weight:${window._cfgState.tab===id?700:400};color:${window._cfgState.tab===id?'var(--accent)':'var(--text2)'};">${lbl}</button>`;
  return `<div>
    <div style="display:flex;border-bottom:1px solid var(--border);margin-bottom:14px;">
      ${tabBtn('compose','docker-compose')}
      ${tabBtn('portainer','Portainer Stack')}
      ${tabBtn('cli','CLI')}
    </div>
    <div id="cfg-toggle-row" style="display:${window._cfgState.tab==='cli'?'none':'flex'};align-items:center;gap:8px;margin-bottom:12px;">
      <label style="display:flex;align-items:center;gap:7px;font-size:12px;cursor:pointer;color:var(--text1);">
        <input type="checkbox" id="cfg-inline-cb" ${window._cfgState.inline?'checked':''} onchange="_cfgToggle()" style="accent-color:var(--accent);width:14px;height:14px;">
        Inliner les valeurs <span style="color:var(--text2);">(sans fichier .env)</span>
      </label>
    </div>
    <div id="cfg-content-area">${optsExtra ? _cfgContentHTMLFull(opts, optsExtra) : _cfgContentHTML(opts)}</div>
  </div>`;
}

// ── Constructeurs d'options ────────────────────────────────────────────────

function _buildCoreOpts(d) {
  const name     = (d.wc_name || 'core-1').trim();
  const restart  = d.wc_restart || 'unless-stopped';
  const logLevel = d.wc_log || 'info';
  const cluster  = !!d.wc_cluster;
  const image    = 'ghcr.io/vincamok/goproxify/core:preview';
  const netBlock = `\nnetworks:\n  goproxify-net:\n    driver: bridge`;
  const portal = !!d.wc_portal;
  const nodeID = (d.wc_cluster_node_id || name).trim();
  const group  = (d.wc_cluster_group || 'ha-1').trim();
  const peers  = (d.wc_cluster_peers || '').trim();
  const envVars = [
    { k:'GPX_IDENTITY_CORE_NODE_NAME', v: name },
    { k:'GPX_PAIRING_SECRET',           v: _wiz.pairingSecret || '' },
    { k:'GPX_ENGINE_LOG_LEVEL',        v: logLevel },
    cluster ? { k:'GPX_CLUSTER_ENABLED',    v: 'true' } : null,
    cluster ? { k:'GPX_CLUSTER_RAFT_PORT',  v: '8002' } : null,
    cluster ? { k:'GPX_CLUSTER_NODE_ID',    v: nodeID } : null,
    cluster ? { k:'GPX_CLUSTER_GROUP_NAME', v: group } : null,
    cluster && peers ? { k:'GPX_CLUSTER_PEERS', v: peers } : null,
    // Compat wizard infra historique (ignoré par Core ; peers poussés par Admin sinon)
    cluster && d.wc_raft_leader && !peers ? { k:'GPX_CLUSTER_RAFT_LEADER', v: d.wc_raft_leader } : null,
    portal ? { k:'GPX_PORTAL_ENABLED', v: 'true' } : null,
  ].filter(Boolean);
  const ports = ['80:80','443:443'];
  if (d.wc_http3) ports.push('443:443/udp');
  ports.push('8000:8000');
  if (cluster) ports.push('8002:8002');
  if (portal) { ports.push('2222:2222'); ports.push('8444:8444'); }
  _wiz.coreSvcName = name;
  return { name, svcName: name, image, envVars, ports, volumes:[`${name}_data:/etc/goproxify`], netBlock, restart };
}

function _buildAgentOpts(d) {
  const isFull  = _wiz.scenario === 'full';
  const name    = (d.wa_name || 'agent-1').trim();
  const restart = d.wa_restart || (isFull ? d.wc_restart : 'unless-stopped') || 'unless-stopped';
  const coreName = isFull ? (d.wc_name || 'goproxify-core') : null;
  const coreURL = d.wa_core_url || (coreName ? `http://${coreName}:8000` : 'http://goproxify-core:8000');
  const image   = 'ghcr.io/vincamok/goproxify/agent:preview';
  const netBlock = `\nnetworks:\n  goproxify-net:\n    driver: bridge`;
  const coreContainer = d.wa_core_container_name || coreName || '';
  const runtime = d.wa_runtime || (d.wa_podman ? 'podman' : (d.wa_docker !== false ? 'docker' : ''));
  const useContainerRuntime = runtime === 'docker' || runtime === 'podman';
  const sockHost = runtime === 'podman' ? '/run/podman/podman.sock' : '/var/run/docker.sock';
  const envVars = [
    { k:'GPX_IDENTITY_AGENT_NODE_NAME',       v: name },
    { k:'GPX_CONTROL_PLANE_CORE_ENDPOINT',    v: coreURL },
    { k:'GPX_PAIRING_SECRET',                 v: _wiz.pairingSecret || '' },
    d.wa_region ? { k:'GPX_IDENTITY_REGION',  v: d.wa_region } : null,
    useContainerRuntime ? { k:'GPX_DOCKER_RUNTIME', v: runtime } : null,
    useContainerRuntime && coreContainer ? { k:'GPX_NETWORK_MANAGEMENT_CORE_CONTAINER_NAME', v: coreContainer } : null,
    d.wa_k8s       ? { k:'GPX_KUBERNETES_ENABLED',     v: 'true' }              : null,
    d.wa_portainer ? { k:'GPX_PORTAINER_ENABLED',      v: 'true' }              : null,
    d.wa_portainer&&d.wa_portainer_url ? { k:'GPX_PORTAINER_URL',     v: d.wa_portainer_url } : null,
    d.wa_portainer&&d.wa_portainer_key ? { k:'GPX_PORTAINER_API_KEY', v: d.wa_portainer_key } : null,
    d.wa_log_fwd   ? { k:'GPX_LOG_FORWARDING_ENABLED', v: 'true' }              : null,
    d.wa_autoscale ? { k:'GPX_AUTOSCALE_ENABLED',      v: 'true' }              : null,
  ].filter(Boolean);
  const volumes = [];
  if (useContainerRuntime) volumes.push(`${sockHost}:${sockHost}:ro`);
  volumes.push(`${name}_data:/etc/goproxify`);
  return { name, svcName: name, image, envVars, ports: [], volumes, netBlock, restart };
}
