// Wizard architecture : toile hôtes + palette → packs + checklist réseau.
// Dépend de shared/infra-config.js et pages/infrastructure.js (_wiz helpers, _build*, declared-nodes).

const _arch = {
  step: 'canvas', // canvas | handoff
  hosts: [],
  haGroupIds: [], // service ids (core) members of one HA group (v1: un seul groupe)
  selectedSvcId: null,
  packs: [], // { hostId, hostName, html, flows, bootstrapUrl }
  pairingSecret: '',
  coreList: [],
  declaredNodes: [],
  onlineCoreEndpoint: '',
  existingCount: 0,
};

function _archUid(prefix) {
  return prefix + '-' + Math.random().toString(36).slice(2, 9);
}

function _archEmptyHost(n) {
  return { id: _archUid('host'), name: t('arch.host_default', { n: n || 1 }) || ('Hôte ' + (n || 1)), services: [], internet: false, region: '' };
}

function _archParseCfg(cfg) {
  if (!cfg) return {};
  if (typeof cfg === 'string') {
    try { return JSON.parse(cfg); } catch { return {}; }
  }
  return typeof cfg === 'object' ? cfg : {};
}

function _archResolveCoreKey(tc, cores) {
  if (!tc) return '';
  const s = String(tc).trim();
  if (cores.some(c => (c.node_name || c.id) === s)) return s;
  const m = s.match(/https?:\/\/([^/:]+)/i);
  if (m) {
    const host = m[1];
    const hit = cores.find(c => (c.node_name || c.id) === host);
    if (hit) return hit.node_name || hit.id;
  }
  return '';
}

function _archLooksColocatedTarget(target, coreName) {
  const t = String(target || '').trim();
  if (!t || !coreName) return false;
  const m = t.match(/https?:\/\/([^/:]+)/i);
  if (!m) return false;
  const host = m[1];
  if (host !== coreName) return false;
  // Hostname docker-compose (pas d’IP, pas de FQDN)
  return !/^\d+\.\d+\.\d+\.\d+$/.test(host) && !host.includes('.');
}

function _archSvcFromExisting(role, node, cfg) {
  const name = (node.display_name || node.node_name || node.name || role).trim();
  const runtimes = node.container_runtimes || [];
  const hasDocker = runtimes.some(r => String(r).toLowerCase().includes('docker'));
  const hasPodman = runtimes.some(r => String(r).toLowerCase().includes('podman'));
  let docker = cfg.docker !== false;
  let podman = !!cfg.podman;
  if (cfg.docker === false && !cfg.podman) docker = false;
  if (hasPodman && !hasDocker) { podman = true; docker = false; }
  else if (hasDocker) { docker = true; podman = false; }
  if (role === 'agent' && cfg.docker === undefined && cfg.podman === undefined && !runtimes.length) {
    docker = true;
    podman = false;
  }
  return {
    id: _archUid(role),
    type: role,
    name,
    access: !!cfg.portal,
    portainer: !!cfg.portainer,
    k8s: !!cfg.k8s,
    docker: role === 'agent' ? docker : false,
    podman: role === 'agent' ? podman : false,
    autoscale: !!cfg.autoscale,
    domains: cfg.domains || '',
    acme: !!cfg.acme,
    acmeEmail: cfg.acme_email || '',
    dnsProvider: cfg.dns_provider || 'none',
    reachable: (cfg.reachable_host || '').trim(),
    portainerUrl: cfg.portainer_url || '',
    portainerKey: cfg.portainer_key || '',
    targetCoreId: '',
    placement: (cfg.placement || '').trim(),
    existing: true,
    status: node.status || 'declared',
  };
}

/** Reprend Cores/Agents live + déclarés sur la toile (hôtes + options). */
function _archHydrateFromExisting(nodes, declared) {
  const list = (Array.isArray(nodes) ? nodes : []).filter(n =>
    (n.role === 'core' || n.role === 'agent') && n.status !== 'pending'
  );
  if (!list.length) return { hosts: [_archEmptyHost(1)], haGroupIds: [], existingCount: 0 };

  const declByName = {};
  for (const d of (Array.isArray(declared) ? declared : [])) {
    if (d && d.name) declByName[d.name] = d;
  }

  const cores = list.filter(n => n.role === 'core');
  const agents = list.filter(n => n.role === 'agent');
  const hosts = [];
  const hostByKey = new Map();
  const coreSvcByName = new Map();
  const haGroupIds = [];

  const ensureHost = (key, opts) => {
    if (hostByKey.has(key)) {
      const h = hostByKey.get(key);
      if (opts.region && !h.region) h.region = opts.region;
      if (opts.internet) h.internet = true;
      return h;
    }
    const h = {
      id: _archUid('host'),
      name: opts.name || key,
      services: [],
      internet: !!opts.internet,
      region: opts.region || '',
    };
    hostByKey.set(key, h);
    hosts.push(h);
    return h;
  };

  for (const c of cores) {
    const cName = (c.node_name || c.id || '').trim();
    if (!cName) continue;
    const d = declByName[cName] || declByName[c.display_name];
    const cfg = _archParseCfg(d && d.config);
    const host = ensureHost('core:' + cName, {
      name: c.display_name || cName,
      region: (d && d.region) || c.region || '',
      internet: !!cfg.internet_exposed,
    });
    const svc = _archSvcFromExisting('core', c, cfg);
    host.services.push(svc);
    coreSvcByName.set(cName, svc);
    if (cfg.cluster) haGroupIds.push(svc.id);
  }

  for (const a of agents) {
    const aName = (a.node_name || a.id || '').trim();
    if (!aName) continue;
    const d = declByName[aName] || declByName[a.display_name];
    const cfg = _archParseCfg(d && d.config);
    const placement = (cfg.placement || '').trim();
    const target = (cfg.target_core || a.target_core || '').trim();
    const coreKey = _archResolveCoreKey(target, cores)
      || _archResolveCoreKey(a.target_core || '', cores);
    let host;
    // Colocated seulement si déclaré ainsi, ou URL docker-interne (http://core-name:8000).
    // Les agents live ont target_core = nom du Core sans être sur le même hôte.
    const colocate = (placement === 'colocated' && coreKey)
      || (placement !== 'remote' && coreKey && _archLooksColocatedTarget(cfg.target_core || '', coreKey));
    if (colocate && hostByKey.has('core:' + coreKey)) {
      host = hostByKey.get('core:' + coreKey);
      if ((d && d.region) || a.region) {
        if (!host.region) host.region = (d && d.region) || a.region || '';
      }
      if (cfg.internet_exposed) host.internet = true;
    } else {
      host = ensureHost('agent:' + aName, {
        name: a.display_name || aName,
        region: (d && d.region) || a.region || '',
        internet: !!cfg.internet_exposed,
      });
    }
    const svc = _archSvcFromExisting('agent', a, cfg);
    if (coreKey && coreSvcByName.has(coreKey)) svc.targetCoreId = coreSvcByName.get(coreKey).id;
    if (colocate) svc.placement = 'colocated';
    else if (!svc.placement) svc.placement = 'remote';
    host.services.push(svc);
  }

  return { hosts: hosts.length ? hosts : [_archEmptyHost(1)], haGroupIds, existingCount: list.length };
}

function openArchWizard() {
  _arch.step = 'canvas';
  _arch.hosts = [_archEmptyHost(1)];
  _arch.haGroupIds = [];
  _arch.selectedSvcId = null;
  _arch.packs = [];
  _arch.pairingSecret = '';
  _arch.coreList = [];
  _arch.declaredNodes = [];
  _arch.onlineCoreEndpoint = '';
  _arch.existingCount = 0;
  Promise.all([
    api('GET', '/pairing-secret').catch(() => null),
    api('GET', '/nodes').catch(() => null),
    api('GET', '/tokens?role=core').catch(() => null),
    api('GET', '/declared-nodes').catch(() => null),
  ]).then(([sec, nodes, tokens, declared]) => {
    _arch.pairingSecret = sec?.secret || '';
    _wiz.pairingSecret = _arch.pairingSecret;
    _arch.coreList = typeof _wizLoadCoreList === 'function' ? _wizLoadCoreList(nodes, tokens) : [];
    _arch.declaredNodes = Array.isArray(declared) ? declared : [];
    _wiz.declaredNodes = _arch.declaredNodes;
    const online = (_arch.coreList || []).find(c => (c.status || '') === 'online' || c.node_endpoint);
    if (online) {
      _arch.onlineCoreEndpoint = online.node_endpoint || online.endpoint || '';
    }
    const hydrated = _archHydrateFromExisting(nodes, _arch.declaredNodes);
    _arch.hosts = hydrated.hosts;
    _arch.haGroupIds = hydrated.haGroupIds;
    _arch.existingCount = hydrated.existingCount || 0;
    // Cores déclarés absents de /nodes → déjà dans nodes via status declared ; sync coreList
    for (const n of _arch.declaredNodes.filter(x => x.role === 'core')) {
      if (_arch.coreList.some(c => c.node_name === n.name)) continue;
      const cfg = _archParseCfg(n.config);
      const host = (cfg.reachable_host || '').trim();
      _arch.coreList.push({
        node_name: n.name,
        display_name: n.name,
        role: 'core',
        status: 'declared',
        node_endpoint: host && typeof _wizCoreEndpoint === 'function' ? _wizCoreEndpoint(host) : '',
      });
    }
    _archRender();
  });
  _archRender();
}

function closeArchWizard() {
  const el = document.getElementById('arch-wizard-overlay');
  if (el) el.remove();
}

function _archRender() {
  let overlay = document.getElementById('arch-wizard-overlay');
  if (!overlay) {
    overlay = document.createElement('div');
    overlay.id = 'arch-wizard-overlay';
    overlay.style.cssText = 'position:fixed;inset:0;z-index:9000;background:rgba(0,0,0,.55);display:flex;align-items:center;justify-content:center;padding:12px;';
    document.body.appendChild(overlay);
  }
  overlay.innerHTML = _arch.step === 'handoff' ? _archHandoffHTML() : _archCanvasHTML();
}

function _archPaletteItem(type, label, accent) {
  return `<div draggable="true" data-arch-type="${type}"
    ondragstart="_archDragStart(event)"
    class="arch-pal-item"
    style="cursor:grab;user-select:none;padding:9px 11px;border-radius:8px;border:1px solid color-mix(in srgb,${accent} 35%,var(--border));background:var(--bg2);font-size:12.5px;font-weight:600;color:var(--text1);display:flex;align-items:center;gap:8px;">
    <span style="width:7px;height:7px;border-radius:50%;background:${accent};flex:none;"></span>
    <span style="line-height:1.25;">${esc(label)}</span>
  </div>`;
}

function _archPaletteSection(title, itemsHTML) {
  return `<div style="margin-bottom:14px;">
    <div style="font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--text2);margin-bottom:7px;opacity:.9;">${esc(title)}</div>
    <div style="display:flex;flex-direction:column;gap:6px;">${itemsHTML}</div>
  </div>`;
}

function _archCanvasHTML() {
  const edgeHosts = _arch.hosts.filter(h => h.internet);
  const privateHosts = _arch.hosts.filter(h => !h.internet);
  const err = _archValidate() || '';
  const inetCount = edgeHosts.length;

  const zone = (title, hint, hosts, emptyKey) => {
    const cards = hosts.map(h => _archHostCard(h)).join('');
    return `<section style="margin-bottom:16px;">
      <div style="display:flex;align-items:baseline;justify-content:space-between;gap:10px;margin-bottom:10px;padding-bottom:8px;border-bottom:1px solid var(--border);">
        <div>
          <div style="font-size:11px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--text2);">${esc(title)}</div>
          <div style="font-size:12px;color:var(--text2);margin-top:3px;line-height:1.4;">${esc(hint)}</div>
        </div>
        <span style="font-size:11px;color:var(--text2);white-space:nowrap;">${hosts.length}</span>
      </div>
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px;min-height:72px;">
        ${cards || `<div style="padding:20px;border:1px dashed var(--border);border-radius:10px;color:var(--text2);font-size:12.5px;background:var(--bg2);">${t(emptyKey)}</div>`}
      </div>
    </section>`;
  };

  return `<div class="card blueprint" style="width:min(1120px,100%);max-height:calc(100vh - 20px);overflow:auto;padding:0;">
    <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
    <div style="padding:18px 22px 14px;border-bottom:1px solid var(--border);background:var(--bg);">
      <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px;">
        <div>
          <div class="card-kicker">${t('arch.kicker')}</div>
          <div style="font-weight:700;font-size:17px;margin-top:2px;letter-spacing:-.01em;">${t('arch.title')}</div>
          <div style="font-size:12.5px;color:var(--text2);margin-top:5px;max-width:44rem;line-height:1.45;">${t('arch.subtitle_map')}</div>
          ${_arch.existingCount ? `<div style="margin-top:8px;font-size:12px;color:var(--text2);">${t('arch.existing_loaded', { n: _arch.existingCount })} · ${t('arch.drag_hint')}</div>` : `<div style="margin-top:8px;font-size:12px;color:var(--text2);">${t('arch.drag_hint')}</div>`}
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end;">
          <button class="btn btn-ghost btn-sm" onclick="closeArchWizard()" style="font-size:18px;line-height:1;">×</button>
        </div>
      </div>
    </div>

    <div style="padding:16px 22px 8px;display:grid;grid-template-columns:minmax(148px,176px) 1fr;gap:16px;align-items:start;">
      <aside style="position:sticky;top:0;">
        ${_archPaletteSection(t('arch.palette.roles'), `
          ${_archPaletteItem('core', t('arch.svc.core'), 'var(--accent)')}
          ${_archPaletteItem('agent', t('arch.svc.agent'), 'var(--green)')}
          ${_archPaletteItem('admin', t('arch.svc.admin'), 'var(--text2)')}
        `)}
        ${_archPaletteSection(t('arch.palette.caps'), `
          ${_archPaletteItem('access', t('arch.svc.access'), 'var(--orange,#f97316)')}
          ${_archPaletteItem('ha', t('arch.svc.ha'), '#fb923c')}
          ${_archPaletteItem('domains', t('arch.svc.domains'), '#eab308')}
          ${_archPaletteItem('autoscale', t('arch.svc.autoscale'), '#a3e635')}
          ${_archPaletteItem('docker', t('arch.svc.docker'), '#22d3ee')}
          ${_archPaletteItem('podman', t('arch.svc.podman'), '#2dd4bf')}
          ${_archPaletteItem('portainer', t('arch.svc.portainer'), '#38bdf8')}
          ${_archPaletteItem('k8s', t('arch.svc.k8s'), '#94a3b8')}
        `)}
        <div style="padding-top:4px;border-top:1px solid var(--border);margin-top:4px;">
          <div style="font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--text2);margin-bottom:7px;">${t('arch.palette.hosts')}</div>
          <button class="btn btn-secondary btn-sm" style="width:100%;" onclick="_archAddHost()">${t('arch.add_host')}</button>
          ${_arch.haGroupIds.length ? `<div style="margin-top:8px;font-size:11px;color:var(--orange,#f97316);">${t('arch.ha_on', { n: _arch.haGroupIds.length })}</div>` : ''}
          <div style="margin-top:10px;font-size:11px;color:var(--text2);line-height:1.4;">${inetCount ? t('arch.inet.marked', { n: inetCount }) : t('arch.inet.ask')}</div>
        </div>
      </aside>

      <div style="min-height:240px;">
        ${zone(t('arch.zone.internet'), t('arch.zone.internet_hint'), edgeHosts, 'arch.zone.internet_empty')}
        ${zone(t('arch.zone.private'), t('arch.zone.private_hint'), privateHosts, 'arch.zone.private_empty')}
      </div>
    </div>

    <div style="padding:8px 22px 18px;">
      ${_arch.selectedSvcId ? _archOptionsPanel() : ''}
      ${(() => { const n = _archAccessHANote(); return n ? `<div style="margin-top:12px;font-size:12px;color:var(--orange,#f97316);">${esc(n)}</div>` : ''; })()}
      ${err ? `<div style="margin-top:12px;font-size:12px;color:var(--red);">${esc(err)}</div>` : ''}
      <div style="margin-top:10px;font-size:11.5px;color:var(--text2);line-height:1.4;">${t('arch.labels_elsewhere')}</div>
      <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:16px;padding-top:12px;border-top:1px solid var(--border);">
        <button class="btn btn-ghost" onclick="closeArchWizard()">${t('common.cancel') || 'Annuler'}</button>
        <button class="btn btn-primary" onclick="_archGoHandoff()" ${err ? 'disabled' : ''}>${t('arch.continue')}</button>
      </div>
    </div>
  </div>`;
}

function _archRoleAccent(type) {
  if (type === 'core') return 'var(--accent)';
  if (type === 'agent') return 'var(--green)';
  if (type === 'admin') return 'var(--text2)';
  return 'var(--border)';
}

function _archHostCard(host) {
  const chips = (host.services || []).map(s => {
    const sel = s.id === _arch.selectedSvcId;
    const badges = [];
    if (s.access) badges.push('Access');
    if (_arch.haGroupIds.includes(s.id)) badges.push('HA');
    if (s.domains || s.acme) badges.push('TLS');
    if (s.autoscale) badges.push('Autoscale');
    if (s.docker) badges.push('Docker');
    if (s.podman) badges.push('Podman');
    if (s.portainer) badges.push('Portainer');
    if (s.k8s) badges.push('K8s');
    if (s.existing) badges.push(s.status === 'online' ? t('arch.badge.online') : t('arch.badge.declared'));
    if (s.type === 'agent' && s.placement === 'colocated') badges.push(t('arch.badge.colocated'));
    const accent = _archRoleAccent(s.type);
    const badgeHTML = badges.map(b =>
      `<span style="font-size:10px;padding:1px 6px;border-radius:4px;background:var(--bg2);color:var(--text2);border:1px solid var(--border);">${esc(b)}</span>`
    ).join('');
    return `<div draggable="true" data-arch-svc="${s.id}"
      ondragstart="_archDragStart(event)"
      onclick="_archSelectSvc('${s.id}')"
      style="display:flex;align-items:flex-start;gap:8px;padding:9px 10px;border-radius:8px;border:1.5px solid ${sel ? accent : 'var(--border)'};border-left:3px solid ${accent};background:${sel ? `color-mix(in srgb,${accent} 10%,var(--bg))` : 'var(--bg)'};cursor:grab;user-select:none;">
      <div style="flex:1;min-width:0;">
        <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">
          <strong style="font-size:12.5px;text-transform:capitalize;">${esc(s.type)}</strong>
          <span style="font-size:12px;color:var(--text2);overflow:hidden;text-overflow:ellipsis;">${esc(s.name)}</span>
        </div>
        ${badges.length ? `<div style="display:flex;flex-wrap:wrap;gap:4px;margin-top:6px;">${badgeHTML}</div>` : ''}
      </div>
      <span onclick="event.stopPropagation();_archRemoveSvc('${host.id}','${s.id}')" style="opacity:.45;cursor:pointer;padding:2px 4px;font-size:14px;line-height:1;" title="${t('common.delete') || '×'}">×</span>
    </div>`;
  }).join('');

  const inet = !!host.internet;
  return `<div ondragover="event.preventDefault();this.style.outline='2px solid var(--accent)'" ondragleave="this.style.outline=''" ondrop="_archDrop(event,'${host.id}');this.style.outline=''"
    style="border:1.5px solid ${inet ? 'color-mix(in srgb,var(--accent) 50%,var(--border))' : 'var(--border)'};border-radius:12px;padding:12px 13px;background:var(--bg);">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;flex-wrap:wrap;">
      <input value="${esc(host.name)}" onchange="_archRenameHost('${host.id}',this.value)"
        style="flex:1;min-width:100px;font-weight:650;font-size:13px;border:1px solid var(--border);border-radius:7px;padding:6px 8px;background:var(--bg2);color:var(--text1);">
      <label style="display:inline-flex;align-items:center;gap:6px;font-size:11px;cursor:pointer;padding:5px 8px;border-radius:6px;border:1px solid ${inet ? 'color-mix(in srgb,var(--accent) 40%,var(--border))' : 'var(--border)'};background:${inet ? 'color-mix(in srgb,var(--accent) 10%,var(--bg2))' : 'var(--bg2)'};color:var(--text1);white-space:nowrap;">
        <input type="checkbox" ${inet ? 'checked' : ''} onchange="_archSetHostInternet('${host.id}',this.checked)" style="accent-color:var(--accent);">
        ${t('arch.host.internet')}
      </label>
      ${_arch.hosts.length > 1 ? `<button class="btn btn-ghost btn-sm" onclick="_archRemoveHost('${host.id}')">×</button>` : ''}
    </div>
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px;">
      <span style="font-size:11px;color:var(--text2);white-space:nowrap;">${t('arch.host.region')}</span>
      <input value="${esc(host.region || '')}" placeholder="eu-west-1"
        onchange="_archSetHostRegion('${host.id}',this.value)"
        style="flex:1;font-size:12px;border:1px solid var(--border);border-radius:7px;padding:5px 8px;background:var(--bg2);color:var(--text1);">
    </div>
    <div style="display:flex;flex-direction:column;gap:7px;min-height:56px;padding:8px;border-radius:9px;border:1.5px dashed color-mix(in srgb,var(--border) 80%,transparent);background:var(--bg2);">
      ${chips || `<span style="font-size:12px;color:var(--text2);padding:8px 4px;">${t('arch.drop_here')}</span>`}
    </div>
  </div>`;
}

const _ARCH_DNS_PROVIDERS = [
  { id: 'none', label: '—' },
  { id: 'cloudflare', label: 'Cloudflare' },
  { id: 'ovh', label: 'OVH' },
  { id: 'gandi', label: 'Gandi' },
  { id: 'route53', label: 'AWS Route53' },
  { id: 'hetzner', label: 'Hetzner' },
];

function _archOptionsPanel() {
  const svc = _archFindSvc(_arch.selectedSvcId);
  if (!svc) return '';
  const host = _archFindHostOfSvc(svc.id);
  let body = '';
  if (svc.type === 'core') {
    const dnsOpts = _ARCH_DNS_PROVIDERS.map(p =>
      `<option value="${p.id}" ${(svc.dnsProvider || 'none') === p.id ? 'selected' : ''}>${esc(p.label)}</option>`
    ).join('');
    body = `
      <label style="display:flex;align-items:center;gap:8px;font-size:13px;cursor:pointer;">
        <input type="checkbox" ${svc.access ? 'checked' : ''} onchange="_archSetOpt('${svc.id}','access',this.checked)"> ${t('arch.opt.access')}
      </label>
      <label style="display:flex;align-items:center;gap:8px;font-size:13px;cursor:pointer;margin-top:8px;">
        <input type="checkbox" ${_arch.haGroupIds.includes(svc.id) ? 'checked' : ''} onchange="_archSetHAMember('${svc.id}',this.checked)"> ${t('arch.opt.ha')}
      </label>
      <div style="margin-top:10px;padding-top:10px;border-top:1px solid var(--border);">
        <div style="font-size:11px;color:var(--text2);margin-bottom:4px;">${t('arch.opt.domains')}</div>
        <input value="${esc(svc.domains || '')}" placeholder="app.example.fr, api.example.fr"
          onchange="_archSetField('${svc.id}','domains',this.value);_archRender()"
          style="width:100%;border:1px solid var(--border);border-radius:6px;padding:6px 8px;background:var(--bg2);color:var(--text1);font-size:12px;">
        <label style="display:flex;align-items:center;gap:8px;font-size:13px;cursor:pointer;margin-top:8px;">
          <input type="checkbox" ${svc.acme ? 'checked' : ''} onchange="_archSetOpt('${svc.id}','acme',this.checked)"> ${t('arch.opt.acme')}
        </label>
        ${svc.acme ? `
        <div style="font-size:11px;color:var(--text2);margin:8px 0 4px;">${t('arch.opt.acme_email')}</div>
        <input value="${esc(svc.acmeEmail || '')}" placeholder="admin@example.fr"
          onchange="_archSetField('${svc.id}','acmeEmail',this.value)"
          style="width:100%;border:1px solid var(--border);border-radius:6px;padding:6px 8px;background:var(--bg2);color:var(--text1);font-size:12px;">
        <div style="font-size:11px;color:var(--text2);margin:8px 0 4px;">${t('arch.opt.dns_provider')}</div>
        <select onchange="_archSetField('${svc.id}','dnsProvider',this.value);_archRender()"
          style="width:100%;border:1px solid var(--border);border-radius:6px;padding:6px 8px;background:var(--bg2);color:var(--text1);font-size:12px;">
          ${dnsOpts}
        </select>
        <div style="font-size:11px;color:var(--text2);margin-top:6px;line-height:1.4;">${t('arch.opt.acme_admin_hint')}</div>
        ` : ''}
      </div>
      <div style="margin-top:8px;">
        <div style="font-size:11px;color:var(--text2);margin-bottom:4px;">${t('arch.opt.reachable')}</div>
        <input value="${esc(svc.reachable || '')}" placeholder="core.example.com ou 10.0.0.5"
          onchange="_archSetField('${svc.id}','reachable',this.value)"
          style="width:100%;border:1px solid var(--border);border-radius:6px;padding:6px 8px;background:var(--bg2);color:var(--text1);font-size:12px;">
      </div>
      <div style="margin-top:8px;font-size:11px;color:var(--text2);">${t('arch.opt.region_from_host', { region: (host && host.region) || '—' })}</div>`;
  } else if (svc.type === 'agent') {
    const coreChoices = _arch.hosts.flatMap(h => (h.services || []).filter(s => s.type === 'core'));
    const targetOpts = coreChoices.map(c =>
      `<option value="${esc(c.id)}" ${svc.targetCoreId === c.id ? 'selected' : ''}>${esc(c.name)}</option>`
    ).join('');
    body = `
      ${coreChoices.length > 1 ? `
      <div style="margin-bottom:8px;">
        <div style="font-size:11px;color:var(--text2);margin-bottom:4px;">${t('arch.opt.target_core')}</div>
        <select onchange="_archSetField('${svc.id}','targetCoreId',this.value)"
          style="width:100%;border:1px solid var(--border);border-radius:6px;padding:6px 8px;background:var(--bg2);color:var(--text1);font-size:12px;">
          <option value="">${t('arch.opt.target_core_auto')}</option>
          ${targetOpts}
        </select>
      </div>` : ''}
      <div style="font-size:11px;color:var(--text2);margin-bottom:6px;">${t('arch.opt.discovery')}</div>
      <label style="display:flex;align-items:center;gap:8px;font-size:13px;cursor:pointer;">
        <input type="checkbox" ${svc.docker ? 'checked' : ''} onchange="_archSetRuntime('${svc.id}','docker',this.checked)"> ${t('arch.opt.docker')}
      </label>
      <label style="display:flex;align-items:center;gap:8px;font-size:13px;cursor:pointer;margin-top:6px;">
        <input type="checkbox" ${svc.podman ? 'checked' : ''} onchange="_archSetRuntime('${svc.id}','podman',this.checked)"> ${t('arch.opt.podman')}
      </label>
      <label style="display:flex;align-items:center;gap:8px;font-size:13px;cursor:pointer;margin-top:8px;">
        <input type="checkbox" ${svc.portainer ? 'checked' : ''} onchange="_archSetOpt('${svc.id}','portainer',this.checked);_archRender()"> ${t('arch.opt.portainer')}
      </label>
      ${svc.portainer ? `
        <input value="${esc(svc.portainerUrl || '')}" placeholder="https://portainer:9443" onchange="_archSetField('${svc.id}','portainerUrl',this.value)"
          style="width:100%;margin-top:6px;border:1px solid var(--border);border-radius:6px;padding:6px 8px;background:var(--bg2);color:var(--text1);font-size:12px;">
        <input value="${esc(svc.portainerKey || '')}" placeholder="ptr_…" type="password" onchange="_archSetField('${svc.id}','portainerKey',this.value)"
          style="width:100%;margin-top:6px;border:1px solid var(--border);border-radius:6px;padding:6px 8px;background:var(--bg2);color:var(--text1);font-size:12px;">` : ''}
      <label style="display:flex;align-items:center;gap:8px;font-size:13px;cursor:pointer;margin-top:8px;">
        <input type="checkbox" ${svc.k8s ? 'checked' : ''} onchange="_archSetOpt('${svc.id}','k8s',this.checked)"> ${t('arch.opt.k8s')}
      </label>
      <label style="display:flex;align-items:center;gap:8px;font-size:13px;cursor:pointer;margin-top:10px;padding-top:10px;border-top:1px solid var(--border);">
        <input type="checkbox" ${svc.autoscale ? 'checked' : ''} onchange="_archSetOpt('${svc.id}','autoscale',this.checked)"> ${t('arch.opt.autoscale')}
      </label>
      ${svc.autoscale ? `<div style="font-size:11px;color:var(--text2);margin-top:6px;line-height:1.4;">${t('arch.opt.autoscale_hint')}</div>` : ''}
      <div style="margin-top:8px;font-size:11px;color:var(--text2);">${t('arch.opt.region_from_host', { region: (host && host.region) || '—' })}</div>`;
  } else if (svc.type === 'admin') {
    const tlsCores = _arch.hosts.flatMap(h => h.services.filter(s => s.type === 'core' && s.acme));
    body = tlsCores.length
      ? `<div style="font-size:12px;color:var(--text2);line-height:1.45;">${t('arch.opt.admin_acme_note')}</div>`
      : `<div style="font-size:12px;color:var(--text2);">${t('arch.opt.none')}</div>`;
  } else {
    body = `<div style="font-size:12px;color:var(--text2);">${t('arch.opt.none')}</div>`;
  }
  return `<div style="margin-top:6px;padding:13px 14px;border:1px solid var(--border);border-radius:11px;background:var(--bg2);">
    <div style="font-size:12px;font-weight:650;margin-bottom:8px;">${t('arch.options_for', { name: svc.name })}</div>
    ${body}
  </div>`;
}

function _archDragStart(ev) {
  const svcId = ev.currentTarget.getAttribute('data-arch-svc');
  const type = ev.currentTarget.getAttribute('data-arch-type');
  if (svcId) {
    ev.dataTransfer.setData('text/arch-svc', svcId);
    ev.dataTransfer.effectAllowed = 'move';
  } else if (type) {
    ev.dataTransfer.setData('text/arch-type', type);
    ev.dataTransfer.effectAllowed = 'copy';
  }
}

function _archDrop(ev, hostId) {
  ev.preventDefault();
  const svcId = ev.dataTransfer.getData('text/arch-svc');
  if (svcId) {
    _archMoveSvc(svcId, hostId);
    return;
  }
  const type = ev.dataTransfer.getData('text/arch-type');
  if (!type) return;
  _archAddService(hostId, type);
}

function _archMoveSvc(svcId, toHostId) {
  const from = _archFindHostOfSvc(svcId);
  const to = _arch.hosts.find(h => h.id === toHostId);
  if (!from || !to || from.id === to.id) return;
  const idx = from.services.findIndex(s => s.id === svcId);
  if (idx < 0) return;
  const [svc] = from.services.splice(idx, 1);
  to.services.push(svc);
  if (svc.type === 'agent') {
    const hasCore = to.services.some(s => s.type === 'core');
    svc.placement = hasCore ? 'colocated' : 'remote';
    if (hasCore) {
      const core = to.services.find(s => s.type === 'core');
      if (core) svc.targetCoreId = core.id;
    }
  }
  // Retirer les hôtes vides orphelins (sauf le dernier)
  _arch.hosts = _arch.hosts.filter(h => (h.services && h.services.length) || h.id === to.id);
  if (!_arch.hosts.length) _arch.hosts = [_archEmptyHost(1)];
  _arch.selectedSvcId = svc.id;
  _archRender();
}

function _archAddHost() {
  const n = _arch.hosts.length + 1;
  _arch.hosts.push(_archEmptyHost(n));
  _archRender();
}

function _archSetHostInternet(hostId, on) {
  const h = _arch.hosts.find(x => x.id === hostId);
  if (h) h.internet = !!on;
  _archRender();
}

function _archSetHostRegion(hostId, region) {
  const h = _arch.hosts.find(x => x.id === hostId);
  if (h) h.region = (region || '').trim();
}

function _archSetRuntime(id, kind, on) {
  const s = _archFindSvc(id);
  if (!s || s.type !== 'agent') return;
  if (kind === 'docker') {
    s.docker = !!on;
    if (on) s.podman = false;
  } else if (kind === 'podman') {
    s.podman = !!on;
    if (on) s.docker = false;
  }
  _archRender();
}

function _archRemoveHost(hostId) {
  const host = _arch.hosts.find(h => h.id === hostId);
  if (host) {
    for (const s of host.services) {
      _arch.haGroupIds = _arch.haGroupIds.filter(id => id !== s.id);
    }
  }
  _arch.hosts = _arch.hosts.filter(h => h.id !== hostId);
  if (!_arch.hosts.length) _archAddHost();
  else _archRender();
}

function _archRenameHost(hostId, name) {
  const h = _arch.hosts.find(x => x.id === hostId);
  if (h) h.name = (name || '').trim() || h.name;
}

function _archFindSvc(id) {
  for (const h of _arch.hosts) {
    const s = (h.services || []).find(x => x.id === id);
    if (s) return s;
  }
  return null;
}

function _archFindHostOfSvc(id) {
  return _arch.hosts.find(h => (h.services || []).some(s => s.id === id));
}

function _archCountType(type) {
  let n = 0;
  for (const h of _arch.hosts) n += (h.services || []).filter(s => s.type === type).length;
  return n;
}

function _archAddService(hostId, type) {
  const host = _arch.hosts.find(h => h.id === hostId);
  if (!host) return;

  if (type === 'ha') {
    _archToggleHA();
    return;
  }

  if (type === 'access') {
    const core = [...host.services].reverse().find(s => s.type === 'core') || _archFindSvc(_arch.selectedSvcId);
    if (!core || core.type !== 'core') {
      toast(t('arch.err.access_needs_core'), 'error');
      return;
    }
    core.access = true;
    _arch.selectedSvcId = core.id;
    _archRender();
    return;
  }
  if (type === 'portainer' || type === 'k8s' || type === 'docker' || type === 'podman' || type === 'autoscale') {
    let agent = host.services.filter(s => s.type === 'agent').slice(-1)[0];
    if (_arch.selectedSvcId) {
      const sel = _archFindSvc(_arch.selectedSvcId);
      if (sel && sel.type === 'agent') agent = sel;
    }
    if (!agent) {
      toast(t('arch.err.opt_needs_agent'), 'error');
      return;
    }
    if (type === 'portainer') agent.portainer = true;
    if (type === 'k8s') agent.k8s = true;
    if (type === 'docker') { agent.docker = true; agent.podman = false; }
    if (type === 'podman') { agent.podman = true; agent.docker = false; }
    if (type === 'autoscale') agent.autoscale = true;
    _arch.selectedSvcId = agent.id;
    _archRender();
    return;
  }
  if (type === 'domains') {
    const core = [...host.services].reverse().find(s => s.type === 'core') || _archFindSvc(_arch.selectedSvcId);
    if (!core || core.type !== 'core') {
      toast(t('arch.err.domains_needs_core'), 'error');
      return;
    }
    core.acme = true;
    if (!core.domains) core.domains = '';
    if (!core.dnsProvider) core.dnsProvider = 'none';
    _arch.selectedSvcId = core.id;
    _archRender();
    return;
  }

  const n = _archCountType(type) + 1;
  const name = type === 'core' ? `core-${n}` : type === 'agent' ? `agent-${n}` : `admin-${n}`;
  const svc = {
    id: _archUid(type),
    type,
    name,
    access: false,
    portainer: false,
    k8s: false,
    docker: type === 'agent',
    podman: false,
    autoscale: false,
    domains: '',
    acme: false,
    acmeEmail: '',
    dnsProvider: 'none',
    reachable: '',
    portainerUrl: '',
    portainerKey: '',
    targetCoreId: '',
    placement: type === 'agent'
      ? (host.services.some(s => s.type === 'core') ? 'colocated' : 'remote')
      : '',
  };
  if (svc.type === 'agent' && svc.placement === 'colocated') {
    const core = host.services.find(s => s.type === 'core');
    if (core) svc.targetCoreId = core.id;
  }
  host.services.push(svc);
  _arch.selectedSvcId = svc.id;
  _archRender();
}

function _archRemoveSvc(hostId, svcId) {
  const host = _arch.hosts.find(h => h.id === hostId);
  if (!host) return;
  host.services = host.services.filter(s => s.id !== svcId);
  _arch.haGroupIds = _arch.haGroupIds.filter(id => id !== svcId);
  if (_arch.selectedSvcId === svcId) _arch.selectedSvcId = null;
  _archRender();
}

function _archSelectSvc(id) {
  _arch.selectedSvcId = id;
  _archRender();
}

function _archSetOpt(id, key, val) {
  const s = _archFindSvc(id);
  if (s) s[key] = !!val;
  _archRender();
}

function _archSetField(id, key, val) {
  const s = _archFindSvc(id);
  if (s) s[key] = val;
}

function _archSetHAMember(id, on) {
  if (on) {
    if (!_arch.haGroupIds.includes(id)) _arch.haGroupIds.push(id);
  } else {
    _arch.haGroupIds = _arch.haGroupIds.filter(x => x !== id);
  }
  _archRender();
}

function _archToggleHA() {
  const cores = [];
  for (const h of _arch.hosts) {
    for (const s of h.services) if (s.type === 'core') cores.push(s.id);
  }
  if (cores.length < 2) {
    toast(t('arch.err.ha_min'), 'error');
    return;
  }
  if (_arch.haGroupIds.length >= 2) {
    _arch.haGroupIds = [];
  } else {
    _arch.haGroupIds = cores.slice();
  }
  _archRender();
}

function _archValidate() {
  const cores = [];
  const agents = [];
  for (const h of _arch.hosts) {
    for (const s of h.services || []) {
      if (s.type === 'core') cores.push({ host: h, svc: s });
      if (s.type === 'agent') agents.push({ host: h, svc: s });
    }
  }
  const total = _arch.hosts.reduce((n, h) => n + (h.services || []).length, 0);
  if (!total) return t('arch.err.empty');
  if (_arch.haGroupIds.length === 1) return t('arch.err.ha_one');
  if (_arch.haGroupIds.length > 0 && _arch.haGroupIds.length < 2) return t('arch.err.ha_one');

  if (_arch.haGroupIds.length >= 2) {
    const haHosts = new Set();
    for (const id of _arch.haGroupIds) {
      const h = _archFindHostOfSvc(id);
      if (h) haHosts.add(h.id);
    }
    if (haHosts.size > 1) {
      for (const id of _arch.haGroupIds) {
        const s = _archFindSvc(id);
        if (s && !(s.reachable || '').trim()) {
          return t('arch.err.ha_reachable', { name: s.name });
        }
      }
    }
  }

  for (const { host, svc } of agents) {
    const hasCoreHere = (host.services || []).some(s => s.type === 'core');
    if (!hasCoreHere && !cores.length && !_arch.onlineCoreEndpoint) {
      return t('arch.err.agent_needs_core');
    }
  }
  return '';
}

function _archHAPeerHost(svc) {
  if (!svc) return '';
  const r = (svc.reachable || '').trim();
  if (r) {
    // host:port ou host seul → host pour peers Raft :8002
    return r.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
  }
  return svc.name;
}

function _archHAPeersCSV(selfId) {
  const parts = [];
  for (const id of _arch.haGroupIds) {
    if (id === selfId) continue;
    const s = _archFindSvc(id);
    if (!s) continue;
    const host = _archHAPeerHost(s);
    parts.push(`${s.name}=http://${host}:8002`);
  }
  return parts.join(',');
}

function _archAccessHANote() {
  if (_arch.haGroupIds.length < 2) return '';
  let n = 0;
  for (const id of _arch.haGroupIds) {
    const s = _archFindSvc(id);
    if (s && s.access) n++;
  }
  if (n < 2) return '';
  return t('arch.note.access_ha');
}

function _archNetworkFlows() {
  const flows = [];
  const multiHost = _arch.hosts.length > 1;
  const hasCore = _arch.hosts.some(h => h.services.some(s => s.type === 'core'));
  const hasAgent = _arch.hosts.some(h => h.services.some(s => s.type === 'agent'));
  const hasAdmin = _arch.hosts.some(h => h.services.some(s => s.type === 'admin'));
  const inetHosts = _arch.hosts.filter(h => h.internet);

  if (hasAdmin && hasCore) {
    flows.push({ from: 'Admin', to: 'Core :8000', dir: t('arch.flow.outbound'), why: 'WS plan de contrôle' });
  } else if (hasCore) {
    flows.push({ from: 'Admin (existant)', to: 'Core :8000', dir: t('arch.flow.outbound'), why: 'WS plan de contrôle' });
  }
  if (hasAgent && hasCore) {
    flows.push({ from: 'Agent', to: 'Core :8000', dir: t('arch.flow.outbound'), why: 'WS + discovery' });
  }
  if (_arch.haGroupIds.length >= 2) {
    flows.push({ from: 'Core', to: 'Core :8000 / :8002', dir: t('arch.flow.peer'), why: 'Peers HA / Raft' });
  }
  if (multiHost) {
    flows.push({ from: t('arch.flow.bootstrap'), to: t('arch.flow.reachable'), dir: t('arch.flow.outbound'), why: t('arch.flow.qr_why') });
  }

  for (const h of _arch.hosts) {
    const edge = !!h.internet;
    for (const s of h.services) {
      if (s.type === 'core' && s.access) {
        flows.push({
          from: edge ? t('arch.flow.internet') : 'Clients / LAN',
          to: `${s.name} :2222 / :8444`,
          dir: t('arch.flow.inbound'),
          why: edge ? t('arch.flow.access_public') : 'Portail Access',
        });
      }
      if (s.type === 'core') {
        flows.push({
          from: edge ? t('arch.flow.internet') : 'LAN',
          to: `${s.name} :80 / :443`,
          dir: t('arch.flow.inbound'),
          why: edge ? t('arch.flow.proxy_public') : 'Trafic proxy',
        });
      }
    }
  }
  if (inetHosts.length) {
    flows.unshift({
      from: t('arch.flow.internet'),
      to: inetHosts.map(h => h.name).join(', '),
      dir: t('arch.flow.inbound'),
      why: t('arch.flow.edge_hosts'),
    });
  }

  const seen = new Set();
  return flows.filter(f => {
    const k = f.from + f.to + f.why;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

function _archResolveCoreEndpoint(agentHost, agentSvc) {
  const localCore = (agentHost.services || []).find(s => s.type === 'core');
  if (localCore) return `http://${localCore.name}:8000`;

  if (agentSvc && agentSvc.targetCoreId) {
    const target = _archFindSvc(agentSvc.targetCoreId);
    if (target && target.type === 'core') {
      const host = (target.reachable || '').trim();
      if (host) return typeof _wizCoreEndpoint === 'function' ? _wizCoreEndpoint(host) : ('http://' + host.replace(/\/$/, '') + (String(host).includes(':') ? '' : ':8000'));
      return `http://${target.name}:8000`;
    }
  }

  // Préférer un Core HA leader / premier Core avec reachable
  const allCores = _arch.hosts.flatMap(h => h.services.filter(s => s.type === 'core'));
  const preferred = allCores.find(c => (c.reachable || '').trim()) || allCores[0];
  if (preferred) {
    const host = (preferred.reachable || '').trim();
    if (host) return typeof _wizCoreEndpoint === 'function' ? _wizCoreEndpoint(host) : ('http://' + host.replace(/\/$/, '') + (String(host).includes(':') ? '' : ':8000'));
    return `http://${preferred.name}:8000`;
  }
  return _arch.onlineCoreEndpoint || 'http://goproxify-core:8000';
}

function _archBuildPacks() {
  _wiz.pairingSecret = _arch.pairingSecret;
  _wiz.scenario = 'full';
  const packs = [];
  const haLeader = _arch.haGroupIds[0] ? _archFindSvc(_arch.haGroupIds[0]) : null;
  const haGroup = 'ha-1';

  for (const host of _arch.hosts) {
    if (!(host.services || []).length) continue;
    const cores = host.services.filter(s => s.type === 'core');
    const agents = host.services.filter(s => s.type === 'agent');
    const admins = host.services.filter(s => s.type === 'admin');

    let coreOpts = null;
    let agentOpts = null;
    if (cores[0]) {
      const c = cores[0];
      const inHA = _arch.haGroupIds.includes(c.id);
      coreOpts = _buildCoreOpts({
        wc_name: c.name,
        wc_cluster: inHA,
        wc_cluster_node_id: c.name,
        wc_cluster_group: haGroup,
        wc_cluster_peers: inHA ? _archHAPeersCSV(c.id) : '',
        wc_raft_leader: inHA && haLeader && haLeader.id !== c.id ? haLeader.name : '',
        wc_portal: !!c.access,
        wc_http3: false,
      });
    }
    if (agents[0]) {
      const a = agents[0];
      const ep = _archResolveCoreEndpoint(host, a);
      const localCore = cores[0];
      const target = a.targetCoreId ? _archFindSvc(a.targetCoreId) : null;
      agentOpts = _buildAgentOpts({
        wa_name: a.name,
        wa_core_url: ep,
        wa_core_container_name: localCore ? localCore.name : (target ? target.name : ''),
        wa_region: (host.region || a.region || '').trim(),
        wa_docker: !!a.docker && !a.podman,
        wa_podman: !!a.podman,
        wa_runtime: a.podman ? 'podman' : (a.docker ? 'docker' : ''),
        wa_k8s: !!a.k8s,
        wa_portainer: !!a.portainer,
        wa_portainer_url: a.portainerUrl || '',
        wa_portainer_key: a.portainerKey || '',
        wa_autoscale: !!a.autoscale,
        wa_placement: localCore ? 'colocated' : 'remote',
      });
      if (localCore && coreOpts) {
        agentOpts = {
          ...agentOpts,
          envVars: (agentOpts.envVars || [])
            .filter(e => e.k !== 'GPX_CONTROL_PLANE_CORE_ENDPOINT' && e.k !== 'GPX_NETWORK_MANAGEMENT_CORE_CONTAINER_NAME')
            .concat([
              { k: 'GPX_CONTROL_PLANE_CORE_ENDPOINT', v: `http://${coreOpts.name}:8000` },
              { k: 'GPX_NETWORK_MANAGEMENT_CORE_CONTAINER_NAME', v: coreOpts.name },
            ]),
        };
      }
    }

    let html = '';
    if (coreOpts && agentOpts) html = _renderConfigUI(coreOpts, agentOpts);
    else if (coreOpts) html = _renderConfigUI(coreOpts);
    else if (agentOpts) html = _renderConfigUI(agentOpts);
    else if (admins.length) {
      const acmeCores = _arch.hosts.flatMap(h => h.services.filter(s => s.type === 'core' && s.acme));
      let hint = `<p style="font-size:13px;color:var(--text2);">${t('arch.admin_hint')}</p>`;
      if (acmeCores.length) {
        const c = acmeCores[0];
        hint += `<div style="font-size:12px;color:var(--text2);margin-top:8px;line-height:1.45;padding:10px;border-radius:8px;background:var(--bg);border:1px solid var(--border);">
          <strong>${t('arch.acme.admin_title')}</strong><br>
          <code>GPX_ACME_ENABLED=true</code>
          ${c.acmeEmail ? `<br><code>GPX_ACME_EMAIL=${esc(c.acmeEmail)}</code>` : ''}
          ${c.dnsProvider && c.dnsProvider !== 'none' ? `<br><code>GPX_ACME_DNS_TYPE=${esc(c.dnsProvider)}</code>` : ''}
          <br><span style="opacity:.85;">${t('arch.acme.admin_token_hint')}</span>
          ${c.domains ? `<br><span style="opacity:.85;">${t('arch.acme.domains_later', { domains: c.domains })}</span>` : ''}
        </div>`;
      }
      html = hint;
    }

    // Annoter pack Core avec domaines pour le handoff
    if (coreOpts && cores[0] && (cores[0].domains || cores[0].acme)) {
      const note = [];
      if (cores[0].domains) note.push(t('arch.acme.domains_later', { domains: cores[0].domains }));
      if (cores[0].acme) note.push(t('arch.acme.admin_title'));
      html = (html || '') + `<div style="font-size:12px;color:var(--text2);margin-top:10px;line-height:1.4;">${note.map(esc).join('<br>')}</div>`;
    }

    const token = _archUid('boot');
    const origin = (typeof location !== 'undefined' && location.origin) ? location.origin : '';
    const bootstrapUrl = `${origin}/bootstrap/${token}`; // remplacé à la création ticket

    let composeText = '', envText = '', cliText = '';
    if (coreOpts && agentOpts) {
      composeText = _cfgComposeTextFull(coreOpts, agentOpts, 'env_file');
      envText = _cfgEnvFileTextFull(coreOpts, agentOpts);
      cliText = _cfgCliText(coreOpts) + '\n\n' + _cfgCliText(agentOpts);
    } else if (coreOpts) {
      composeText = _cfgComposeText(coreOpts, 'env_file');
      envText = _cfgEnvFileText(coreOpts);
      cliText = _cfgCliText(coreOpts);
    } else if (agentOpts) {
      composeText = _cfgComposeText(agentOpts, 'env_file');
      envText = _cfgEnvFileText(agentOpts);
      cliText = _cfgCliText(agentOpts);
    }

    let coreEp = '';
    if (agentOpts) {
      const hit = (agentOpts.envVars || []).find(e => e.k === 'GPX_CONTROL_PLANE_CORE_ENDPOINT');
      coreEp = hit ? hit.v : '';
    } else if (cores[0] && cores[0].reachable) {
      coreEp = typeof _wizCoreEndpoint === 'function' ? _wizCoreEndpoint(cores[0].reachable) : cores[0].reachable;
    }

    packs.push({
      hostId: host.id,
      hostName: host.name,
      html,
      coreOpts,
      agentOpts,
      bootstrapUrl,
      qrCode: '',
      scriptUrl: '',
      installCmd: '',
      coreEndpoint: coreEp,
      composeText,
      envText,
      cliText,
      services: host.services.slice(),
    });
  }
  return packs;
}

async function _archPersistDeclared() {
  for (const pack of _arch.packs) {
    const roles = [];
    if (pack.coreOpts) roles.push({ role: 'core', opts: pack.coreOpts, svc: pack.services.find(s => s.type === 'core') });
    if (pack.agentOpts) roles.push({ role: 'agent', opts: pack.agentOpts, svc: pack.services.find(s => s.type === 'agent') });
    for (const r of roles) {
      try {
        const hostMeta = _arch.hosts.find(h => h.id === pack.hostId);
        const placement = r.role === 'agent'
          ? ((r.svc && r.svc.placement) || (pack.coreOpts && pack.agentOpts ? 'colocated' : 'remote'))
          : undefined;
        const cfg = {
          image: r.opts.image,
          env_vars: r.opts.envVars,
          restart: r.opts.restart,
          docker: !!(r.svc && r.svc.docker),
          podman: !!(r.svc && r.svc.podman),
          k8s: !!(r.svc && r.svc.k8s),
          portainer: !!(r.svc && r.svc.portainer),
          portainer_url: (r.svc && r.svc.portainerUrl) || '',
          portainer_key: (r.svc && r.svc.portainerKey) || '',
          autoscale: !!(r.svc && r.svc.autoscale),
          domains: (r.svc && r.svc.domains) || '',
          acme: !!(r.svc && r.svc.acme),
          acme_email: (r.svc && r.svc.acmeEmail) || '',
          dns_provider: (r.svc && r.svc.dnsProvider) || 'none',
          placement,
          target_core: r.role === 'agent' ? ((pack.agentOpts.envVars || []).find(e => e.k === 'GPX_CONTROL_PLANE_CORE_ENDPOINT') || {}).v : undefined,
          reachable_host: (r.svc && r.svc.reachable) || '',
          internet_exposed: !!(hostMeta && hostMeta.internet),
          cluster: _arch.haGroupIds.includes(r.svc && r.svc.id),
          portal: !!(r.svc && r.svc.access),
          arch_bootstrap: pack.bootstrapUrl,
          auto_accept: true,
        };
        await api('POST', '/declared-nodes', {
          role: r.role,
          name: r.opts.name,
          region: (hostMeta && hostMeta.region) || '',
          environment: '',
          config: cfg,
        });
      } catch (e) {
        console.warn('declared-nodes save failed:', e.message);
      }
    }
  }
}

async function _archGoHandoff() {
  const err = _archValidate();
  if (err) { toast(err, 'error'); return; }
  _arch.packs = _archBuildPacks();
  await _archPersistDeclared();
  await _archCreateTickets();
  _arch.step = 'handoff';
  _archRender();
}

async function _archCreateTickets() {
  for (const p of _arch.packs) {
    try {
      const nodeNames = [];
      if (p.coreOpts && p.coreOpts.name) nodeNames.push(p.coreOpts.name);
      if (p.agentOpts && p.agentOpts.name) nodeNames.push(p.agentOpts.name);
      const res = await api('POST', '/bootstrap-tickets', {
        host_name: p.hostName,
        core_endpoint: p.coreEndpoint || '',
        ttl_hours: 24,
        auto_accept: true,
        node_names: nodeNames,
        payload: {
          compose_text: p.composeText || '',
          env_text: p.envText || '',
          cli_text: p.cliText || '',
          note: t('arch.ticket_note') || '',
          auto_accept: true,
          node_names: nodeNames,
        },
      });
      if (res && res.url) p.bootstrapUrl = res.url;
      if (res && res.script_url) p.scriptUrl = res.script_url;
      if (res && res.install_cmd) p.installCmd = res.install_cmd;
      if (res && res.qr_code) p.qrCode = res.qr_code;
      // Pré-approbation Agent sur le(s) Core(s) avant connexion
      if (p.agentOpts && p.agentOpts.name) {
        try {
          await api('POST', '/agents/' + encodeURIComponent(p.agentOpts.name) + '/approve');
        } catch (e) {
          console.warn('agent pre-approve failed:', e.message);
        }
      }
    } catch (e) {
      console.warn('bootstrap-tickets failed:', e.message);
    }
  }
}

function _archCopyBootstrap(i) {
  const p = _arch.packs[i];
  if (!p) return;
  navigator.clipboard.writeText(p.bootstrapUrl).then(() => toast(t('common.copied') || 'Copié', 'success'));
}

function _archCopyInstall(i) {
  const p = _arch.packs[i];
  if (!p || !p.installCmd) return;
  navigator.clipboard.writeText(p.installCmd).then(() => toast(t('common.copied') || 'Copié', 'success'));
}

function _archHandoffHTML() {
  const flows = _archNetworkFlows();
  const flowRows = flows.map(f => `
    <tr>
      <td style="padding:6px 8px;font-size:12px;">${esc(f.from)}</td>
      <td style="padding:6px 8px;font-size:12px;">${esc(f.to)}</td>
      <td style="padding:6px 8px;font-size:12px;color:var(--text2);">${esc(f.dir)}</td>
      <td style="padding:6px 8px;font-size:12px;color:var(--text2);">${esc(f.why)}</td>
    </tr>`).join('');

  const packsHTML = _arch.packs.map((p, i) => `
    <div style="margin-bottom:18px;padding:14px;border:1px solid var(--border);border-radius:10px;background:var(--bg2);">
      <div style="font-weight:600;font-size:14px;margin-bottom:8px;">${esc(p.hostName)}</div>
      <div style="display:flex;gap:16px;flex-wrap:wrap;align-items:flex-start;margin-bottom:12px;">
        ${p.qrCode ? `<img src="${esc(p.qrCode)}" alt="QR" width="160" height="160" style="border-radius:8px;background:#fff;padding:8px;">` : ''}
        <div style="flex:1;min-width:200px;">
          ${p.installCmd ? `
          <div style="font-size:12px;color:var(--text2);margin-bottom:6px;">${t('arch.install_label')}</div>
          <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:10px;">
            <code style="font-size:11px;word-break:break-all;flex:1;background:var(--bg);padding:8px;border-radius:6px;">${esc(p.installCmd)}</code>
            <button class="btn btn-primary btn-sm" onclick="_archCopyInstall(${i})">${t('dockerlbl.copy') || 'Copier'}</button>
          </div>` : ''}
          <div style="font-size:12px;color:var(--text2);margin-bottom:6px;">${t('arch.bootstrap_label')}</div>
          <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
            <code style="font-size:11px;word-break:break-all;flex:1;">${esc(p.bootstrapUrl)}</code>
            <button class="btn btn-ghost btn-sm" onclick="_archCopyBootstrap(${i})">${t('dockerlbl.copy') || 'Copier'}</button>
            <a class="btn btn-secondary btn-sm" href="${esc(p.bootstrapUrl)}" target="_blank" rel="noopener">${t('arch.open_ticket')}</a>
          </div>
          <div style="font-size:11px;color:var(--text2);margin-top:8px;">${t('arch.qr_hint')}</div>
        </div>
      </div>
      ${p.html || ''}
    </div>`).join('');

  const inetHosts = _arch.hosts.filter(h => h.internet);
  const inetBanner = inetHosts.length
    ? `<div style="margin-bottom:12px;font-size:12.5px;padding:10px 12px;border-radius:9px;border:1px solid color-mix(in srgb,var(--accent) 30%,var(--border));background:color-mix(in srgb,var(--accent) 8%,var(--bg2));">${t('arch.inet.handoff', { names: inetHosts.map(h => h.name).join(', ') })}</div>`
    : `<div style="margin-bottom:12px;font-size:12.5px;padding:10px 12px;border-radius:9px;border:1px dashed var(--border);color:var(--text2);">${t('arch.inet.handoff_none')}</div>`;

  return `<div class="card blueprint" style="width:min(1080px,100%);max-height:calc(100vh - 20px);overflow:auto;padding:0;">
    <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
    <div style="padding:20px 24px 14px;background:linear-gradient(180deg,color-mix(in srgb,var(--accent) 8%,var(--bg)),var(--bg));border-bottom:1px solid var(--border);">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;">
        <div>
          <div class="card-kicker">${t('arch.kicker')}</div>
          <div style="font-weight:700;font-size:17px;margin-top:2px;">${t('arch.handoff_title')}</div>
        </div>
        <button class="btn btn-ghost btn-sm" onclick="closeArchWizard()" style="font-size:18px;line-height:1;">×</button>
      </div>
    </div>
    <div style="padding:16px 24px 20px;">
    ${inetBanner}
    ${(() => { const n = _archAccessHANote(); return n ? `<div style="margin-bottom:12px;font-size:12px;color:var(--orange,#f97316);">${esc(n)}</div>` : ''; })()}
    <div style="margin-bottom:16px;">
      <div style="font-size:12px;font-weight:650;margin-bottom:8px;">${t('arch.flows_title')}</div>
      <div style="overflow-x:auto;border:1px solid var(--border);border-radius:10px;">
        <table style="width:100%;border-collapse:collapse;">
          <thead><tr style="background:var(--bg2);">
            <th style="padding:6px 8px;font-size:11px;text-align:left;">${t('arch.flow.from')}</th>
            <th style="padding:6px 8px;font-size:11px;text-align:left;">${t('arch.flow.to')}</th>
            <th style="padding:6px 8px;font-size:11px;text-align:left;">${t('arch.flow.dir')}</th>
            <th style="padding:6px 8px;font-size:11px;text-align:left;">${t('arch.flow.why')}</th>
          </tr></thead>
          <tbody>${flowRows || `<tr><td colspan="4" style="padding:10px;font-size:12px;color:var(--text2);">${t('arch.flows_none')}</td></tr>`}</tbody>
        </table>
      </div>
    </div>
    ${packsHTML}
    <div style="display:flex;justify-content:space-between;gap:8px;margin-top:8px;padding-top:12px;border-top:1px solid var(--border);">
      <button class="btn btn-ghost" onclick="_arch.step='canvas';_archRender()">${t('arch.back_canvas')}</button>
      <button class="btn btn-primary" onclick="closeArchWizard();navigate('infrastructure')">${t('arch.done')}</button>
    </div>
    </div>
  </div>`;
}
