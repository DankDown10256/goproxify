// Wizard architecture : toile hôtes + palette → packs + checklist réseau.
// Dépend de shared/infra-config.js et pages/infrastructure.js (_wiz helpers, _build*, declared-nodes).

const _arch = {
  step: 'canvas', // canvas | handoff
  hosts: [],
  haGroups: [], // [{id:'ha-1', members:['svc-id-a','svc-id-b']}, ...] — N groupes HA possibles
  selectedSvcId: null,
  selectedHostId: null,
  loading: false,
  packs: [], // { hostId, hostName, html, flows, bootstrapUrl }
  pairingSecret: '',
  jwtSecret: '',
  edgeList: [],
  declaredNodes: [],
  onlineEdgeEndpoint: '',
  existingCount: 0,
  acmeProviders: [],
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

function _archResolveEdgeKey(tc, edges) {
  if (!tc) return '';
  const s = String(tc).trim();
  if (edges.some(c => (c.node_name || c.id) === s)) return s;
  const m = s.match(/https?:\/\/([^/:]+)/i);
  if (m) {
    const host = m[1];
    const hit = edges.find(c => (c.node_name || c.id) === host);
    if (hit) return hit.node_name || hit.id;
  }
  return '';
}

function _archLooksColocatedTarget(target, edgeName) {
  const t = String(target || '').trim();
  if (!t || !edgeName) return false;
  const m = t.match(/https?:\/\/([^/:]+)/i);
  if (!m) return false;
  const host = m[1];
  if (host !== edgeName) return false;
  // Hostname docker-compose (pas d’IP, pas de FQDN)
  return !/^\d+\.\d+\.\d+\.\d+$/.test(host) && !host.includes('.');
}

function _archHostFromEndpoint(ep) {
  if (!ep) return '';
  try {
    const u = new URL(ep);
    return u.hostname || '';
  } catch { return ''; }
}

function _archSvcFromExisting(role, node, cfg) {
  const name = (node.display_name || node.node_name || node.name || role).trim();
  const nodeName = (node.node_name || node.name || '').trim();
  // UUID stable du nœud live (absent pour les nœuds purement déclarés)
  const nodeId = (!node.id || String(node.id).startsWith('cfg:') || String(node.id).startsWith('dn_')) ? '' : (node.id || '');
  const runtimes = node.container_runtimes || [];
  const hasDocker = runtimes.some(r => String(r).toLowerCase().includes('docker'));
  const hasPodman = runtimes.some(r => String(r).toLowerCase().includes('podman'));
  let docker = cfg.docker !== false;
  let podman = !!cfg.podman;
  if (cfg.docker === false && !cfg.podman) docker = false;
  if (hasPodman && !hasDocker) { podman = true; docker = false; }
  else if (hasDocker) { docker = true; podman = false; }
  if (role === 'agent' && cfg.docker === undefined && cfg.podman === undefined && !runtimes.length && node.status !== 'online') {
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
    domains: cfg.domains || '',
    acme: !!cfg.acme,
    acmeEmail: cfg.acme_email || '',
    dnsProvider: cfg.dns_provider || 'none',
    reachable: (cfg.reachable_host || '').trim() || (role === 'edge' ? _archHostFromEndpoint(node.endpoint || node.node_endpoint || '') : ''),
    portainerUrl: cfg.portainer_url || '',
    portainerKey: cfg.portainer_key || '',
    targetEdgeId: '',
    placement: (cfg.placement || '').trim(),
    existing: true,
    status: node.status || 'declared',
    nodeName,
    nodeId,
    delegationsOut: [],
    delegationsIn: [],
  };
}

/** Reprend passerelles/Agents live + déclarés sur la toile (hôtes + options). */
function _archHydrateFromExisting(nodes, declared) {
  const rawList = (Array.isArray(nodes) ? nodes : []).filter(n =>
    (n.role === 'edge' || n.role === 'agent') && n.status !== 'pending'
  );
  // Deduplicate: when a node appears as both live (online/offline) and declared, keep live.
  // Live nodes use node_name; declared nodes use name — check both fields.
  const _nodeKey = n => (n.node_name || n.name || n.display_name || n.id || '').trim();
  const liveKeys = new Set(
    rawList.filter(n => n.status !== 'declared').map(n => n.role + ':' + _nodeKey(n))
  );
  const list = rawList.filter(n => {
    if (n.status !== 'declared') return true;
    return !liveKeys.has(n.role + ':' + _nodeKey(n));
  });
  if (!list.length) return { hosts: [_archEmptyHost(1)], haGroups: [], existingCount: 0 };

  const declByName = {};
  for (const d of (Array.isArray(declared) ? declared : [])) {
    if (d && d.name) declByName[d.name] = d;
  }

  const edges = list.filter(n => n.role === 'edge');
  const agents = list.filter(n => n.role === 'agent');
  const hosts = [];
  const hostByKey = new Map();
  const edgeSvcByName = new Map();
  const haGroupsByGid = {}; // gid → [svc.id]

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

  for (const c of edges) {
    const cName = (c.node_name || c.name || c.id || '').trim();
    if (!cName) continue;
    const d = declByName[cName] || declByName[c.display_name];
    const cfg = _archParseCfg(d && d.config);
    const host = ensureHost('edge:' + cName, {
      name: c.display_name || cName,
      region: (d && d.region) || c.region || '',
      internet: !!cfg.internet_exposed,
    });
    const svc = _archSvcFromExisting('edge', c, cfg);
    host.services.push(svc);
    edgeSvcByName.set(cName, svc);
    if (cfg.cluster) {
      const gid = cfg.cluster_group || 'ha-1';
      if (!haGroupsByGid[gid]) haGroupsByGid[gid] = [];
      haGroupsByGid[gid].push(svc.id);
    }
  }

  for (const a of agents) {
    const aName = (a.node_name || a.name || a.id || '').trim();
    if (!aName) continue;
    const d = declByName[aName] || declByName[a.display_name];
    const cfg = _archParseCfg(d && d.config);
    const placement = (cfg.placement || '').trim();
    const target = (cfg.target_edge || a.target_edge || '').trim();
    const edgeKey = _archResolveEdgeKey(target, edges)
      || _archResolveEdgeKey(a.target_edge || '', edges);
    let host;
    // Cas single-stack Docker Compose : 1 passerelle + 1 Agent sans placement déclaré → même hôte.
    const onlyEdgeKey = edges.length === 1 ? (edges[0].node_name || edges[0].id || '').trim() : '';
    const effectiveEdgeKey = edgeKey || (edges.length === 1 && agents.length === 1 && !placement ? onlyEdgeKey : '');
    const colocate = (placement === 'colocated' && effectiveEdgeKey)
      || (placement !== 'remote' && effectiveEdgeKey && _archLooksColocatedTarget(cfg.target_edge || '', effectiveEdgeKey))
      || (edges.length === 1 && agents.length === 1 && !placement && !!effectiveEdgeKey);
    if (colocate && hostByKey.has('edge:' + effectiveEdgeKey)) {
      host = hostByKey.get('edge:' + effectiveEdgeKey);
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
    if (effectiveEdgeKey && edgeSvcByName.has(effectiveEdgeKey)) svc.targetEdgeId = edgeSvcByName.get(effectiveEdgeKey).id;
    if (colocate) svc.placement = 'colocated';
    else if (!svc.placement) svc.placement = 'remote';
    host.services.push(svc);
  }

  // Auto-place Admin on the first internet-facing Edge host (or first Edge host).
  // Admin is always co-deployed with Edge and never reported by the heartbeat.
  if (hosts.length && !hosts.some(h => h.services.some(s => s.type === 'admin'))) {
    const adminHost = hosts.find(h => h.internet && h.services.some(s => s.type === 'edge'))
      || hosts.find(h => h.services.some(s => s.type === 'edge'))
      || hosts[0];
    adminHost.services.unshift({
      id: _archUid('admin'),
      type: 'admin',
      name: 'goproxify-admin',
      access: false, portainer: false, k8s: false, docker: false, podman: false,
      domains: '', acme: false, acmeEmail: '', dnsProvider: 'none',
      reachable: '', portainerUrl: '', portainerKey: '', targetEdgeId: '', placement: '',
      existing: true, status: 'online',
    });
  }

  const haGroups = Object.entries(haGroupsByGid).map(([id, members]) => ({ id, members }));
  return { hosts: hosts.length ? hosts : [_archEmptyHost(1)], haGroups, existingCount: list.length };
}

// ── Modèle : Hôte (machine) → Rôle (service) → Capacité (option du rôle) ──

const _ARCH_ROLES = {
  edge:  { accent: 'var(--accent)', label: 'arch.svc.edge',  desc: 'arch.role.edge_desc' },
  agent: { accent: 'var(--green)',  label: 'arch.svc.agent', desc: 'arch.role.agent_desc' },
  admin: { accent: 'var(--purple)', label: 'arch.svc.admin', desc: 'arch.role.admin_desc' },
};

// Capacités GoProxify : toujours portées par un rôle, jamais posées seules sur un hôte.
const _ARCH_CAPS = [
  { id: 'access',    role: 'edge',  label: 'arch.svc.access',    desc: 'arch.cap.access_desc',    chip: 'Access' },
  { id: 'ha',        role: 'edge',  label: 'arch.svc.ha',        desc: 'arch.cap.ha_desc',        chip: 'HA' },
  { id: 'tls',       role: 'edge',  label: 'arch.svc.domains',   desc: 'arch.cap.tls_desc',       chip: 'TLS' },
  { id: 'docker',    role: 'agent', label: 'arch.svc.docker',    desc: 'arch.cap.docker_desc',    chip: 'Docker' },
  { id: 'podman',    role: 'agent', label: 'arch.svc.podman',    desc: 'arch.cap.podman_desc',    chip: 'Podman' },
  { id: 'portainer', role: 'agent', label: 'arch.svc.portainer', desc: 'arch.cap.portainer_desc', chip: 'Portainer' },
  { id: 'k8s',       role: 'agent', label: 'arch.svc.k8s',       desc: 'arch.cap.k8s_desc',       chip: 'K8s' },
];

const _ARCH_ICONS = {
  host:  '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="7" rx="1"/><rect x="3" y="13" width="18" height="7" rx="1"/><line x1="6.5" y1="7.5" x2="6.5" y2="7.5"/><line x1="6.5" y1="16.5" x2="6.5" y2="16.5"/></svg>',
  edge:  '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="7" y="7" width="10" height="10" rx="1"/><path d="M10 3v4M14 3v4M10 17v4M14 17v4M3 10h4M3 14h4M17 10h4M17 14h4"/></svg>',
  agent: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="2"/><path d="M8.5 15.5a5 5 0 0 1 0-7M15.5 8.5a5 5 0 0 1 0 7M5.6 18.4a9 9 0 0 1 0-12.8M18.4 5.6a9 9 0 0 1 0 12.8"/></svg>',
  admin: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><line x1="4" y1="8" x2="20" y2="8"/><line x1="4" y1="16" x2="20" y2="16"/><circle cx="9" cy="8" r="2"/><circle cx="15" cy="16" r="2"/></svg>',
  cap:   '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="8.5"/><line x1="12" y1="8.5" x2="12" y2="15.5"/><line x1="8.5" y1="12" x2="15.5" y2="12"/></svg>',
  globe: '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><line x1="3" y1="12" x2="21" y2="12"/><path d="M12 3a15 15 0 0 1 0 18a15 15 0 0 1 0-18z"/></svg>',
  lock:  '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="10" width="16" height="10" rx="1.5"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg>',
  trash: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4h6v2"/></svg>',
};

function _archRoleAccent(type) {
  return (_ARCH_ROLES[type] || {}).accent || 'var(--border)';
}

// ── Helpers groupes HA ────────────────────────────────────────────────────────

function _archGroupOfSvc(svcId) {
  return _arch.haGroups.find(g => g.members.includes(svcId)) || null;
}
function _archInHA(svcId) {
  return _arch.haGroups.some(g => g.members.includes(svcId));
}
function _archNextGroupId() {
  const ids = new Set(_arch.haGroups.map(g => g.id));
  let n = 1;
  while (ids.has('ha-' + n)) n++;
  return 'ha-' + n;
}

// ─────────────────────────────────────────────────────────────────────────────

/** Capacités actives d'un rôle, dans l'ordre du catalogue. */
function _archSvcCaps(svc) {
  return _ARCH_CAPS.filter(c => {
    if (c.role !== svc.type) return false;
    if (c.id === 'ha')  return _archInHA(svc.id);
    if (c.id === 'tls') return !!(svc.domains || svc.acme);
    return !!svc[c.id];
  });
}

function _archMarkPendingDeploy(name) {
  try {
    const s = JSON.parse(localStorage.getItem('gpx_pending_deploy') || '{}');
    s[name] = { savedAt: new Date().toISOString() };
    localStorage.setItem('gpx_pending_deploy', JSON.stringify(s));
  } catch {}
}

window.archMarkDeployed = function(name) {
  try {
    const s = JSON.parse(localStorage.getItem('gpx_pending_deploy') || '{}');
    delete s[name];
    localStorage.setItem('gpx_pending_deploy', JSON.stringify(s));
  } catch {}
  navigate('infrastructure');
};

function openArchWizard() {
  _arch.step = 'canvas';
  _arch.hosts = [_archEmptyHost(1)];
  _arch.haGroups = [];
  _arch.selectedSvcId = null;
  _arch.selectedHostId = null;
  _arch.packs = [];
  _arch.pairingSecret = '';
  _arch.edgeList = [];
  _arch.declaredNodes = [];
  _arch.onlineEdgeEndpoint = '';
  _arch.existingCount = 0;
  _arch.loading = true;
  _archLoad();
  navigate('architecture');
}

function _archGoToCanvas() {
  _arch.step = 'canvas';
  if (!_arch.hosts.length || (_arch.hosts.length === 1 && !_arch.hosts[0].services.length)) {
    _arch.loading = true;
    _archLoad();
  } else {
    _archRender();
  }
}

function _archLoad() {
  return Promise.all([
    api('GET', '/pairing-secret').catch(() => null),
    api('GET', '/nodes').catch(() => null),
    api('GET', '/tokens?role=edge').catch(() => null),
    api('GET', '/declared-nodes').catch(() => null),
    api('GET', '/portal/enabled').catch(() => null),
    api('GET', '/domains').catch(() => null),
    api('GET', '/acme/providers').catch(() => []),
  ]).then(([sec, nodes, tokens, declared, portalEnabled, domains, acmeProviders]) => {
    _arch.acmeProviders = Array.isArray(acmeProviders) ? acmeProviders : [];
    const portalEdges = portalEnabled?.edges || {};
    _arch.pairingSecret = sec?.secret || '';
    _wiz.pairingSecret = _arch.pairingSecret;
    if (!_arch.jwtSecret) {
      const arr = new Uint8Array(32);
      (typeof crypto !== 'undefined' && crypto.getRandomValues) ? crypto.getRandomValues(arr) : arr.forEach((_,i,a) => a[i] = Math.floor(Math.random()*256));
      _arch.jwtSecret = Array.from(arr).map(b => b.toString(16).padStart(2,'0')).join('');
    }
    _arch.edgeList = typeof _wizLoadEdgeList === 'function' ? _wizLoadEdgeList(nodes, tokens) : [];
    _arch.declaredNodes = Array.isArray(declared) ? declared : [];
    _wiz.declaredNodes = _arch.declaredNodes;
    const online = (_arch.edgeList || []).find(c => (c.status || '') === 'online' || c.node_endpoint);
    if (online) {
      _arch.onlineEdgeEndpoint = online.node_endpoint || online.endpoint || '';
    }
    const hydrated = _archHydrateFromExisting(nodes, _arch.declaredNodes);
    _arch.hosts = hydrated.hosts;
    _arch.haGroups = hydrated.haGroups;
    _arch.existingCount = hydrated.existingCount || 0;
    // Applique l'état portail Access depuis les settings Admin
    for (const h of _arch.hosts) {
      for (const s of h.services || []) {
        if (s.type === 'edge') {
          const key = (s.nodeName && s.nodeName in portalEdges) ? s.nodeName
                    : (s.name in portalEdges) ? s.name : null;
          if (key !== null) s.access = !!portalEdges[key];
        }
      }
    }
    // Prérempli les domaines des services passerelle depuis la table /domains.
    // domain.edge_id = UUID token → matché via tokens (id + node_name).
    // On écrase aussi svc.acme et svc.dnsProvider d'après les vraies données.
    if (Array.isArray(domains) && domains.length) {
      const tokenByID = new Map();
      for (const tok of (Array.isArray(tokens) ? tokens : [])) {
        if (tok.id && tok.node_name) tokenByID.set(tok.id, tok.node_name);
      }
      // index par node_name : { domains[], hasAcme, dnsProvider }
      const infoByEdgeName = new Map();
      // délégations : sourceNodeName → [{id, domain, targetName, mode}], targetNodeName → [...]
      const delegOut = new Map();
      const delegIn  = new Map();
      for (const d of domains) {
        if (!d.domain || !d.edge_id) continue;
        const nodeName = tokenByID.get(d.edge_id) || d.edge_id;
        const info = infoByEdgeName.get(nodeName) || { domainList: [], hasAcme: false, dnsProvider: 'none' };
        info.domainList.push(d.domain);
        // Une délégation (delegated_to_edge_id non vide) n'est pas de l'ACME
        if (!d.delegated_to_edge_id && d.cert_method === 'dns') {
          info.hasAcme = true;
          if (d.dns_provider && d.dns_provider !== 'none') info.dnsProvider = d.dns_provider;
        }
        infoByEdgeName.set(nodeName, info);
        if (d.delegated_to_edge_id) {
          const targetName = tokenByID.get(d.delegated_to_edge_id) || d.delegated_to_edge_id;
          const mode = d.delegation_mode || 'passthrough';
          const entry = { id: d.id, domain: d.domain, targetName, sourceName: nodeName, mode };
          if (!delegOut.has(nodeName)) delegOut.set(nodeName, []);
          delegOut.get(nodeName).push(entry);
          if (!delegIn.has(targetName)) delegIn.set(targetName, []);
          delegIn.get(targetName).push(entry);
        }
      }
      for (const h of _arch.hosts) {
        for (const s of h.services || []) {
          if (s.type !== 'edge') continue;
          const key = s.nodeName || s.name;
          const info = infoByEdgeName.get(key) || infoByEdgeName.get(s.name);
          s.domains = info ? info.domainList.join(', ') : '';
          // N'activer ACME depuis les domaines que dans le sens positif :
          // si un domaine dns existe → forcer true ; sinon laisser la valeur du declared config.
          if (info && info.hasAcme) {
            s.acme = true;
            if (info.dnsProvider && info.dnsProvider !== 'none') s.dnsProvider = info.dnsProvider;
          }
          s.delegationsOut = delegOut.get(key) || delegOut.get(s.name) || [];
          s.delegationsIn  = delegIn.get(key)  || delegIn.get(s.name)  || [];
        }
      }
    }
    // Passerelles déclarées absents de /nodes → déjà dans nodes via status declared ; sync edgeList
    for (const n of _arch.declaredNodes.filter(x => x.role === 'edge')) {
      if (_arch.edgeList.some(c => c.node_name === n.name)) continue;
      const cfg = _archParseCfg(n.config);
      const host = (cfg.reachable_host || '').trim();
      _arch.edgeList.push({
        node_name: n.name,
        display_name: n.name,
        role: 'edge',
        status: 'declared',
        node_endpoint: host && typeof _wizEdgeEndpoint === 'function' ? _wizEdgeEndpoint(host) : '',
      });
    }
    _arch.loading = false;
    _archRender();
  });
}

function closeArchWizard() {
  navigate('infrastructure');
}

async function _archSaveTopology() {
  const allSvcs = _arch.hosts.flatMap(h =>
    (h.services || [])
      .filter(s => s.type === 'edge' || s.type === 'agent')
      .map(s => ({ svc: s, host: h }))
  );
  if (!allSvcs.length) { toast(t('arch.save_nothing') || 'Aucun nœud à enregistrer', 'warning'); return; }

  // Nœuds présents avant la sauvegarde (pour détecter les suppressions / renommages)
  const prevDeclared = [...(_arch.declaredNodes || [])];

  const saved = [];
  for (const { svc, host } of allSvcs) {
    const cfg = { internet_exposed: !!host.internet, reachable_host: svc.reachable || '' };
    if (svc.nodeId) cfg.node_id = svc.nodeId; // UUID stable du nœud live
    if (svc.type === 'edge') {
      cfg.portal        = !!svc.access;
      cfg.cluster       = _archInHA(svc.id);
      cfg.cluster_group = (() => { const g = _archGroupOfSvc(svc.id); return g ? g.id : ''; })();
      cfg.domains       = svc.domains || '';
      cfg.acme          = !!svc.acme;
      cfg.acme_email    = svc.acmeEmail || '';
      cfg.dns_provider  = svc.dnsProvider || 'none';
    }
    if (svc.type === 'agent') {
      cfg.docker         = !!svc.docker;
      cfg.podman         = !!svc.podman;
      cfg.k8s            = !!svc.k8s;
      cfg.portainer      = !!svc.portainer;
      cfg.portainer_url  = svc.portainerUrl || '';
      cfg.portainer_key  = svc.portainerKey || '';
      cfg.placement      = svc.placement || '';
    }

    // Si renommage, supprimer l'ancienne entrée
    const prevName = svc._prevEdgeName || svc._prevAgentName;
    if (prevName && prevName !== svc.name) {
      const old = prevDeclared.find(n => n.role === svc.type && n.name === prevName);
      if (old && old.id && !old.id.startsWith('cfg:')) {
        await api('DELETE', '/declared-nodes/' + old.id).catch(() => {});
      }
    }

    // Pour les nœuds live, utiliser node_name comme clé d'upsert (pas le display_name)
    // pour éviter de créer un doublon si display_name ≠ node_name.
    const declName = svc.nodeName || svc.name;
    const result = await api('POST', '/declared-nodes', {
      role: svc.type,
      name: declName,
      region: host.region || '',
      environment: '',
      config: cfg,
    }).catch(() => null);
    if (result) saved.push(result);
  }

  // Supprimer les declared-nodes DB qui ne sont plus sur le canvas
  const canvasKeys = new Set(allSvcs.map(({ svc }) => svc.type + ':' + (svc.nodeName || svc.name)));
  for (const n of prevDeclared) {
    if (n.id && !n.id.startsWith('cfg:') && !canvasKeys.has(n.role + ':' + n.name)) {
      await api('DELETE', '/declared-nodes/' + n.id).catch(() => {});
    }
  }

  // Synchroniser la config ACME vers l'Admin depuis les paramètres des services passerelle.
  // L'email ACME est configuré sur la passerelle dans le wizard, mais persiste côté Admin.
  // On se base sur acmeEmail seul (svc.acme peut être false si aucun domaine dns n'est encore créé).
  const acmeEdgeSvc = allSvcs.find(({ svc }) => svc.type === 'edge' && svc.acmeEmail);
  if (acmeEdgeSvc) {
    const c = acmeEdgeSvc.svc;
    await api('PUT', '/settings/acme', {
      enabled: !!c.acme,
      email: c.acmeEmail,
      dns_type: c.dnsProvider !== 'none' ? (c.dnsProvider || '') : '',
    }).catch(() => {});
  }

  // Appliquer le portail Access sur les passerelles en ligne
  for (const { svc } of allSvcs) {
    if (svc.type === 'edge' && (svc.status === 'online') ) {
      const edgeName = svc.nodeName || svc.name;
      const q = '?edge=' + encodeURIComponent(edgeName);
      const existing = await api('GET', '/portal' + q).catch(() => ({}));
      await api('PUT', '/portal' + q, { ...existing, enabled: !!svc.access }).catch(() => {});
    }
  }

  // Recharge declaredNodes pour refléter l'état persisté
  const fresh = await api('GET', '/declared-nodes').catch(() => null);
  if (fresh) { _arch.declaredNodes = fresh; _wiz.declaredNodes = fresh; }

  toast(t('common.saved') || 'Enregistré', 'success');
  _archRender();
}

pages.architecture = function() {
  if (!_arch.hosts.length && !_arch.loading) {
    _arch.loading = true;
    _archLoad();
  }
  _archRender();
};

function _archRender() {
  const content = document.getElementById('content');
  if (!content || state.page !== 'architecture') return;
  content.innerHTML = _arch.step === 'handoff' ? _archHandoffHTML() : _archCanvasHTML();
};

// ── Bibliothèque (rail gauche) ────────────────────────────────────────────

function _archRoleSourceHTML(type) {
  const r = _ARCH_ROLES[type];
  return `<div draggable="true" data-arch-type="${type}" ondragstart="_archDragStart(event)"
    class="arch-role-src" style="--arch-accent:${r.accent};" title="${t('arch.drag_role_hint')}">
    <span class="arch-glyph">${_ARCH_ICONS[type]}</span>
    <span style="min-width:0;">
      <span class="arch-role-src-name">${esc(t(r.label))}</span>
      <span class="arch-role-src-desc" style="display:block;">${esc(t(r.desc))}</span>
    </span>
  </div>`;
}

function _archCapLegendHTML() {
  return `<div class="arch-cap-legend">${_ARCH_CAPS.map(c => `
    <div class="arch-cap-legend-row">
      <span class="arch-cap-dot" style="--arch-accent:${_archRoleAccent(c.role)};"></span>
      <strong>${esc(t(c.label))}</strong>
      <span class="arch-cap-scope">${esc(t(_ARCH_ROLES[c.role].label))}</span>
    </div>`).join('')}</div>`;
}

function _archLibraryHTML() {
  // Raccourci "Ajouter un agent" quand une passerelle est déjà présent sur la toile
  const hasEdges = _arch.hosts.some(h => (h.services || []).some(s => s.type === 'edge'));
  const quickAddHTML = hasEdges ? `
    <div class="arch-panel">
      <div class="arch-panel-head">
        <div class="arch-panel-title">${t('infra.add_agent')}</div>
        <div class="arch-panel-sub">${t('arch.lib.quickadd_sub') || 'Ajouter un agent à l\'infrastructure existante'}</div>
      </div>
      <div class="arch-panel-body">
        <button class="btn btn-primary btn-sm" style="width:100%;justify-content:center;" onclick="_archQuickAddAgent()">${t('arch.add_host') ? (t('infra.add_agent')) : 'Ajouter un agent'}</button>
      </div>
    </div>` : '';

  return `${quickAddHTML}
    <div class="arch-panel">
      <div class="arch-panel-head">
        <div class="arch-panel-title">${t('arch.palette.hosts')}</div>
        <div class="arch-panel-sub">${t('arch.lib.hosts_sub')}</div>
      </div>
      <div class="arch-panel-body">
        <button class="btn btn-secondary btn-sm" style="width:100%;justify-content:center;" onclick="_archAddHost()">${t('arch.add_host')}</button>
      </div>
    </div>

    <div class="arch-panel">
      <div class="arch-panel-head">
        <div class="arch-panel-title">${t('arch.palette.roles')}</div>
        <div class="arch-panel-sub">${t('arch.lib.roles_sub')}</div>
      </div>
      <div class="arch-panel-body">
        ${_archRoleSourceHTML('edge')}
        ${_archRoleSourceHTML('agent')}
        ${_archRoleSourceHTML('admin')}
      </div>
    </div>

    <div class="arch-panel">
      <div class="arch-panel-head">
        <div class="arch-panel-title">${t('arch.palette.caps')}</div>
        <div class="arch-panel-sub">${t('arch.lib.caps_sub')}</div>
      </div>
      <div class="arch-panel-body">${_archCapLegendHTML()}</div>
    </div>`;
}

/** Ajoute un agent sur le premier hôte qui contient une passerelle (ou un nouvel hôte), et ouvre l'inspecteur. */
function _archQuickAddAgent() {
  // Cherche un hôte avec une passerelle pour co-localiser l'agent, sinon crée un hôte dédié
  let host = _arch.hosts.find(h => (h.services || []).some(s => s.type === 'edge'));
  if (!host) {
    host = _archEmptyHost(_arch.hosts.length + 1);
    _arch.hosts.push(host);
  }
  _archAddService(host.id, 'agent');
}

// ── Toile ─────────────────────────────────────────────────────────────────

function _archLegendHTML() {
  const step = (level, glyph, name, desc) => `
    <div class="arch-legend-step" data-level="${level}">
      <span class="arch-legend-glyph">${glyph}</span>
      <span style="min-width:0;">
        <span class="arch-legend-name">${esc(name)}</span>
        <span class="arch-legend-desc" style="display:block;">${esc(desc)}</span>
      </span>
    </div>`;
  return `<div class="arch-legend">
    ${step('host', _ARCH_ICONS.host, t('arch.level.host'), t('arch.level.host_desc'))}
    ${step('role', _ARCH_ICONS.edge, t('arch.level.role'), t('arch.level.role_desc'))}
    ${step('cap',  _ARCH_ICONS.cap,  t('arch.level.cap'),  t('arch.level.cap_desc'))}
  </div>`;
}

function _archZoneHTML(zone, title, hint, hosts, emptyKey) {
  const body = hosts.length
    ? hosts.map(h => _archHostCard(h)).join('')
    : `<div class="arch-zone-empty">${t(emptyKey)}</div>`;
  return `<section class="arch-zone" data-zone="${zone}">
    <div class="arch-zone-head">
      <span class="arch-zone-title">${esc(title)}</span>
      <span class="arch-zone-hint">${esc(hint)}</span>
      <span class="arch-zone-count">${hosts.length}</span>
    </div>
    <div class="arch-zone-body">${body}</div>
  </section>`;
}

function _archCountsHTML() {
  const roles = _arch.hosts.flatMap(h => h.services || []);
  const caps = roles.reduce((n, s) => n + _archSvcCaps(s).length, 0);
  return `<div class="arch-summary">
    <span><b>${_arch.hosts.length}</b> ${esc(t('arch.count.hosts'))}</span>
    <span><b>${roles.length}</b> ${esc(t('arch.count.roles'))}</span>
    <span><b>${caps}</b> ${esc(t('arch.count.caps'))}</span>
  </div>`;
}

function _archCanvasHTML() {
  if (_arch.loading) {
    return `<p style="color:var(--text2)">${t('common.loading')}</p>`;
  }
  const edgeHosts = _arch.hosts.filter(h => h.internet);
  const privateHosts = _arch.hosts.filter(h => !h.internet);
  const err = _archValidate() || '';
  const haNote = _archAccessHANote();

  return `<div class="arch-page">
    <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap;">
      <div style="min-width:0;">
        <div class="card-kicker">${t('arch.kicker')}</div>
        <h2 style="font-family:var(--font-heading);font-size:20px;font-weight:700;margin:0;letter-spacing:-.01em;">${t('arch.title')}</h2>
        <p style="font-size:12.5px;color:var(--text2);margin-top:5px;max-width:52rem;line-height:1.5;">${t('arch.subtitle_map')}</p>
        ${_arch.existingCount ? `<p style="font-size:12px;color:var(--text2);margin-top:4px;">${t('arch.existing_loaded', { n: _arch.existingCount })}</p>` : ''}
      </div>
      <button class="btn btn-ghost btn-sm" onclick="closeArchWizard()">${t('arch.back_infra')}</button>
    </div>

    ${_archLegendHTML()}

    <div class="arch-layout">
      <aside class="arch-rail">${_archLibraryHTML()}</aside>

      <div style="min-width:0;">
        ${_archZoneHTML('edge', t('arch.zone.internet'), t('arch.zone.internet_hint'), edgeHosts, 'arch.zone.internet_empty')}
        ${_archZoneHTML('private', t('arch.zone.private'), t('arch.zone.private_hint'), privateHosts, 'arch.zone.private_empty')}
      </div>

      <aside class="arch-rail arch-rail-right">${_archInspectorHTML()}</aside>
    </div>

    ${haNote ? `<div class="arch-msg" data-tone="warn">${esc(haNote)}</div>` : ''}
    ${err ? `<div class="arch-msg" data-tone="error">${esc(err)}</div>` : ''}
    <div class="arch-msg" data-tone="info">${t('arch.labels_elsewhere')}</div>

    <div class="arch-actionbar">
      ${_archCountsHTML()}
      <div class="arch-actionbar-btns">
        ${_arch.packs.length
          ? ''
          : `<button class="btn btn-ghost" onclick="closeArchWizard()">${t('common.cancel') || 'Annuler'}</button>`
        }
        <button class="btn btn-ghost" onclick="_archSaveTopology()" ${err ? 'disabled' : ''}>${t('arch.save_topology') || 'Enregistrer'}</button>
        <button class="btn btn-primary" onclick="_archGoHandoff()" ${err ? 'disabled' : ''}>${t('arch.continue')}</button>
      </div>
    </div>
  </div>`;
}

function _archRoleCardHTML(host, svc) {
  const accent = _archRoleAccent(svc.type);
  const sel = svc.id === _arch.selectedSvcId;
  const caps = _archSvcCaps(svc);
  const chips = caps.map(c =>
    `<span class="arch-chip">${esc(c.chip)}</span>`
  ).join('');
  const state = [];
  if (svc.existing) state.push(svc.status === 'online' ? t('arch.badge.online') : t('arch.badge.declared'));
  if (svc.type === 'agent' && svc.placement === 'colocated') state.push(t('arch.badge.colocated'));
  const stateChips = state.map(s => `<span class="arch-chip" data-kind="state">${esc(s)}</span>`).join('');

  return `<div draggable="true" data-arch-svc="${svc.id}" ondragstart="_archDragStart(event)"
    onclick="event.stopPropagation();_archSelectSvc('${svc.id}')"
    class="arch-role${sel ? ' selected' : ''}" style="--arch-accent:${accent};"
    title="${t('arch.drag_move_hint')}">
    <span class="arch-glyph">${_ARCH_ICONS[svc.type] || ''}</span>
    <span class="arch-role-main">
      <span class="arch-role-id">
        <span class="arch-role-kind">${esc(t(_ARCH_ROLES[svc.type].label))}</span>
        <span class="arch-role-name">${esc(svc.name)}</span>
      </span>
      ${(chips || stateChips)
        ? `<span class="arch-role-caps">${chips}${stateChips}</span>`
        : `<span class="arch-role-nocap">${t('arch.role.no_cap')}</span>`}
    </span>
    <button class="arch-role-del" title="${t('common.delete') || 'Supprimer'}"
      onclick="event.stopPropagation();_archRemoveSvc('${host.id}','${svc.id}')">${_ARCH_ICONS.trash}</button>
  </div>`;
}

function _archHostCard(host) {
  const inet = !!host.internet;
  const sel = host.id === _arch.selectedHostId && !_arch.selectedSvcId;
  const roles = (host.services || []).map(s => _archRoleCardHTML(host, s)).join('');
  const addBtn = type => `<button class="arch-addrole" style="--arch-accent:${_archRoleAccent(type)};"
    onclick="event.stopPropagation();_archAddService('${host.id}','${type}')">+ ${esc(t(_ARCH_ROLES[type].label))}</button>`;

  return `<div class="arch-host${sel ? ' selected' : ''}" data-host-id="${host.id}"
    onclick="_archSelectHost('${host.id}')"
    ondragover="event.preventDefault();this.classList.add('drop-active')"
    ondragleave="this.classList.remove('drop-active')"
    ondrop="this.classList.remove('drop-active');_archDrop(event,'${host.id}')">
    <div class="arch-host-head">
      <span class="arch-host-glyph">${_ARCH_ICONS.host}</span>
      <input class="arch-host-name" value="${esc(host.name)}" aria-label="${t('arch.host.name')}"
        onclick="event.stopPropagation()" onchange="_archRenameHost('${host.id}',this.value)">
    </div>
    <div class="arch-host-meta">
      <button type="button" class="arch-host-zonetag" data-on="${inet ? 1 : 0}" aria-pressed="${inet}"
        title="${t('arch.host.internet_hint')}"
        onclick="event.stopPropagation();_archSetHostInternet('${host.id}',${!inet})">
        ${inet ? _ARCH_ICONS.globe : _ARCH_ICONS.lock}${esc(inet ? t('arch.host.internet') : t('arch.host.private'))}
      </button>
      <input class="arch-host-region" value="${esc(host.region || '')}" placeholder="${t('arch.host.region_ph')}"
        aria-label="${t('arch.host.region')}"
        onclick="event.stopPropagation()" onchange="_archSetHostRegion('${host.id}',this.value)">
    </div>
    <div class="arch-host-slot">
      ${roles || `<div class="arch-host-drop">${t('arch.drop_here')}</div>`}
    </div>
    <div class="arch-host-foot">
      ${addBtn('edge')}${addBtn('agent')}${addBtn('admin')}
      ${_arch.hosts.length > 1 ? `<button class="btn-icon arch-host-del" style="color:var(--red);" title="${t('arch.host.remove')}"
        onclick="event.stopPropagation();_archRemoveHost('${host.id}')">${_ARCH_ICONS.trash}</button>` : ''}
    </div>
  </div>`;
}

// ── Inspecteur (rail droit) ───────────────────────────────────────────────

const _ARCH_DNS_PROVIDERS = [
  { id: 'none', label: '—' },
  { id: 'cloudflare', label: 'Cloudflare' },
  { id: 'ovh', label: 'OVH' },
  { id: 'gandi', label: 'Gandi' },
  { id: 'route53', label: 'AWS Route53' },
  { id: 'hetzner', label: 'Hetzner' },
];

/** Ligne capacité : case à cocher + libellé + explication. */
function _archCapRow(on, label, desc, onchange, extraHTML) {
  return `<label class="arch-cap" data-on="${on ? 1 : 0}">
      <input type="checkbox" ${on ? 'checked' : ''} onchange="${onchange}">
      <span style="min-width:0;">
        <span class="arch-cap-label" style="display:block;">${label}</span>
        <span class="arch-cap-desc" style="display:block;">${esc(desc)}</span>
      </span>
    </label>${on && extraHTML ? `<div class="arch-cap-extra">${extraHTML}</div>` : ''}`;
}

function _archGroup(title, bodyHTML) {
  return `<div><div class="arch-group-title">${esc(title)}</div>${bodyHTML}</div>`;
}

function _archField(label, inputHTML) {
  return `<div class="arch-field"><span class="arch-field-label">${label}</span>${inputHTML}</div>`;
}

function _archInspectorHTML() {
  const svc = _arch.selectedSvcId ? _archFindSvc(_arch.selectedSvcId) : null;
  if (svc) return _archInspectRole(svc);
  const host = _arch.selectedHostId ? _arch.hosts.find(h => h.id === _arch.selectedHostId) : null;
  if (host) return _archInspectHost(host);
  return `<div class="arch-panel">
    <div class="arch-panel-head"><div class="arch-panel-title">${t('arch.inspector')}</div></div>
    <div class="arch-insp-empty">${t('arch.inspector_empty')}</div>
  </div>`;
}

function _archInspectHost(host) {
  const inet = !!host.internet;
  const roles = host.services || [];
  const rolesHTML = roles.length
    ? roles.map(s => `<button class="arch-addrole" style="--arch-accent:${_archRoleAccent(s.type)};display:block;width:100%;text-align:left;margin-bottom:5px;"
        onclick="_archSelectSvc('${s.id}')">${esc(t(_ARCH_ROLES[s.type].label))} · ${esc(s.name)}</button>`).join('')
    : `<div class="arch-cap-desc">${t('arch.host.no_role')}</div>`;

  return `<div class="arch-panel">
    <div class="arch-insp-head">
      <div class="arch-insp-level">${t('arch.level.host')}</div>
      <div class="arch-insp-name">${esc(host.name)}</div>
      <div class="arch-insp-note">${t('arch.host.insp_note')}</div>
    </div>
    <div class="arch-insp-body">
      ${_archGroup(t('arch.group.identity'),
        _archField(t('arch.host.name'), `<input class="arch-input" value="${esc(host.name)}" onchange="_archRenameHost('${host.id}',this.value);_archRender()">`) +
        _archField(t('arch.host.region'), `<input class="arch-input" value="${esc(host.region || '')}" placeholder="eu-west-1" onchange="_archSetHostRegion('${host.id}',this.value)">`)
      )}
      ${_archGroup(t('arch.group.network'),
        _archCapRow(inet, t('arch.host.internet'), t('arch.host.internet_hint'),
          `_archSetHostInternet('${host.id}',this.checked)`)
      )}
      ${_archGroup(t('arch.group.roles_on_host'), rolesHTML)}
      ${_arch.hosts.length > 1 ? `<button class="btn btn-ghost btn-sm" style="color:var(--red);align-self:flex-start;" onclick="_archRemoveHost('${host.id}')">${t('arch.host.remove')}</button>` : ''}
    </div>
  </div>`;
}

function _archInspectRole(svc) {
  const host = _archFindHostOfSvc(svc.id);
  const accent = _archRoleAccent(svc.type);
  let body = '';

  if (svc.type === 'edge') {
    const namedProviders = _arch.acmeProviders || [];
    const dnsProviderList = namedProviders.length
      ? [{ id: 'none', label: '—' }, ...namedProviders.map(p => ({ id: p.id, label: `${p.name} (${p.type})` }))]
      : _ARCH_DNS_PROVIDERS;
    const dnsOpts = dnsProviderList.map(p =>
      `<option value="${p.id}" ${(svc.dnsProvider || 'none') === p.id ? 'selected' : ''}>${esc(p.label)}</option>`
    ).join('');
    body = `
      ${_archGroup(t('arch.group.identity'),
        _archField(t('arch.role.name'), `<input class="arch-input" value="${esc(svc.name)}" oninput="_archSetField('${svc.id}','name',this.value)">` + _archImpactBadge('restart', svc.existing)) +
        _archField(t('arch.opt.reachable'), `<input class="arch-input" value="${esc(svc.reachable || '')}" placeholder="edge.example.com" oninput="_archSetField('${svc.id}','reachable',this.value)">`) +
        `<div class="arch-cap-desc">${t('arch.opt.region_from_host', { region: (host && host.region) || '—' })}</div>`
      )}
      ${_archGroup(t('arch.group.caps'),
        _archCapRow(!!svc.access, t('arch.svc.access') + _archImpactBadge('restart', svc.existing && svc.status !== 'online'), t('arch.cap.access_desc'),
          `_archSetOpt('${svc.id}','access',this.checked)`) +
        _archCapRow(_archInHA(svc.id), t('arch.svc.ha') + _archImpactBadge('redeploy', svc.existing), t('arch.cap.ha_desc'),
          `_archSetHAGroup('${svc.id}',this.checked,'')`,
          (() => {
            const curGroup = _archGroupOfSvc(svc.id);
            const peers = curGroup ? curGroup.members.filter(id => id !== svc.id).map(id => { const p = _archFindSvc(id); return p ? p.name : id; }) : [];
            const groupOpts = _arch.haGroups.map(g =>
              `<option value="${esc(g.id)}" ${curGroup && curGroup.id === g.id ? 'selected' : ''}>${esc(g.id.replace(/^ha-(\d+)$/, t('arch.ha.group_n') + ' $1'))}</option>`
            ).join('') + `<option value="new">${esc(t('arch.ha.new_group'))}</option>`;
            return `<div style="margin-bottom:4px;">${esc(t('arch.ha.group'))} : <select class="arch-select" style="display:inline-block;width:auto;margin-left:4px;" onchange="_archSetHAGroup('${svc.id}',true,this.value)">${groupOpts}</select></div>` +
              (peers.length
                ? `<div class="arch-cap-desc">${esc(t('arch.ha.peers', { names: peers.join(', ') }))}</div>`
                : `<div class="arch-cap-desc">${esc(t('arch.ha.peers_none'))}</div>`);
          })()) +
        _archCapRow(!!(svc.domains || svc.acme), t('arch.svc.domains') + _archImpactBadge('restart', svc.existing), t('arch.cap.tls_desc'),
          `_archSetTLS('${svc.id}',this.checked)`,
          _archField(t('arch.opt.domains'), `<input class="arch-input" value="${esc(svc.domains || '')}" placeholder="app.example.fr, api.example.fr" oninput="_archSetField('${svc.id}','domains',this.value)">`) +
          _archCapRow(!!svc.acme, t('arch.opt.acme'), t('arch.cap.acme_desc'),
            `_archSetOpt('${svc.id}','acme',this.checked)`,
            _archField(t('arch.opt.acme_email'), `<input class="arch-input" value="${esc(svc.acmeEmail || '')}" placeholder="admin@example.fr" oninput="_archSetField('${svc.id}','acmeEmail',this.value)">`) +
            _archField(t('arch.opt.dns_provider'), `<select class="arch-select" onchange="_archSetField('${svc.id}','dnsProvider',this.value);_archRender()">${dnsOpts}</select>`) +
            `<div class="arch-cap-desc">${t('arch.opt.acme_admin_hint')}</div>`
          )
        )
      )}
      ${(() => {
        const dOut = svc.delegationsOut || [];
        const dIn  = svc.delegationsIn  || [];
        if (!dOut.length && !dIn.length) return '';
        const outHTML = dOut.length ? `
          <div class="arch-cap-desc" style="margin-bottom:8px;">${esc(t('arch.deleg.out_desc'))}</div>
          ${dOut.map(d => `
            <div style="padding:8px 0;border-bottom:1px solid var(--border);">
              <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:5px;">
                <span style="font-size:12px;font-weight:600;flex:1;min-width:0;">${esc(d.domain)}</span>
                <span style="font-size:11px;color:var(--text2);">→ ${esc(d.targetName)}</span>
              </div>
              <div style="display:flex;gap:10px;flex-wrap:wrap;">
                <label style="display:flex;align-items:center;gap:4px;font-size:11.5px;cursor:pointer;" title="${esc(t('arch.deleg.passthrough_hint'))}">
                  <input type="radio" name="dmode_${esc(d.id)}" value="passthrough" ${d.mode !== 'terminate' ? 'checked' : ''} onchange="_archSetDelegMode('${esc(d.id)}','passthrough')">
                  ${esc(t('arch.deleg.passthrough'))}
                </label>
                <label style="display:flex;align-items:center;gap:4px;font-size:11.5px;cursor:pointer;" title="${esc(t('arch.deleg.terminate_hint'))}">
                  <input type="radio" name="dmode_${esc(d.id)}" value="terminate" ${d.mode === 'terminate' ? 'checked' : ''} onchange="_archSetDelegMode('${esc(d.id)}','terminate')">
                  ${esc(t('arch.deleg.terminate'))}
                </label>
              </div>
            </div>`).join('')}
        ` : '';
        const inHTML = dIn.length ? `
          ${dOut.length ? `<div style="margin-top:10px;"></div>` : ''}
          <div class="arch-cap-desc" style="margin-bottom:6px;">${esc(t('arch.deleg.in_desc'))}</div>
          ${dIn.map(d => `
            <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;padding:5px 0;border-bottom:1px solid var(--border);">
              <span style="font-size:12px;font-weight:600;flex:1;min-width:0;">${esc(d.domain)}</span>
              <span style="font-size:11px;color:var(--text2);">${esc(t('arch.deleg.from'))} ${esc(d.sourceName)}</span>
              <span style="font-size:11px;padding:2px 6px;border-radius:4px;background:var(--bg2,var(--bg));color:var(--text2);">${esc(d.mode === 'terminate' ? t('arch.deleg.terminate') : t('arch.deleg.passthrough'))}</span>
            </div>`).join('')}
        ` : '';
        return _archGroup(t('arch.group.delegations'), outHTML + inHTML);
      })()}`;
  } else if (svc.type === 'agent') {
    const edges = _arch.hosts.flatMap(h => (h.services || []).filter(s => s.type === 'edge'));
    const targetOpts = edges.map(c =>
      `<option value="${esc(c.id)}" ${svc.targetEdgeId === c.id ? 'selected' : ''}>${esc(c.name)}</option>`
    ).join('');
    body = `
      ${_archGroup(t('arch.group.identity'),
        _archField(t('arch.role.name'), `<input class="arch-input" value="${esc(svc.name)}" oninput="_archSetField('${svc.id}','name',this.value)">` + _archImpactBadge('restart', svc.existing)) +
        (edges.length > 1
          ? _archField(t('arch.opt.target_edge'),
              `<select class="arch-select" onchange="_archSetField('${svc.id}','targetEdgeId',this.value)">
                <option value="">${t('arch.opt.target_edge_auto')}</option>${targetOpts}
              </select>`)
          : '') +
        `<div class="arch-cap-desc">${t('arch.opt.region_from_host', { region: (host && host.region) || '—' })}</div>`
      )}
      ${_archGroup(t('arch.opt.discovery'),
        _archCapRow(!!svc.docker, t('arch.svc.docker') + _archImpactBadge('redeploy', svc.existing), t('arch.cap.docker_desc'),
          `_archSetRuntime('${svc.id}','docker',this.checked)`) +
        _archCapRow(!!svc.podman, t('arch.svc.podman') + _archImpactBadge('redeploy', svc.existing), t('arch.cap.podman_desc'),
          `_archSetRuntime('${svc.id}','podman',this.checked)`) +
        _archCapRow(!!svc.portainer, t('arch.svc.portainer') + _archImpactBadge('restart', svc.existing), t('arch.cap.portainer_desc'),
          `_archSetOpt('${svc.id}','portainer',this.checked)`,
          _archField('URL' + (svc.portainer && !svc.portainerUrl ? ' <span style="color:var(--red);font-size:10px;font-weight:700;vertical-align:middle;">*</span>' : ''),
            `<input class="arch-input" style="${svc.portainer && !svc.portainerUrl ? 'border-color:var(--red);' : ''}" value="${esc(svc.portainerUrl || '')}" placeholder="https://portainer:9443" oninput="_archSetField('${svc.id}','portainerUrl',this.value)">`) +
          _archField(t('arch.opt.portainer_key') + (svc.portainer && !svc.portainerKey ? ' <span style="color:var(--red);font-size:10px;font-weight:700;vertical-align:middle;">*</span>' : ''),
            `<input class="arch-input" type="password" style="${svc.portainer && !svc.portainerKey ? 'border-color:var(--red);' : ''}" value="${esc(svc.portainerKey || '')}" placeholder="ptr_…" oninput="_archSetField('${svc.id}','portainerKey',this.value)">`)
        ) +
        _archCapRow(!!svc.k8s, t('arch.svc.k8s') + _archImpactBadge('restart', svc.existing), t('arch.cap.k8s_desc'),
          `_archSetOpt('${svc.id}','k8s',this.checked)`)
      )}
      `;
  } else {
    const tlsEdges = _arch.hosts.flatMap(h => (h.services || []).filter(s => s.type === 'edge' && s.acme));
    body = `
      ${_archGroup(t('arch.group.identity'),
        _archField(t('arch.role.name'), `<input class="arch-input" value="${esc(svc.name)}" onchange="_archSetField('${svc.id}','name',this.value);_archRender()">`)
      )}
      ${_archGroup(t('arch.group.caps'), `<div class="arch-cap-desc">${
        tlsEdges.length ? t('arch.opt.admin_acme_note') : t('arch.opt.none')
      }</div>`)}`;
  }

  return `<div class="arch-panel" style="--arch-accent:${accent};">
    <div class="arch-insp-head">
      <div class="arch-insp-level">${t('arch.level.role')} · ${esc(t(_ARCH_ROLES[svc.type].label))}</div>
      <div class="arch-insp-name">${esc(svc.name)}</div>
      <div class="arch-insp-note">${t('arch.role.insp_note', { host: (host && host.name) || '—' })}</div>
    </div>
    <div class="arch-insp-body">
      ${body}
      <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;">
        <button class="btn btn-ghost btn-sm" style="color:var(--red);"
          onclick="_archRemoveSvc('${host ? host.id : ''}','${svc.id}')">${t('arch.role.remove')}</button>
      </div>
    </div>
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
    const hasEdge = to.services.some(s => s.type === 'edge');
    svc.placement = hasEdge ? 'colocated' : 'remote';
    if (hasEdge) {
      const edge = to.services.find(s => s.type === 'edge');
      if (edge) svc.targetEdgeId = edge.id;
    }
  }
  // Retirer les hôtes vides orphelins (sauf le dernier)
  _arch.hosts = _arch.hosts.filter(h => (h.services && h.services.length) || h.id === to.id);
  if (!_arch.hosts.length) _arch.hosts = [_archEmptyHost(1)];
  _arch.selectedSvcId = svc.id;
  _arch.selectedHostId = to.id;
  _archRender();
}

function _archAddHost() {
  const n = _arch.hosts.length + 1;
  const host = _archEmptyHost(n);
  _arch.hosts.push(host);
  _arch.selectedHostId = host.id;
  _arch.selectedSvcId = null;
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
    const rmIds = new Set(host.services.map(s => s.id));
    for (const g of _arch.haGroups) g.members = g.members.filter(id => !rmIds.has(id));
    _arch.haGroups = _arch.haGroups.filter(g => g.members.length > 0);
  }
  if (_arch.selectedHostId === hostId) {
    _arch.selectedHostId = null;
    _arch.selectedSvcId = null;
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
  if (!host || !_ARCH_ROLES[type]) return;

  const n = _archCountType(type) + 1;
  const name = type === 'edge' ? `edge-${n}` : type === 'agent' ? `agent-${n}` : `admin-${n}`;
  const svc = {
    id: _archUid(type),
    type,
    name,
    access: false,
    portainer: false,
    k8s: false,
    docker: type === 'agent',
    podman: false,
    domains: '',
    acme: false,
    acmeEmail: '',
    dnsProvider: 'none',
    reachable: '',
    portainerUrl: '',
    portainerKey: '',
    targetEdgeId: '',
    placement: type === 'agent'
      ? (host.services.some(s => s.type === 'edge') ? 'colocated' : 'remote')
      : '',
  };
  if (svc.type === 'agent' && svc.placement === 'colocated') {
    const edge = host.services.find(s => s.type === 'edge');
    if (edge) svc.targetEdgeId = edge.id;
  }
  host.services.push(svc);
  _arch.selectedSvcId = svc.id;
  _arch.selectedHostId = host.id;
  _archRender();
}

function _archRemoveSvc(hostId, svcId) {
  const host = _arch.hosts.find(h => h.id === hostId);
  if (!host) return;
  host.services = host.services.filter(s => s.id !== svcId);
  for (const g of _arch.haGroups) g.members = g.members.filter(id => id !== svcId);
  _arch.haGroups = _arch.haGroups.filter(g => g.members.length > 0);
  if (_arch.selectedSvcId === svcId) _arch.selectedSvcId = null;
  _archRender();
}

function _archSelectSvc(id) {
  _arch.selectedSvcId = id;
  const host = _archFindHostOfSvc(id);
  _arch.selectedHostId = host ? host.id : null;
  _archRender();
}

async function _archApplyPortal(edgeName, enabled) {
  try {
    const q = '?edge=' + encodeURIComponent(edgeName);
    const existing = await api('GET', '/portal' + q).catch(() => ({}));
    await api('PUT', '/portal' + q, { ...existing, enabled: !!enabled });
    toast(t('arch.toast.portal_applied'), 'success');
  } catch (e) {
    toast(t('common.error_msg', { msg: e.message }), 'error');
  }
}

async function _archSetDelegMode(domainId, mode) {
  try {
    const existing = await api('GET', '/domains/' + encodeURIComponent(domainId));
    if (!existing) return;
    await api('PUT', '/domains/' + encodeURIComponent(domainId), {
      domain: existing.domain,
      edge_id: existing.edge_id,
      dns_provider: existing.dns_provider || '',
      dns_credentials: existing.dns_credentials || null,
      cert_method: existing.cert_method || 'manual',
      delegated_to_edge_id: existing.delegated_to_edge_id || '',
      delegated_endpoint: existing.delegated_endpoint || '',
      delegation_mode: mode,
    });
    for (const h of _arch.hosts) {
      for (const s of h.services || []) {
        for (const d of [...(s.delegationsOut || []), ...(s.delegationsIn || [])]) {
          if (d.id === domainId) d.mode = mode;
        }
      }
    }
    toast(t('arch.deleg.mode_saved'), 'success');
  } catch (e) {
    toast(t('common.error_msg', { msg: e.message }), 'error');
    _archRender();
  }
}

/** Clic sur le châssis : sélectionne l'hôte lui-même (pas un rôle). */
function _archSelectHost(hostId) {
  _arch.selectedHostId = hostId;
  _arch.selectedSvcId = null;
  _archRender();
}

/**
 * Badge d'impact pour les nœuds existants.
 * level: 'restart' (docker compose restart) | 'redeploy' (docker compose up -d)
 * Affiché uniquement si svc.existing est vrai.
 */
function _archImpactBadge(level, existing) {
  if (!existing) return '';
  const isRedeploy = level === 'redeploy';
  const label = t(isRedeploy ? 'arch.impact.redeploy' : 'arch.impact.restart');
  const hint  = t(isRedeploy ? 'arch.impact.redeploy_hint' : 'arch.impact.restart_hint');
  const color = isRedeploy ? 'var(--orange, #f59e0b)' : 'var(--text2)';
  const icon  = isRedeploy
    ? '<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a9 9 0 0 0-9-9 9 9 0 0 0-6.36 2.64L3 8"/><path d="M3 3v5h5"/><path d="M3 12a9 9 0 0 0 9 9 9 9 0 0 0 6.36-2.64L21 16"/><path d="M16 16h5v5"/></svg>'
    : '<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><path d="M20.5 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>';
  return `<span title="${esc(hint)}" style="display:inline-flex;align-items:center;gap:3px;font-size:10px;font-weight:600;color:${color};vertical-align:middle;margin-left:6px;cursor:help;white-space:nowrap;">${icon} ${esc(label)}</span>`;
}

/** Capacité « Domaines & TLS » : l'éteindre efface domaines + ACME. */
function _archSetTLS(id, on) {
  const s = _archFindSvc(id);
  if (!s) return;
  if (!on) {
    s.domains = '';
    s.acme = false;
  } else if (!s.acme) {
    s.acme = true;
  }
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

/** Ajoute/retire une passerelle d'un groupe HA. groupId='new' crée un groupe, ''=auto. */
function _archSetHAGroup(id, on, groupId) {
  // Retire de tout groupe existant
  for (const g of _arch.haGroups) g.members = g.members.filter(m => m !== id);
  _arch.haGroups = _arch.haGroups.filter(g => g.members.length > 0);

  if (on) {
    if (!groupId || groupId === 'new') {
      // Crée un nouveau groupe
      _arch.haGroups.push({ id: _archNextGroupId(), members: [id] });
    } else {
      const g = _arch.haGroups.find(g => g.id === groupId);
      if (g) g.members.push(id);
      else _arch.haGroups.push({ id: groupId, members: [id] });
    }
  }
  _archRender();
}

function _archValidate() {
  const edges = [];
  const agents = [];
  for (const h of _arch.hosts) {
    for (const s of h.services || []) {
      if (s.type === 'edge') edges.push({ host: h, svc: s });
      if (s.type === 'agent') agents.push({ host: h, svc: s });
    }
  }
  const total = _arch.hosts.reduce((n, h) => n + (h.services || []).length, 0);
  if (!total) return t('arch.err.empty');
  for (const g of _arch.haGroups) {
    if (g.members.length === 1) return t('arch.err.ha_one');
    const haHosts = new Set();
    for (const id of g.members) {
      const h = _archFindHostOfSvc(id);
      if (h) haHosts.add(h.id);
    }
    if (haHosts.size > 1) {
      for (const id of g.members) {
        const s = _archFindSvc(id);
        if (s && !(s.reachable || '').trim()) {
          return t('arch.err.ha_reachable', { name: s.name });
        }
      }
    }
  }

  for (const { host, svc } of agents) {
    const hasEdgeHere = (host.services || []).some(s => s.type === 'edge');
    if (!hasEdgeHere && !edges.length && !_arch.onlineEdgeEndpoint) {
      return t('arch.err.agent_needs_edge');
    }
    if (svc.portainer && !svc.portainerUrl) return t('arch.err.portainer_url', { name: svc.name });
    if (svc.portainer && !svc.portainerKey) return t('arch.err.portainer_key', { name: svc.name });
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
  const g = _archGroupOfSvc(selfId);
  if (!g) return '';
  const parts = [];
  for (const id of g.members) {
    if (id === selfId) continue;
    const s = _archFindSvc(id);
    if (!s) continue;
    const host = _archHAPeerHost(s);
    parts.push(`${s.name}=http://${host}:8002`);
  }
  return parts.join(',');
}

function _archHALeaderOf(svcId) {
  const g = _archGroupOfSvc(svcId);
  if (!g || !g.members.length) return null;
  return g.members[0] === svcId ? null : _archFindSvc(g.members[0]);
}

function _archAccessHANote() {
  for (const g of _arch.haGroups) {
    if (g.members.length < 2) continue;
    let n = 0;
    for (const id of g.members) {
      const s = _archFindSvc(id);
      if (s && s.access) n++;
    }
    if (n >= 2) return t('arch.note.access_ha');
  }
  return '';
}

function _archNetworkFlows() {
  const flows = [];
  const multiHost = _arch.hosts.length > 1;
  const hasEdge = _arch.hosts.some(h => h.services.some(s => s.type === 'edge'));
  const hasAgent = _arch.hosts.some(h => h.services.some(s => s.type === 'agent'));
  const hasAdmin = _arch.hosts.some(h => h.services.some(s => s.type === 'admin'));
  const inetHosts = _arch.hosts.filter(h => h.internet);

  if (hasAdmin && hasEdge) {
    flows.push({ from: 'Admin', to: 'Edge :8000', dir: t('arch.flow.outbound'), why: 'WS plan de contrôle' });
  } else if (hasEdge) {
    flows.push({ from: 'Admin (existant)', to: 'Edge :8000', dir: t('arch.flow.outbound'), why: 'WS plan de contrôle' });
  }
  if (hasAgent && hasEdge) {
    flows.push({ from: 'Agent', to: 'Edge :8000', dir: t('arch.flow.outbound'), why: 'WS + discovery' });
  }
  if (_arch.haGroups.some(g => g.members.length >= 2)) {
    flows.push({ from: 'Edge', to: 'Edge :8000 / :8002', dir: t('arch.flow.peer'), why: 'Peers HA / Raft' });
  }
  if (multiHost) {
    flows.push({ from: t('arch.flow.bootstrap'), to: t('arch.flow.reachable'), dir: t('arch.flow.outbound'), why: t('arch.flow.qr_why') });
  }

  for (const h of _arch.hosts) {
    const edge = !!h.internet;
    for (const s of h.services) {
      if (s.type === 'edge' && s.access) {
        flows.push({
          from: edge ? t('arch.flow.internet') : 'Clients / LAN',
          to: `${s.name} :2222 / :8444`,
          dir: t('arch.flow.inbound'),
          why: edge ? t('arch.flow.access_public') : 'Portail Access',
        });
      }
      if (s.type === 'edge') {
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

function _archResolveEdgeEndpoint(agentHost, agentSvc) {
  const localEdge = (agentHost.services || []).find(s => s.type === 'edge');
  if (localEdge) return `http://${localEdge.name}:8000`;

  if (agentSvc && agentSvc.targetEdgeId) {
    const target = _archFindSvc(agentSvc.targetEdgeId);
    if (target && target.type === 'edge') {
      const host = (target.reachable || '').trim();
      if (host) return typeof _wizEdgeEndpoint === 'function' ? _wizEdgeEndpoint(host) : ('http://' + host.replace(/\/$/, '') + (String(host).includes(':') ? '' : ':8000'));
      return `http://${target.name}:8000`;
    }
  }

  // Préférer une passerelle HA leader / premiÃ¨re passerelle avec reachable
  const allEdges = _arch.hosts.flatMap(h => h.services.filter(s => s.type === 'edge'));
  const preferred = allEdges.find(c => (c.reachable || '').trim()) || allEdges[0];
  if (preferred) {
    const host = (preferred.reachable || '').trim();
    if (host) return typeof _wizEdgeEndpoint === 'function' ? _wizEdgeEndpoint(host) : ('http://' + host.replace(/\/$/, '') + (String(host).includes(':') ? '' : ':8000'));
    return `http://${preferred.name}:8000`;
  }
  return _arch.onlineEdgeEndpoint || 'http://goproxify-edge:8000';
}

function _archBuildPacks() {
  _wiz.pairingSecret = _arch.pairingSecret;
  _wiz.scenario = 'full';
  const packs = [];

  for (const host of _arch.hosts) {
    if (!(host.services || []).length) continue;
    const edges = host.services.filter(s => s.type === 'edge');
    const agents = host.services.filter(s => s.type === 'agent');
    const admins = host.services.filter(s => s.type === 'admin');

    let edgeOpts = null;
    let agentOpts = null;
    if (edges[0]) {
      const c = edges[0];
      const cGroup = _archGroupOfSvc(c.id);
      const inHA = !!cGroup && cGroup.members.length >= 2;
      const haLeader = inHA ? _archFindSvc(cGroup.members[0]) : null;
      edgeOpts = _buildEdgeOpts({
        wc_name: c.name,
        wc_cluster: inHA,
        wc_cluster_node_id: c.name,
        wc_cluster_group: cGroup ? cGroup.id : 'ha-1',
        wc_cluster_peers: inHA ? _archHAPeersCSV(c.id) : '',
        wc_raft_leader: inHA && haLeader && haLeader.id !== c.id ? haLeader.name : '',
        wc_portal: !!c.access,
        wc_http3: false,
      });
    }
    if (agents[0]) {
      const a = agents[0];
      const ep = _archResolveEdgeEndpoint(host, a);
      const localEdge = edges[0];
      const target = a.targetEdgeId ? _archFindSvc(a.targetEdgeId) : null;
      agentOpts = _buildAgentOpts({
        wa_name: a.name,
        wa_edge_url: ep,
        wa_edge_container_name: localEdge ? localEdge.name : (target ? target.name : ''),
        wa_region: (host.region || a.region || '').trim(),
        wa_docker: !!a.docker && !a.podman,
        wa_podman: !!a.podman,
        wa_runtime: a.podman ? 'podman' : (a.docker ? 'docker' : ''),
        wa_k8s: !!a.k8s,
        wa_portainer: !!a.portainer,
        wa_portainer_url: a.portainerUrl || '',
        wa_portainer_key: a.portainerKey || '',
        wa_placement: localEdge ? 'colocated' : 'remote',
      });
      if (localEdge && edgeOpts) {
        agentOpts = {
          ...agentOpts,
          envVars: (agentOpts.envVars || [])
            .filter(e => e.k !== 'GPX_CONTROL_PLANE_EDGE_ENDPOINT' && e.k !== 'GPX_NETWORK_MANAGEMENT_EDGE_CONTAINER_NAME')
            .concat([
              { k: 'GPX_CONTROL_PLANE_EDGE_ENDPOINT', v: `http://${edgeOpts.name}:8000` },
              { k: 'GPX_NETWORK_MANAGEMENT_EDGE_CONTAINER_NAME', v: edgeOpts.name },
            ]),
        };
      }
    }

    const packUid = host.id;

    // Build Admin opts when Admin is co-located on this host
    let adminOpts = null;
    if (admins.length && edgeOpts) {
      adminOpts = _buildAdminOpts({
        wa_edge_name: edgeOpts.name,
        wa_jwt_secret: _arch.jwtSecret,
        wa_admin_email: (admins[0].acmeEmail || '').trim() || 'admin@example.com',
        wa_admin_password: 'CHANGE_ME',
      });
    }

    let html = '';
    if (edgeOpts && agentOpts) html = _renderConfigUI(edgeOpts, agentOpts, packUid, adminOpts);
    else if (edgeOpts) html = _renderConfigUI(edgeOpts, null, packUid, adminOpts);
    else if (agentOpts) html = _renderConfigUI(agentOpts, null, packUid, null);

    // ACME hint stays as annotation after the compose tabs
    if (admins.length) {
      const acmeEdges = _arch.hosts.flatMap(h => h.services.filter(s => s.type === 'edge' && s.acme));
      if (acmeEdges.length) {
        const c = acmeEdges[0];
        const hint = `<div style="font-size:12px;color:var(--text2);margin-top:10px;line-height:1.45;padding:10px;border-radius:8px;background:var(--bg);border:1px solid var(--border);">
          <strong>${t('arch.acme.admin_title')}</strong><br>
          <code>GPX_ACME_ENABLED=true</code>
          ${c.acmeEmail ? `<br><code>GPX_ACME_EMAIL=${esc(c.acmeEmail)}</code>` : ''}
          ${c.dnsProvider && c.dnsProvider !== 'none' ? `<br><code>GPX_ACME_DNS_TYPE=${esc(c.dnsProvider)}</code>` : ''}
          <br><span style="opacity:.85;">${t('arch.acme.admin_token_hint')}</span>
          ${c.domains ? `<br><span style="opacity:.85;">${t('arch.acme.domains_later', { domains: c.domains })}</span>` : ''}
        </div>`;
        html = (html || '') + hint;
      }
    }

    // Annotate Edge pack with domains for handoff
    if (edgeOpts && edges[0] && (edges[0].domains || edges[0].acme)) {
      const note = [];
      if (edges[0].domains) note.push(t('arch.acme.domains_later', { domains: edges[0].domains }));
      if (edges[0].acme) note.push(t('arch.acme.admin_title'));
      html = (html || '') + `<div style="font-size:12px;color:var(--text2);margin-top:10px;line-height:1.4;">${note.map(esc).join('<br>')}</div>`;
    }

    const token = _archUid('boot');
    const origin = (typeof location !== 'undefined' && location.origin) ? location.origin : '';
    const bootstrapUrl = `${origin}/bootstrap/${token}`; // remplacé à la création ticket

    let composeText = '', envText = '', cliText = '';
    if (edgeOpts && agentOpts && adminOpts) {
      composeText = _cfgComposeTextFullAdmin(edgeOpts, agentOpts, adminOpts, 'env_file');
      envText = _cfgEnvFileTextFull(edgeOpts, agentOpts) + '\n' + adminOpts.envVars.map(({k,v}) => `${k}=${v}`).join('\n');
      cliText = _cfgCliText(edgeOpts) + '\n\n' + _cfgCliText(agentOpts) + '\n\n' + _cfgCliText(adminOpts);
    } else if (edgeOpts && agentOpts) {
      composeText = _cfgComposeTextFull(edgeOpts, agentOpts, 'env_file');
      envText = _cfgEnvFileTextFull(edgeOpts, agentOpts);
      cliText = _cfgCliText(edgeOpts) + '\n\n' + _cfgCliText(agentOpts);
    } else if (edgeOpts && adminOpts) {
      composeText = _cfgComposeTextAdmin(edgeOpts, adminOpts, 'env_file');
      envText = [...edgeOpts.envVars, ...adminOpts.envVars].map(({k,v}) => `${k}=${v}`).join('\n');
      cliText = _cfgCliText(edgeOpts) + '\n\n' + _cfgCliText(adminOpts);
    } else if (edgeOpts) {
      composeText = _cfgComposeText(edgeOpts, 'env_file');
      envText = _cfgEnvFileText(edgeOpts);
      cliText = _cfgCliText(edgeOpts);
    } else if (agentOpts) {
      composeText = _cfgComposeText(agentOpts, 'env_file');
      envText = _cfgEnvFileText(agentOpts);
      cliText = _cfgCliText(agentOpts);
    }

    let edgeEp = '';
    if (agentOpts) {
      const hit = (agentOpts.envVars || []).find(e => e.k === 'GPX_CONTROL_PLANE_EDGE_ENDPOINT');
      edgeEp = hit ? hit.v : '';
    } else if (edges[0] && edges[0].reachable) {
      edgeEp = typeof _wizEdgeEndpoint === 'function' ? _wizEdgeEndpoint(edges[0].reachable) : edges[0].reachable;
    }

    packs.push({
      hostId: host.id,
      hostName: host.name,
      html,
      edgeOpts,
      agentOpts,
      bootstrapUrl,
      qrCode: '',
      scriptUrl: '',
      installCmd: '',
      edgeEndpoint: edgeEp,
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
    if (pack.edgeOpts) roles.push({ role: 'edge', opts: pack.edgeOpts, svc: pack.services.find(s => s.type === 'edge') });
    if (pack.agentOpts) roles.push({ role: 'agent', opts: pack.agentOpts, svc: pack.services.find(s => s.type === 'agent') });
    for (const r of roles) {
      try {
        const hostMeta = _arch.hosts.find(h => h.id === pack.hostId);
        const placement = r.role === 'agent'
          ? ((r.svc && r.svc.placement) || (pack.edgeOpts && pack.agentOpts ? 'colocated' : 'remote'))
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
          domains: (r.svc && r.svc.domains) || '',
          acme: !!(r.svc && r.svc.acme),
          acme_email: (r.svc && r.svc.acmeEmail) || '',
          dns_provider: (r.svc && r.svc.dnsProvider) || 'none',
          placement,
          target_edge: r.role === 'agent' ? ((pack.agentOpts.envVars || []).find(e => e.k === 'GPX_CONTROL_PLANE_EDGE_ENDPOINT') || {}).v : undefined,
          reachable_host: (r.svc && r.svc.reachable) || '',
          internet_exposed: !!(hostMeta && hostMeta.internet),
          cluster: _archInHA(r.svc && r.svc.id),
          cluster_group: (() => { const g = _archGroupOfSvc(r.svc && r.svc.id); return g ? g.id : ''; })(),
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
        _archMarkPendingDeploy(r.opts.name);
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
  try { localStorage.setItem('gpx_last_packs', JSON.stringify(_arch.packs)); } catch {}
  _arch.step = 'handoff';
  _archRender();
}

async function _archCreateTickets() {
  for (const p of _arch.packs) {
    try {
      const nodeNames = [];
      if (p.edgeOpts && p.edgeOpts.name) nodeNames.push(p.edgeOpts.name);
      if (p.agentOpts && p.agentOpts.name) nodeNames.push(p.agentOpts.name);
      const res = await api('POST', '/bootstrap-tickets', {
        host_name: p.hostName,
        edge_endpoint: p.edgeEndpoint || '',
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
      // Pré-approbation Agent sur le(s) passerelle(s) avant connexion
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

// ── Handoff : édition inline des paramètres sans regénérer les tickets ───────

function _archHandoffSetField(packIdx, role, field, value) {
  const p = _arch.packs[packIdx];
  if (!p) return;
  const svc = (p.services || []).find(s => s.type === role);
  if (svc) {
    // Mémoriser le nom original avant la première modification de nom
    if (field === 'name' && role === 'edge' && !p._prevEdgeName && svc.name !== value) {
      p._prevEdgeName = svc.name;
    }
    if (field === 'name' && role === 'agent' && !p._prevAgentName && svc.name !== value) {
      p._prevAgentName = svc.name;
    }
    svc[field] = value;
  }
  // Sync aussi dans _arch.hosts pour cohérence toile ↔ handoff
  for (const h of _arch.hosts) {
    const hs = (h.services || []).find(s => s.type === role && (role === 'edge'
      ? (p.edgeOpts && s.name === p.edgeOpts.name) || s.id === (svc && svc.id)
      : (p.agentOpts && s.name === p.agentOpts.name) || s.id === (svc && svc.id)));
    if (hs) hs[field] = value;
  }
}

async function _archHandoffSave(packIdx) {
  const p = _arch.packs[packIdx];
  if (!p) return;
  // Rebuild opts + textes pour ce pack uniquement
  const host = _arch.hosts.find(h => h.id === p.hostId);
  if (!host) return;
  const edges = host.services.filter(s => s.type === 'edge');
  const agents = host.services.filter(s => s.type === 'agent');
  const admins = host.services.filter(s => s.type === 'admin');
  if (edges[0]) {
    const c = edges[0];
    const cGroup = _archGroupOfSvc(c.id);
    const inHA = !!cGroup && cGroup.members.length >= 2;
    const haLeader = inHA ? _archFindSvc(cGroup.members[0]) : null;
    p.edgeOpts = _buildEdgeOpts({
      wc_name: c.name,
      wc_cluster: inHA,
      wc_cluster_node_id: c.name,
      wc_cluster_group: cGroup ? cGroup.id : 'ha-1',
      wc_cluster_peers: inHA ? _archHAPeersCSV(c.id) : '',
      wc_raft_leader: inHA && haLeader && haLeader.id !== c.id ? haLeader.name : '',
      wc_portal: !!c.access,
      wc_http3: false,
    });
  }
  if (agents[0]) {
    const a = agents[0];
    const ep = _archResolveEdgeEndpoint(host, a);
    p.agentOpts = _buildAgentOpts({
      wa_name: a.name,
      wa_edge_url: ep,
      wa_edge_container_name: edges[0] ? edges[0].name : '',
      wa_region: (host.region || '').trim(),
      wa_docker: !!a.docker && !a.podman,
      wa_podman: !!a.podman,
      wa_runtime: a.podman ? 'podman' : (a.docker ? 'docker' : ''),
      wa_k8s: !!a.k8s,
      wa_portainer: !!a.portainer,
      wa_portainer_url: a.portainerUrl || '',
      wa_portainer_key: a.portainerKey || '',
      wa_placement: edges[0] ? 'colocated' : 'remote',
    });
  }
  let adminOpts = null;
  if (admins.length && p.edgeOpts) {
    adminOpts = _buildAdminOpts({
      wa_edge_name: p.edgeOpts.name,
      wa_jwt_secret: _arch.jwtSecret,
      wa_admin_email: (admins[0].acmeEmail || '').trim() || 'admin@example.com',
      wa_admin_password: 'CHANGE_ME',
    });
  }
  if (p.edgeOpts && p.agentOpts && adminOpts) {
    p.composeText = _cfgComposeTextFullAdmin(p.edgeOpts, p.agentOpts, adminOpts, 'env_file');
    p.envText = _cfgEnvFileTextFull(p.edgeOpts, p.agentOpts) + '\n' + adminOpts.envVars.map(({k,v}) => `${k}=${v}`).join('\n');
    p.cliText = _cfgCliText(p.edgeOpts) + '\n\n' + _cfgCliText(p.agentOpts) + '\n\n' + _cfgCliText(adminOpts);
  } else if (p.edgeOpts && p.agentOpts) {
    p.composeText = _cfgComposeTextFull(p.edgeOpts, p.agentOpts, 'env_file');
    p.envText = _cfgEnvFileTextFull(p.edgeOpts, p.agentOpts);
    p.cliText = _cfgCliText(p.edgeOpts) + '\n\n' + _cfgCliText(p.agentOpts);
  } else if (p.edgeOpts && adminOpts) {
    p.composeText = _cfgComposeTextAdmin(p.edgeOpts, adminOpts, 'env_file');
    p.envText = [...p.edgeOpts.envVars, ...adminOpts.envVars].map(({k,v}) => `${k}=${v}`).join('\n');
    p.cliText = _cfgCliText(p.edgeOpts) + '\n\n' + _cfgCliText(adminOpts);
  } else if (p.edgeOpts) {
    p.composeText = _cfgComposeText(p.edgeOpts, 'env_file');
    p.envText = _cfgEnvFileText(p.edgeOpts);
    p.cliText = _cfgCliText(p.edgeOpts);
  } else if (p.agentOpts) {
    p.composeText = _cfgComposeText(p.agentOpts, 'env_file');
    p.envText = _cfgEnvFileText(p.agentOpts);
    p.cliText = _cfgCliText(p.agentOpts);
  }
  try { localStorage.setItem('gpx_last_packs', JSON.stringify(_arch.packs)); } catch {}
  // Persistance declared-nodes avec les nouvelles valeurs
  try {
    if (p.edgeOpts) {
      const c = edges[0];
      const cfg = {
        reachable_host: (c && c.reachable) || '',
        docker: !!(c && c.docker), podman: !!(c && c.podman),
        portal: !!(c && c.access),
        cluster: _archInHA(c && c.id),
        cluster_group: (() => { const g = _archGroupOfSvc(c && c.id); return g ? g.id : ''; })(),
        internet_exposed: !!(host && host.internet),
        auto_accept: true,
      };
      // Supprimer l'ancienne entrée si le nom a changé (évite doublon)
      if (p._prevEdgeName && p._prevEdgeName !== p.edgeOpts.name) {
        const old = (_arch.declaredNodes || []).find(n => n.role === 'edge' && n.name === p._prevEdgeName);
        if (old && old.id && !old.id.startsWith('cfg:')) {
          await api('DELETE', '/declared-nodes/' + old.id).catch(() => {});
        }
        p._prevEdgeName = null;
      }
      await api('POST', '/declared-nodes', { role: 'edge', name: p.edgeOpts.name, region: (host && host.region) || '', environment: '', config: cfg }).catch(() => {});
    }
  } catch {}
  toast(t('common.saved') || 'Enregistré', 'success');
  _archRender();
}

function _archHandoffShowConfig(packIdx) {
  const p = _arch.packs[packIdx];
  if (!p) return;
  const tabs = [
    { id: 'compose', label: 'docker-compose.yml', text: p.composeText || '' },
    { id: 'env',     label: '.env',               text: p.envText || '' },
    { id: 'cli',     label: 'CLI',                text: p.cliText || '' },
  ].filter(tab => tab.text.trim());

  const tabsHTML = tabs.map((tab, i) =>
    `<button class="btn ${i === 0 ? 'btn-primary' : 'btn-ghost'} btn-sm" id="arch-cfg-tab-${i}"
      onclick="_archHandoffSwitchTab(${packIdx},${i})">${esc(tab.label)}</button>`
  ).join('');

  const contentsHTML = tabs.map((tab, i) =>
    `<div id="arch-cfg-body-${i}" style="${i !== 0 ? 'display:none;' : ''}position:relative;">
      <button class="btn btn-ghost btn-sm" style="position:absolute;top:6px;right:6px;"
        onclick="navigator.clipboard.writeText(${JSON.stringify(tab.text)}).then(()=>toast(t('common.copied')||'Copié','success'))">${t('dockerlbl.copy') || 'Copier'}</button>
      <pre style="background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:14px 12px;font-size:11px;overflow:auto;max-height:400px;white-space:pre;tab-size:2;">${esc(tab.text)}</pre>
    </div>`
  ).join('');

  const modalHTML = `<div id="arch-cfg-modal" style="position:fixed;inset:0;z-index:1000;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,.5);"
    onclick="if(event.target===this)this.remove()">
    <div style="background:var(--bg2,var(--surface));border:1px solid var(--border);border-radius:10px;padding:20px;width:min(720px,95vw);max-height:85vh;overflow-y:auto;display:flex;flex-direction:column;gap:12px;" onclick="event.stopPropagation()">
      <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;">
        <strong style="font-size:14px;">${esc(p.hostName)} — ${t('arch.show_config') || 'Configuration'}</strong>
        <button class="btn btn-ghost btn-sm" onclick="document.getElementById('arch-cfg-modal').remove()">✕</button>
      </div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;">${tabsHTML}</div>
      ${contentsHTML}
    </div>
  </div>`;
  document.body.insertAdjacentHTML('beforeend', modalHTML);
}

window._archHandoffSwitchTab = function(packIdx, tabIdx) {
  let i = 0;
  while (document.getElementById('arch-cfg-body-' + i)) {
    document.getElementById('arch-cfg-body-' + i).style.display = i === tabIdx ? '' : 'none';
    const btn = document.getElementById('arch-cfg-tab-' + i);
    if (btn) { btn.className = 'btn btn-sm ' + (i === tabIdx ? 'btn-primary' : 'btn-ghost'); }
    i++;
  }
};

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
      <td style="padding:6px 10px;font-size:12px;">${esc(f.from)}</td>
      <td style="padding:6px 10px;font-size:12px;">${esc(f.to)}</td>
      <td style="padding:6px 10px;font-size:12px;color:var(--text2);">${esc(f.dir)}</td>
      <td style="padding:6px 10px;font-size:12px;color:var(--text2);">${esc(f.why)}</td>
    </tr>`).join('');

  const packsHTML = _arch.packs.map((p, i) => {
    const roleChips = (p.services || []).map(s =>
      `<span class="arch-chip" style="--arch-accent:${_archRoleAccent(s.type)};">${esc(t(_ARCH_ROLES[s.type].label))} · ${esc(s.name)}</span>`
    ).join('');
    const edgeSvc = (p.services || []).find(s => s.type === 'edge');
    const agentSvc = (p.services || []).find(s => s.type === 'agent');
    const paramFields = `
      <div style="display:flex;flex-direction:column;gap:8px;margin-bottom:12px;">
        ${edgeSvc ? `
        <div class="arch-field">
          <span class="arch-field-label">${t('arch.role.name')} (Edge)</span>
          <input class="arch-input" value="${esc(edgeSvc.name)}" oninput="_archHandoffSetField(${i},'edge','name',this.value)">
        </div>
        <div class="arch-field">
          <span class="arch-field-label">${t('arch.opt.reachable')}</span>
          <input class="arch-input" value="${esc(edgeSvc.reachable || '')}" placeholder="edge.example.com" oninput="_archHandoffSetField(${i},'edge','reachable',this.value)">
        </div>` : ''}
        ${agentSvc ? `
        <div class="arch-field">
          <span class="arch-field-label">${t('arch.role.name')} (Agent)</span>
          <input class="arch-input" value="${esc(agentSvc.name)}" oninput="_archHandoffSetField(${i},'agent','name',this.value)">
        </div>` : ''}
      </div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px;">
        <button class="btn btn-primary btn-sm" onclick="_archHandoffSave(${i})">${t('common.save') || 'Enregistrer'}</button>
        <button class="btn btn-secondary btn-sm" onclick="_archHandoffShowConfig(${i})">${t('arch.show_config') || 'Voir la configuration'}</button>
      </div>`;
    return `
    <div class="arch-panel" style="margin-bottom:14px;">
      <div class="arch-panel-head" style="display:flex;align-items:center;gap:9px;flex-wrap:wrap;">
        <span class="arch-host-glyph">${_ARCH_ICONS.host}</span>
        <span style="font-size:13.5px;font-weight:700;">${esc(p.hostName)}</span>
        <span style="display:flex;gap:4px;flex-wrap:wrap;margin-left:auto;">${roleChips}</span>
      </div>
      <div class="arch-panel-body" style="gap:14px;">
        ${paramFields}
        <div style="display:flex;gap:16px;flex-wrap:wrap;align-items:flex-start;">
          ${p.qrCode ? `<img src="${esc(p.qrCode)}" alt="QR" width="150" height="150" style="background:#fff;padding:8px;border:1px solid var(--border);">` : ''}
          <div style="flex:1;min-width:220px;">
            ${p.installCmd ? `
            <div class="arch-field-label">${t('arch.install_label')}</div>
            <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:12px;">
              <code style="font-size:11px;word-break:break-all;flex:1 1 220px;background:var(--bg);padding:8px 9px;border:1px solid var(--border);">${esc(p.installCmd)}</code>
              <button class="btn btn-primary btn-sm" onclick="_archCopyInstall(${i})">${t('dockerlbl.copy') || 'Copier'}</button>
            </div>` : ''}
            <div class="arch-field-label">${t('arch.bootstrap_label')}</div>
            <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
              <code style="font-size:11px;word-break:break-all;flex:1 1 220px;background:var(--bg);padding:8px 9px;border:1px solid var(--border);">${esc(p.bootstrapUrl)}</code>
              <button class="btn btn-ghost btn-sm" onclick="_archCopyBootstrap(${i})">${t('dockerlbl.copy') || 'Copier'}</button>
              <a class="btn btn-secondary btn-sm" href="${esc(p.bootstrapUrl)}" target="_blank" rel="noopener">${t('arch.open_ticket')}</a>
            </div>
            <div class="arch-cap-desc" style="margin-top:8px;">${t('arch.qr_hint')}</div>
          </div>
        </div>
      </div>
    </div>`;
  }).join('');

  const inetHosts = _arch.hosts.filter(h => h.internet);
  const inetBanner = inetHosts.length
    ? `<div class="arch-msg" data-tone="info">${t('arch.inet.handoff', { names: inetHosts.map(h => h.name).join(', ') })}</div>`
    : `<div class="arch-msg">${t('arch.inet.handoff_none')}</div>`;
  const haNote = _archAccessHANote();

  return `<div class="arch-page">
    <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap;">
      <div style="min-width:0;">
        <div class="card-kicker">${t('arch.kicker')}</div>
        <h2 style="font-family:var(--font-heading);font-size:20px;font-weight:700;margin:0;letter-spacing:-.01em;">${t('arch.handoff_title')}</h2>
        <p style="font-size:12.5px;color:var(--text2);margin-top:5px;max-width:52rem;line-height:1.5;">${t('arch.handoff_sub')}</p>
      </div>
      <button class="btn btn-ghost btn-sm" onclick="_archGoToCanvas()">${t('arch.edit_topology') || 'Modifier la topologie'}</button>
    </div>

    ${inetBanner}
    ${haNote ? `<div class="arch-msg" data-tone="warn">${esc(haNote)}</div>` : ''}

    <div class="arch-panel">
      <div class="arch-panel-head"><div class="arch-panel-title">${t('arch.flows_title')}</div></div>
      <div class="table-wrap"><table style="width:100%;border-collapse:collapse;">
        <thead><tr style="background:var(--bg3);">
          <th style="padding:7px 10px;font-size:11px;text-align:left;">${t('arch.flow.from')}</th>
          <th style="padding:7px 10px;font-size:11px;text-align:left;">${t('arch.flow.to')}</th>
          <th style="padding:7px 10px;font-size:11px;text-align:left;">${t('arch.flow.dir')}</th>
          <th style="padding:7px 10px;font-size:11px;text-align:left;">${t('arch.flow.why')}</th>
        </tr></thead>
        <tbody>${flowRows || `<tr><td colspan="4" style="padding:10px;font-size:12px;color:var(--text2);">${t('arch.flows_none')}</td></tr>`}</tbody>
      </table></div>
    </div>

    ${packsHTML}

    <div class="arch-actionbar">
      <div class="arch-summary"><span>${t('arch.handoff_packs', { n: _arch.packs.length })}</span></div>
      <div class="arch-actionbar-btns">
        <button class="btn btn-ghost" onclick="_archGoToCanvas()">${t('arch.edit_topology') || 'Modifier la topologie'}</button>
        <button class="btn btn-primary" onclick="navigate('infrastructure')">${t('arch.done')}</button>
      </div>
    </div>
  </div>`;
}
