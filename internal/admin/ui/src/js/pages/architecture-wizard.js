// Mode édition de l'infrastructure : schéma (hôtes → rôles → capacités), suivi des modifications
// par rapport à l'état chargé, revue puis enregistrement dans architecture.json.
// Dépend de shared/infra-config.js, shared/arch-schema.js et pages/infrastructure.js (_wiz helpers, _build*).

const _arch = {
  hosts: [],
  haGroups: [], // [{id:'ha-1', members:['svc-id-a','svc-id-b']}, ...] — N groupes HA possibles
  base: null,   // copie de { hosts, haGroups } au chargement : référence des modifications non enregistrées
  selectedSvcId: null,
  selectedHostId: null,
  inspTab: 'caps',
  loading: false,
  pairingSecret: '',
  jwtSecret: '',
  edgeList: [],
  declaredNodes: [], // nœuds de architecture.json
  nodes: [],         // état live (/nodes)
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
  let docker = cfg.docker !== false && !(cfg.podman && cfg.docker === undefined);
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
    const host = ensureHost(cfg.host ? 'host:' + cfg.host : 'edge:' + cName, {
      name: cfg.host || c.display_name || cName,
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
    if (cfg.host) {
      // L'hôte est déclaré dans architecture.json : pas d'heuristique de co-location.
      host = ensureHost('host:' + cfg.host, { name: cfg.host, region: (d && d.region) || a.region || '', internet: !!cfg.internet_exposed });
    } else if (colocate && hostByKey.has('edge:' + effectiveEdgeKey)) {
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
    const hostEdge = host.services.find(s => s.type === 'edge');
    if (cfg.host) {
      if (hostEdge) { svc.placement = 'colocated'; svc.targetEdgeId = hostEdge.id; } else if (!svc.placement) svc.placement = 'remote';
    } else if (colocate) svc.placement = 'colocated';
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

function openArchWizard() {
  _arch.hosts = [_archEmptyHost(1)];
  _arch.haGroups = [];
  _arch.selectedSvcId = null;
  _arch.selectedHostId = null;
  _arch.pairingSecret = '';
  _arch.edgeList = [];
  _arch.declaredNodes = [];
  _arch.onlineEdgeEndpoint = '';
  _arch.existingCount = 0;
  _arch.loading = true;
  _archLoad();
  navigate('architecture');
}

function _archLoad() {
  return Promise.all([
    api('GET', '/pairing-secret').catch(() => null),
    api('GET', '/nodes').catch(() => null),
    api('GET', '/tokens?role=edge').catch(() => null),
    api('GET', '/architecture').catch(() => null),
    api('GET', '/portal/enabled').catch(() => null),
    api('GET', '/domains').catch(() => null),
    api('GET', '/acme/providers').catch(() => []),
  ]).then(([sec, nodes, tokens, archFile, portalEnabled, domains, acmeProviders]) => {
    const declared = archFile && Array.isArray(archFile.nodes) ? archFile.nodes : null;
    _arch.nodes = Array.isArray(nodes) ? nodes : [];
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
    _archSnapshot();
    _archRender();
  });
}

function closeArchWizard() {
  navigate('infrastructure');
}

// ── Suivi des modifications : écart entre la toile et l'état chargé (_arch.base) ──

function _archSnapshot() {
  _arch.base = JSON.parse(JSON.stringify({ hosts: _arch.hosts, haGroups: _arch.haGroups }));
}

// Champ d'un rôle → impact sur un nœud déjà déployé.
const _ARCH_CHG_FIELDS = {
  name: 'restart', reachable: 'restart', access: 'restart', domains: 'restart', acme: 'restart',
  acmeEmail: 'restart', dnsProvider: 'restart', docker: 'redeploy', podman: 'redeploy', portainer: 'restart',
  portainerUrl: 'restart', portainerKey: 'restart', k8s: 'restart', targetEdgeId: 'restart',
};
const _ARCH_IMPACT_RANK = { decl: 0, live: 1, restart: 2, redeploy: 3, install: 4 };
const _ARCH_BOOL_FIELDS = new Set(['access', 'acme', 'docker', 'podman', 'portainer', 'k8s']);

function _archNorm(v) { return v === undefined || v === null || v === false ? '' : v; }

function _archFieldLabel(f) {
  const k = {
    access: 'arch.svc.access', acme: 'arch.opt.acme', docker: 'arch.svc.docker', podman: 'arch.svc.podman',
    portainer: 'arch.svc.portainer', k8s: 'arch.svc.k8s', reachable: 'arch.opt.reachable', domains: 'arch.opt.domains',
    acmeEmail: 'arch.opt.acme_email', dnsProvider: 'arch.opt.dns_provider', portainerKey: 'arch.opt.portainer_key',
    targetEdgeId: 'arch.opt.target_edge',
  }[f];
  return k ? t(k) : f === 'portainerUrl' ? 'Portainer URL' : f;
}

function _archBaseIndex() {
  if (!_arch.base) return null;
  const svcs = new Map(), hostOf = new Map(), hosts = new Map(), group = new Map();
  for (const h of _arch.base.hosts) {
    hosts.set(h.id, h);
    for (const s of h.services || []) { svcs.set(s.id, s); hostOf.set(s.id, h); }
  }
  for (const g of _arch.base.haGroups || []) for (const id of g.members) group.set(id, g.id);
  return { svcs, hostOf, hosts, group };
}

/** Liste des modifications : { kind: add|mod|del|host, svc, host, parts, impact }. L'Admin n'est pas enregistré, il est ignoré. */
function _archChanges() {
  const bi = _archBaseIndex();
  if (!bi) return [];
  const out = [];
  const cur = new Set();
  const curGroup = new Map();
  for (const g of _arch.haGroups) for (const id of g.members) curGroup.set(id, g.id);
  for (const h of _arch.hosts) {
    for (const s of h.services || []) {
      cur.add(s.id);
      if (s.type === 'admin') continue;
      const b = bi.svcs.get(s.id);
      if (!b) { out.push({ kind: 'add', svc: s, host: h, newHost: !bi.hosts.has(h.id), impact: 'install' }); continue; }
      const parts = [];
      let impact = null;
      const bump = lvl => { if (!impact || _ARCH_IMPACT_RANK[lvl] > _ARCH_IMPACT_RANK[impact]) impact = lvl; };
      for (const [f, lvl] of Object.entries(_ARCH_CHG_FIELDS)) {
        if (_archNorm(b[f]) === _archNorm(s[f])) continue;
        if (f === 'name') parts.push(t('as.chg.renamed', { from: b.name }));
        else if (_ARCH_BOOL_FIELDS.has(f)) parts.push(t(s[f] ? 'as.chg.on' : 'as.chg.off', { cap: _archFieldLabel(f) }));
        else parts.push(t('as.chg.field', { field: _archFieldLabel(f) }));
        // Access est appliqué en direct aux passerelles connectées lors de l'enregistrement.
        bump(f === 'access' && s.status === 'online' ? 'live' : lvl);
      }
      const bg = bi.group.get(s.id) || '', cg = curGroup.get(s.id) || '';
      if (bg !== cg) { parts.push(t('as.chg.ha', { from: bg || '—', to: cg || '—' })); bump('redeploy'); }
      const bh = bi.hostOf.get(s.id);
      if (bh && bh.id !== h.id) { parts.push(t('as.chg.moved', { from: bh.name, to: h.name })); bump('redeploy'); }
      if (!parts.length) continue;
      out.push({ kind: 'mod', svc: s, host: h, parts, impact: s.status === 'declared' ? 'decl' : impact });
    }
    const bh = bi.hosts.get(h.id);
    if (bh && (h.services || []).some(s => s.type !== 'admin')) {
      const parts = [];
      if (bh.name !== h.name) parts.push(t('as.chg.host_renamed', { from: bh.name }));
      if (!!bh.internet !== !!h.internet) parts.push(t(h.internet ? 'as.chg.host_inet_on' : 'as.chg.host_inet_off'));
      if ((bh.region || '') !== (h.region || '')) parts.push(t('as.chg.host_region', { from: bh.region || '—', to: h.region || '—' }));
      if (parts.length) out.push({ kind: 'host', host: h, parts, impact: 'decl' });
    }
  }
  for (const [id, b] of bi.svcs) {
    if (cur.has(id) || b.type === 'admin') continue;
    out.push({ kind: 'del', svc: b, host: bi.hostOf.get(id), impact: 'decl', live: !!b.existing && b.status !== 'declared' });
  }
  return out;
}

function _archChangeOf(id) {
  return (_arch._chg || []).find(c => c.svc && c.svc.id === id && c.kind !== 'del') || null;
}

/** Rôles retirés dont l'hôte est toujours sur la toile (affichés barrés, avec « Rétablir »). */
function _archRemovedOn(hostId) {
  return (_arch._chg || []).filter(c => c.kind === 'del' && c.host && c.host.id === hostId).map(c => c.svc);
}

function _archIsNewHost(hostId) {
  return !!_arch.base && !_arch.base.hosts.some(h => h.id === hostId);
}

function _archBaseSvc(id) {
  for (const h of (_arch.base && _arch.base.hosts) || []) {
    const s = (h.services || []).find(x => x.id === id);
    if (s) return s;
  }
  return null;
}

function _archCapDiff(s) {
  const b = _archBaseSvc(s.id);
  if (!b) return { add: [], del: [] };
  const before = _asCaps(_arch.base, b), after = _asCaps(_arch, s);
  return { add: after.filter(c => !before.includes(c)), del: before.filter(c => !after.includes(c)) };
}

/** « Avant : … » sous un champ modifié d'un rôle déjà présent au chargement. */
function _archBefore(svc, field) {
  const b = _archBaseSvc(svc.id);
  if (!b || _archNorm(b[field]) === _archNorm(svc[field])) return '';
  let v = _ARCH_BOOL_FIELDS.has(field) ? t(b[field] ? 'as.ins.on' : 'as.ins.off') : (b[field] || '—');
  if (field === 'targetEdgeId') v = b[field] ? ((_archFindSvc(b[field]) || _archBaseSvc(b[field]) || {}).name || '—') : t('arch.opt.target_edge_auto');
  return `<span class="as-before">${esc(t('as.ins.before', { v }))}</span>`;
}

function asRestoreSvc(id) {
  const bi = _archBaseIndex();
  if (!bi || _archFindSvc(id)) return;
  const b = bi.svcs.get(id), bh = bi.hostOf.get(id);
  if (!b || !bh) return;
  let host = _arch.hosts.find(h => h.id === bh.id);
  if (!host) {
    host = Object.assign(JSON.parse(JSON.stringify(bh)), { services: [] });
    _arch.hosts.push(host);
  }
  host.services.push(JSON.parse(JSON.stringify(b)));
  const gid = bi.group.get(id);
  if (gid) {
    const g = _arch.haGroups.find(x => x.id === gid);
    if (g) { if (!g.members.includes(id)) g.members.push(id); } else _arch.haGroups.push({ id: gid, members: [id] });
  }
  _arch.selectedSvcId = id;
  _arch.selectedHostId = host.id;
  _archRender();
}

/** Après une saisie sans re-rendu : met à jour le compteur et la liste des modifications. */
function _archRefreshChanges() {
  if (state.page !== 'architecture') return;
  _arch._chg = _archChanges();
  const n = _arch._chg.length;
  const cnt = document.getElementById('as-edit-n');
  if (cnt) cnt.textContent = _archCountLabel(n);
  const btn = document.getElementById('as-edit-save');
  if (btn) btn.textContent = n ? t('as.edit.review_n', { n }) : t('as.edit.review');
  const list = document.getElementById('as-chgs');
  if (list) list.outerHTML = _asChangesHTML(_arch._chg);
}

function _archCountLabel(n) {
  return n ? t(n === 1 ? 'as.edit.one_change' : 'as.edit.n_changes', { n }) : t('as.edit.no_change');
}

function _asImpactSummary(list) {
  const cnt = {};
  for (const c of list) cnt[c.impact] = (cnt[c.impact] || 0) + 1;
  return ['install', 'redeploy', 'restart', 'live', 'decl'].filter(k => cnt[k]).map(k => t('as.imp.n.' + k, { n: cnt[k] })).join(', ');
}

function _asChangeRow(c, withRestore) {
  const sym = { add: '+', mod: '~', host: '~', del: '−' }[c.kind];
  const name = c.kind === 'host' ? c.host.name : c.svc.name;
  let desc;
  if (c.kind === 'add') desc = t(c.newHost ? 'as.chg.add_new_host' : 'as.chg.add', { host: c.host.name });
  else if (c.kind === 'del') desc = t('as.chg.del', { host: c.host ? c.host.name : '—' });
  else desc = c.parts.join(' · ');
  const restore = withRestore && c.kind === 'del'
    ? `<button type="button" class="as-restore" onclick="asRestoreSvc('${esc(c.svc.id)}')">${esc(t('as.edit.restore'))}</button>` : '<span></span>';
  return `<div class="as-chg" data-k="${c.kind}"><span class="as-chg-s" aria-hidden="true">${sym}</span><b>${esc(name)}</b>
    <span class="as-chg-d">${esc(desc)}</span><span class="as-chg-i" data-imp="${c.impact}">${esc(t('as.imp.' + c.impact))}</span>${restore}</div>`;
}

function _asChangesHTML(list) {
  return `<section class="as-chgs" id="as-chgs" aria-label="${esc(t('as.edit.changes', { n: list.length }))}">
    <div class="as-chgs-h"><h3>${esc(t('as.edit.changes', { n: list.length }))}</h3>${list.length ? `<span>${esc(t('as.imp.summary', { list: _asImpactSummary(list) }))}</span>` : ''}</div>
    ${list.length ? list.map(c => _asChangeRow(c, true)).join('') : `<div class="as-chgs-empty">${esc(t('as.edit.no_changes_hint'))}</div>`}
  </section>`;
}

function asCancelEdit() {
  const n = (_arch._chg || []).length;
  if (!n) { closeArchWizard(); return; }
  modal(esc(t('as.edit.discard_title')),
    `<p style="margin:0;font-size:13.5px;line-height:1.5">${esc(t('as.edit.discard_confirm', { n }))}</p>`,
    `<button class="btn btn-secondary" onclick="closeModal()">${esc(t('as.edit.keep_editing'))}</button>
     <button class="btn btn-danger" onclick="closeModal();closeArchWizard()">${esc(t('as.edit.discard'))}</button>`);
}

/** Revue avant enregistrement : liste des modifications, impact, contrôles. */
function asOpenReview() {
  const list = _arch._chg = _archChanges();
  const err = _archValidate();
  const haNote = _archAccessHANote();
  const liveDel = list.filter(c => c.kind === 'del' && c.live);
  _asOverlay(`<div class="as-mh"><b>${esc(t('as.rev.title'))}</b>
      <button class="btn btn-ghost btn-sm" style="margin-left:auto" onclick="asCloseModal()" aria-label="${esc(t('common.close'))}">×</button></div>
    <p class="as-rev-sub">${esc(t('as.rev.sub'))}</p>
    ${list.length
      ? `<div class="as-chgs as-chgs-flat">${list.map(c => _asChangeRow(c, false)).join('')}</div>
         <p class="as-rev-imp">${esc(t('as.imp.summary', { list: _asImpactSummary(list) }))}</p>`
      : `<div class="arch-msg" data-tone="info">${esc(t('as.rev.none'))}</div>`}
    <div class="as-rev-msgs">
      ${liveDel.map(c => `<div class="arch-msg" data-tone="warn">${esc(t('as.rev.live_removed', { name: c.svc.name }))}</div>`).join('')}
      ${haNote ? `<div class="arch-msg" data-tone="warn">${esc(haNote)}</div>` : ''}
      ${err ? `<div class="arch-msg" data-tone="error">${esc(err)}</div>` : ''}
    </div>
    <div class="as-acts" style="justify-content:flex-end">
      <button class="btn btn-secondary" onclick="asCloseModal()">${esc(t('common.cancel'))}</button>
      <button class="btn btn-primary" id="as-rev-save" ${err ? 'disabled' : ''} onclick="asReviewSave()">${esc(t('as.rev.save'))}</button>
    </div>`);
}

async function asReviewSave() {
  const btn = document.getElementById('as-rev-save');
  if (btn) { btn.disabled = true; btn.textContent = t('as.rev.saving'); }
  const added = (_arch._chg || []).filter(c => c.kind === 'add');
  const hosts = [...new Map(added.map(c => [c.host.id, c.host])).values()];
  const ok = await _archSaveTopology();
  if (!ok) {
    if (btn) { btn.disabled = false; btn.textContent = t('as.rev.save'); }
    return;
  }
  _asOverlay(`<div class="as-mh"><b>${esc(t('as.rev.done'))}</b></div>
    ${hosts.length ? `<p class="as-rev-sub">${esc(t('as.rev.install_hint'))}</p>
      ${hosts.map(h => `<div class="as-ver"><div><b>${esc(h.name)}</b><small>${esc(added.filter(c => c.host.id === h.id).map(c => c.svc.name).join(', '))}</small></div>
        <div class="as-ver-b"><button class="btn btn-secondary btn-sm" onclick="asOpenConfig('${h.id}','f')">${esc(t('as.config'))}</button></div></div>`).join('')}` : ''}
    <div class="as-acts" style="justify-content:flex-end">
      <button class="btn btn-primary" onclick="asCloseModal();closeArchWizard()">${esc(t('as.rev.finish'))}</button>
    </div>`);
}

async function _archSaveTopology() {
  const allSvcs = _arch.hosts.flatMap(h =>
    (h.services || [])
      .filter(s => s.type === 'edge' || s.type === 'agent')
      .map(s => ({ svc: s, host: h }))
  );
  if (!allSvcs.length) { toast(t('arch.save_nothing') || 'Aucun nœud à enregistrer', 'warning'); return false; }

  // Nœuds présents avant la sauvegarde (pour détecter les suppressions / renommages)
  const prevDeclared = [...(_arch.declaredNodes || [])];

  const saved = [];
  for (const { svc, host } of allSvcs) {
    const cfg = { host: host.name, internet_exposed: !!host.internet, reachable_host: svc.reachable || '' };
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
  const freshFile = await api('GET', '/architecture').catch(() => null);
  const fresh = freshFile && Array.isArray(freshFile.nodes) ? freshFile.nodes : null;
  if (fresh) { _arch.declaredNodes = fresh; _wiz.declaredNodes = fresh; }

  toast(t('common.saved') || 'Enregistré', 'success');
  _archSnapshot();
  _archRender();
  return true;
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
  content.innerHTML = _archCanvasHTML();
};

/** Mode édition : barre d'édition, toile (hôtes ou tiers), modifications en cours et inspecteur. */
function _archCanvasHTML() {
  if (_arch.loading) return `<p style="color:var(--text2)">${t('common.loading')}</p>`;
  window._asEdit = true;
  _arch._chg = _archChanges();
  const n = _arch._chg.length;
  const err = _archValidate() || '';
  const haNote = _archAccessHANote();
  return `<div class="arch-page">
    <div class="as-editbar" role="region" aria-label="${esc(t('as.edit.mode'))}">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 20l4-1 11-11-3-3L5 16z"/></svg>
      <b>${esc(t('as.edit.mode'))}</b><span class="as-editbar-sep" aria-hidden="true"></span>
      <span id="as-edit-n" class="as-editbar-n" aria-live="polite">${esc(_archCountLabel(n))}</span>
      <span class="as-editbar-sp"></span>
      <button class="btn btn-ghost btn-sm" onclick="asOpenConfig(null,'v')">${esc(t('as.history'))}</button>
      <button class="btn btn-secondary btn-sm" onclick="asCancelEdit()">${esc(t(n ? 'common.cancel' : 'as.edit.close'))}</button>
      <button class="btn btn-primary btn-sm" id="as-edit-save" onclick="asOpenReview()" ${err ? 'disabled' : ''}>${esc(n ? t('as.edit.review_n', { n }) : t('as.edit.review'))}</button>
    </div>
    <div class="as-wz">
      <div class="as-wz-main">
        ${_asEditToolbarHTML(_arch)}
        ${asSchemaHTML(_arch, { edit: true, selectedId: _arch.selectedSvcId, selectedHostId: _arch.selectedHostId })}
        ${haNote ? `<div class="arch-msg" data-tone="warn">${esc(haNote)}</div>` : ''}
        ${err ? `<div class="arch-msg" data-tone="error">${esc(err)}</div>` : ''}
        ${_asChangesHTML(_arch._chg)}
      </div>
      <aside class="as-wz-ins">${asInspectorHTML()}</aside>
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

/** Ligne capacité : interrupteur + libellé + explication ; « Avant : … » si elle a changé depuis le chargement. */
function _archCapRow(on, label, desc, onchange, extraHTML, beforeHTML) {
  return `<label class="arch-cap" data-on="${on ? 1 : 0}"${beforeHTML ? ' data-chg="1"' : ''}>
      <input type="checkbox" role="switch" ${on ? 'checked' : ''} onchange="${onchange}">
      <span style="min-width:0;">
        <span class="arch-cap-label" style="display:block;">${label}</span>
        <span class="arch-cap-desc" style="display:block;">${esc(desc)}</span>
        ${beforeHTML || ''}
      </span>
    </label>${on && extraHTML ? `<div class="arch-cap-extra">${extraHTML}</div>` : ''}`;
}

function _archGroup(title, bodyHTML) {
  return `<div><div class="arch-group-title">${esc(title)}</div>${bodyHTML}</div>`;
}

function _archField(label, inputHTML) {
  return `<div class="arch-field"><span class="arch-field-label">${label}</span>${inputHTML}</div>`;
}

function asInsTab(tab) {
  _arch.inspTab = tab;
  _archRender();
}

/** « Avant : … » d'une capacité dérivée (HA, TLS) : état au chargement vs état courant. */
function _archBeforeState(svc, was, now, wasLabel) {
  if (!_archBaseSvc(svc.id) || was === now) return '';
  return `<span class="as-before">${esc(t('as.ins.before', { v: wasLabel }))}</span>`;
}

function _archEdgeCapsHTML(svc) {
  const b = _archBaseSvc(svc.id);
  const namedProviders = _arch.acmeProviders || [];
  const dnsProviderList = namedProviders.length
    ? [{ id: 'none', label: '—' }, ...namedProviders.map(p => ({ id: p.id, label: `${p.name} (${p.type})` }))]
    : _ARCH_DNS_PROVIDERS;
  const dnsOpts = dnsProviderList.map(p =>
    `<option value="${p.id}" ${(svc.dnsProvider || 'none') === p.id ? 'selected' : ''}>${esc(p.label)}</option>`
  ).join('');
  const baseGroup = (((_arch.base && _arch.base.haGroups) || []).find(g => g.members.includes(svc.id)) || {}).id || '';
  const curGroup = _archGroupOfSvc(svc.id);
  const bTls = !!(b && (b.domains || b.acme));
  const tls = !!(svc.domains || svc.acme);
  return _archCapRow(!!svc.access, t('arch.svc.access') + _archImpactBadge('restart', svc.existing && svc.status !== 'online'), t('arch.cap.access_desc'),
      `_archSetOpt('${svc.id}','access',this.checked)`, '', _archBefore(svc, 'access')) +
    _archCapRow(!!curGroup, t('arch.svc.ha') + _archImpactBadge('redeploy', svc.existing), t('arch.cap.ha_desc'),
      `_archSetHAGroup('${svc.id}',this.checked,'')`,
      (() => {
        const peers = curGroup ? curGroup.members.filter(id => id !== svc.id).map(id => { const p = _archFindSvc(id); return p ? p.name : id; }) : [];
        const groupOpts = _arch.haGroups.map(g =>
          `<option value="${esc(g.id)}" ${curGroup && curGroup.id === g.id ? 'selected' : ''}>${esc(g.id.replace(/^ha-(\d+)$/, t('arch.ha.group_n') + ' $1'))}</option>`
        ).join('') + `<option value="new">${esc(t('arch.ha.new_group'))}</option>`;
        return `<div style="margin-bottom:4px;">${esc(t('arch.ha.group'))} : <select class="arch-select" style="display:inline-block;width:auto;margin-left:4px;" onchange="_archSetHAGroup('${svc.id}',true,this.value)">${groupOpts}</select></div>` +
          `<div class="arch-cap-desc">${esc(peers.length ? t('arch.ha.peers', { names: peers.join(', ') }) : t('arch.ha.peers_none'))}</div>`;
      })(),
      _archBeforeState(svc, baseGroup, curGroup ? curGroup.id : '', baseGroup || t('as.ins.off'))) +
    _archCapRow(tls, t('arch.svc.domains') + _archImpactBadge('restart', svc.existing), t('arch.cap.tls_desc'),
      `_archSetTLS('${svc.id}',this.checked)`,
      _archField(t('arch.opt.domains'), `<input class="arch-input" value="${esc(svc.domains || '')}" placeholder="app.example.fr, api.example.fr" oninput="_archSetField('${svc.id}','domains',this.value)">` + _archBefore(svc, 'domains')) +
      _archCapRow(!!svc.acme, t('arch.opt.acme'), t('arch.cap.acme_desc'),
        `_archSetOpt('${svc.id}','acme',this.checked)`,
        _archField(t('arch.opt.acme_email'), `<input class="arch-input" value="${esc(svc.acmeEmail || '')}" placeholder="admin@example.fr" oninput="_archSetField('${svc.id}','acmeEmail',this.value)">`) +
        _archField(t('arch.opt.dns_provider'), `<select class="arch-select" onchange="_archSetField('${svc.id}','dnsProvider',this.value);_archRender()">${dnsOpts}</select>`) +
        `<div class="arch-cap-desc">${t('arch.opt.acme_admin_hint')}</div>`,
        _archBefore(svc, 'acme')),
      _archBeforeState(svc, bTls, tls, t(bTls ? 'as.ins.on' : 'as.ins.off')));
}

function _archDelegationsHTML(svc) {
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
}

function _archAgentCapsHTML(svc) {
  const req = missing => missing ? ' <span style="color:var(--red);font-size:10px;font-weight:700;vertical-align:middle;">*</span>' : '';
  return `<div class="arch-cap-desc" style="margin-bottom:6px">${t('as.platforms_hint')}</div>` +
    _archCapRow(!!svc.docker, t('arch.svc.docker') + _archImpactBadge('redeploy', svc.existing), t('arch.cap.docker_desc'),
      `_archSetRuntime('${svc.id}','docker',this.checked)`, '', _archBefore(svc, 'docker')) +
    _archCapRow(!!svc.podman, t('arch.svc.podman') + _archImpactBadge('redeploy', svc.existing), t('arch.cap.podman_desc'),
      `_archSetRuntime('${svc.id}','podman',this.checked)`, '', _archBefore(svc, 'podman')) +
    _archCapRow(!!svc.portainer, t('arch.svc.portainer') + _archImpactBadge('restart', svc.existing), t('arch.cap.portainer_desc'),
      `_archSetOpt('${svc.id}','portainer',this.checked)`,
      _archField('URL' + req(svc.portainer && !svc.portainerUrl),
        `<input class="arch-input" style="${svc.portainer && !svc.portainerUrl ? 'border-color:var(--red);' : ''}" value="${esc(svc.portainerUrl || '')}" placeholder="https://portainer:9443" oninput="_archSetField('${svc.id}','portainerUrl',this.value)">`) +
      _archField(t('arch.opt.portainer_key') + req(svc.portainer && !svc.portainerKey),
        `<input class="arch-input" type="password" style="${svc.portainer && !svc.portainerKey ? 'border-color:var(--red);' : ''}" value="${esc(svc.portainerKey || '')}" placeholder="ptr_…" oninput="_archSetField('${svc.id}','portainerKey',this.value)">`),
      _archBefore(svc, 'portainer')) +
    _archCapRow(!!svc.k8s, t('arch.svc.k8s') + _archImpactBadge('restart', svc.existing), t('arch.cap.k8s_desc'),
      `_archSetOpt('${svc.id}','k8s',this.checked)`, '', _archBefore(svc, 'k8s'));
}

function _archAgentNetHTML(svc, host) {
  const edges = _arch.hosts.flatMap(h => (h.services || []).filter(s => s.type === 'edge'));
  const local = host && (host.services || []).find(s => s.type === 'edge');
  let html = `<div class="arch-cap-desc" style="margin-bottom:8px">${esc(t(local ? 'as.ins.colocated' : 'as.ins.remote'))}</div>`;
  if (edges.length > 1) {
    const targetOpts = edges.map(c => `<option value="${esc(c.id)}" ${svc.targetEdgeId === c.id ? 'selected' : ''}>${esc(c.name)}</option>`).join('');
    html += _archField(t('arch.opt.target_edge'),
      `<select class="arch-select" onchange="_archSetField('${svc.id}','targetEdgeId',this.value)">
        <option value="">${t('arch.opt.target_edge_auto')}</option>${targetOpts}
      </select>` + _archBefore(svc, 'targetEdgeId'));
  } else if (edges.length === 1) {
    html += `<div class="arch-cap-desc">${esc(t('as.ins.target_only', { name: edges[0].name }))}</div>`;
  } else {
    html += `<div class="arch-cap-desc">${esc(t('arch.err.agent_needs_edge'))}</div>`;
  }
  return html;
}

function _archInspectRole(svc) {
  const host = _archFindHostOfSvc(svc.id);
  const tabs = svc.type === 'admin'
    ? []
    : [['gen', 'as.ins.tab.general'], ['caps', 'as.ins.tab.caps'], ['net', 'as.ins.tab.network']];
  if (tabs.length && !tabs.some(([id]) => id === _arch.inspTab)) _arch.inspTab = 'caps';
  const tab = tabs.length ? _arch.inspTab : 'gen';
  const chg = _archChangeOf(svc.id);

  const hostOpts = _arch.hosts.map(h => `<option value="${esc(h.id)}"${host && h.id === host.id ? ' selected' : ''}>${esc(h.name)}</option>`).join('')
    + `<option value="new">${esc(t('as.new_host'))}</option>`;
  const general = _archGroup(t('arch.group.identity'),
      _archField(t('arch.role.name'), `<input class="arch-input" value="${esc(svc.name)}" oninput="_archSetField('${svc.id}','name',this.value)">` + _archImpactBadge('restart', svc.existing) + _archBefore(svc, 'name'))) +
    _archGroup(t('as.host'),
      _archField(t('as.ins.run_on'), `<select class="arch-select" onchange="asMoveSvc('${svc.id}',this.value)">${hostOpts}</select>`) +
      `<div class="arch-cap-desc">${t('arch.opt.region_from_host', { region: esc((host && host.region) || '—') })}</div>` +
      (host ? `<div class="as-acts" style="margin-top:8px">
        <button class="btn btn-secondary btn-sm" onclick="_archSelectHost('${host.id}')">${esc(t('as.ins.edit_host'))}</button>
        <button class="btn btn-secondary btn-sm" onclick="asOpenConfig('${host.id}')">${esc(t('as.config'))}</button></div>` : ''));

  let body = '';
  if (svc.type === 'admin') {
    const tlsEdges = _arch.hosts.flatMap(h => (h.services || []).filter(s => s.type === 'edge' && s.acme));
    body = general + `<div class="arch-cap-desc">${tlsEdges.length ? t('arch.opt.admin_acme_note') : t('arch.opt.none')}</div>`;
  } else if (tab === 'gen') {
    body = general;
  } else if (tab === 'caps') {
    body = svc.type === 'edge' ? _archEdgeCapsHTML(svc) : _archAgentCapsHTML(svc);
  } else if (svc.type === 'edge') {
    body = _archField(t('arch.opt.reachable'), `<input class="arch-input" value="${esc(svc.reachable || '')}" placeholder="edge.example.com" oninput="_archSetField('${svc.id}','reachable',this.value)">` + _archBefore(svc, 'reachable')) +
      `<div class="arch-cap-desc">${esc(t('as.ins.reachable_hint'))}</div>` + _archDelegationsHTML(svc);
  } else {
    body = _archAgentNetHTML(svc, host);
  }

  const badge = chg ? `<span class="as-bd" data-k="${chg.kind === 'add' ? 'new' : 'mod'}">${esc(t(chg.kind === 'add' ? 'as.edit.new' : 'as.edit.modified'))}</span>` : '';
  return `<div class="as-ins-h" style="--k:${_AS_ROLE[svc.type].k}">
      <span class="as-ins-k">${esc(t('as.ins.on_host', { role: t(_ARCH_ROLES[svc.type].label), host: host ? host.name : '—' }))}</span>
      <div class="as-ins-n"><b>${esc(svc.name)}</b>${badge}</div>
      <div class="as-ins-tabs" role="tablist">${tabs.map(([id, k]) => `<button type="button" role="tab" aria-selected="${tab === id}" onclick="asInsTab('${id}')">${esc(t(k))}</button>`).join('')}</div>
    </div>
    <div class="as-ins-b">${body}</div>
    <div class="as-ins-f"><button class="btn btn-ghost btn-sm" style="color:var(--red);margin-left:auto" onclick="_archRemoveSvc('${host ? host.id : ''}','${svc.id}')">${esc(t('arch.role.remove'))}</button></div>`;
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
  _archRefreshChanges();
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
  _archRevealInspector();
}

/** Écran étroit : l'inspecteur passe sous la toile, on l'amène à l'écran après une sélection. */
function _archRevealInspector() {
  if (window.innerWidth > 1180) return;
  document.querySelector('.as-wz-ins')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
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
  _archRevealInspector();
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
  _archRefreshChanges();
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

  // Préférer une passerelle HA leader / première passerelle avec reachable
  const allEdges = _arch.hosts.flatMap(h => h.services.filter(s => s.type === 'edge'));
  const preferred = allEdges.find(c => (c.reachable || '').trim()) || allEdges[0];
  if (preferred) {
    const host = (preferred.reachable || '').trim();
    if (host) return typeof _wizEdgeEndpoint === 'function' ? _wizEdgeEndpoint(host) : ('http://' + host.replace(/\/$/, '') + (String(host).includes(':') ? '' : ':8000'));
    return `http://${preferred.name}:8000`;
  }
  return _arch.onlineEdgeEndpoint || 'http://goproxify-edge:8000';
}

/** Un pack par hôte : tous les rôles de l'hôte (passerelles, agents, Admin) dans un même Compose. */
function _archBuildPacks() {
  _wiz.pairingSecret = _arch.pairingSecret;
  _wiz.scenario = 'full';
  const packs = [];

  for (const host of _arch.hosts) {
    const svcs = host.services || [];
    if (!svcs.length) continue;
    const edges = svcs.filter(s => s.type === 'edge');
    const agents = svcs.filter(s => s.type === 'agent');
    const admins = svcs.filter(s => s.type === 'admin');

    const edgeOpts = edges.map(c => {
      const cGroup = _archGroupOfSvc(c.id);
      const inHA = !!cGroup && cGroup.members.length >= 2;
      const haLeader = inHA ? _archFindSvc(cGroup.members[0]) : null;
      return _buildEdgeOpts({
        wc_name: c.name,
        wc_cluster: inHA,
        wc_cluster_node_id: c.name,
        wc_cluster_group: cGroup ? cGroup.id : 'ha-1',
        wc_cluster_peers: inHA ? _archHAPeersCSV(c.id) : '',
        wc_raft_leader: inHA && haLeader && haLeader.id !== c.id ? haLeader.name : '',
        wc_portal: !!c.access,
        wc_http3: false,
      });
    });

    const agentOpts = agents.map(a => {
      const localEdge = edgeOpts[0];
      let opts = _buildAgentOpts({
        wa_name: a.name,
        wa_edge_url: _archResolveEdgeEndpoint(host, a),
        wa_edge_container_name: localEdge ? localEdge.name : '',
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
      if (localEdge) {
        opts = {
          ...opts,
          envVars: opts.envVars
            .filter(e => e.k !== 'GPX_CONTROL_PLANE_EDGE_ENDPOINT' && e.k !== 'GPX_NETWORK_MANAGEMENT_EDGE_CONTAINER_NAME')
            .concat([
              { k: 'GPX_CONTROL_PLANE_EDGE_ENDPOINT', v: `http://${localEdge.name}:8000` },
              { k: 'GPX_NETWORK_MANAGEMENT_EDGE_CONTAINER_NAME', v: localEdge.name },
            ]),
        };
      }
      return opts;
    });

    const adminOpts = admins.length && edgeOpts.length
      ? _buildAdminOpts({
          wa_edge_name: edgeOpts[0].name,
          wa_jwt_secret: _arch.jwtSecret,
          wa_admin_email: (admins[0].acmeEmail || '').trim() || 'admin@example.com',
          wa_admin_password: 'CHANGE_ME',
        })
      : null;

    const all = [...edgeOpts, ...agentOpts, ...(adminOpts ? [adminOpts] : [])];
    if (!all.length) continue;

    // Plusieurs passerelles ou agents sur l'hôte : leurs variables se chevauchent (nom de nœud, secrets), donc
    // le Compose porte les variables en ligne. Sinon : un seul .env, comme le script d'installation l'attend.
    const multi = edgeOpts.length > 1 || agentOpts.length > 1;
    const composeSvc = o => {
      let block = _cfgComposeSvc(o, multi ? 'inline' : 'env_file');
      if (o.command === 'agent' && edgeOpts.length) {
        block = block.replace('    networks:\n      - goproxify_net', `    depends_on:\n      - ${edgeOpts[0].svcName || edgeOpts[0].name}\n    networks:\n      - goproxify_net`);
      }
      return block;
    };
    const volNames = all.flatMap(o => o.volumes.filter(v => !v.includes('docker.sock') && !v.includes('podman.sock')).map(v => `  ${v.split(':')[0]}:`));
    const composeText = `services:\n${all.map(composeSvc).join('\n\n')}\n\nvolumes:\n${[...new Set(volNames)].join('\n')}\n${all[0].netBlock}`;
    const seenKeys = new Set();
    const envText = multi ? '' : all.flatMap(o => o.envVars).filter(({ k }) => !seenKeys.has(k) && seenKeys.add(k)).map(({ k, v }) => `${k}=${v}`).join('\n');
    const cliText = all.map(_cfgCliText).join('\n\n');

    let edgeEp = '';
    if (agentOpts.length) {
      const hit = (agentOpts[0].envVars || []).find(e => e.k === 'GPX_CONTROL_PLANE_EDGE_ENDPOINT');
      edgeEp = hit ? hit.v : '';
    } else if (edges[0] && edges[0].reachable) {
      edgeEp = typeof _wizEdgeEndpoint === 'function' ? _wizEdgeEndpoint(edges[0].reachable) : edges[0].reachable;
    }

    packs.push({
      hostId: host.id,
      hostName: host.name,
      edgeOpts,
      agentOpts,
      adminOpts,
      bootstrapUrl: '',
      qrCode: '',
      scriptUrl: '',
      installCmd: '',
      edgeEndpoint: edgeEp,
      composeText,
      envText,
      cliText,
      services: svcs.slice(),
    });
  }
  return packs;
}


async function _archCreateTickets(packs) {
  for (const p of packs) {
    try {
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
      for (const a of p.agentOpts) {
        try {
          await api('POST', '/agents/' + encodeURIComponent(a.name) + '/approve');
        } catch (e) {
          console.warn('agent pre-approve failed:', e.message);
        }
      }
    } catch (e) {
      console.warn('bootstrap-tickets failed:', e.message);
    }
  }
}
