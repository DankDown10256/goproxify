// ── Registre des pages ─────────────────────────────────────────────────────
// pages['id'] = function() { ... }  ← pattern historique (rétro-compat)
// App.registerPage(id, module)       ← nouveau pattern module
const pages = {};

const App = {
  // Enregistre un module de page.
  // module = { title?, actions?(ctx), render(container, ctx) }
  registerPage(id, module) {
    pages[id] = async function() {
      const ctx = { edge: state.selectedEdge, token: state.token };
      const ta = document.getElementById('topbar-actions');
      if (ta) ta.innerHTML = module.actions ? module.actions(ctx) : '';
      const container = document.getElementById('content');
      if (container) await module.render(container, ctx);
    };
  },
};

// ── Ensembles de pages par catégorie ──────────────────────────────────────
  const SETTINGS_PAGES = new Set([
  'snippets','error-pages','portal-templates','tokens','api-tokens','alerts','alert-channels','audit',
  'security','security-bans','security-vulns','security-rules','automation','automation-flow','automation-history','rules-store','mcp-access',
  'backups','import','docker-labels','prism',
]);
const EDGE_PAGES = new Set([
  'edge-trafic','edge-proxies','edge-streams','edge-waf','edge-ipfilter',
  'edge-certs','edge-auth','edge-logs-access','edge-logs-system',
  'edge-observability','edge-obs-synthese','edge-obs-alerts','edge-prism','edge-metrics','edge-cluster','edge-tokens','edge-settings','edge-general','ip-profiles',
  'edge-security','edge-security-vulns','edge-security-posture','edge-security-bans','edge-security-sentinel',
  'edge-tunnel',
  'portal','portal-settings','portal-sessions','portal-approvals','portal-policy','portal-recordings','portal-audit','edge-portal-catalog','edge-portal-users','snippets',
]);
const SECURITY_PAGES = new Set([
  'security','security-bans','security-vulns','security-sentinel','security-posture','security-rules','automation','automation-flow','automation-history','rules-store',
  'edge-security','edge-security-vulns','edge-security-posture','edge-security-bans','edge-security-sentinel',
]);

// ── Sidebar mobile ────────────────────────────────────────────────────────
const SIDEBAR_MQ = 768;

function syncSidebarUi(open) {
  const app = document.getElementById('app');
  const overlay = document.getElementById('sidebar-overlay');
  const btn = document.getElementById('sidebar-toggle-btn');
  app?.classList.toggle('sidebar-open', open);
  overlay?.classList.toggle('active', open);
  if (btn) {
    btn.setAttribute('aria-expanded', open ? 'true' : 'false');
    btn.setAttribute('aria-controls', 'sidebar');
  }
}

function toggleSidebar() {
  const sidebar = document.getElementById('sidebar');
  if (!sidebar) return;
  const open = sidebar.classList.toggle('open');
  syncSidebarUi(open);
}

function closeSidebar() {
  document.getElementById('sidebar')?.classList.remove('open');
  syncSidebarUi(false);
}

function openSidebar() {
  const sidebar = document.getElementById('sidebar');
  if (!sidebar) return;
  sidebar.classList.add('open');
  syncSidebarUi(true);
}

window.toggleSidebar = toggleSidebar;
window.closeSidebar = closeSidebar;
window.openSidebar = openSidebar;

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeSidebar();
});

window.addEventListener('resize', () => {
  if (window.innerWidth > SIDEBAR_MQ) closeSidebar();
});

// ── Navigation principale ──────────────────────────────────────────────────
function navigate(page) {
  if (typeof stopLogsSSE === 'function') stopLogsSSE();
  // Convention : une page qui démarre un setInterval/timer peut attacher
  // content._cleanup = () => clearInterval(...) pour l'arrêter en quittant
  // la page — sinon le timer continue de tourner et écrase #content même
  // après navigation.
  const outgoing = document.getElementById('content');
  if (outgoing && typeof outgoing._cleanup === 'function') {
    outgoing._cleanup();
    outgoing._cleanup = null;
  }
  state.page = page;
  if (location.hash.slice(1) !== page) history.pushState(null, '', '#' + page);

  // Ferme la sidebar sur mobile après navigation
  if (window.innerWidth <= SIDEBAR_MQ) closeSidebar();

  syncNavActive(page);
  renderPageTabs(page);

  // Titre de page depuis la config
  const titles = APP_CONFIG.pageTitles || {};
  const edgeName = state.selectedEdge?.display_name || state.selectedEdge?.node_name || '';
  const edgePrefix = (EDGE_PAGES.has(page) && edgeName) ? `${edgeName} — ` : '';
  const pt = document.getElementById('page-title');
  if (pt) pt.textContent = edgePrefix + (typeof gpxPageLabel === 'function' ? gpxPageLabel(page, titles[page]) : (titles[page] || page));

  // Reset actions topbar (chaque page les re-remplit si besoin)
  const ta = document.getElementById('topbar-actions');
  if (ta) ta.innerHTML = '';

  const fn = pages[page];
  const content = document.getElementById('content');
  if (fn) {
    fn();
  } else if (content) {
    content.innerHTML = `<div class="empty"><p>${typeof t === 'function' ? t('common.wip') : 'Page under construction.'}</p></div>`;
  }
}

// Page demandée par l'URL (#page) ; les pages passerelle exigent une passerelle sélectionnée.
function pageFromHash() {
  const page = location.hash.slice(1);
  if (!page || !pages[page]) return null;
  if (EDGE_PAGES.has(page) && !state.selectedEdge) return null;
  return page;
}

window.addEventListener('hashchange', () => {
  if (!state.token) return;
  const page = pageFromHash();
  if (page && page !== state.page) navigate(page);
});

function pageTabGroup(page) {
  return (APP_CONFIG.pageTabs || []).find(g => g.tabs.some(tab => tab.page === page)) || null;
}

function renderPageTabs(page) {
  const el = document.getElementById('page-tabs');
  if (!el) return;
  const group = pageTabGroup(page);
  if (!group) { el.hidden = true; el.innerHTML = ''; return; }
  el.hidden = false;
  el.innerHTML = group.tabs.map(tab => {
    const label = t('sec.tab.' + tab.key);
    const active = tab.page === page;
    return `<button type="button" class="tab${active ? ' active' : ''}" role="tab" aria-selected="${active}" onclick="navigate('${esc(tab.page)}')">${esc(label === 'sec.tab.' + tab.key ? tab.label : label)}</button>`;
  }).join('');
  el.querySelector('.tab.active')?.scrollIntoView({ inline: 'center', block: 'nearest' });
}

function syncNavActive(page) {
  const navPage = pageTabGroup(page)?.root || page;
  document.querySelectorAll('.nav-item').forEach(el => {
    el.classList.toggle('active', el.dataset.page === navPage);
    el.classList.remove('parent-active');
  });
  // Ouvre le groupe parent si on est sur une page enfant (ou le parent lui-même)
  document.querySelectorAll('.nav-group').forEach(group => {
    const parentPage = group.dataset.parent;
    const childPages = (group.dataset.children || '').split(',').filter(Boolean);
    const onBranch = page === parentPage || childPages.includes(page);
    group.classList.toggle('open', onBranch || group.classList.contains('pinned-open'));
    if (onBranch && page !== parentPage) {
      const parentItem = group.querySelector(`:scope > .nav-item[data-page="${parentPage}"]`);
      if (parentItem) parentItem.classList.add('parent-active');
    }
  });
}

window.toggleNavGroup = function(ev, groupId) {
  ev.stopPropagation();
  const group = document.getElementById(groupId);
  if (!group) return;
  const willOpen = !group.classList.contains('open');
  group.classList.toggle('open', willOpen);
  group.classList.toggle('pinned-open', willOpen);
};

// ── Génération de la sidebar depuis APP_CONFIG ─────────────────────────────
function renderNavItem(item) {
  const children = item.children || [];
  const lp = item.labelPage || item.page;
  const itemLabel = typeof gpxPageLabel === 'function' ? gpxPageLabel(lp, item.label) : item.label;
  if (children.length) {
    const gid = `nav-group-${esc(item.page)}`;
    const childPages = children.map(c => c.page).join(',');
    const chevron = `<svg class="nav-item-chevron" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" onclick="toggleNavGroup(event,'${gid}')"><path d="M6 3l5 5-5 5"/></svg>`;
    return `
      <div class="nav-group" id="${gid}" data-parent="${esc(item.page)}" data-children="${esc(childPages)}">
        <div class="nav-item" data-page="${esc(item.page)}" onclick="navigate('${esc(item.page)}')">
          ${item.icon || ''}
          <span class="nav-item-label">${esc(itemLabel)}</span>
          ${chevron}
        </div>
        <div class="nav-children">
          ${children.map(c => `
            <div class="nav-item" data-page="${esc(c.page)}" onclick="navigate('${esc(c.page)}')">
              ${c.icon || ''}
              ${esc(c.navKey ? t(c.navKey) : typeof gpxPageLabel === 'function' ? gpxPageLabel(c.page, c.label) : c.label)}
            </div>
          `).join('')}
        </div>
      </div>`;
  }
  return `
    <div class="nav-item" data-page="${esc(item.page)}" onclick="navigate('${esc(item.page)}')">
      ${item.icon || ''}
      ${esc(itemLabel)}
    </div>`;
}

// Pages équivalentes entre l'espace Admin et une passerelle : on reste sur la
// même rubrique quand on change d'espace.
const SPACE_EQUIV = {
  'admin-trafic': 'edge-trafic',
  'admin-observability': 'edge-observability',
  'obs-synthese': 'edge-obs-synthese',
  'obs-metrics': 'edge-metrics',
  'obs-alerts': 'edge-obs-alerts',
  'logs': 'edge-logs-access',
  'logs-system': 'edge-logs-system',
  'prism': 'edge-prism',
  'security': 'edge-security',
  'security-bans': 'edge-security-bans',
  'security-vulns': 'edge-security-vulns',
  'security-sentinel': 'edge-security-sentinel',
  'security-posture': 'edge-security-posture',
};
const SPACE_EQUIV_REV = Object.fromEntries(Object.entries(SPACE_EQUIV).map(([a, e]) => [e, a]));

let _navUser = null;

function _navItemsFor(edge, user) {
  if (edge) {
    const ctx = { hasEdgeScope: Role.hasEdgeScope(edge.node_name || edge.id || '') };
    return (APP_CONFIG.edgeNav || [])
      .filter(item => !item.guard || item.guard(ctx))
      .map(item => item.children?.length
        ? { ...item, children: item.children.filter(c => !c.guard || c.guard(ctx)) }
        : item);
  }
  const raw = APP_CONFIG.nav || [];
  // Compat : ancien format sections { label, items } → aplatit ; nouveau format = liste plate.
  const flat = raw.length && raw[0]?.items
    ? raw.flatMap(section => (section.guard && !section.guard(user)) ? [] : (section.items || []))
    : raw;
  return flat
    .filter(item => !item.guard || item.guard(user))
    .map(item => item.children?.length
      ? { ...item, children: item.children.filter(c => !c.guard || c.guard(user)) }
      : item);
}

// Rubriques communes d'abord, puis une section nommée (Plateforme / Passerelle).
function _renderNavSections(items) {
  const common = items.filter(it => !it.section);
  const named = [];
  items.filter(it => it.section).forEach(it => {
    let grp = named.find(g => g.name === it.section);
    if (!grp) named.push(grp = { name: it.section, items: [] });
    grp.items.push(it);
  });
  const label = n => typeof gpxNavSectionLabel === 'function' ? gpxNavSectionLabel(n) : n;
  return [
    common.length ? `<div class="nav-section">${common.map(renderNavItem).join('')}</div>` : '',
    ...named.map(g => `<div class="nav-section"><div class="nav-label">${esc(label(g.name))}</div>${g.items.map(renderNavItem).join('')}</div>`),
  ].join('');
}

function renderNav(user) {
  _navUser = user;
  renderSpaceNav();
  refreshNavEdges();
}

function renderSpaceNav() {
  const navEl = document.getElementById('sidebar-nav');
  if (!navEl) return;
  const edge = state.selectedEdge;
  navEl.innerHTML = _renderNavSections(_navItemsFor(edge, _navUser));

  const head = document.getElementById('space-head');
  if (head) {
    const tr = (k, d) => typeof t === 'function' ? t(k) : d;
    const name = edge ? (edge.display_name || edge.node_name || edge.id) : tr('nav.section.Administration', 'Administration');
    const sub = edge ? (edge.status === 'online' ? 'Online' : 'Offline') : tr('nav.all_edges', 'All gateways');
    head.innerHTML = `<b>${esc(name)}</b><span>${esc(sub)}</span>`;
  }
  if (state.page) syncNavActive(state.page);
  renderSpaceRail();
}

// ── Rail d'espaces : Admin + une pastille par passerelle accessible ────────────
let _navEdgesCache = [];

function _navEdgeKey(edge) {
  return edge?.node_name || edge?.id || '';
}

function _navEdgesCfg() {
  return APP_CONFIG.navEdges || { overflowAt: 6 };
}

function _edgeInitials(edge) {
  const name = (edge.display_name || edge.node_name || edge.id || '?').replace(/^edge[-_ ]?/i, '');
  return (name.replace(/[^\p{L}\p{N}]/gu, '').slice(0, 2) || '?').toUpperCase();
}

async function refreshNavEdges() {
  if (!state.token) {
    _navEdgesCache = [];
    renderSpaceRail();
    return;
  }
  try {
    const nodes = await api('GET', '/nodes');
    _navEdgesCache = (nodes || [])
      .filter(n => n.role === 'edge' && n.status !== 'pending' && n.status !== 'declared')
      .filter(n => Role.hasAccessToEdge(n))
      .sort((a, b) => {
        const an = (a.display_name || a.node_name || '').toLowerCase();
        const bn = (b.display_name || b.node_name || '').toLowerCase();
        return an.localeCompare(bn, typeof gpxBCP47 === 'function' ? gpxBCP47() : undefined);
      });
    window._navEdges = _navEdgesCache;
    // Garde _edgeNodes à jour pour openEdge / selectEdge depuis d'autres pages
    if (!window._edgeNodes?.length) window._edgeNodes = _navEdgesCache;
  } catch {
    // Pas de token / erreur réseau : on garde le rail tel quel
  }
  renderSpaceRail();
}

function renderSpaceRail() {
  const rail = document.getElementById('space-rail');
  if (!rail) return;
  const selectedKey = _navEdgeKey(state.selectedEdge);
  const adminLabel = typeof t === 'function' ? t('nav.section.Administration') : 'Administration';
  const many = _navEdgesCache.length > (_navEdgesCfg().overflowAt || 6);
  const searchLabel = typeof t === 'function' ? t('nav.search_edge') : 'Search';
  rail.innerHTML = `
    <button type="button" class="space-btn${selectedKey ? '' : ' active'}" title="${esc(adminLabel)}" aria-label="${esc(adminLabel)}" onclick="deselectEdge()">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 11l9-8 9 8"/><path d="M5 10v10h14V10"/></svg>
    </button>
    ${_navEdgesCache.length ? '<div class="space-sep"></div>' : ''}
    <div class="space-list">
      ${_navEdgesCache.map((c, i) => {
        const label = c.display_name || c.node_name || c.id || '—';
        const sel = selectedKey && _navEdgeKey(c) === selectedKey;
        return `<button type="button" class="space-btn${sel ? ' active' : ''}" title="${esc(label)}" aria-label="${esc(label)}" onclick="openNavEdge(${i})">
          ${esc(_edgeInitials(c))}<span class="space-dot ${c.status === 'online' ? 'online' : 'offline'}" aria-hidden="true"></span>
        </button>`;
      }).join('')}
    </div>
    ${many ? `<button type="button" class="space-btn" title="${esc(searchLabel)}" aria-label="${esc(searchLabel)}" onclick="toggleSpacePicker(event)">
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/></svg>
    </button>` : ''}`;
}

// ── Recherche d'une passerelle quand le rail devient long ──────────────────────
window.toggleSpacePicker = function(ev) {
  ev?.stopPropagation?.();
  const picker = document.getElementById('space-picker');
  if (!picker) return;
  picker.hidden = !picker.hidden;
  if (!picker.hidden) {
    const input = document.getElementById('space-picker-input');
    input.value = '';
    filterSpacePicker('');
    input.focus();
  }
};

window.filterSpacePicker = function(q) {
  const list = document.getElementById('space-picker-list');
  if (!list) return;
  const f = (q || '').trim().toLowerCase();
  list.innerHTML = _navEdgesCache
    .map((c, i) => ({ c, i, label: c.display_name || c.node_name || c.id || '—' }))
    .filter(x => !f || x.label.toLowerCase().includes(f))
    .map(x => `<div class="nav-item" onclick="openNavEdge(${x.i});toggleSpacePicker()">
      <span class="space-dot-inline ${x.c.status === 'online' ? 'online' : 'offline'}" aria-hidden="true"></span>
      <span class="nav-item-label">${esc(x.label)}</span>
    </div>`).join('') || `<div class="space-picker-empty">${typeof t === 'function' ? t('common.edges_none') : 'No gateway found'}</div>`;
};

document.addEventListener('click', (e) => {
  const picker = document.getElementById('space-picker');
  if (picker && !picker.hidden && !picker.contains(e.target)) picker.hidden = true;
});

window.openNavEdge = function(i) {
  const edge = (window._navEdges || _navEdgesCache)[i];
  if (!edge) return;
  selectEdge(edge, SPACE_EQUIV[state.page]);
};

// ── Sélection / désélection d'une passerelle ─────────────────────────────────────
// page optionnelle : destination après sélection (défaut Routage).
// Évite la course openEdge()+navigate(X) où selectEdge écrasait toujours vers edge-trafic.
function selectEdge(edge, page) {
  state.selectedEdge = edge;
  renderSpaceNav();
  navigate(page || 'edge-trafic');
}

function deselectEdge() {
  const target = SPACE_EQUIV_REV[state.page] || 'dashboard';
  state.selectedEdge = null;
  renderSpaceNav();
  navigate(target);
}
