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
  'security','security-bans','security-vulns','security-threats','security-rules','automation','rules-store','mcp-access',
  'backups','import','docker-labels','prism',
]);
const EDGE_PAGES = new Set([
  'edge-trafic','edge-proxies','edge-streams','edge-waf','edge-ipfilter',
  'edge-certs','edge-auth','edge-logs-access','edge-logs-system',
  'edge-observability','edge-prism','edge-metrics','edge-cluster','edge-tokens','edge-settings','edge-general','ip-profiles',
  'edge-security','edge-security-vulns','edge-security-posture','edge-security-bans','edge-security-sentinel',
  'edge-tunnel',
  'portal','portal-audit','edge-portal-catalog','edge-portal-users','snippets',
]);
const SECURITY_PAGES = new Set([
  'security','security-bans','security-vulns','security-threats','security-rules','automation','rules-store',
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

function syncNavActive(page) {
  document.querySelectorAll('.nav-item').forEach(el => {
    el.classList.toggle('active', el.dataset.page === page);
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
  const itemLabel = typeof gpxPageLabel === 'function' ? gpxPageLabel(item.page, item.label) : item.label;
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
              ${esc(typeof gpxPageLabel === 'function' ? gpxPageLabel(c.page, c.label) : c.label)}
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

function renderNav(user) {
  const navEl = document.getElementById('sidebar-nav');
  if (!navEl) return;

  const raw = APP_CONFIG.nav || [];
  // Compat : ancien format sections { label, items } → aplatit ; nouveau format = liste plate.
  const flat = raw.length && raw[0]?.items
    ? raw.flatMap(section => {
        if (section.guard && !section.guard(user)) return [];
        return (section.items || []);
      })
    : raw;

  const filterItem = (item) => {
    if (item.guard && !item.guard(user)) return null;
    if (!item.children?.length) return item;
    const children = item.children.filter(c => !c.guard || c.guard(user));
    return { ...item, children };
  };
  const items = flat.map(filterItem).filter(Boolean);

  const infraIdx = items.findIndex(it => it.page === 'infrastructure');
  const before = infraIdx >= 0 ? items.slice(0, infraIdx + 1) : items.slice(0, 1);
  const after  = infraIdx >= 0 ? items.slice(infraIdx + 1) : items.slice(1);

  const edgesBlock = `<div class="nav-section nav-edges-section" id="nav-edges-section" hidden>
      <div class="nav-edges-header" id="nav-edges-header" onclick="onNavEdgesHeaderClick(event)">
        <div class="nav-label nav-edges-label">
          <span>${typeof t === 'function' ? t('nav.edges') : 'Passerelles'}</span>
          <span class="nav-edges-count" id="nav-edges-count"></span>
        </div>
        <button type="button" class="nav-edges-toggle" id="nav-edges-toggle"
          onclick="toggleNavEdgesList(event)" title="${typeof t === 'function' ? t('common.edges_toggle') : 'Show / hide'}" hidden aria-expanded="true">
          <svg class="nav-item-chevron" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 3l5 5-5 5"/></svg>
        </button>
      </div>
      <div class="nav-edges-selected" id="nav-edges-selected" hidden></div>
      <div class="nav-edges-body" id="nav-edges-body">
        <div class="nav-edges-search-wrap" id="nav-edges-search-wrap" hidden>
          <input type="search" class="nav-edges-search" id="nav-edges-search"
            placeholder="${typeof t === 'function' ? t('common.edges_search') : 'Search a passerelle…'}" autocomplete="off"
            oninput="filterNavEdges(this.value)">
        </div>
        <div class="nav-edges-list" id="nav-edges-list"></div>
        <div class="nav-edges-empty" id="nav-edges-empty" hidden>${typeof t === 'function' ? t('common.edges_none') : 'No passerelle found'}</div>
      </div>
    </div>`;

  navEl.innerHTML = [
    `<div class="nav-section">${before.map(renderNavItem).join('')}</div>`,
    edgesBlock,
    after.length ? `<div class="nav-section">${after.map(renderNavItem).join('')}</div>` : '',
  ].join('');

  // Section passerelle contextuelle (masquée par défaut) — items de la passerelle sélectionnée
  navEl.insertAdjacentHTML('beforeend', `
    <div class="edge-nav-section" id="edge-nav-section" style="display:none">
      <div class="edge-nav-header">
        <span id="edge-nav-name" class="edge-nav-name"></span>
        <button class="edge-nav-close" onclick="deselectEdge()" title="${typeof t === 'function' ? t('common.close') : 'Close'}">✕</button>
      </div>
      <div id="edge-nav-items"></div>
    </div>
  `);

  if (state.page) syncNavActive(state.page);
  _navEdgesCollapsed = null;
  _navEdgesFilter = '';
  const searchInput = document.getElementById('nav-edges-search');
  if (searchInput) searchInput.value = '';
  refreshNavEdges();
}

// ── Liste des passerelles accessibles dans la sidebar ────────────────────────────
let _navEdgesCache = [];
let _navEdgesFilter = '';
let _navEdgesCollapsed = null; // null = auto selon overflow / sélection

function _navEdgeKey(edge) {
  return edge?.node_name || edge?.id || '';
}

function _navEdgesCfg() {
  return APP_CONFIG.navEdges || { overflowAt: 6, listMaxHeight: 220 };
}

async function refreshNavEdges() {
  const section = document.getElementById('nav-edges-section');
  if (!section) return;
  if (!state.token) {
    section.hidden = true;
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
    // Pas de token / erreur réseau : on laisse la section telle quelle
    if (!_navEdgesCache.length) {
      section.hidden = true;
      return;
    }
  }

  section.hidden = !_navEdgesCache.length;
  if (!_navEdgesCache.length) return;

  const cfg = _navEdgesCfg();
  const overflow = _navEdgesCache.length > (cfg.overflowAt || 6);
  const countEl = document.getElementById('nav-edges-count');
  if (countEl) countEl.textContent = String(_navEdgesCache.length);

  const searchWrap = document.getElementById('nav-edges-search-wrap');
  const toggleBtn  = document.getElementById('nav-edges-toggle');
  if (searchWrap) searchWrap.hidden = !overflow;
  if (toggleBtn)  toggleBtn.hidden  = !overflow;

  const listEl = document.getElementById('nav-edges-list');
  if (listEl) {
    listEl.style.maxHeight = overflow ? `${cfg.listMaxHeight || 220}px` : '';
    listEl.classList.toggle('nav-edges-list--scroll', overflow);
  }

  // Collapse auto : si trop de edges et aucune passerelle sélectionnée → replié
  // pour laisser le menu admin / observabilité visibles d'emblée.
  if (_navEdgesCollapsed === null) {
    _navEdgesCollapsed = overflow && !state.selectedEdge;
  }
  _applyNavEdgesCollapsed();
  renderNavEdgesList(_navEdgesFilter);
}

function _applyNavEdgesCollapsed() {
  const body = document.getElementById('nav-edges-body');
  const toggle = document.getElementById('nav-edges-toggle');
  const section = document.getElementById('nav-edges-section');
  const collapsed = !!_navEdgesCollapsed;
  if (body) body.hidden = collapsed;
  if (toggle) toggle.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
  if (section) section.classList.toggle('nav-edges-collapsed', collapsed);
  _renderNavEdgesSelectedChip();
}

function _renderNavEdgesSelectedChip() {
  const chip = document.getElementById('nav-edges-selected');
  if (!chip) return;
  const edge = state.selectedEdge;
  const show = !!edge && !!_navEdgesCollapsed;
  chip.hidden = !show;
  if (!show) { chip.innerHTML = ''; return; }
  const label = edge.display_name || edge.node_name || edge.id || '—';
  const online = edge.status === 'online';
  chip.innerHTML = `
    <div class="nav-item nav-edge-item selected" title="${esc(label)}"
         onclick="event.stopPropagation();openNavEdge(${_navEdgesCache.findIndex(c => _navEdgeKey(c) === _navEdgeKey(edge))})">
      <span class="nav-edge-dot ${online ? 'online' : 'offline'}" aria-hidden="true"></span>
      <span class="nav-item-label">${esc(label)}</span>
    </div>`;
}

window.toggleNavEdgesList = function(ev) {
  ev?.stopPropagation?.();
  _navEdgesCollapsed = !_navEdgesCollapsed;
  _applyNavEdgesCollapsed();
};

window.onNavEdgesHeaderClick = function(ev) {
  // Toggle uniquement en mode overflow (bouton visible)
  const toggle = document.getElementById('nav-edges-toggle');
  if (!toggle || toggle.hidden) return;
  if (ev.target.closest('.nav-edges-search')) return;
  toggleNavEdgesList(ev);
};

window.filterNavEdges = function(q) {
  _navEdgesFilter = (q || '').trim().toLowerCase();
  renderNavEdgesList(_navEdgesFilter);
};

function renderNavEdgesList(filter) {
  const listEl = document.getElementById('nav-edges-list');
  const emptyEl = document.getElementById('nav-edges-empty');
  if (!listEl) return;

  const selectedKey = _navEdgeKey(state.selectedEdge);
  let edges = _navEdgesCache;
  if (filter) {
    edges = edges.filter(c => {
      const name = (c.display_name || c.node_name || c.id || '').toLowerCase();
      return name.includes(filter);
    });
  }

  // En mode filtre : garde la passerelle sélectionnée visible en tête s'il matche ou hors filtre
  if (selectedKey && filter) {
    const sel = _navEdgesCache.find(c => _navEdgeKey(c) === selectedKey);
    if (sel && !edges.some(c => _navEdgeKey(c) === selectedKey)) {
      edges = [sel, ...edges];
    }
  }

  if (emptyEl) emptyEl.hidden = edges.length > 0;
  listEl.innerHTML = edges.map((c, i) => {
    const key = _navEdgeKey(c);
    const label = c.display_name || c.node_name || c.id || '—';
    const online = c.status === 'online';
    const selected = selectedKey && key === selectedKey;
    const idx = _navEdgesCache.findIndex(x => _navEdgeKey(x) === key);
    return `
      <div class="nav-item nav-edge-item${selected ? ' selected' : ''}"
           data-edge-key="${esc(key)}"
           title="${esc(label)}"
           onclick="openNavEdge(${idx})">
        <span class="nav-edge-dot ${online ? 'online' : 'offline'}" aria-hidden="true"></span>
        <span class="nav-item-label">${esc(label)}</span>
      </div>`;
  }).join('');
}

window.openNavEdge = function(i) {
  const edge = (window._navEdges || _navEdgesCache)[i];
  if (!edge) return;
  selectEdge(edge);
};

function syncNavEdgeSelection() {
  const selectedKey = _navEdgeKey(state.selectedEdge);
  document.querySelectorAll('#nav-edges-list .nav-edge-item').forEach(el => {
    el.classList.toggle('selected', !!selectedKey && el.dataset.edgeKey === selectedKey);
  });
  _renderNavEdgesSelectedChip();
}

// ── Rendu des items passerelle selon le rôle et le scope ────────────────────────
// Réutilise renderNavItem (groupes children) — même markup que la nav admin.
function renderEdgeNav(edge) {
  const el = document.getElementById('edge-nav-items');
  if (!el) return;
  // Scope "edge" explicite requis pour WAF, IP filter, Paramètres passerelle
  const hasEdgeScope = Role.hasEdgeScope(edge?.node_name || edge?.id || '');
  const ctx = { hasEdgeScope };
  const items = (APP_CONFIG.edgeNav || []).filter(item => {
    if (!item.guard) return true;
    return item.guard(ctx);
  }).map(item => {
    if (!item.children?.length) return item;
    return {
      ...item,
      children: item.children.filter(c => !c.guard || c.guard(ctx)),
    };
  });
  el.innerHTML = items.map(renderNavItem).join('');
}

// ── Sélection / désélection d'une passerelle ─────────────────────────────────────
// page optionnelle : destination après sélection (défaut Trafic).
// Évite la course openEdge()+navigate(X) où selectEdge écrasait toujours vers edge-trafic.
function selectEdge(edge, page) {
  state.selectedEdge = edge;
  const section = document.getElementById('edge-nav-section');
  const nameEl  = document.getElementById('edge-nav-name');
  if (section) section.style.display = '';
  if (nameEl)  nameEl.textContent = edge.display_name || edge.node_name || edge.id;
  renderEdgeNav(edge);
  syncNavEdgeSelection();
  navigate(page || 'edge-trafic');
}

function deselectEdge() {
  state.selectedEdge = null;
  const section = document.getElementById('edge-nav-section');
  if (section) section.style.display = 'none';
  syncNavEdgeSelection();
  // Repasse en auto : replie si overflow pour libérer le menu admin
  _navEdgesCollapsed = null;
  const cfg = _navEdgesCfg();
  const overflow = _navEdgesCache.length > (cfg.overflowAt || 6);
  if (overflow) {
    _navEdgesCollapsed = true;
    _applyNavEdgesCollapsed();
  }
  navigate('infrastructure');
}
