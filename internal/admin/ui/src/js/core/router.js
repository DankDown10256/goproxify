// ── Registre des pages ─────────────────────────────────────────────────────
// pages['id'] = function() { ... }  ← pattern historique (rétro-compat)
// App.registerPage(id, module)       ← nouveau pattern module
const pages = {};

const App = {
  // Enregistre un module de page.
  // module = { title?, actions?(ctx), render(container, ctx) }
  registerPage(id, module) {
    pages[id] = async function() {
      const ctx = { core: state.selectedCore, token: state.token };
      const ta = document.getElementById('topbar-actions');
      if (ta) ta.innerHTML = module.actions ? module.actions(ctx) : '';
      const container = document.getElementById('content');
      if (container) await module.render(container, ctx);
    };
  },
};

// ── Ensembles de pages par catégorie ──────────────────────────────────────
  const SETTINGS_PAGES = new Set([
  'snippets','error-pages','portal-templates','tokens','api-tokens','alerts','alert-channels','audit','security',
  'security-vulns','security-posture','security-bans',
  'backups','import','docker-labels','prism',
]);
const CORE_PAGES = new Set([
  'core-trafic','core-proxies','core-streams','core-waf','core-ipfilter',
  'core-certs','core-auth','core-logs-access','core-logs-system',
  'core-observability','core-prism','core-metrics','core-cluster','core-settings','core-general','ip-profiles',
  'core-security','core-security-vulns','core-security-posture','core-security-bans',
  'portal','portal-audit','core-portal-catalog','core-portal-users','snippets',
]);
const SECURITY_PAGES = new Set([
  'security','security-vulns','security-posture','security-bans',
  'core-security','core-security-vulns','core-security-posture','core-security-bans',
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
  state.page = page;

  // Ferme la sidebar sur mobile après navigation
  if (window.innerWidth <= SIDEBAR_MQ) closeSidebar();

  syncNavActive(page);

  // Titre de page depuis la config
  const titles = APP_CONFIG.pageTitles || {};
  const coreName = state.selectedCore?.display_name || state.selectedCore?.node_name || '';
  const corePrefix = (CORE_PAGES.has(page) && coreName) ? `${coreName} — ` : '';
  const pt = document.getElementById('page-title');
  if (pt) pt.textContent = corePrefix + (typeof gpxPageLabel === 'function' ? gpxPageLabel(page, titles[page]) : (titles[page] || page));

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

  const coresBlock = `<div class="nav-section nav-cores-section" id="nav-cores-section" hidden>
      <div class="nav-cores-header" id="nav-cores-header" onclick="onNavCoresHeaderClick(event)">
        <div class="nav-label nav-cores-label">
          <span>${typeof t === 'function' ? t('nav.cores') : 'Cores'}</span>
          <span class="nav-cores-count" id="nav-cores-count"></span>
        </div>
        <button type="button" class="nav-cores-toggle" id="nav-cores-toggle"
          onclick="toggleNavCoresList(event)" title="${typeof t === 'function' ? t('common.cores_toggle') : 'Show / hide'}" hidden aria-expanded="true">
          <svg class="nav-item-chevron" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 3l5 5-5 5"/></svg>
        </button>
      </div>
      <div class="nav-cores-selected" id="nav-cores-selected" hidden></div>
      <div class="nav-cores-body" id="nav-cores-body">
        <div class="nav-cores-search-wrap" id="nav-cores-search-wrap" hidden>
          <input type="search" class="nav-cores-search" id="nav-cores-search"
            placeholder="${typeof t === 'function' ? t('common.cores_search') : 'Search a Core…'}" autocomplete="off"
            oninput="filterNavCores(this.value)">
        </div>
        <div class="nav-cores-list" id="nav-cores-list"></div>
        <div class="nav-cores-empty" id="nav-cores-empty" hidden>${typeof t === 'function' ? t('common.cores_none') : 'No Core found'}</div>
      </div>
    </div>`;

  navEl.innerHTML = [
    `<div class="nav-section">${before.map(renderNavItem).join('')}</div>`,
    coresBlock,
    after.length ? `<div class="nav-section">${after.map(renderNavItem).join('')}</div>` : '',
  ].join('');

  // Section Core contextuelle (masquée par défaut) — items du Core sélectionné
  navEl.insertAdjacentHTML('beforeend', `
    <div class="core-nav-section" id="core-nav-section" style="display:none">
      <div class="core-nav-header">
        <span id="core-nav-name" class="core-nav-name"></span>
        <button class="core-nav-close" onclick="deselectCore()" title="${typeof t === 'function' ? t('common.close') : 'Close'}">✕</button>
      </div>
      <div id="core-nav-items"></div>
    </div>
  `);

  if (state.page) syncNavActive(state.page);
  _navCoresCollapsed = null;
  _navCoresFilter = '';
  const searchInput = document.getElementById('nav-cores-search');
  if (searchInput) searchInput.value = '';
  refreshNavCores();
}

// ── Liste des Cores accessibles dans la sidebar ────────────────────────────
let _navCoresCache = [];
let _navCoresFilter = '';
let _navCoresCollapsed = null; // null = auto selon overflow / sélection

function _navCoreKey(core) {
  return core?.node_name || core?.id || '';
}

function _navCoresCfg() {
  return APP_CONFIG.navCores || { overflowAt: 6, listMaxHeight: 220 };
}

async function refreshNavCores() {
  const section = document.getElementById('nav-cores-section');
  if (!section) return;
  if (!state.token) {
    section.hidden = true;
    return;
  }
  try {
    const nodes = await api('GET', '/nodes');
    _navCoresCache = (nodes || [])
      .filter(n => n.role === 'core' && n.status !== 'pending' && n.status !== 'declared')
      .filter(n => Role.hasAccessToCore(n))
      .sort((a, b) => {
        const an = (a.display_name || a.node_name || '').toLowerCase();
        const bn = (b.display_name || b.node_name || '').toLowerCase();
        return an.localeCompare(bn, typeof gpxBCP47 === 'function' ? gpxBCP47() : undefined);
      });
    window._navCores = _navCoresCache;
    // Garde _coreNodes à jour pour openCore / selectCore depuis d'autres pages
    if (!window._coreNodes?.length) window._coreNodes = _navCoresCache;
  } catch {
    // Pas de token / erreur réseau : on laisse la section telle quelle
    if (!_navCoresCache.length) {
      section.hidden = true;
      return;
    }
  }

  section.hidden = !_navCoresCache.length;
  if (!_navCoresCache.length) return;

  const cfg = _navCoresCfg();
  const overflow = _navCoresCache.length > (cfg.overflowAt || 6);
  const countEl = document.getElementById('nav-cores-count');
  if (countEl) countEl.textContent = String(_navCoresCache.length);

  const searchWrap = document.getElementById('nav-cores-search-wrap');
  const toggleBtn  = document.getElementById('nav-cores-toggle');
  if (searchWrap) searchWrap.hidden = !overflow;
  if (toggleBtn)  toggleBtn.hidden  = !overflow;

  const listEl = document.getElementById('nav-cores-list');
  if (listEl) {
    listEl.style.maxHeight = overflow ? `${cfg.listMaxHeight || 220}px` : '';
    listEl.classList.toggle('nav-cores-list--scroll', overflow);
  }

  // Collapse auto : si trop de cores et aucun Core sélectionné → replié
  // pour laisser le menu admin / observabilité visibles d'emblée.
  if (_navCoresCollapsed === null) {
    _navCoresCollapsed = overflow && !state.selectedCore;
  }
  _applyNavCoresCollapsed();
  renderNavCoresList(_navCoresFilter);
}

function _applyNavCoresCollapsed() {
  const body = document.getElementById('nav-cores-body');
  const toggle = document.getElementById('nav-cores-toggle');
  const section = document.getElementById('nav-cores-section');
  const collapsed = !!_navCoresCollapsed;
  if (body) body.hidden = collapsed;
  if (toggle) toggle.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
  if (section) section.classList.toggle('nav-cores-collapsed', collapsed);
  _renderNavCoresSelectedChip();
}

function _renderNavCoresSelectedChip() {
  const chip = document.getElementById('nav-cores-selected');
  if (!chip) return;
  const core = state.selectedCore;
  const show = !!core && !!_navCoresCollapsed;
  chip.hidden = !show;
  if (!show) { chip.innerHTML = ''; return; }
  const label = core.display_name || core.node_name || core.id || '—';
  const online = core.status === 'online';
  chip.innerHTML = `
    <div class="nav-item nav-core-item selected" title="${esc(label)}"
         onclick="event.stopPropagation();openNavCore(${_navCoresCache.findIndex(c => _navCoreKey(c) === _navCoreKey(core))})">
      <span class="nav-core-dot ${online ? 'online' : 'offline'}" aria-hidden="true"></span>
      <span class="nav-item-label">${esc(label)}</span>
    </div>`;
}

window.toggleNavCoresList = function(ev) {
  ev?.stopPropagation?.();
  _navCoresCollapsed = !_navCoresCollapsed;
  _applyNavCoresCollapsed();
};

window.onNavCoresHeaderClick = function(ev) {
  // Toggle uniquement en mode overflow (bouton visible)
  const toggle = document.getElementById('nav-cores-toggle');
  if (!toggle || toggle.hidden) return;
  if (ev.target.closest('.nav-cores-search')) return;
  toggleNavCoresList(ev);
};

window.filterNavCores = function(q) {
  _navCoresFilter = (q || '').trim().toLowerCase();
  renderNavCoresList(_navCoresFilter);
};

function renderNavCoresList(filter) {
  const listEl = document.getElementById('nav-cores-list');
  const emptyEl = document.getElementById('nav-cores-empty');
  if (!listEl) return;

  const selectedKey = _navCoreKey(state.selectedCore);
  let cores = _navCoresCache;
  if (filter) {
    cores = cores.filter(c => {
      const name = (c.display_name || c.node_name || c.id || '').toLowerCase();
      return name.includes(filter);
    });
  }

  // En mode filtre : garde le Core sélectionné visible en tête s'il matche ou hors filtre
  if (selectedKey && filter) {
    const sel = _navCoresCache.find(c => _navCoreKey(c) === selectedKey);
    if (sel && !cores.some(c => _navCoreKey(c) === selectedKey)) {
      cores = [sel, ...cores];
    }
  }

  if (emptyEl) emptyEl.hidden = cores.length > 0;
  listEl.innerHTML = cores.map((c, i) => {
    const key = _navCoreKey(c);
    const label = c.display_name || c.node_name || c.id || '—';
    const online = c.status === 'online';
    const selected = selectedKey && key === selectedKey;
    const idx = _navCoresCache.findIndex(x => _navCoreKey(x) === key);
    return `
      <div class="nav-item nav-core-item${selected ? ' selected' : ''}"
           data-core-key="${esc(key)}"
           title="${esc(label)}"
           onclick="openNavCore(${idx})">
        <span class="nav-core-dot ${online ? 'online' : 'offline'}" aria-hidden="true"></span>
        <span class="nav-item-label">${esc(label)}</span>
      </div>`;
  }).join('');
}

window.openNavCore = function(i) {
  const core = (window._navCores || _navCoresCache)[i];
  if (!core) return;
  selectCore(core);
};

function syncNavCoreSelection() {
  const selectedKey = _navCoreKey(state.selectedCore);
  document.querySelectorAll('#nav-cores-list .nav-core-item').forEach(el => {
    el.classList.toggle('selected', !!selectedKey && el.dataset.coreKey === selectedKey);
  });
  _renderNavCoresSelectedChip();
}

// ── Rendu des items Core selon le rôle et le scope ────────────────────────
// Réutilise renderNavItem (groupes children) — même markup que la nav admin.
function renderCoreNav(core) {
  const el = document.getElementById('core-nav-items');
  if (!el) return;
  // Scope "core" explicite requis pour WAF, IP filter, Paramètres Core
  const hasCoreScope = Role.hasCoreScope(core?.node_name || core?.id || '');
  const ctx = { hasCoreScope };
  const items = (APP_CONFIG.coreNav || []).filter(item => {
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

// ── Sélection / désélection d'un Core ─────────────────────────────────────
// page optionnelle : destination après sélection (défaut Trafic).
// Évite la course openCore()+navigate(X) où selectCore écrasait toujours vers core-trafic.
function selectCore(core, page) {
  state.selectedCore = core;
  const section = document.getElementById('core-nav-section');
  const nameEl  = document.getElementById('core-nav-name');
  if (section) section.style.display = '';
  if (nameEl)  nameEl.textContent = core.display_name || core.node_name || core.id;
  renderCoreNav(core);
  syncNavCoreSelection();
  navigate(page || 'core-trafic');
}

function deselectCore() {
  state.selectedCore = null;
  const section = document.getElementById('core-nav-section');
  if (section) section.style.display = 'none';
  syncNavCoreSelection();
  // Repasse en auto : replie si overflow pour libérer le menu admin
  _navCoresCollapsed = null;
  const cfg = _navCoresCfg();
  const overflow = _navCoresCache.length > (cfg.overflowAt || 6);
  if (overflow) {
    _navCoresCollapsed = true;
    _applyNavCoresCollapsed();
  }
  navigate('infrastructure');
}
