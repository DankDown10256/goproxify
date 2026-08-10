// ── Authentification ───────────────────────────────────────────────────────
let _mfaToken = '';
let _mfaMethod = '';

async function doLogin() {
  const email = document.getElementById('login-email').value;
  const pass  = document.getElementById('login-pass').value;
  try {
    const res = await fetch('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: pass }),
    });
    if (!res.ok) { toast(t('login.bad_creds'), 'error'); return; }
    const data = await res.json();
    if (res.status === 202 && data.mfa_required) {
      _mfaToken = data.mfa_token || '';
      const methods = data.methods || [];
      _mfaMethod = methods.length > 0 ? (methods[0].method || methods[0].type || '') : 'totp';
      const selector = document.getElementById('mfa-method-selector');
      const hint = document.getElementById('mfa-hint');
      if (selector && methods.length > 1) {
        selector.style.display = 'flex';
        selector.innerHTML = methods.map(m => {
          const label = t('mfa.method.' + (m.method||m.type||'')) !== ('mfa.method.' + (m.method||m.type||''))
            ? t('mfa.method.' + (m.method||m.type||''))
            : (m.method||m.type||'');
          return `<button class="btn btn-secondary" style="font-size:12px;" onclick="_selectMFAMethod('${esc(m.method||m.type||'')}',this)">${esc(label)}</button>`;
        }).join('');
      } else if (selector) {
        selector.style.display = 'none';
      }
      if (hint) {
        const hk = 'mfa.hint.' + _mfaMethod;
        hint.textContent = t(hk) !== hk ? t(hk) : t('mfa.hint.default');
      }
      const codeEl = document.getElementById('mfa-code');
      if (codeEl) codeEl.value = '';
      const codeField = codeEl?.closest('.field');
      if (codeField) codeField.style.display = _mfaMethod === 'webauthn' ? 'none' : '';
      document.getElementById('mfa-backdrop').style.display = 'flex';
      if (_mfaMethod === 'webauthn') {
        doWebAuthnLogin();
        return;
      }
      setTimeout(() => codeEl?.focus(), 50);
      return;
    }
    state.token = data.token;
    localStorage.setItem('gpx_token', data.token);
    await afterLogin();
  } catch(e) { toast(e.message, 'error'); }
}

function _selectMFAMethod(method, btn) {
  _mfaMethod = method;
  const selector = document.getElementById('mfa-method-selector');
  if (selector) selector.querySelectorAll('button').forEach(b => b.classList.toggle('btn-primary', b === btn));
  const hint = document.getElementById('mfa-hint');
  if (hint) {
    const hk = 'mfa.hint.' + method;
    hint.textContent = t(hk) !== hk ? t(hk) : t('mfa.hint.default');
  }
  const codeField = document.getElementById('mfa-code')?.closest('.field');
  if (codeField) codeField.style.display = method === 'webauthn' ? 'none' : '';
  if (method === 'webauthn') {
    doWebAuthnLogin();
  }
}

async function doMFAChallenge() {
  if (_mfaMethod === 'webauthn') {
    await doWebAuthnLogin();
    return;
  }
  const code  = document.getElementById('mfa-code')?.value?.trim();
  const trust = document.getElementById('mfa-trust')?.checked || false;
  if (!code) return;
  try {
    const res = await fetch('/api/v1/auth/mfa/challenge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mfa_token: _mfaToken, method: _mfaMethod, code, trust_device: trust }),
    });
    if (!res.ok) { toast(t('login.mfa_invalid'), 'error'); return; }
    const data = await res.json();
    document.getElementById('mfa-backdrop').style.display = 'none';
    state.token = data.token;
    localStorage.setItem('gpx_token', data.token);
    await afterLogin();
  } catch(e) { toast(e.message, 'error'); }
}

async function doWebAuthnLogin() {
  if (!window.PublicKeyCredential) {
    toast(t('account.mfa_webauthn_unavailable'), 'error');
    return;
  }
  if (!_mfaToken) {
    toast(t('login.mfa_invalid'), 'error');
    return;
  }
  try {
    const beginRes = await fetch('/api/v1/auth/mfa/webauthn/login/begin', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + _mfaToken,
      },
      body: JSON.stringify({ mfa_token: _mfaToken }),
    });
    if (!beginRes.ok) { toast(t('login.mfa_invalid'), 'error'); return; }
    const begin = await beginRes.json();
    const options = begin.options || begin;
    const pk = options.publicKey || options;
    const challengeID = begin.challenge_id || '';
    pk.challenge = b64url(pk.challenge);
    if (pk.allowCredentials) {
      pk.allowCredentials = pk.allowCredentials.map(c => ({ ...c, id: b64url(c.id) }));
    }
    const cred = await navigator.credentials.get({ publicKey: pk });
    if (!cred) { toast(t('account.mfa_webauthn_cancelled'), 'info'); return; }
    const trust = document.getElementById('mfa-trust')?.checked || false;
    const finishRes = await fetch('/api/v1/auth/mfa/webauthn/login/finish', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        mfa_token: _mfaToken,
        user_id: begin.user_id,
        challenge_id: challengeID,
        trust_device: trust,
        response: {
          id: cred.id,
          rawId: b64encode(cred.rawId),
          type: cred.type,
          response: {
            authenticatorData: b64encode(cred.response.authenticatorData),
            clientDataJSON: b64encode(cred.response.clientDataJSON),
            signature: b64encode(cred.response.signature),
            userHandle: cred.response.userHandle ? b64encode(cred.response.userHandle) : undefined,
          },
        },
      }),
    });
    if (!finishRes.ok) { toast(t('login.mfa_invalid'), 'error'); return; }
    const data = await finishRes.json();
    document.getElementById('mfa-backdrop').style.display = 'none';
    state.token = data.token;
    localStorage.setItem('gpx_token', data.token);
    await afterLogin();
  } catch(e) { toast(e.message || t('account.mfa_webauthn_error'), 'error'); }
}

function b64url(v) {
  if (typeof v === 'string') {
    const b = atob(v.replace(/-/g,'+').replace(/_/g,'/'));
    const a = new Uint8Array(b.length);
    for (let i=0;i<b.length;i++) a[i]=b.charCodeAt(i);
    return a.buffer;
  }
  return v;
}
function b64encode(buf) {
  const b = new Uint8Array(buf);
  return btoa(String.fromCharCode(...b)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
}

function showForgotPassword() {
  document.getElementById('forgot-backdrop').style.display = 'flex';
  setTimeout(() => document.getElementById('forgot-email')?.focus(), 50);
}

async function doForgotPassword() {
  const email = document.getElementById('forgot-email')?.value;
  if (!email) return;
  try {
    await fetch('/api/v1/auth/reset-password', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    toast(t('login.reset_sent'), 'success');
  } catch { toast(t('login.reset_err'), 'error'); }
  document.getElementById('forgot-backdrop').style.display = 'none';
}

function showPairingLogin() {
  document.getElementById('pairing-backdrop').style.display = 'flex';
  setTimeout(() => document.getElementById('pairing-token')?.focus(), 50);
}

async function doPairingLogin() {
  const token = document.getElementById('pairing-token')?.value?.trim();
  if (!token) return;
  state.token = token;
  localStorage.setItem('gpx_token', token);
  document.getElementById('pairing-backdrop').style.display = 'none';
  try { await afterLogin(); } catch {
    toast('Token invalide', 'error');
    state.token = '';
    localStorage.removeItem('gpx_token');
  }
}

function doLogout() {
  localStorage.removeItem('gpx_token');
  state.token = '';
  try {
    document.cookie = '_gpx_device=; path=/; Max-Age=0; SameSite=Lax';
  } catch (_) { /* ignore */ }
  showLogin();
}

function showLogin() {
  document.getElementById('login-page').style.display = 'flex';
  document.getElementById('app').style.display = 'none';
  if (typeof applyStaticI18n === 'function') applyStaticI18n();
}

function showApp() {
  document.getElementById('login-page').style.display = 'none';
  document.getElementById('app').style.display = 'flex';
  initSkin();
  updateThemeLabel();
  api('GET', '/auth/me').then(u => {
    state.user = u;
    updateSidebarUser(u);
    renderNav(u);
  }).catch(() => { state.user = null; renderNav(null); });
}

async function afterLogin() {
  showApp();
  startTopbarClock();
  if (await checkNeedOnboarding()) {
    onb.step = 0; onb.mode = null; onb.infra = null; onb.token = null;
    onb.withAgent = false; onb.withLanding = false; onb.dnsProvider = 'none';
    onb.backupData = null; onb.backupSummary = null; onb.configProxies = null;
    navigate('onboarding');
    return;
  }
  // Deep-link depuis les pages d'erreur Core : /?gpx_page=logs&search=<request-id>&component=core
  const params = new URLSearchParams(location.search);
  if (params.get('gpx_page') === 'logs') {
    history.replaceState(null, '', location.pathname || '/');
    const search = params.get('search') || '';
    const component = params.get('component') || 'core';
    const kind = params.get('kind') || 'access';
    if (typeof openLogs === 'function') {
      logsFilters.search = search;
      logsFilters.level = '';
      logsFilters.domain = '';
      logsFilters.ip = '';
      logsFilters.method = '';
      logsFilters.status = '';
      logsFilters.path = '';
      logsFilters.date_from = '';
      logsFilters.date_to = '';
      openLogs({ kind, component, keepFilters: true });
      state.page = 'logs';
      if (window.innerWidth <= 768) closeSidebar();
      syncNavActive('logs');
      const titles = APP_CONFIG.pageTitles || {};
      const pt = document.getElementById('page-title');
      if (pt) pt.textContent = titles.logs || 'Logs';
      return;
    }
    navigate('logs');
    return;
  }
  navigate('dashboard');
}

function updateSidebarUser(u) {
  if (!u) return;
  const avatarEl = document.getElementById('sidebar-avatar');
  const nameEl   = document.getElementById('sidebar-user-name');
  const roleEl   = document.getElementById('sidebar-user-role');
  const initials = (u.name || u.email || '?').split(/\s+/).map(w => w[0]).join('').toUpperCase().slice(0,2);
  if (avatarEl) avatarEl.textContent = initials;
  if (nameEl)   nameEl.textContent   = u.name || u.email || '—';
  if (roleEl)   roleEl.textContent   = u.role  || '';
}


// ── Helpers ────────────────────────────────────────────────────────────────
function modal(title, bodyHtml, footerHtml, large = false, headerRight = '') {
  closeModal();
  const ov = document.createElement('div');
  ov.className = 'dialog-backdrop';
  ov.id = 'modal-overlay';
  ov.onclick = e => { if (e.target === ov) closeModal(); };
  ov.innerHTML = `
    <div class="dialog blueprint${large?' modal-lg':''}">
      <div class="modal-header" style="padding:20px 24px 16px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--border);">
        <span class="dialog-title" style="padding:0;">${title}</span>
        <div style="display:flex;align-items:center;gap:12px;">
          ${headerRight}
          <button class="btn btn-ghost btn-icon" onclick="closeModal()">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
          </button>
        </div>
      </div>
      <div class="dialog-body">${bodyHtml}</div>
      ${footerHtml ? `<div class="dialog-actions">${footerHtml}</div>` : ''}
    </div>`;
  document.body.append(ov);
}
function closeModal() { document.getElementById('modal-overlay')?.remove(); }

document.addEventListener('keydown', e => {
  if (e.key !== 'Escape') return;
  closeModal();
  ['trafic-modal-container','proxies-modal-container','user-modal-container','team-modal-container'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.innerHTML = '';
  });
});

let _confirmCb = null;
function confirm_(msg, fn) {
  _confirmCb = fn;
  modal(t('common.confirm'), `<p style="margin:0;font-size:13.5px;opacity:.8;">${esc(msg)}</p>`,
    `<button class="btn btn-secondary" onclick="closeModal()">${t('common.cancel')}</button>
     <button class="btn btn-danger" onclick="closeModal();if(_confirmCb){const f=_confirmCb;_confirmCb=null;f();}">${t('common.delete')}</button>`);
}

function fmtDate(iso) {
  if (!iso) return '—';
  const loc = typeof gpxBCP47 === 'function' ? gpxBCP47() : 'en-US';
  const opts = { dateStyle:'short', timeStyle:'short' };
  if (state.timezone) opts.timeZone = state.timezone;
  try {
    return new Date(iso).toLocaleString(loc, opts);
  } catch {
    return new Date(iso).toLocaleString(loc, { dateStyle:'short', timeStyle:'short' });
  }
}

function typeBadge(type) {
  const m = { http:'tag-blue', https:'tag-green', tcp:'tag-orange', udp:'tag-accent' };
  return `<span class="tag ${m[type]||'tag-neutral'}">${esc(String(type||'?').toUpperCase())}</span>`;
}

// Alias utilisé par le dashboard (identique à infraCoreCard, défini plus bas)
function coreCard(n, idx) { return infraCoreCard(n, idx); }

// Rendu SVG de la topologie dans #topology-container
function renderTopology(nodes, health) {
  const container = document.getElementById('topology-container');
  if (!container) return;

  const cores  = nodes.filter(n => n.role === 'core');
  const agents = nodes.filter(n => n.role === 'agent');
  const adminOk = health?.status === 'ok';
  const adminNode = { node_name: 'Admin', role: 'admin', status: adminOk ? 'online' : 'offline', version: health?.version || '' };

  // Connecteur vertical animé simple
  const vline = (h=14) =>
    `<div style="display:flex;justify-content:center;"><div style="width:2px;height:${h}px;background:var(--accent);opacity:.4;position:relative;overflow:hidden;"><div style="position:absolute;top:0;left:0;right:0;height:8px;background:var(--accent);animation:connFlow 1.2s linear infinite;"></div></div></div>`;

  // H-connecteur : barre horizontale + N décrochements vers le bas
  const hbranch = (n, w, g) => {
    if (n === 0) return '';
    const dropLine = `<div style="width:2px;height:20px;background:var(--accent);opacity:.4;position:relative;overflow:hidden;"><div style="position:absolute;top:0;left:0;right:0;height:8px;background:var(--accent);animation:connFlow 1.2s linear infinite;"></div></div>`;
    const drop = (sw) => `<div style="flex:0 0 ${sw}px;display:flex;justify-content:center;">${dropLine}</div>`;
    if (n === 1) return `<div style="display:flex;justify-content:center;">${drop(w)}</div>`;
    const bar = `<div style="position:absolute;top:0;left:${w/2}px;right:${w/2}px;height:2px;background:var(--accent);opacity:.35;transform:translateY(-50%);"></div>`;
    return `<div style="position:relative;display:flex;gap:${g}px;">${bar}${Array.from({length:n},()=>drop(w)).join('')}</div>`;
  };

  const topoTileInner = (label, sublabel, kicker, ok, declared=false, alertDot=false, version='') =>
    `<div class="card blueprint" style="padding:12px 16px;display:flex;align-items:center;gap:12px;${declared?'opacity:.45;filter:grayscale(.6);':''}">
      <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
      ${alertDot ? '<div class="topo-alert-dot"></div>' : ''}
      <div style="flex:1;min-width:0;">
        <div class="card-kicker" style="font-size:9px;">${esc(kicker)}</div>
        <div style="font-weight:700;font-size:13px;margin-top:1px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${esc(label)}</div>
        <div style="font-size:10px;opacity:.4;font-family:monospace;margin-top:1px;">${esc(sublabel)}</div>
      </div>
      <div style="flex:none;display:flex;flex-direction:column;align-items:flex-end;gap:4px;">
        ${statusBadge(ok, declared)}
        <span style="font-size:10px;opacity:.45;font-family:monospace;">v${esc(version || '—')}</span>
      </div>
    </div>`;

  // Registre des objets nœuds pour éviter JSON dans les attributs onclick
  window._infraNodeMap = window._infraNodeMap || {};
  window._infraNodeMap['admin'] = adminNode;

  const wrapTile = (nodeId, nodeObj, inner, dblclick='') => {
    window._infraNodeMap[nodeId] = nodeObj;
    const sel = window._topoSelection && window._topoSelection.has(nodeId) ? 'selected' : '';
    const dbl = dblclick ? `ondblclick="event.stopPropagation();${dblclick}"` : '';
    return `<div class="topo-tile-wrap ${sel}" data-node-id="${nodeId}" onclick="_topoSelect('${nodeId}')" ${dbl}>${inner}</div>`;
  };

  const CORE_W = 250, AGENT_W = 195, SLOT_GAP = 20, AGENT_GAP = 10;

  // Groupe les agents par Core (target_core = node_name, ou URL contenant le nom)
  const agentsByCore = {};
  const resolveCoreKey = (tc) => {
    if (!tc || tc === '__orphans__') return '__orphans__';
    if (cores.some(c => (c.node_name || c.id) === tc)) return tc;
    // URL http://core-name:8000 → core-name
    const m = String(tc).match(/https?:\/\/([^/:]+)/i);
    if (m) {
      const host = m[1];
      const hit = cores.find(c => (c.node_name || c.id) === host);
      if (hit) return hit.node_name || hit.id;
    }
    return tc;
  };
  for (const a of agents) {
    const tc = resolveCoreKey(a.target_core) || '__orphans__';
    (agentsByCore[tc] = agentsByCore[tc] || []).push(a);
  }

  const mkAgentTile = a => {
    const aId = a.status === 'declared' ? a.id : (a.node_name || a.id);
    const alert = (a.cpu_pct > 80 || a.mem_pct > 80);
    const dbl = a.status === 'declared' ? `openInfraWizard('agent')` : '';
    return wrapTile(aId, a, topoTileInner(a.display_name||a.node_name||'agent', (a.container_runtimes||[]).join(', ')||'—', 'Agent', a.status==='online', a.status==='declared', alert, a.version||''), dbl);
  };

  // Chaque Core = une colonne ; largeur du slot = max(CORE_W, largeur rangée agents)
  const coreCols = cores.map(c => {
    const cName = c.node_name || c.id;
    const myAgents = agentsByCore[cName] || [];
    const n = myAgents.length;
    const agentRowW = n > 0 ? n * AGENT_W + (n-1) * AGENT_GAP : 0;
    const slotW = Math.max(CORE_W, agentRowW);

    const cId = c.status === 'declared' ? c.id : (c.node_name || c.id);
    const alert = (c.cpu_pct > 80 || c.mem_pct > 80);
    const dbl = c.status === 'declared' ? `openInfraWizard('core')` : '';
    const coreTileHTML = `<div style="width:${CORE_W}px;">${wrapTile(cId, c, topoTileInner(c.display_name||c.node_name||'core', c.endpoint||'—', 'Data Plane', c.status==='online', c.status==='declared', alert, c.version||''), dbl)}</div>`;

    const agentsHTML = n > 0 ?
      vline(12) + hbranch(n, AGENT_W, AGENT_GAP) +
      `<div style="display:flex;gap:${AGENT_GAP}px;">` +
      myAgents.map(a => `<div style="width:${AGENT_W}px;">${mkAgentTile(a)}</div>`).join('') +
      `</div>` : '';

    return { slotW, html:
      `<div style="flex:0 0 ${slotW}px;display:flex;flex-direction:column;align-items:center;">${coreTileHTML}${agentsHTML}</div>` };
  });

  // Admin tile
  const adminHTML =
    `<div style="display:flex;justify-content:center;"><div style="width:${CORE_W}px;">` +
    wrapTile('admin', adminNode, topoTileInner('Admin', 'control plane · SQLite', 'Control Plane', adminOk, false, false, adminNode.version||'')) +
    `</div></div>`;

  // H-connecteur Admin → Cores (slots de largeurs potentiellement différentes)
  let adminToCoresHTML = '';
  if (cores.length === 1) {
    adminToCoresHTML = vline(14);
  } else if (cores.length > 1) {
    const dropLine = `<div style="width:2px;height:20px;background:var(--accent);opacity:.4;position:relative;overflow:hidden;"><div style="position:absolute;top:0;left:0;right:0;height:8px;background:var(--accent);animation:connFlow 1.2s linear infinite;"></div></div>`;
    const dropsHTML = coreCols.map(({slotW}) =>
      `<div style="flex:0 0 ${slotW}px;display:flex;justify-content:center;">${dropLine}</div>`
    ).join('');
    const firstHalf = coreCols[0].slotW / 2;
    const lastHalf  = coreCols[coreCols.length-1].slotW / 2;
    const bar = `<div style="position:absolute;top:0;left:${firstHalf}px;right:${lastHalf}px;height:2px;background:var(--accent);opacity:.35;transform:translateY(-50%);"></div>`;
    adminToCoresHTML = vline(14) +
      `<div style="position:relative;display:flex;gap:${SLOT_GAP}px;">${bar}${dropsHTML}</div>`;
  }

  const coresRowHTML = cores.length ?
    adminToCoresHTML +
    `<div style="display:flex;gap:${SLOT_GAP}px;justify-content:center;align-items:flex-start;">` +
    coreCols.map(c => c.html).join('') + `</div>` : '';

  // Agents orphelins : déclarés sans Core cible résolu (même logique URL→nom que le grouping)
  const knownCoreNames = new Set(cores.map(c => c.node_name || c.id));
  const orphanAgents = agents.filter(a => {
    if (a.status !== 'declared') return false;
    const key = resolveCoreKey(a.target_core);
    return !key || key === '__orphans__' || !knownCoreNames.has(key);
  });
  const orphansHTML = orphanAgents.length ? (
    vline(14) +
    `<div style="margin-top:4px;display:flex;flex-direction:column;align-items:center;gap:4px;">` +
    `<div style="font-size:10px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--text2);opacity:.5;margin-bottom:4px;">En attente de connexion</div>` +
    `<div style="display:flex;gap:${AGENT_GAP}px;flex-wrap:wrap;justify-content:center;">` +
    orphanAgents.map(a => `<div style="width:${AGENT_W}px;">${mkAgentTile(a)}</div>`).join('') +
    `</div></div>`
  ) : '';

  container.innerHTML =
    `<div style="display:flex;flex-direction:column;align-items:center;overflow-x:auto;padding:4px 8px 12px;">` +
    adminHTML + coresRowHTML + orphansHTML + `</div>`;
}
function statusBadge(ok, declared) {
  if (declared) return '<span class="tag" style="background:var(--bg3);color:var(--text2);opacity:.7;">○ Non connecté</span>';
  return ok
    ? '<span class="tag tag-green">● Actif</span>'
    : '<span class="tag tag-red">● Inactif</span>';
}

// ── PAGE: Dashboard ────────────────────────────────────────────────────────
