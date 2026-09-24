// ── PAGE: Politiques d'accès
// Vue matricielle croisée : domaines × sujets (utilisateurs, équipes, tokens Core).
// Chaque cellule indique le mode d'accès (read / write) ou "—".
// La colonne Cores montre quel(s) token(s) reçoit ce domaine et si une délégation existe.

pages['access-policies'] = async function () {
  const content = document.getElementById('content');
  const ta = document.getElementById('topbar-actions');
  if (ta) ta.innerHTML = '';
  await renderAccessPolicies(content);
};

// Extrait pour être réutilisé comme section dans "Gestion d'équipe" (workspaces.js).
async function renderAccessPolicies(content) {
  content.innerHTML = `<p style="color:var(--text2)">${t('access.loading')}</p>`;

  try {
    // ── Chargement parallèle ────────────────────────────────────────────────
    const [domains, usersRaw, teams, tokens] = await Promise.all([
      api('GET', '/domains').catch(() => []),
      api('GET', '/users').catch(() => []),
      api('GET', '/teams').catch(() => []),
      api('GET', '/tokens?role=core').catch(() => []),
    ]);

    // Détails scopes par utilisateur (parallel)
    const userDetails = await Promise.all(
      (usersRaw || []).map(u =>
        api('GET', `/users/${encodeURIComponent(u.id)}`).catch(() => u)
      )
    );

    // Scopes par équipe (parallel)
    const teamScopes = {};
    await Promise.all(
      (teams || []).map(async tm => {
        try {
          const sc = await api('GET', `/teams/${encodeURIComponent(tm.id)}/scopes`) || [];
          teamScopes[tm.id] = sc;
        } catch (_) { teamScopes[tm.id] = []; }
      })
    );

    // Scopes par token Core (parallel) — uniquement tokens actifs non révoqués
    const now = Date.now();
    const activeCoreTokens = (tokens || []).filter(tok =>
      !tok.revoked && (!tok.expires_at || new Date(tok.expires_at).getTime() > now)
    );
    const tokenScopes = {};
    await Promise.all(
      activeCoreTokens.map(async tok => {
        try {
          const sc = await api('GET', `/tokens/${encodeURIComponent(tok.id)}/scopes`) || [];
          tokenScopes[tok.id] = sc;
        } catch (_) { tokenScopes[tok.id] = []; }
      })
    );

    // ── Filtrage : seuls les users admin ou avec des grants sont intéressants ──
    const relevantUsers = (userDetails || []).filter(u =>
      u.role === 'admin' || u.role === 'superadmin' || (u.scopes && u.scopes.length > 0)
    );
    const relevantTeams = (teams || []).filter(tm =>
      (teamScopes[tm.id] || []).length > 0
    );

    if (!(domains || []).length) {
      content.innerHTML = `
        <h1 style="margin:0 0 4px;font-size:28px;font-family:var(--font-heading);font-weight:600;">${t('access.title')}</h1>
        <p style="opacity:.65;font-size:14px;margin:0 0 20px">${t('access.subtitle')}</p>
        <div class="empty"><p>${t('access.empty')}</p></div>`;
      return;
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    function domainMatch(scopeVal, domain) {
      const s = String(scopeVal || '').toLowerCase().trim();
      const d = String(domain || '').toLowerCase().trim();
      if (!s || !d) return false;
      if (s === d || s === '*') return true;
      if (s.startsWith('*.')) {
        const suffix = s.slice(1); // ".example.com"
        if (d.endsWith(suffix) && d.length > suffix.length) return true;
        if (d === s.slice(2)) return true; // *.example.com covers example.com
      }
      return false;
    }

    // Mode effectif (write > read) pour un sujet sur un domaine
    function effectiveMode(scopes, domain) {
      let best = null;
      for (const sc of (scopes || [])) {
        const type = sc.scope_type || sc.type;
        const val  = sc.scope_value || sc.value;
        const mode = sc.access_mode || sc.mode || 'read';
        if (type === 'core') { best = 'write'; break; }
        if (type === 'domain' && domainMatch(val, domain)) {
          if (mode === 'write') { best = 'write'; break; }
          if (!best) best = 'read';
        }
        if (type === 'proxy') {
          // proxy scope gives read at minimum (domain-level check not possible client-side)
          if (!best) best = 'read';
        }
      }
      return best;
    }

    function modeTag(mode) {
      if (!mode) return `<span style="color:var(--text3);font-size:11px">${t('access.no_grant')}</span>`;
      const [cls, label] = mode === 'write'
        ? ['tag-accent', t('access.mode.write')]
        : ['tag-neutral', t('access.mode.read')];
      return `<span class="tag ${cls}" style="font-size:10px">${esc(label)}</span>`;
    }

    function tokenLabel(tok) {
      return tok.node_name || tok.id?.slice(0, 8) || '?';
    }

    function coreName(id) {
      const tok = activeCoreTokens.find(t => t.id === id || t.node_name === id);
      return tok ? tokenLabel(tok) : (id ? id.slice(0, 10) : '—');
    }

    // Token(s) couvrant ce domaine
    function tokensForDomain(domain, entryId, delegId) {
      const relevant = [];
      for (const tok of activeCoreTokens) {
        const scopes = tokenScopes[tok.id] || [];
        const isEntry = tok.id === entryId || tok.node_name === entryId;
        const isDeleg = tok.id === delegId || tok.node_name === delegId;
        const rbac = (tok.rbac_role || 'admin').toLowerCase();
        const noScope = scopes.length === 0;
        const covers = (rbac === 'admin' || rbac === 'superadmin') && noScope
          ? true // admin token sans scope = accès global
          : scopes.some(sc => {
              if (sc.scope_type === 'core') return true;
              return sc.scope_type === 'domain' && domainMatch(sc.scope_value, domain);
            });
        if (covers || isEntry || isDeleg) {
          relevant.push({ tok, isEntry, isDeleg });
        }
      }
      return relevant;
    }

    // ── Rendu ────────────────────────────────────────────────────────────────

    const certTag = d => {
      const exp = d.cert_expires_at ? new Date(d.cert_expires_at) : null;
      const days = exp ? Math.round((exp - Date.now()) / 86400000) : null;
      if (days == null) return '';
      if (days < 0)  return `<span class="tag tag-red" style="font-size:10px">${t('domains.cert_expired')}</span>`;
      if (days < 30) return `<span class="tag tag-yellow" style="font-size:10px">${t('domains.cert_days_warn', {n:days})}</span>`;
      return `<span class="tag tag-green" style="font-size:10px">${t('domains.cert_valid', {n:days})}</span>`;
    };

    const thUser = `text-align:center;font-size:11px;font-weight:500;max-width:100px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;padding-bottom:6px`;

    const userColsHtml = relevantUsers.map(u => {
      const label = u.email?.split('@')[0] || u.email || u.id;
      const isGlobalAdmin = (u.role === 'admin' || u.role === 'superadmin') && !(u.scopes?.length > 0);
      return `<th title="${esc(u.email)}" style="${thUser}">
        ${esc(label)}${isGlobalAdmin ? '<br><span class="tag tag-accent" style="font-size:9px;vertical-align:top">admin</span>' : ''}
      </th>`;
    }).join('');

    const teamColsHtml = relevantTeams.map(tm =>
      `<th style="${thUser}">${esc(tm.name)}</th>`
    ).join('');

    const rows = (domains || []).map(d => {
      const domain = d.domain;
      const entryId = d.core_id;
      const delegId = d.delegated_to_core_id;

      // Colonne Core d'entrée + délégation
      const entryTag = entryId
        ? `<span class="tag tag-neutral" style="font-size:10px">${esc(coreName(entryId))}</span>`
        : `<span style="color:var(--text3)">—</span>`;
      const delegTag = delegId
        ? `<span class="tag tag-accent" style="font-size:10px" title="${esc(d.delegated_endpoint||'')}">→ ${esc(coreName(delegId))}</span>`
        : '';

      // Cellules utilisateurs
      const userCells = relevantUsers.map(u => {
        const isGlobalAdmin = (u.role === 'admin' || u.role === 'superadmin') && !(u.scopes?.length > 0);
        if (isGlobalAdmin) return `<td style="text-align:center">${modeTag('write')}</td>`;
        const mode = effectiveMode(u.scopes, domain);
        return `<td style="text-align:center">${modeTag(mode)}</td>`;
      }).join('');

      // Cellules équipes
      const teamCells = relevantTeams.map(tm => {
        const scopes = teamScopes[tm.id] || [];
        const mode = effectiveMode(scopes, domain);
        return `<td style="text-align:center">${modeTag(mode)}</td>`;
      }).join('');

      // Cellule Cores : liste des tokens qui reçoivent ce domaine
      const coreEntries = tokensForDomain(domain, entryId, delegId);
      const coreCellHtml = coreEntries.length === 0
        ? `<td><span style="color:var(--text3);font-size:11px">—</span></td>`
        : `<td><div style="display:flex;flex-wrap:wrap;gap:3px;align-items:center">
            ${coreEntries.map(({ tok, isEntry, isDeleg }) => {
              const label = tokenLabel(tok);
              const mark  = isEntry ? ' ●' : (isDeleg ? ' ⇢' : '');
              return `<span class="tag tag-neutral" style="font-size:10px" title="${esc(tok.node_name||tok.id)}">${esc(label)}${mark}</span>`;
            }).join('')}
          </div></td>`;

      return `<tr>
        <td>
          <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap">
            <b style="font-size:13px">${esc(domain)}</b>
            ${certTag(d)}
          </div>
          ${delegId ? `<div style="margin-top:3px">${entryTag} ${delegTag}</div>` : `<div style="margin-top:3px">${entryTag}</div>`}
        </td>
        ${userCells}
        ${teamCells}
        ${coreCellHtml}
      </tr>`;
    }).join('');

    const noUsers = relevantUsers.length === 0;
    const noTeams = relevantTeams.length === 0;

    content.innerHTML = `
      <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:16px;flex-wrap:wrap;margin-bottom:20px">
        <div>
          <h1 style="margin:0 0 4px;font-size:28px;font-family:var(--font-heading);font-weight:600;">${t('access.title')}</h1>
          <p style="margin:0;opacity:.65;font-size:14px;">${t('access.subtitle')}</p>
        </div>
        <div style="display:flex;gap:8px">
          <button class="btn btn-ghost btn-sm" onclick="navigate('users')">${t('access.col.users')}</button>
          <button class="btn btn-ghost btn-sm" onclick="navigate('tokens')">${t('access.col.cores')}</button>
        </div>
      </div>

      <div class="card blueprint" style="overflow:hidden">
        <div class="table-wrap" style="overflow-x:auto">
          <table class="table" style="min-width:600px">
            <thead>
              <tr>
                <th style="min-width:180px" rowspan="2">${t('access.col.domain')}</th>
                ${noUsers ? '' : `<th colspan="${relevantUsers.length}" style="text-align:center;border-left:1px solid var(--border);font-size:10px;text-transform:uppercase;letter-spacing:.06em;opacity:.6">${t('access.col.users')}</th>`}
                ${noTeams ? '' : `<th colspan="${relevantTeams.length}" style="text-align:center;border-left:1px solid var(--border);font-size:10px;text-transform:uppercase;letter-spacing:.06em;opacity:.6">${t('access.col.teams')}</th>`}
                <th rowspan="2" style="text-align:center;border-left:1px solid var(--border)">${t('access.col.cores')}</th>
              </tr>
              <tr style="border-bottom:2px solid var(--border)">
                ${noUsers ? '' : userColsHtml}
                ${noTeams ? '' : teamColsHtml}
              </tr>
            </thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
      </div>

      <div style="margin-top:12px;font-size:11px;color:var(--text3);display:flex;gap:16px;flex-wrap:wrap">
        <span>● = Core d'entrée</span>
        <span>⇢ = Core délégué</span>
        <span style="opacity:.7">${t('access.global_admin')} : droits complets sans grants explicites</span>
      </div>`;

  } catch (e) {
    content.innerHTML = `<p style="color:var(--red)">${esc(e.message)}</p>`;
  }
}

// La page "access" (clic sur le groupe nav lui-même) redirige vers Politiques
// d'accès — vue globale croisée domaines × sujets, landing la plus utile pour
// le groupe "Accès".
pages.access = async function () {
  navigate('access-policies');
};
