// ── PAGE: Accès MCP — périmètre d'accès du serveur MCP
// 1) IP sources autorisées à appeler /mcp (allowlist, appliquée serveur).
// 2) Utilisateurs porteurs d'un token PAT actif (visibilité admin globale).
// 3) Catalogue de scopes ↔ outils MCP, pour référence.
// La création/édition des scopes d'un PAT reste self-service sur
// "Mes tokens API" (un PAT est personnel à son porteur).

pages['mcp-access'] = async function() {
  const content = document.getElementById('content');
  document.getElementById('topbar-actions').innerHTML =
    `<button class="btn btn-ghost" onclick="navigate('api-tokens')">${t('mcp_access.manage_my_tokens') || 'Gérer mes tokens'}</button>`;
  content.innerHTML = `<p style="color:var(--text2)">${t('common.loading')}</p>`;

  let scopes = [], tokens = [], allowedIPs = [];
  try {
    const [scopesRes, tokensRes, ipsRes] = await Promise.all([
      api('GET', '/mcp-access/scopes').catch(() => []),
      api('GET', '/mcp-access/tokens').catch(() => []),
      api('GET', '/mcp-access/allowed-ips').catch(() => ({ ips: [] })),
    ]);
    scopes = scopesRes || [];
    tokens = tokensRes || [];
    allowedIPs = ipsRes?.ips || [];
  } catch {}

  content.innerHTML = `
    <div class="page-header">
      <h1 style="margin:0 0 4px;font-size:28px;font-family:var(--font-heading);font-weight:600;">${t('mcp_access.title') || 'Accès MCP'}</h1>
      <p style="margin:0;opacity:0.65;font-size:14px;">${t('mcp_access.subtitle') || 'Périmètre d\'accès du serveur MCP : IP sources autorisées, utilisateurs porteurs d\'un token, et scopes exposés.'}</p>
    </div>

    <div class="card" style="padding:16px 20px;margin:16px 0">
      <h6 style="margin:0 0 6px;font-size:11px;text-transform:uppercase;letter-spacing:0.09em;opacity:0.5;">${t('mcp_access.ips_title') || 'IP sources autorisées'}</h6>
      <p style="margin:0 0 12px;font-size:12px;color:var(--text2)">${t('mcp_access.ips_hint') || 'Une IP ou un CIDR par ligne (ex. 203.0.113.4 ou 10.0.0.0/24). Liste vide = aucune restriction (tout PAT valide peut appeler /mcp, quelle que soit son origine).'}</p>
      <textarea id="mcp-ips-textarea" class="input" rows="6" style="width:100%;font-family:monospace;font-size:12px;resize:vertical"
        placeholder="203.0.113.4&#10;10.0.0.0/24">${esc((allowedIPs||[]).join('\n'))}</textarea>
      <div style="margin-top:10px;display:flex;align-items:center;gap:10px">
        <button class="btn btn-primary btn-sm" onclick="saveMcpAllowedIPs()">${t('mcp_access.ips_save') || 'Enregistrer'}</button>
        <span style="font-size:12px;color:${allowedIPs.length ? 'var(--green)' : 'var(--text2)'}">
          ${allowedIPs.length
            ? (t('mcp_access.ips_active', { n: allowedIPs.length }) || `${allowedIPs.length} entrée(s) actives — accès restreint`)
            : (t('mcp_access.ips_open') || 'Aucune restriction active')}
        </span>
      </div>
    </div>

    <div class="card" style="padding:16px 20px;margin:16px 0">
      <h6 style="margin:0 0 10px;font-size:11px;text-transform:uppercase;letter-spacing:0.09em;opacity:0.5;">${t('mcp_access.tokens_title') || 'Utilisateurs avec un token MCP actif'}</h6>
      <table class="tbl">
        <thead><tr>
          <th>${t('mcp_access.col_owner') || 'Porteur'}</th>
          <th>${t('mcp_access.col_label') || 'Label'}</th>
          <th>${t('mcp_access.col_scopes') || 'Scopes'}</th>
          <th>${t('mcp_access.col_expires') || 'Expire'}</th>
          <th>${t('mcp_access.col_last_used') || 'Dernier usage'}</th>
        </tr></thead>
        <tbody>
          ${(tokens||[]).map(tok => `
            <tr>
              <td style="font-size:13px;font-weight:500">${esc(tok.owner_email)}</td>
              <td style="font-size:13px;color:var(--text2)">${esc(tok.label)}</td>
              <td>${(tok.scopes||[]).length
                ? tok.scopes.map(s => `<span class="tag tag-neutral" style="font-size:10px;margin:2px">${esc(s)}</span>`).join('')
                : `<span style="opacity:0.4;font-size:12px">—</span>`}</td>
              <td style="font-size:12px">${tok.expires_at ? fmtDate(tok.expires_at) : (t('tokens.never') || 'Jamais')}</td>
              <td style="font-size:12px">${tok.last_used_at ? fmtDate(tok.last_used_at) : '—'}</td>
            </tr>`).join('') || `<tr><td colspan="5" style="opacity:0.5">${t('mcp_access.tokens_empty') || 'Aucun token actif — aucun utilisateur ne peut accéder au MCP.'}</td></tr>`}
        </tbody>
      </table>
    </div>

    <div class="card" style="padding:16px 20px">
      <h6 style="margin:0 0 10px;font-size:11px;text-transform:uppercase;letter-spacing:0.09em;opacity:0.5;">${t('mcp_access.scopes_title') || 'Catalogue de scopes (référence)'}</h6>
      <table class="tbl">
        <thead><tr>
          <th>${t('mcp_access.col_scope') || 'Scope'}</th>
          <th>${t('mcp_access.col_desc') || 'Description'}</th>
          <th>${t('mcp_access.col_tools') || 'Outils MCP couverts'}</th>
        </tr></thead>
        <tbody>
          ${(scopes||[]).map(s => `
            <tr>
              <td><code style="font-size:12px">${esc(s.id)}</code></td>
              <td style="font-size:13px;color:var(--text2)">${esc(s.description)}</td>
              <td>${(s.tools||[]).length
                ? s.tools.map(tool => `<span class="tag tag-neutral" style="font-size:10px;margin:2px">${esc(tool)}</span>`).join('')
                : `<span style="opacity:0.4;font-size:12px">—</span>`}</td>
            </tr>`).join('') || `<tr><td colspan="3" style="opacity:0.5">${t('common.empty') || 'Aucun scope.'}</td></tr>`}
        </tbody>
      </table>
    </div>
  `;
};

window.saveMcpAllowedIPs = async function() {
  const raw = document.getElementById('mcp-ips-textarea')?.value || '';
  const ips = raw.split('\n').map(s => s.trim()).filter(Boolean);
  try {
    await api('PUT', '/mcp-access/allowed-ips', { ips });
    toast(t('mcp_access.ips_saved') || 'Liste enregistrée', 'success');
    navigate('mcp-access');
  } catch (e) {
    toast(e?.message || (t('mcp_access.ips_save_err') || 'IP ou CIDR invalide'), 'error');
  }
};
