// ── PAGE: Accès MCP — périmètre d'accès du serveur MCP
// Vue admin (lecture seule) du catalogue de scopes ↔ outils MCP, et des PAT
// actifs sur l'instance. La création/édition des scopes d'un PAT reste
// self-service sur "Mes tokens API" (un PAT est personnel à son porteur) ;
// cette page donne à l'admin la visibilité globale sur le périmètre exposé.

pages['mcp-access'] = async function() {
  const content = document.getElementById('content');
  document.getElementById('topbar-actions').innerHTML =
    `<button class="btn btn-ghost" onclick="navigate('api-tokens')">${t('mcp_access.manage_my_tokens') || 'Gérer mes tokens'}</button>`;
  content.innerHTML = `<p style="color:var(--text2)">${t('common.loading')}</p>`;

  let scopes = [], tokens = [];
  try {
    [scopes, tokens] = await Promise.all([
      api('GET', '/mcp-access/scopes').catch(() => []),
      api('GET', '/mcp-access/tokens').catch(() => []),
    ]);
  } catch {}

  content.innerHTML = `
    <div class="page-header">
      <h1 style="margin:0 0 4px;font-size:28px;font-family:var(--font-heading);font-weight:600;">${t('mcp_access.title') || 'Accès MCP'}</h1>
      <p style="margin:0;opacity:0.65;font-size:14px;">${t('mcp_access.subtitle') || 'Périmètre d\'accès exposé par le serveur MCP : scopes disponibles, outils couverts, et tokens actifs sur l\'instance.'}</p>
    </div>

    <div class="card" style="padding:16px 20px;margin:16px 0">
      <h6 style="margin:0 0 10px;font-size:11px;text-transform:uppercase;letter-spacing:0.09em;opacity:0.5;">${t('mcp_access.scopes_title') || 'Catalogue de scopes'}</h6>
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

    <div class="card" style="padding:16px 20px">
      <h6 style="margin:0 0 10px;font-size:11px;text-transform:uppercase;letter-spacing:0.09em;opacity:0.5;">${t('mcp_access.tokens_title') || 'Tokens actifs sur l\'instance'}</h6>
      <table class="tbl">
        <thead><tr>
          <th>${t('mcp_access.col_label') || 'Label'}</th>
          <th>${t('mcp_access.col_owner') || 'Porteur'}</th>
          <th>${t('mcp_access.col_scopes') || 'Scopes'}</th>
          <th>${t('mcp_access.col_expires') || 'Expire'}</th>
          <th>${t('mcp_access.col_last_used') || 'Dernier usage'}</th>
        </tr></thead>
        <tbody>
          ${(tokens||[]).map(tok => `
            <tr>
              <td style="font-size:13px">${esc(tok.label)}</td>
              <td style="font-size:13px;color:var(--text2)">${esc(tok.owner_email)}</td>
              <td>${(tok.scopes||[]).length
                ? tok.scopes.map(s => `<span class="tag tag-neutral" style="font-size:10px;margin:2px">${esc(s)}</span>`).join('')
                : `<span style="opacity:0.4;font-size:12px">—</span>`}</td>
              <td style="font-size:12px">${tok.expires_at ? fmtDate(tok.expires_at) : (t('tokens.never') || 'Jamais')}</td>
              <td style="font-size:12px">${tok.last_used_at ? fmtDate(tok.last_used_at) : '—'}</td>
            </tr>`).join('') || `<tr><td colspan="5" style="opacity:0.5">${t('mcp_access.tokens_empty') || 'Aucun token actif.'}</td></tr>`}
        </tbody>
      </table>
    </div>
  `;
};
