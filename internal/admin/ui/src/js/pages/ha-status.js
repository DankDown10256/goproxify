// ── PAGE: Statut HA (High Availability)

pages['ha-status'] = async function() {
  const content = document.getElementById('content');
  content.innerHTML = `<p style="color:var(--text2)">${t('common.loading')}</p>`;

  let ha = null;
  try {
    const resp = await fetch('/ha/status', { headers: { Authorization: 'Bearer ' + state.token } });
    if (resp.ok) ha = await resp.json();
  } catch (_) {}

  if (!ha) {
    content.innerHTML = `
      <div class="card blueprint" style="padding:40px;text-align:center;color:var(--text2)">
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="margin:0 auto 12px;display:block;opacity:.4"><circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/></svg>
        <p style="margin:0">${t('ha.not_configured')}</p>
      </div>`;
    return;
  }

  const roleTag = ha.is_leader
    ? `<span class="tag tag-green" style="font-size:13px;padding:4px 10px">Leader</span>`
    : `<span class="tag tag-neutral" style="font-size:13px;padding:4px 10px">Follower</span>`;

  const row = (label, value) => `
    <div style="display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px solid var(--border)">
      <span style="font-size:13px;color:var(--text2)">${esc(label)}</span>
      <span style="font-size:13px;font-family:monospace;font-weight:600">${esc(value||'—')}</span>
    </div>`;

  content.innerHTML = `
    <div style="max-width:480px;display:flex;flex-direction:column;gap:16px">
      <div class="card blueprint">
        <div class="card-header">
          <span class="card-title">${t('ha.title')}</span>
          <div style="margin-left:auto">${roleTag}</div>
        </div>
        <div style="padding:4px 16px 16px">
          ${row(t('ha.node_id'), ha.node_id)}
          ${row(t('ha.leader_id'), ha.leader_id || t('ha.unknown'))}
          ${row(t('ha.role'), ha.is_leader ? t('ha.role_leader') : t('ha.role_follower'))}
        </div>
      </div>
      <div style="text-align:right">
        <button class="btn btn-ghost btn-sm" onclick="navigate('ha-status')">${t('common.refresh')}</button>
      </div>
    </div>`;
};
