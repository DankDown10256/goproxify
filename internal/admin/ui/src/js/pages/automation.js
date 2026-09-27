// ── PAGE: Automatisation — vue d'ensemble et journal
// Onglets « Automatisations » : security-rules, automation-flow (automation-flow.js), rules-store.
// Onglets « Alertes » : alert-channels, alerts.

function _auHistState(h) {
  if (h.error) return 'err';
  if (h.action_taken) return 'ok';
  if (h.cond_result) return 'warn';
  return 'idle';
}

window._auGo = function(page, opts) {
  Object.assign(window, opts || {});
  navigate(page);
};

pages.automation = async function() {
  const content = document.getElementById('content');
  document.getElementById('topbar-actions').innerHTML =
    `<button class="btn btn-primary btn-sm" onclick="_auGo('automation-flow',{_flowSel:'new'})">${t('automation.new_rule')}</button>`;
  content.innerHTML = `<p style="color:var(--text2)">${t('common.loading')}</p>`;

  const [rules, channels, templates, history] = await Promise.all([
    api('GET', '/rules-engine/rules').catch(() => []),
    api('GET', '/alert-channels').catch(() => []),
    api('GET', '/rules-engine/templates').catch(() => []),
    api('GET', '/rules-engine/history').catch(() => []),
  ]);
  const R = rules || [], C = channels || [], H = history || [];
  const activeRules = R.filter(r => r.enabled).length;
  const activeChannels = C.filter(c => c.enabled !== false).length;

  const now = Date.now();
  const last24 = H.filter(h => now - new Date(h.fired_at).getTime() < 864e5);
  const buckets = Array.from({ length: 24 }, () => ({ n: 0, err: 0 }));
  last24.forEach(h => {
    const idx = 23 - Math.floor((now - new Date(h.fired_at).getTime()) / 36e5);
    if (idx < 0 || idx > 23) return;
    if (h.action_taken) buckets[idx].n++;
    if (h.error) buckets[idx].err++;
  });
  const max = Math.max(1, ...buckets.map(b => b.n + b.err));
  const executed = last24.filter(h => h.action_taken).length;
  const failed = last24.filter(h => h.error).length;

  const tile = (page, label, value, sub, color) => `
    <div class="sec-tile" style="cursor:pointer" onclick="navigate('${page}')">
      <div class="sec-tile-label">${label}</div>
      <div class="sec-tile-value" style="color:${color}">${value}</div>
      <div class="sec-tile-sub">${sub}</div>
    </div>`;

  content.innerHTML = `
    <p style="margin:0 0 16px;font-size:13px;color:var(--text2)">${t('automation.subtitle')}</p>
    ${failed ? `<div class="au-banner"><span>⚠</span><div style="flex:1"><b>${t('automation.failed_banner', { n: failed })}</b></div>
      <button class="btn btn-ghost btn-sm" onclick="_auGo('automation-history',{_auJournalFilter:'err'})">${t('automation.see_failures')}</button></div>` : ''}
    <div class="sec-tiles" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:12px">
      ${tile('security-rules', t('automation.tile_rules'), activeRules, `${R.length} ${t('common.total')}`, activeRules ? 'var(--accent)' : 'var(--text3)')}
      ${tile('automation-history', t('automation.tile_runs'), executed, t('automation.tile_runs_sub', { n: failed }), failed ? 'var(--yellow)' : 'var(--green)')}
      ${tile('alert-channels', t('automation.tile_channels'), activeChannels, `${C.length} ${t('common.total')}`, activeChannels ? 'var(--green)' : 'var(--text3)')}
      ${tile('rules-store', t('automation.tile_store'), (templates || []).length, t('automation.tile_store_sub'), 'var(--accent)')}
    </div>
    <div class="au-grid">
      <div class="card" style="padding:16px 18px">
        <div style="font-weight:600;font-size:13px">${t('automation.activity_24h')}</div>
        <div class="au-bars" style="margin-top:14px">${buckets.map((b, i) =>
          `<i class="${b.err ? 'err' : ''}" style="height:${Math.max(3, Math.round((b.n + b.err) / max * 72))}px" title="${b.n} ${t('automation.tile_runs').toLowerCase()}${b.err ? `, ${b.err} ⚠` : ''} — −${23 - i} h"></i>`).join('')}</div>
        <div style="display:flex;justify-content:space-between;font-size:11px;color:var(--text3);margin-top:4px"><span>−24 h</span><span>${t('automation.now')}</span></div>
      </div>
      <div class="card" style="padding:16px 18px">
        <div style="font-weight:600;font-size:13px;margin-bottom:6px">${t('automation.recent')}</div>
        ${H.slice(0, 6).map(h => `<div class="au-feed-row"><span class="au-dot ${_auHistState(h)}"></span>
          <div style="min-width:0"><div>${esc(h.rule_name || h.rule_id)}</div>
          <div style="font-size:11.5px;color:var(--text3)">${fmtDate(h.fired_at)}${h.detail ? ' · ' + esc(h.detail).slice(0, 90) : ''}</div></div></div>`).join('')
          || `<p style="font-size:12.5px;color:var(--text3)">${t('security.rules.no_history')}</p>`}
      </div>
    </div>
    <div class="card" style="padding:16px 18px;margin-top:12px">
      <div style="font-weight:600;font-size:13px">${t('automation.shortcuts')}</div>
      <div class="au-chips">
        <button class="btn btn-ghost btn-sm" onclick="_auGo('automation-flow',{_flowSel:'new'})">${t('automation.new_rule')}</button>
        <button class="btn btn-ghost btn-sm" onclick="navigate('automation-flow')">${t('automation.open_flow')}</button>
        <button class="btn btn-ghost btn-sm" onclick="navigate('rules-store')">${t('automation.install_template')}</button>
        <button class="btn btn-ghost btn-sm" onclick="navigate('alert-channels')">${t('automation.test_channels')}</button>
        <button class="btn btn-ghost btn-sm" onclick="navigate('alerts')">${t('automation.edit_routing')}</button>
      </div>
    </div>`;
};

pages['automation-history'] = async function() {
  const content = document.getElementById('content');
  document.getElementById('topbar-actions').innerHTML = '';
  content.innerHTML = `<p style="color:var(--text2)">${t('common.loading')}</p>`;
  try { window._auHistory = await api('GET', '/rules-engine/history') || []; }
  catch (e) { toast(e.message, 'error'); window._auHistory = []; }
  window._auJournalFilter = window._auJournalFilter || 'all';
  _auRenderJournal();
};

window._auSetFilter = function(f) {
  window._auJournalFilter = f;
  _auRenderJournal();
};

function _auRenderJournal() {
  const f = window._auJournalFilter;
  const rows = (window._auHistory || []).filter(h => f === 'all' || _auHistState(h) === f);
  const filters = [['all', t('automation.f_all')], ['ok', t('automation.f_ok')], ['err', t('automation.f_err')], ['warn', t('automation.f_warn')], ['idle', t('automation.f_idle')]];
  const label = { ok: 'automation.s_ok', err: 'automation.s_err', warn: 'automation.s_warn', idle: 'automation.s_idle' };
  const tag = { ok: 'tag-green', err: 'tag-red', warn: 'tag-yellow', idle: 'tag-neutral' };
  document.getElementById('content').innerHTML = `
    <p style="margin:0 0 14px;font-size:13px;color:var(--text2)">${t('automation.journal_hint')}</p>
    <div style="display:flex;gap:6px;margin-bottom:14px;flex-wrap:wrap">${filters.map(([v, l]) =>
      `<button class="btn btn-sm${f === v ? ' btn-primary' : ' btn-ghost'}" onclick="_auSetFilter('${v}')">${l}</button>`).join('')}</div>
    ${rows.length ? `<div class="table-wrap"><table><thead><tr>
      <th>${t('common.date')}</th><th>${t('security.rules.rule')}</th><th>${t('automation.col_result')}</th><th>${t('security.rules.col_detail')}</th>
    </tr></thead><tbody>${rows.map(h => { const s = _auHistState(h); return `<tr>
      <td style="font-size:11px;white-space:nowrap">${fmtDate(h.fired_at)}</td>
      <td style="font-size:12px">${esc(h.rule_name || h.rule_id)}</td>
      <td><span class="tag ${tag[s]}" style="font-size:10px">${t(label[s])}</span></td>
      <td style="font-size:11px;color:var(--text2)">${esc(h.error || h.detail || '')}</td></tr>`; }).join('')}</tbody></table></div>`
      : `<div class="empty"><p>${t('security.rules.no_history')}</p></div>`}`;
}
