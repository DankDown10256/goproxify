// ── PAGE: Planifications (cron) ──────────────────────────────────────────────
// Déclenche une action du moteur de règles (mêmes types qu'une règle : notify,
// ban_ip, disable_proxy, enable_strict, webhook_call, run_backup) à heure fixe,
// indépendamment de toute condition. Réutilise les champs d'action de
// security.js (_ACTION_TYPES, _reActFieldsHTML, _reUpdateActFields).

const SCHED_PRESETS = [
  ['', 'automation.sched_custom'],
  ['0 3 * * *', 'automation.sched_daily_3am'],
  ['0 * * * *', 'automation.sched_hourly'],
  ['*/15 * * * *', 'automation.sched_every_15min'],
  ['0 8 * * 1', 'automation.sched_monday_8am'],
  ['0 0 1 * *', 'automation.sched_monthly'],
];

function _schedCollectAction() {
  const type = document.getElementById('re-act-type')?.value;
  const action = { type };
  if (type === 'disable_proxy') {
    action.proxy_id = document.getElementById('re-act-proxy-id')?.value || '';
  } else if (type === 'ban_ip') {
    action.ban_duration = document.getElementById('re-act-ban-dur')?.value || '';
    action.ban_reason = document.getElementById('re-act-ban-reason')?.value || '';
  } else if (type === 'notify') {
    action.notify_severity = document.getElementById('re-act-sev')?.value || 'warning';
    action.notify_message = document.getElementById('re-act-msg')?.value || '';
  } else if (type === 'enable_strict') {
    action.strict_duration = document.getElementById('re-act-strict-dur')?.value || '30m';
  } else if (type === 'webhook_call') {
    action.webhook_url = document.getElementById('re-act-webhook-url')?.value || '';
  } else if (type === 'run_backup') {
    action.backup_retention = parseInt(document.getElementById('re-act-backup-retention')?.value || '0', 10);
  }
  return action;
}

function _schedActionSummary(action) {
  const label = (typeof _ACTION_TYPES !== 'undefined' ? _ACTION_TYPES : []).find(a => a.value === action?.type)?.label || action?.type || '—';
  return esc(label);
}

pages['automation-schedules'] = async function() {
  const content = document.getElementById('content');
  document.getElementById('topbar-actions').innerHTML =
    `<button class="btn btn-primary btn-sm" onclick="_schedOpenModal()">${t('automation.sched_new')}</button>`;
  content.innerHTML = `<p style="color:var(--text2)">${t('common.loading')}</p>`;
  try { window._schedTasks = await api('GET', '/scheduled-tasks') || []; }
  catch (e) { toast(e.message, 'error'); window._schedTasks = []; }
  _schedRender();
};

function _schedRender() {
  const tasks = window._schedTasks || [];
  document.getElementById('content').innerHTML = `
    <p style="margin:0 0 14px;font-size:13px;color:var(--text2)">${t('automation.sched_hint')}</p>
    ${tasks.length ? `<div style="display:flex;flex-direction:column;gap:10px">${tasks.map((tk, i) => `
      <div class="card blueprint" style="padding:14px 16px;display:flex;align-items:center;gap:12px;flex-wrap:wrap">
        <div style="flex:1;min-width:200px">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
            <span style="font-weight:600;font-size:13.5px">${esc(tk.name)}</span>
            <span class="tag ${tk.enabled ? 'tag-green' : 'tag-neutral'}" style="font-size:10px">${tk.enabled ? t('security.rules.enabled') : t('security.rules.disabled')}</span>
          </div>
          <div style="font-size:11.5px;color:var(--text2);margin-top:4px"><code>${esc(tk.cron_expr)}</code> → ${_schedActionSummary(tk.action)}</div>
          <div style="font-size:11px;color:var(--text3);margin-top:2px">${tk.last_run_at ? t('automation.sched_last_run', { when: fmtDate(tk.last_run_at) }) : t('automation.sched_never_run')}</div>
        </div>
        <button class="btn btn-ghost btn-sm" onclick="_schedRunNow('${esc(tk.id)}',this)">▶ ${t('automation.sched_run_now')}</button>
        <button class="btn btn-ghost btn-sm" onclick="_schedHistory('${esc(tk.id)}','${esc(tk.name)}')">${t('automation.sched_history')}</button>
        <button class="btn btn-ghost btn-sm" onclick="_schedOpenModal('${esc(tk.id)}')">${t('common.edit')}</button>
        <button class="btn btn-ghost btn-sm" style="color:var(--red)" onclick="_schedDelete('${esc(tk.id)}','${esc(tk.name)}')">${t('common.delete')}</button>
      </div>`).join('')}</div>`
      : `<div class="empty"><p>${t('automation.sched_none')}</p></div>`}`;
}

window._schedOpenModal = function(id) {
  const existing = id ? (window._schedTasks || []).find(x => x.id === id) : null;
  const action = existing?.action || { type: 'notify' };
  const actOptions = (typeof _ACTION_TYPES !== 'undefined' ? _ACTION_TYPES : [])
    .map(a => `<option value="${a.value}"${action.type === a.value ? ' selected' : ''}>${a.label}</option>`).join('');
  const body = `
    <div style="display:flex;flex-direction:column;gap:12px">
      <div class="field" style="margin:0">
        <label class="field-label">${t('common.name')}</label>
        <input id="sched-name" class="input" value="${esc(existing?.name || '')}" placeholder="${t('automation.sched_name_ph')}">
      </div>
      <div class="field" style="margin:0">
        <label class="field-label">${t('automation.sched_preset')}</label>
        <select id="sched-preset" class="input" style="height:32px" onchange="document.getElementById('sched-cron').value=this.value">
          ${SCHED_PRESETS.map(([expr, key]) => `<option value="${esc(expr)}"${existing?.cron_expr === expr ? ' selected' : ''}>${t(key)}</option>`).join('')}
        </select>
      </div>
      <div class="field" style="margin:0">
        <label class="field-label">${t('automation.sched_cron')} <span style="font-weight:400;color:var(--text3)">${t('automation.sched_cron_hint')}</span></label>
        <input id="sched-cron" class="input" style="font-family:monospace" value="${esc(existing?.cron_expr || '')}" placeholder="0 3 * * *">
      </div>
      <div class="field" style="margin:0">
        <label class="field-label">${t('security.rules.action')}</label>
        <select id="re-act-type" class="input" style="height:32px" onchange="_reUpdateActFields(this.value)">${actOptions}</select>
      </div>
      <div id="re-act-fields" style="display:grid;grid-template-columns:1fr 1fr;gap:10px">${typeof _reActFieldsHTML === 'function' ? _reActFieldsHTML(action.type || 'notify', action) : ''}</div>
      <label style="display:flex;align-items:center;gap:8px;font-size:12.5px">
        <input type="checkbox" id="sched-enabled" ${existing?.enabled !== false ? 'checked' : ''}>
        <span>${t('security.rules.activate_now')}</span>
      </label>
    </div>`;
  modal(id ? t('automation.sched_edit') : t('automation.sched_new'), body,
    `<button class="btn btn-secondary" onclick="closeModal()">${t('common.cancel')}</button>
     <button class="btn btn-primary" onclick="_schedSave('${esc(id || '')}')">${t('common.save')}</button>`);
};

window._schedSave = async function(id) {
  const name = document.getElementById('sched-name')?.value?.trim();
  const cronExpr = document.getElementById('sched-cron')?.value?.trim();
  if (!name || !cronExpr) { toast(t('automation.sched_fields_required'), 'error'); return; }
  const payload = {
    name, cron_expr: cronExpr, action: _schedCollectAction(),
    enabled: document.getElementById('sched-enabled')?.checked !== false,
  };
  try {
    if (id) await api('PUT', `/scheduled-tasks/${id}`, payload);
    else await api('POST', '/scheduled-tasks', payload);
    closeModal();
    toast(t('common.saved'), 'success');
    pages['automation-schedules']();
  } catch (e) { toast(e.message, 'error'); }
};

window._schedDelete = async function(id, name) {
  if (!confirm(t('security.rules.delete_confirm', { name }))) return;
  try {
    await api('DELETE', `/scheduled-tasks/${id}`);
    toast(t('security.rules.deleted'), 'success');
    pages['automation-schedules']();
  } catch (e) { toast(e.message, 'error'); }
};

window._schedRunNow = async function(id, btn) {
  btn.disabled = true;
  const original = btn.textContent;
  btn.textContent = '…';
  try {
    await api('POST', `/scheduled-tasks/${id}/run`);
    toast(t('automation.sched_ran'), 'success');
    pages['automation-schedules']();
  } catch (e) {
    toast(e.message, 'error');
    btn.disabled = false;
    btn.textContent = original;
  }
};

window._schedHistory = async function(id, name) {
  let runs = [];
  try { runs = await api('GET', `/scheduled-tasks/${id}/runs`) || []; }
  catch (e) { toast(e.message, 'error'); return; }
  const body = runs.length
    ? `<div style="display:flex;flex-direction:column;gap:6px;max-height:400px;overflow:auto">${runs.map(r => `
        <div style="display:flex;align-items:center;gap:10px;font-size:12.5px;padding:6px 0;border-bottom:1px dashed var(--border)">
          <span class="tag ${r.success ? 'tag-green' : 'tag-red'}" style="font-size:10px">${r.success ? t('automation.s_ok') : t('automation.s_err')}</span>
          <span style="color:var(--text2)">${fmtDate(r.ran_at)}</span>
          ${r.error ? `<span style="color:var(--red);font-size:11px">${esc(r.error)}</span>` : ''}
        </div>`).join('')}</div>`
    : `<p style="font-size:12.5px;color:var(--text3)">${t('security.rules.no_history')}</p>`;
  modal(t('automation.sched_history_title', { name }), body, `<button class="btn btn-secondary" onclick="closeModal()">${t('common.close')}</button>`);
};
