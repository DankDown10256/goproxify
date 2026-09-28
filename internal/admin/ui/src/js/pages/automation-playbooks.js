// ── PAGE: Playbooks ──────────────────────────────────────────────────────────
// Enchaîne plusieurs étapes (action, attente, condition, approbation).
// Déclenché comme une action du moteur de règles (type run_playbook) ou
// manuellement (bouton Exécuter). Réutilise les sélecteurs de condition/action
// de security.js (_COND_TYPES, _ACTION_TYPES, _reCondFieldsHTML, _reActFieldsHTML)
// pour l'étape en cours d'ajout — une seule étape s'édite à la fois, donc pas
// de collision d'id avec la fenêtre d'édition de règle.

const PB_STEP_TYPES = [
  ['action', 'automation.pb_step_action'],
  ['wait', 'automation.pb_step_wait'],
  ['condition', 'automation.pb_step_condition'],
  ['approval', 'automation.pb_step_approval'],
];

function _pbStepSummary(step) {
  if (step.type === 'action') {
    const label = (typeof _ACTION_TYPES !== 'undefined' ? _ACTION_TYPES : []).find(a => a.value === step.action?.type)?.label || step.action?.type;
    return `${t('automation.pb_step_action')} — ${esc(label || '—')}`;
  }
  if (step.type === 'wait') return `${t('automation.pb_step_wait')} — ${step.wait_sec || 0}s`;
  if (step.type === 'condition') {
    const label = (typeof _COND_TYPES !== 'undefined' ? _COND_TYPES : []).find(c => c.value === step.condition?.type)?.label || step.condition?.type;
    return `${t('automation.pb_step_condition')} — ${esc(label || '—')}`;
  }
  if (step.type === 'approval') return t('automation.pb_step_approval');
  return step.type;
}

pages['automation-playbooks'] = async function() {
  const content = document.getElementById('content');
  document.getElementById('topbar-actions').innerHTML =
    `<button class="btn btn-primary btn-sm" onclick="_pbOpenModal()">${t('automation.pb_new')}</button>`;
  content.innerHTML = `<p style="color:var(--text2)">${t('common.loading')}</p>`;
  try { window._pbList = await api('GET', '/playbooks') || []; }
  catch (e) { toast(e.message, 'error'); window._pbList = []; }
  _pbRender();
};

function _pbRender() {
  const list = window._pbList || [];
  document.getElementById('content').innerHTML = `
    <p style="margin:0 0 14px;font-size:13px;color:var(--text2)">${t('automation.pb_hint')}</p>
    ${list.length ? `<div style="display:flex;flex-direction:column;gap:10px">${list.map(pb => `
      <div class="card blueprint" style="padding:14px 16px;display:flex;align-items:center;gap:12px;flex-wrap:wrap">
        <div style="flex:1;min-width:200px">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
            <span style="font-weight:600;font-size:13.5px">${esc(pb.name)}</span>
            <span class="tag ${pb.enabled ? 'tag-green' : 'tag-neutral'}" style="font-size:10px">${pb.enabled ? t('security.rules.enabled') : t('security.rules.disabled')}</span>
            <span class="tag tag-blue" style="font-size:10px">${(pb.steps || []).length} ${t('automation.pb_steps_count')}</span>
          </div>
          ${pb.description ? `<div style="font-size:11.5px;color:var(--text2);margin-top:4px">${esc(pb.description)}</div>` : ''}
        </div>
        <button class="btn btn-ghost btn-sm" onclick="_pbRunNow('${esc(pb.id)}',this)">▶ ${t('automation.pb_run')}</button>
        <button class="btn btn-ghost btn-sm" onclick="_pbHistory('${esc(pb.id)}','${esc(pb.name)}')">${t('automation.sched_history')}</button>
        <button class="btn btn-ghost btn-sm" onclick="_pbOpenModal('${esc(pb.id)}')">${t('common.edit')}</button>
        <button class="btn btn-ghost btn-sm" style="color:var(--red)" onclick="_pbDelete('${esc(pb.id)}','${esc(pb.name)}')">${t('common.delete')}</button>
      </div>`).join('')}</div>`
      : `<div class="empty"><p>${t('automation.pb_none')}</p></div>`}`;
}

window._pbOpenModal = function(id) {
  const existing = id ? (window._pbList || []).find(x => x.id === id) : null;
  window._pbEditingId = id || '';
  window._pbSteps = existing ? JSON.parse(JSON.stringify(existing.steps || [])) : [];
  window._pbName = existing?.name || '';
  window._pbDesc = existing?.description || '';
  window._pbEnabled = existing?.enabled !== false;
  window._pbAddingType = null;
  _pbShowModal();
};

function _pbShowModal() {
  const isNew = !window._pbEditingId;
  const body = window._pbAddingType ? _pbStepEditorHTML(window._pbAddingType) : `
    <div style="display:flex;flex-direction:column;gap:12px">
      <div class="field" style="margin:0">
        <label class="field-label">${t('common.name')}</label>
        <input id="pb-name" class="input" value="${esc(window._pbName)}" oninput="window._pbName=this.value" placeholder="${t('automation.pb_name_ph')}">
      </div>
      <div class="field" style="margin:0">
        <label class="field-label">${t('security.rules.description')}</label>
        <input id="pb-desc" class="input" value="${esc(window._pbDesc)}" oninput="window._pbDesc=this.value">
      </div>
      <div class="field" style="margin:0">
        <label class="field-label">${t('automation.pb_steps')}</label>
        <div style="display:flex;flex-direction:column;gap:6px;margin-top:4px">
          ${window._pbSteps.map((s, i) => `
            <div style="display:flex;align-items:center;gap:8px;padding:7px 10px;background:var(--bg2);border-radius:8px">
              <span style="font-size:11px;color:var(--text3);width:18px">${i + 1}.</span>
              <span style="flex:1;font-size:12.5px">${_pbStepSummary(s)}</span>
              <button type="button" class="btn btn-ghost btn-sm" onclick="_pbRemoveStep(${i})">✕</button>
            </div>`).join('') || `<p style="font-size:12px;color:var(--text3);margin:0">${t('automation.pb_no_steps')}</p>`}
        </div>
        <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:8px">
          ${PB_STEP_TYPES.map(([v, key]) => `<button type="button" class="btn btn-ghost btn-sm" onclick="_pbBeginAddStep('${v}')">+ ${t(key)}</button>`).join('')}
        </div>
      </div>
      <label style="display:flex;align-items:center;gap:8px;font-size:12.5px">
        <input type="checkbox" id="pb-enabled" ${window._pbEnabled ? 'checked' : ''} onchange="window._pbEnabled=this.checked">
        <span>${t('security.rules.activate_now')}</span>
      </label>
    </div>`;
  const footer = window._pbAddingType
    ? `<button class="btn btn-secondary" onclick="window._pbAddingType=null;_pbShowModal()">${t('common.cancel')}</button>
       <button class="btn btn-primary" onclick="_pbConfirmAddStep()">${t('automation.pb_add_step')}</button>`
    : `<button class="btn btn-secondary" onclick="closeModal()">${t('common.cancel')}</button>
       <button class="btn btn-primary" onclick="_pbSave()">${t('common.save')}</button>`;
  modal(isNew ? t('automation.pb_new') : t('automation.pb_edit'), body, footer);
}

function _pbStepEditorHTML(type) {
  if (type === 'action') {
    return `<div style="display:flex;flex-direction:column;gap:10px">
      <select id="re-act-type" class="input" style="height:32px" onchange="_reUpdateActFields(this.value)">
        ${(typeof _ACTION_TYPES !== 'undefined' ? _ACTION_TYPES : []).map(a => `<option value="${a.value}">${a.label}</option>`).join('')}
      </select>
      <div id="re-act-fields" style="display:grid;grid-template-columns:1fr 1fr;gap:10px">${typeof _reActFieldsHTML === 'function' ? _reActFieldsHTML('disable_proxy', {}) : ''}</div>
    </div>`;
  }
  if (type === 'condition') {
    return `<div style="display:flex;flex-direction:column;gap:10px">
      <select id="re-cond-type" class="input" style="height:32px" onchange="_reUpdateCondFields(this.value)">
        ${(typeof _COND_TYPES !== 'undefined' ? _COND_TYPES : []).map(c => `<option value="${c.value}">${c.label}</option>`).join('')}
      </select>
      <div id="re-cond-fields" style="display:grid;grid-template-columns:1fr 1fr;gap:10px">${typeof _reCondFieldsHTML === 'function' ? _reCondFieldsHTML('cve_critical', {}) : ''}</div>
      <p style="font-size:11.5px;color:var(--text2);margin:0">${t('automation.pb_condition_hint')}</p>
    </div>`;
  }
  if (type === 'wait') {
    return `<div class="field" style="margin:0">
      <label class="field-label">${t('automation.pb_wait_label')}</label>
      <input id="pb-wait-sec" type="number" class="input" min="1" value="60">
    </div>`;
  }
  return `<p style="font-size:12.5px;color:var(--text2)">${t('automation.pb_approval_hint')}</p>`;
}

window._pbBeginAddStep = function(type) {
  window._pbAddingType = type;
  _pbShowModal();
};

window._pbConfirmAddStep = function() {
  const type = window._pbAddingType;
  let step = { type };
  if (type === 'action') {
    step.action = typeof _pbCollectAction === 'function' ? _pbCollectAction() : { type: document.getElementById('re-act-type')?.value };
  } else if (type === 'condition') {
    const condType = document.getElementById('re-cond-type')?.value;
    step.condition = _pbCollectCondition(condType);
  } else if (type === 'wait') {
    step.wait_sec = Math.max(1, parseInt(document.getElementById('pb-wait-sec')?.value || '60', 10));
  }
  window._pbSteps.push(step);
  window._pbAddingType = null;
  _pbShowModal();
};

// Réutilise la logique de collecte de condition de security.js (mêmes ids que
// l'étape en cours d'édition) sans dupliquer le mapping champ par champ.
function _pbCollectCondition(condType) {
  const condition = { type: condType };
  if (condType === 'cve_critical') {
    condition.cvss_threshold = parseFloat(document.getElementById('re-cvss')?.value || '9');
    condition.proxy_id = document.getElementById('re-proxy-id')?.value || '';
  } else if (condType === 'ban_spike') {
    condition.ban_count = parseInt(document.getElementById('re-ban-count')?.value || '20', 10);
    condition.ban_window = document.getElementById('re-ban-window')?.value || '1h';
  } else if (condType === 'engine_silent') {
    condition.engine_type = document.getElementById('re-engine-type')?.value || 'fail2ban';
    condition.silent_minutes = parseInt(document.getElementById('re-silent-min')?.value || '10', 10);
  } else if (condType === 'proxy_error_rate') {
    condition.error_rate_threshold = parseFloat(document.getElementById('re-err-rate')?.value || '20');
    condition.error_rate_window = document.getElementById('re-err-window')?.value || '5m';
  } else if (condType === 'ban_repeat') {
    condition.repeat_count = parseInt(document.getElementById('re-repeat-count')?.value || '3', 10);
    condition.repeat_window = document.getElementById('re-repeat-window')?.value || '24h';
  } else if (condType === 'node_offline') {
    condition.node_name = document.getElementById('re-node-name')?.value || '';
    condition.offline_minutes = parseInt(document.getElementById('re-offline-min')?.value || '5', 10);
  } else if (condType === 'cert_expiring') {
    condition.domain = document.getElementById('re-cert-domain')?.value || '';
    condition.days_left = parseInt(document.getElementById('re-cert-days')?.value || '15', 10);
  }
  return condition;
}

// Collecte l'action de l'étape en cours (mêmes ids que le formulaire de règle).
function _pbCollectAction() {
  const type = document.getElementById('re-act-type')?.value;
  const action = { type };
  if (type === 'disable_proxy') action.proxy_id = document.getElementById('re-act-proxy-id')?.value || '';
  else if (type === 'ban_ip') {
    action.ban_duration = document.getElementById('re-act-ban-dur')?.value || '';
    action.ban_reason = document.getElementById('re-act-ban-reason')?.value || '';
  } else if (type === 'notify') {
    action.notify_severity = document.getElementById('re-act-sev')?.value || 'warning';
    action.notify_message = document.getElementById('re-act-msg')?.value || '';
  } else if (type === 'enable_strict') action.strict_duration = document.getElementById('re-act-strict-dur')?.value || '30m';
  else if (type === 'webhook_call') action.webhook_url = document.getElementById('re-act-webhook-url')?.value || '';
  else if (type === 'run_backup') action.backup_retention = parseInt(document.getElementById('re-act-backup-retention')?.value || '0', 10);
  else if (type === 'run_playbook') action.playbook_id = document.getElementById('re-act-playbook-id')?.value || '';
  return action;
}

window._pbRemoveStep = function(i) {
  window._pbSteps.splice(i, 1);
  _pbShowModal();
};

window._pbSave = async function() {
  const name = window._pbName?.trim();
  if (!name) { toast(t('automation.pb_name_required'), 'error'); return; }
  if (!window._pbSteps.length) { toast(t('automation.pb_steps_required'), 'error'); return; }
  const payload = { name, description: window._pbDesc || '', steps: window._pbSteps, enabled: window._pbEnabled !== false };
  try {
    if (window._pbEditingId) await api('PUT', `/playbooks/${window._pbEditingId}`, payload);
    else await api('POST', '/playbooks', payload);
    closeModal();
    toast(t('common.saved'), 'success');
    pages['automation-playbooks']();
  } catch (e) { toast(e.message, 'error'); }
};

window._pbDelete = async function(id, name) {
  if (!confirm(t('security.rules.delete_confirm', { name }))) return;
  try {
    await api('DELETE', `/playbooks/${id}`);
    toast(t('security.rules.deleted'), 'success');
    pages['automation-playbooks']();
  } catch (e) { toast(e.message, 'error'); }
};

window._pbRunNow = async function(id, btn) {
  btn.disabled = true;
  try {
    await api('POST', `/playbooks/${id}/run`);
    toast(t('automation.pb_started'), 'success');
  } catch (e) { toast(e.message, 'error'); }
  btn.disabled = false;
};

const PB_STATUS_TAG = { running: 'tag-blue', waiting_approval: 'tag-yellow', completed: 'tag-green', failed: 'tag-red', stopped: 'tag-neutral' };
const PB_STATUS_LABEL = {
  running: 'automation.pb_s_running', waiting_approval: 'automation.pb_s_waiting', completed: 'automation.pb_s_completed',
  failed: 'automation.pb_s_failed', stopped: 'automation.pb_s_stopped',
};

window._pbHistory = async function(id, name) {
  let runs = [];
  try { runs = await api('GET', `/playbooks/${id}/runs`) || []; }
  catch (e) { toast(e.message, 'error'); return; }
  window._pbRuns = runs;
  _pbRenderHistory(name);
};

function _pbRenderHistory(name) {
  const runs = window._pbRuns || [];
  const body = runs.length
    ? `<div style="display:flex;flex-direction:column;gap:8px;max-height:420px;overflow:auto">${runs.map(r => `
        <div class="card" style="padding:10px 12px">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
            <span class="tag ${PB_STATUS_TAG[r.status] || 'tag-neutral'}" style="font-size:10px">${t(PB_STATUS_LABEL[r.status] || r.status)}</span>
            <span style="font-size:11.5px;color:var(--text2)">${fmtDate(r.started_at)}</span>
            <span style="font-size:11px;color:var(--text3)">${t('automation.pb_step_n', { n: r.current_step + 1, total: (r.log || []).length })}</span>
            ${r.status === 'waiting_approval' ? `
              <button class="btn btn-primary btn-sm" onclick="_pbDecideRun('${esc(r.id)}',true,'${esc(name)}')">${t('automation.approve')}</button>
              <button class="btn btn-ghost btn-sm" onclick="_pbDecideRun('${esc(r.id)}',false,'${esc(name)}')">${t('automation.reject')}</button>` : ''}
          </div>
          <div style="margin-top:6px;font-size:11.5px;color:var(--text2)">${(r.log || []).map(l =>
            `<div>${l.success ? '✓' : '✗'} ${esc(_pbStepSummary({ type: l.type, action: {}, condition: {} }))}${l.detail ? ' — ' + esc(l.detail) : ''}</div>`).join('')}</div>
        </div>`).join('')}</div>`
    : `<p style="font-size:12.5px;color:var(--text3)">${t('security.rules.no_history')}</p>`;
  modal(t('automation.sched_history_title', { name }), body, `<button class="btn btn-secondary" onclick="closeModal()">${t('common.close')}</button>`);
}

window._pbDecideRun = async function(runID, approve, name) {
  try {
    await api('POST', `/playbooks/runs/${runID}/${approve ? 'approve' : 'reject'}`);
    toast(approve ? t('automation.approved') : t('automation.rejected'), 'success');
    const runs = await api('GET', `/playbooks/${window._pbList?.find(p => p.name === name)?.id}/runs`).catch(() => window._pbRuns);
    window._pbRuns = runs || window._pbRuns;
    _pbRenderHistory(name);
  } catch (e) { toast(e.message, 'error'); }
};
