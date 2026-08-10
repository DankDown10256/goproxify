// ── PAGE: Alertes & canaux
// Extrait de pages-all.js — phase 4.

// ── PAGE: Alerts ───────────────────────────────────────────────────────────
const ALERT_TRIGGER_GROUPS = {
  'alerts.group.infrastructure': ['node_offline', 'scale_event', 'health_escalation'],
  'alerts.group.certificates': ['cert_expiring', 'cert_expired'],
  'alerts.group.configuration': ['config_change'],
  'alerts.group.security': ['auth_failure'],
  'alerts.group.performance': ['http_error_rate', 'latency_p95'],
};
const CHANNELS = ['email', 'webhook', 'ntfy', 'gotify'];
const CHANNEL_META = {
  email: { labelKey: 'alerts.ch.email', helpKey: 'alerts.ch.email_help' },
  webhook: { labelKey: 'alerts.ch.webhook', helpKey: 'alerts.ch.webhook_help' },
  ntfy: { labelKey: 'alerts.ch.ntfy', helpKey: 'alerts.ch.ntfy_help' },
  gotify: { labelKey: 'alerts.ch.gotify', helpKey: 'alerts.ch.gotify_help' },
};

pages.alerts = async function() {
  const content = document.getElementById('content');
  document.getElementById('topbar-actions').innerHTML =
    `<button class="btn btn-primary" onclick="openAlertModal()">${t('alerts.new_rule')}</button>`;
  content.innerHTML = `
    <div class="card blueprint">
      <div class="card-header">
        <span class="card-title">${t('alerts.rules_title')}</span>
      </div>
      <div style="padding:40px;text-align:center;color:var(--text2)">
        <p>${t('alerts.rules_desc')}</p>
        <button class="btn btn-primary" style="margin-top:16px" onclick="openAlertModal()">${t('alerts.create_rule')}</button>
      </div>
    </div>`;
};

window.openAlertModal = function() {
  const triggerGroupHtml = Object.entries(ALERT_TRIGGER_GROUPS).map(([groupKey, triggers]) => `
    <div class="alert-section-card">
      <div class="alert-section-title">${esc(t(groupKey))}</div>
      <div class="trigger-list">
        ${triggers.map(trig => `
          <div class="trigger-chip" data-trigger="${trig}" onclick="this.classList.toggle('selected')">
            ${esc(trig.replace(/_/g, ' '))}
          </div>`).join('')}
      </div>
    </div>
  `).join('');
  const channelsHtml = CHANNELS.map((c) => {
    const meta = CHANNEL_META[c] || { labelKey: c, helpKey: '' };
    return `
      <label class="alert-channel-card">
        <input type="checkbox" id="al-ch-${c}" onchange="toggleAlertChannelFields()">
        <div>
          <div style="font-size:13px;font-weight:600;line-height:1.2;">${esc(t(meta.labelKey))}</div>
          <div style="font-size:11px;color:var(--text3);margin-top:2px;">${esc(t(meta.helpKey))}</div>
        </div>
      </label>`;
  }).join('');
  modal(t('alerts.modal_new'), `
    <div class="alert-form-layout">
      <div class="alert-section-card">
        <div class="alert-section-title">${t('alerts.step1')}</div>
        <div class="field">
          <label class="field-label">${t('alerts.rule_name')}</label>
          <input id="al-name" class="input" placeholder="${esc(t('alerts.rule_name_ph'))}">
        </div>
        <div class="field">
          <label class="field-label">${t('alerts.scope')}</label>
          <input id="al-scope" class="input" placeholder="${esc(t('alerts.scope_ph'))}">
          <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:8px;">
            <button class="btn btn-ghost btn-sm" type="button" onclick="setAlertScope('global')">${t('alerts.scope_global')}</button>
            <button class="btn btn-ghost btn-sm" type="button" onclick="setAlertScope('*.prod.*')">${t('alerts.scope_prod')}</button>
            <button class="btn btn-ghost btn-sm" type="button" onclick="setAlertScope('*.staging.*')">${t('alerts.scope_staging')}</button>
          </div>
        </div>
      </div>

      <div class="alert-section-card">
        <div class="alert-section-title">${t('alerts.step2')}</div>
        <div style="font-size:12px;color:var(--text2);margin-bottom:10px;">
          ${t('alerts.triggers_hint')}
        </div>
        <div class="alert-trigger-groups">${triggerGroupHtml}</div>
      </div>

      <div class="alert-section-card">
        <div class="alert-section-title">${t('alerts.step3')}</div>
        <div style="font-size:12px;color:var(--text2);margin-bottom:10px;">
          ${t('alerts.channels_hint')}
        </div>
        <div class="alert-channel-grid">${channelsHtml}</div>
        <div id="al-field-email" class="field" style="display:none;margin-top:12px;">
          <label class="field-label">${t('alerts.email_recipient')}</label>
          <input id="al-email" class="input" type="email" placeholder="ops@example.fr">
        </div>
        <div id="al-field-webhook" class="field" style="display:none;">
          <label class="field-label">${t('alerts.webhook_url')}</label>
          <input id="al-webhook" class="input" placeholder="https://hooks.slack.com/...">
        </div>
      </div>
    </div>
  `,
    `<button class="btn btn-secondary" onclick="closeModal()">${t('common.cancel')}</button>
     <button class="btn btn-primary" onclick="saveAlert()">${t('common.save')}</button>`,
    true);
  toggleAlertChannelFields();
};
window.setAlertScope = function(scope) {
  const input = document.getElementById('al-scope');
  if (input) input.value = scope;
};
window.toggleAlertChannelFields = function() {
  const emailChecked = !!document.getElementById('al-ch-email')?.checked;
  const webhookChecked = !!document.getElementById('al-ch-webhook')?.checked;
  const emailField = document.getElementById('al-field-email');
  const webhookField = document.getElementById('al-field-webhook');
  if (emailField) emailField.style.display = emailChecked ? '' : 'none';
  if (webhookField) webhookField.style.display = webhookChecked ? '' : 'none';
};
window.saveAlert = function() {
  const name = (document.getElementById('al-name')?.value || '').trim();
  if (!name) { toast(t('alerts.err_name'), 'error'); return; }
  const selectedTriggers = [...document.querySelectorAll('.trigger-chip.selected')];
  if (!selectedTriggers.length) { toast(t('alerts.err_trigger'), 'error'); return; }
  const selectedChannels = CHANNELS.filter((c) => document.getElementById(`al-ch-${c}`)?.checked);
  if (!selectedChannels.length) { toast(t('alerts.err_channel'), 'error'); return; }
  toast(t('alerts.saved'), 'success');
  closeModal();
};


// ── PAGE: Alert Channels ───────────────────────────────────────────────────
const _chSvg = (paths) =>
  `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">${paths}</svg>`;

const CHANNEL_TYPE_ICONS = {
  email:   _chSvg('<rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 7 9 7 9-7"/>'),
  webhook: _chSvg('<path d="M18 16.98h-5.99c-1.1 0-1.95.94-2.48 1.9A4 4 0 0 1 2 17c.01-.7.2-1.4.57-2"/><path d="m6 17 3.13-5.78c.53-.97.1-2.18-.5-3.1a4 4 0 1 1 6.89-4.06"/><path d="m12 6 3.13 5.73C15.66 12.7 16.9 13 18 13a4 4 0 0 1 0 8"/>'),
  ntfy:    _chSvg('<path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/><circle cx="18" cy="6" r="3" fill="currentColor" stroke="none"/>'),
  gotify:  _chSvg('<path d="M6 9a6 6 0 0 1 12 0c0 7 3 7 3 9H3c0-2 3-2 3-9"/><path d="M10 21a2 2 0 0 0 4 0"/>'),
  jira:    _chSvg('<path d="M12 3 5.5 9.5a4.5 4.5 0 0 0 6.36 6.36L12 15.7"/><path d="m12 21 6.5-6.5a4.5 4.5 0 0 0-6.36-6.36L12 8.3"/>'),
  linear:  _chSvg('<path d="M4 20V4l16 16H4z"/>'),
  github:  _chSvg('<path d="M9 19c-4.3 1.4-4.3-2.1-6-2.5"/><path d="M15 22v-3.9a3.4 3.4 0 0 0-1-2.6c3.2-.4 6.5-1.6 6.5-7.1A5.4 5.4 0 0 0 19 4.1 5 5 0 0 0 18.9 1S17.7.7 15 2.6a11.2 11.2 0 0 0-6 0C6.3.7 5.1 1 5.1 1A5 5 0 0 0 5 4.1 5.4 5.4 0 0 0 3.5 8.4c0 5.5 3.3 6.7 6.5 7.1a3.4 3.4 0 0 0-1 2.6V22"/>'),
  gitlab:  _chSvg('<path d="M12 21 18.8 12.5 16.4 3.8 13.9 10.2h-3.8L7.6 3.8 5.2 12.5 12 21z"/>'),
  zammad:  _chSvg('<path d="M4 7h12l4 4v7a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V9a2 2 0 0 1 2-2z"/><path d="M16 7v4h4"/><path d="M8 13h5"/><path d="M8 16h8"/>'),
  glpi:    _chSvg('<rect x="3" y="4" width="18" height="12" rx="1.5"/><path d="M8 20h8"/><path d="M12 16v4"/><path d="M7 8h4"/><path d="M7 11h6"/>'),
};

const CHANNEL_TYPES = [
  { id: 'email',   labelKey: 'alerts.type.email',   shortKey: 'alerts.type.email_short',   color: '#3b82f6' },
  { id: 'webhook', labelKey: 'alerts.type.webhook', shortKey: 'alerts.type.webhook_short', color: '#8b5cf6' },
  { id: 'ntfy',    labelKey: 'alerts.type.ntfy',    shortKey: 'alerts.type.ntfy',          color: '#0ea5e9' },
  { id: 'gotify',  labelKey: 'alerts.type.gotify',  shortKey: 'alerts.type.gotify',        color: '#06b6d4' },
  { id: 'jira',    labelKey: 'alerts.type.jira',    shortKey: 'alerts.type.jira',          color: '#2684ff' },
  { id: 'linear',  labelKey: 'alerts.type.linear',  shortKey: 'alerts.type.linear',        color: '#5e6ad2' },
  { id: 'github',  labelKey: 'alerts.type.github',  shortKey: 'alerts.type.github_short',  color: '#6b7280' },
  { id: 'gitlab',  labelKey: 'alerts.type.gitlab',  shortKey: 'alerts.type.gitlab_short',  color: '#fc6d26' },
  { id: 'zammad',  labelKey: 'alerts.type.zammad',  shortKey: 'alerts.type.zammad',        color: '#eab308' },
  { id: 'glpi',    labelKey: 'alerts.type.glpi',    shortKey: 'alerts.type.glpi',          color: '#22c55e' },
];

function channelTypeMeta(id) {
  return CHANNEL_TYPES.find(ct => ct.id === id) || CHANNEL_TYPES[0];
}

function channelTypeIconHtml(id, size = 18) {
  const meta = channelTypeMeta(id);
  const svg = (CHANNEL_TYPE_ICONS[id] || CHANNEL_TYPE_ICONS.webhook).replace('width="18"', `width="${size}"`).replace('height="18"', `height="${size}"`);
  return `<span class="ch-type-icon" style="--ch-color:${meta.color}" aria-hidden="true">${svg}</span>`;
}

function channelTypeLabel(id) {
  return t(channelTypeMeta(id).labelKey);
}

const CHANNEL_FIELDS = {
  email:   [['host','alerts.field.host','mail.example.fr'],['port','alerts.field.port','587'],['username','alerts.field.username','user@example.fr'],['password','alerts.field.password','','password'],['from','alerts.field.from','goproxify@example.fr'],['to','alerts.field.to','ops@example.fr']],
  webhook: [['url','alerts.field.url','https://hooks.slack.com/…'],['secret','alerts.field.secret','','password']],
  ntfy:    [['url','alerts.field.url','https://ntfy.sh'],['topic','alerts.field.topic','goproxify-alerts'],['token','alerts.field.token_optional','','password']],
  gotify:  [['url','alerts.field.url','https://gotify.example.fr'],['token','alerts.field.token','','password']],
  jira:    [['url','alerts.field.jira_url','https://xyz.atlassian.net'],['username','alerts.field.username',''],['token','alerts.field.token','','password'],['project','alerts.field.project','OPS'],['issue_type','alerts.field.issue_type','Bug']],
  linear:  [['api_key','alerts.field.api_key','','password'],['team_id','alerts.field.team_id','']],
  github:  [['token','alerts.field.pat','','password'],['owner','alerts.field.owner',''],['repo','alerts.field.repo','']],
  gitlab:  [['url','alerts.field.url','https://gitlab.com'],['token','alerts.field.access_token','','password'],['project_id','alerts.field.project_id','']],
  zammad:  [['url','alerts.field.url','https://zammad.example.fr'],['token','alerts.field.token','','password'],['group_id','alerts.field.group_id','1']],
  glpi:    [['url','alerts.field.url','https://glpi.example.fr'],['app_token','alerts.field.app_token','','password'],['user_token','alerts.field.user_token','','password']],
};

pages['alert-channels'] = async function() {
  document.getElementById('topbar-actions').innerHTML =
    `<button class="btn btn-primary" onclick="openChannelModal()">${t('alerts.new_channel')}</button>`;
  const content = document.getElementById('content');
  content.innerHTML = `<p style="color:var(--text2)">${t('common.loading')}</p>`;
  try {
    const chans = await api('GET', '/alert-channels');
    content.innerHTML = `
      <div class="card blueprint" style="padding:0">
        <div class="table-wrap">
          <table>
            <thead><tr><th>${t('alerts.col.name')}</th><th>${t('alerts.col.type')}</th><th>${t('alerts.col.status')}</th><th>${t('alerts.col.actions')}</th></tr></thead>
            <tbody>
              ${(chans||[]).length ? (chans||[]).map(c => `<tr>
                <td><b>${esc(c.name)}</b></td>
                <td><span class="ch-type-pill">${channelTypeIconHtml(c.type, 14)}<span>${esc(channelTypeLabel(c.type))}</span></span></td>
                <td>${c.enabled ? `<span class="tag tag-green">${t('alerts.active')}</span>` : `<span class="tag tag-neutral">${t('alerts.inactive')}</span>`}</td>
                <td>
                  <button class="btn btn-secondary btn-sm" onclick="testChannel('${esc(c.id)}','${esc(c.name)}')">${t('alerts.test')}</button>
                  <button class="btn btn-ghost btn-icon btn-sm" onclick="openChannelModal('${esc(c.id)}')" title="${esc(t('common.edit'))}"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></button>
                  <button class="btn btn-ghost btn-icon btn-sm" onclick="deleteChannel('${esc(c.id)}','${esc(c.name)}')" title="${esc(t('common.delete'))}"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg></button>
                </td>
              </tr>`).join('') : `<tr><td colspan="4" class="empty"><p>${t('alerts.no_channels')}</p></td></tr>`}
            </tbody>
          </table>
        </div>
      </div>`;
  } catch(e) { content.innerHTML = `<p style="color:var(--red)">${esc(e.message)}</p>`; }
};

window.testChannel = async function(id, name) {
  toast(t('alerts.test_running', { name }), 'info');
  try {
    await api('POST', `/alert-channels/${id}/test`, {});
    toast(t('alerts.test_ok', { name }), 'success');
  } catch(e) { toast(t('alerts.test_fail', { msg: e.message }), 'error'); }
};

window.deleteChannel = function(id, name) {
  confirm_(t('alerts.delete_confirm', { name }), async () => {
    await api('DELETE', `/alert-channels/${id}`);
    toast(t('alerts.deleted'), 'success');
    navigate('alert-channels');
  });
};

window.openChannelModal = async function(id) {
  let existing = null;
  if (id) { try { existing = (await api('GET','/alert-channels')||[]).find(c=>c.id===id); } catch {} }
  const type = existing?.type || 'webhook';
  const typeLocked = !!id;

  function buildFields(chType) {
    const fields = CHANNEL_FIELDS[chType] || [];
    return fields.map(([k, labelKey, ph, inputType]) => `
      <div class="field">
        <label class="field-label">${t(labelKey)}</label>
        <input id="ch-${k}" class="input" type="${inputType||'text'}" placeholder="${ph||''}"
          value="${esc(existing?.config?.[k] && !['password','token','api_key','secret','user_token','app_token'].includes(k) ? existing.config[k] : '')}">
      </div>`).join('');
  }

  function buildTypePicker(selected) {
    if (typeLocked) {
      const meta = channelTypeMeta(selected);
      return `
        <div class="ch-type-locked">
          ${channelTypeIconHtml(selected, 18)}
          <div class="ch-type-locked-text">
            <span class="ch-type-locked-label">${esc(t(meta.labelKey))}</span>
            <span class="ch-type-locked-hint">${esc(t('alerts.type_locked'))}</span>
          </div>
          <input type="hidden" id="ch-type" value="${esc(selected)}">
        </div>`;
    }
    return `
      <input type="hidden" id="ch-type" value="${esc(selected)}">
      <div class="ch-type-grid" role="listbox" aria-label="${esc(t('alerts.col.type'))}">
        ${CHANNEL_TYPES.map(ct => `
          <button type="button" role="option" class="ch-type-card${ct.id === selected ? ' active' : ''}"
            data-type="${ct.id}" aria-selected="${ct.id === selected}"
            onclick="selectChannelType('${ct.id}')">
            ${channelTypeIconHtml(ct.id, 18)}
            <span class="ch-type-card-label">${esc(t(ct.shortKey))}</span>
          </button>`).join('')}
      </div>`;
  }

  const body = `
    <div class="ch-form">
      <div class="field">
        <label class="field-label">${t('alerts.col.name')}</label>
        <input id="ch-name" class="input" placeholder="slack-ops" value="${esc(existing?.name||'')}">
      </div>
      <div class="field">
        <label class="field-label">${t('alerts.col.type')}</label>
        ${buildTypePicker(type)}
      </div>
      <div class="field">
        <label class="field-label" style="display:flex;align-items:center;gap:8px">
          ${t('common.enabled')}
          <label class="toggle"><input type="checkbox" id="ch-enabled" ${existing?.enabled!==false?'checked':''}><span class="toggle-slider"></span></label>
        </label>
      </div>
      <div id="ch-fields" class="ch-fields">${buildFields(type)}</div>
    </div>`;

  window.selectChannelType = function(chType) {
    const input = document.getElementById('ch-type');
    if (!input || input.value === chType) return;
    input.value = chType;
    document.querySelectorAll('.ch-type-card').forEach(btn => {
      const on = btn.dataset.type === chType;
      btn.classList.toggle('active', on);
      btn.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    document.getElementById('ch-fields').innerHTML = buildFields(chType);
  };

  window.updateChannelFields = function() {
    const chType = document.getElementById('ch-type').value;
    document.getElementById('ch-fields').innerHTML = buildFields(chType);
  };

  modal(id ? t('alerts.edit_channel') : t('alerts.new_channel_modal'), body,
    `<button class="btn btn-secondary" onclick="closeModal()">${t('common.cancel')}</button>
     <button class="btn btn-primary" onclick="saveChannel('${esc(id||'')}')">${t('common.save')}</button>`);
};

window.saveChannel = async function(id) {
  const name    = document.getElementById('ch-name').value.trim();
  const type    = document.getElementById('ch-type').value;
  const enabled = document.getElementById('ch-enabled').checked;
  const fields  = CHANNEL_FIELDS[type] || [];
  const config  = {};
  for (const [k] of fields) {
    const v = document.getElementById('ch-' + k)?.value;
    if (v) config[k] = v;
  }
  if (type === 'email' && config.to) {
    config.to = config.to.split(',').map(s => s.trim()).filter(Boolean);
  }
  try {
    if (id) {
      await api('PUT', `/alert-channels/${id}`, { name, config, enabled });
      toast(t('alerts.updated'), 'success');
    } else {
      await api('POST', '/alert-channels', { name, type, config, enabled });
      toast(t('alerts.created'), 'success');
    }
    closeModal();
    navigate('alert-channels');
  } catch(e) { toast(e.message, 'error'); }
};

