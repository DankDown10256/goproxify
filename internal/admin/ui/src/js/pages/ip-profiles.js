// ── PAGE: IP Profiles
// Extrait de pages-all.js — phase 4.

// ── PAGE: IP Profiles ──────────────────────────────────────────────────────

const IPPROF_MODE_KEYS = { deny: 'ipprof.mode.deny', allow: 'ipprof.mode.allow' };
const IPPROF_MODE_BADGE = { deny: 'tag-red', allow: 'tag-green' };
const IPPROF_FORMAT_KEYS = {
  plain: 'ipprof.format.plain',
  'json-aws': 'ipprof.format.json_aws',
  'json-gcp': 'ipprof.format.json_gcp',
  'json-fastly': 'ipprof.format.json_fastly',
  'tsv-dshield': 'ipprof.format.tsv_dshield',
};
const IPPROF_FORMAT_SHORT_KEYS = {
  plain: 'ipprof.format.plain',
  'json-aws': 'ipprof.format.json_aws_short',
  'json-gcp': 'ipprof.format.json_gcp_short',
  'json-fastly': 'ipprof.format.json_fastly_short',
  'tsv-dshield': 'ipprof.format.tsv_dshield',
};

function ipprofFormatLabel(fmt, short) {
  const keys = short ? IPPROF_FORMAT_SHORT_KEYS : IPPROF_FORMAT_KEYS;
  return t(keys[fmt] || fmt);
}

pages['ip-profiles'] = async function() {
  document.getElementById('page-title').textContent = t('ipprof.page_title');
  const content = document.getElementById('content');
  content.innerHTML = `<div style="display:flex;align-items:center;gap:12px;margin-bottom:18px">
    <h2 style="margin:0;flex:1">${t('ipprof.heading')}</h2>
    <button class="btn btn-primary" onclick="ipProfileCreate()">${t('ipprof.new')}</button>
  </div>
  <p style="color:var(--text2);margin-bottom:20px">${t('ipprof.intro')}</p>
  <div id="ip-profiles-list"><div class="spinner"></div></div>`;

  await ipProfilesLoad();
};

async function ipProfilesLoad() {
  const box = document.getElementById('ip-profiles-list');
  if (!box) return;
  let profiles;
  try { profiles = await api('GET', '/ip-profiles'); } catch(e) { box.innerHTML = `<div class="alert alert-danger">${t('ipprof.error', { msg: e.message })}</div>`; return; }

  if (!profiles.length) {
    box.innerHTML = `<div style="text-align:center;padding:40px;color:var(--text2)">${t('ipprof.empty')}</div>`;
    return;
  }

  box.innerHTML = `<table class="table">
    <thead><tr><th>${t('ipprof.col.name')}</th><th>${t('ipprof.col.type')}</th><th>${t('ipprof.col.mode')}</th><th>${t('ipprof.col.format')}</th><th>${t('ipprof.col.cidrs')}</th><th>${t('ipprof.col.updated')}</th><th>${t('ipprof.col.active')}</th><th></th></tr></thead>
    <tbody>${profiles.map(p => `<tr>
      <td><strong>${esc(p.name)}</strong></td>
      <td><span class="tag tag-neutral">${esc(p.profile_type||'custom')}</span></td>
      <td><span class="tag ${IPPROF_MODE_BADGE[p.mode]||'tag-neutral'}">${t(IPPROF_MODE_KEYS[p.mode]||p.mode)}</span></td>
      <td style="font-size:12px;color:var(--text2)">${esc(ipprofFormatLabel(p.feed_format))}</td>
      <td>${(p.cidrs||[]).length.toLocaleString()}</td>
      <td style="font-size:12px;color:var(--text2)">${p.last_updated_at ? new Date(p.last_updated_at).toLocaleString(typeof gpxBCP47==='function'?gpxBCP47():'en-US') : '—'}</td>
      <td><label class="toggle" title="${esc(t('ipprof.toggle_title'))}">
        <input type="checkbox" ${p.enabled?'checked':''} onchange="ipProfileToggle('${p.id}',this.checked,${JSON.stringify(p).replace(/"/g,'&quot;')})">
        <span class="toggle-slider"></span>
      </label></td>
      <td style="display:flex;gap:6px">
        <button class="btn btn-sm" onclick="ipProfileRefresh('${p.id}','${esc(p.name)}')" title="${esc(t('ipprof.refresh_title'))}">↻</button>
        <button class="btn btn-sm btn-danger" onclick="ipProfileDelete('${p.id}','${esc(p.name)}')">✕</button>
      </td>
    </tr>`).join('')}</tbody>
  </table>`;
}

async function ipProfileRefresh(id, name) {
  try {
    await api('POST', `/ip-profiles/${id}/refresh`);
    toast(t('ipprof.refreshed', { name }), 'success');
    await ipProfilesLoad();
  } catch(e) { toast(e.message, 'error'); }
}

async function ipProfileToggle(id, enabled, profile) {
  try {
    await api('PUT', `/ip-profiles/${id}`, {
      name: profile.name, mode: profile.mode,
      feed_urls: profile.feed_urls, feed_format: profile.feed_format,
      refresh_interval_h: profile.refresh_interval_h, enabled,
    });
  } catch(e) { toast(e.message, 'error'); await ipProfilesLoad(); }
}

async function ipProfileDelete(id, name) {
  if (!confirm(t('ipprof.delete_confirm', { name }))) return;
  await api('DELETE', `/ip-profiles/${id}`);
  toast(t('ipprof.deleted'), 'success');
  await ipProfilesLoad();
}

function ipProfileCreate() {
  const modal = document.createElement('div');
  modal.className = 'modal-overlay';
  modal.innerHTML = `<div class="modal" style="max-width:520px">
    <h3 style="margin-top:0">${t('ipprof.new_modal')}</h3>
    <div class="field"><label>${t('ipprof.name')}</label><input id="np-name" class="input" placeholder="${esc(t('ipprof.name_ph'))}"></div>
    <div class="field"><label>${t('ipprof.type')}</label><input id="np-type" class="input" placeholder="custom"></div>
    <div class="field"><label>${t('ipprof.mode')}</label>
      <select id="np-mode" class="input">
        <option value="deny">${t('ipprof.mode.deny_opt')}</option>
        <option value="allow">${t('ipprof.mode.allow_opt')}</option>
      </select></div>
    <div class="field"><label>${t('ipprof.feed_urls')}</label><textarea id="np-urls" class="input" rows="3" placeholder="https://..."></textarea></div>
    <div class="field"><label>${t('ipprof.format')}</label>
      <select id="np-format" class="input">
        <option value="plain">${t('ipprof.format.plain')}</option>
        <option value="json-aws">${t('ipprof.format.json_aws_short')}</option>
        <option value="json-gcp">${t('ipprof.format.json_gcp_short')}</option>
        <option value="json-fastly">${t('ipprof.format.json_fastly_short')}</option>
        <option value="tsv-dshield">${t('ipprof.format.tsv_dshield')}</option>
      </select></div>
    <div class="field"><label>${t('ipprof.refresh_interval')}</label>
      <input id="np-interval" class="input" type="number" value="24" min="1"></div>
    <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:16px">
      <button class="btn" onclick="this.closest('.modal-overlay').remove()">${t('common.cancel')}</button>
      <button class="btn btn-primary" onclick="ipProfileSave(this)">${t('common.create')}</button>
    </div>
  </div>`;
  document.body.appendChild(modal);
}

async function ipProfileSave(btn) {
  const urls = document.getElementById('np-urls').value.split('\n').map(u=>u.trim()).filter(Boolean);
  const body = {
    name: document.getElementById('np-name').value.trim(),
    profile_type: document.getElementById('np-type').value.trim() || 'custom',
    mode: document.getElementById('np-mode').value,
    feed_urls: urls,
    feed_format: document.getElementById('np-format').value,
    refresh_interval_h: parseInt(document.getElementById('np-interval').value)||24,
    enabled: true,
  };
  try {
    await api('POST', '/ip-profiles', body);
    btn.closest('.modal-overlay').remove();
    toast(t('ipprof.created'), 'success');
    await ipProfilesLoad();
  } catch(e) { toast(e.message, 'error'); }
}

