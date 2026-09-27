// ── PAGE: Automatisation — vue d'ensemble et journal
// Onglets « Automatisations » : security-rules, automation-flow (automation-flow.js), rules-store.
// Onglets « Alertes » : alert-channels, alerts.

function _auHistState(h) {
  if (h.error === 'silenced') return 'silenced';
  if (h.error === 'pending_approval') return 'pending';
  if (h.error) return 'err';
  if (h.action_taken) return 'ok';
  if (h.cond_result) return 'warn';
  return 'idle';
}

window._auGo = function(page, opts) {
  Object.assign(window, opts || {});
  navigate(page);
};

window._auDecidePending = async function(id, approve, btn) {
  btn.disabled = true;
  try {
    await api('POST', `/rules-engine/pending/${id}/${approve ? 'approve' : 'reject'}`);
    toast(approve ? t('automation.approved') : t('automation.rejected'), 'success');
    pages.automation();
  } catch (e) { toast(e.message, 'error'); btn.disabled = false; }
};

pages.automation = async function() {
  const content = document.getElementById('content');
  document.getElementById('topbar-actions').innerHTML =
    `<button class="btn btn-primary btn-sm" onclick="_auGo('automation-flow',{_flowSel:'new'})">${t('automation.new_rule')}</button>`;
  content.innerHTML = `<p style="color:var(--text2)">${t('common.loading')}</p>`;

  const [rules, channels, templates, history, pending] = await Promise.all([
    api('GET', '/rules-engine/rules').catch(() => []),
    api('GET', '/alert-channels').catch(() => []),
    api('GET', '/rules-engine/templates').catch(() => []),
    api('GET', '/rules-engine/history').catch(() => []),
    api('GET', '/rules-engine/pending?status=pending').catch(() => []),
  ]);
  const R = rules || [], C = channels || [], H = history || [];
  const P = pending || [];
  window._auPending = P;
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
    ${P.length ? `<div class="card" style="padding:14px 16px;margin-bottom:12px;border-color:var(--accent)">
      <div style="font-weight:600;font-size:13px;margin-bottom:8px">${t('automation.pending_banner', { n: P.length })}</div>
      <div style="display:flex;flex-direction:column;gap:8px">${P.map(p => `
        <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;padding:8px 10px;background:var(--surf2, var(--bg2));border-radius:8px">
          <div style="flex:1;min-width:180px">
            <b style="font-size:12.5px">${esc(p.rule_name)}</b>
            <div style="font-size:11.5px;color:var(--text2)">${esc(p.action?.type || '')} · ${fmtDate(p.created_at)}</div>
          </div>
          <button class="btn btn-primary btn-sm" onclick="_auDecidePending('${esc(p.id)}',true,this)">${t('automation.approve')}</button>
          <button class="btn btn-ghost btn-sm" onclick="_auDecidePending('${esc(p.id)}',false,this)">${t('automation.reject')}</button>
        </div>`).join('')}</div>
    </div>` : ''}
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
        <button class="btn btn-ghost btn-sm" onclick="_auExportYaml()">${t('automation.export_yaml')}</button>
        <button class="btn btn-ghost btn-sm" onclick="_auImportYaml()">${t('automation.import_yaml')}</button>
      </div>
    </div>
    <input type="file" id="au-import-file" accept=".yaml,.yml" style="display:none">`;
  document.getElementById('au-import-file').onchange = _auImportYamlFile;
};

// Export/Import GitOps : règles, canaux et silences en un document YAML.
window._auExportYaml = async function() {
  try {
    const res = await fetch('/api/v1/rules-engine/export', { headers: { Authorization: 'Bearer ' + state.token } });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const text = await res.text();
    const blob = new Blob([text], { type: 'application/x-yaml' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'automation.yaml';
    a.click();
    URL.revokeObjectURL(a.href);
  } catch (e) { toast(e.message, 'error'); }
};

window._auImportYaml = function() {
  document.getElementById('au-import-file')?.click();
};

window._auImportYamlFile = async function(ev) {
  const file = ev.target.files?.[0];
  if (!file) return;
  ev.target.value = '';
  try {
    const text = await file.text();
    const res = await fetch('/api/v1/rules-engine/import', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + state.token, 'Content-Type': 'application/x-yaml' },
      body: text,
    });
    if (!res.ok) throw new Error(await res.text().catch(() => 'HTTP ' + res.status));
    const summary = await res.json();
    toast(t('automation.import_summary', {
      rc: summary.rules_created, ru: summary.rules_updated,
      cc: summary.channels_created, cu: summary.channels_updated, sc: summary.silences_created,
    }), 'success');
    pages.automation();
  } catch (e) { toast(e.message, 'error'); }
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
  const filters = [['all', t('automation.f_all')], ['ok', t('automation.f_ok')], ['err', t('automation.f_err')], ['warn', t('automation.f_warn')], ['silenced', t('automation.f_silenced')], ['pending', t('automation.f_pending')], ['idle', t('automation.f_idle')]];
  const label = { ok: 'automation.s_ok', err: 'automation.s_err', warn: 'automation.s_warn', idle: 'automation.s_idle', silenced: 'automation.s_silenced', pending: 'automation.s_pending' };
  const tag = { ok: 'tag-green', err: 'tag-red', warn: 'tag-yellow', idle: 'tag-neutral', silenced: 'tag-neutral', pending: 'tag-blue' };
  document.getElementById('content').innerHTML = `
    <p style="margin:0 0 14px;font-size:13px;color:var(--text2)">${t('automation.journal_hint')}</p>
    <div style="display:flex;gap:6px;margin-bottom:14px;flex-wrap:wrap">${filters.map(([v, l]) =>
      `<button class="btn btn-sm${f === v ? ' btn-primary' : ' btn-ghost'}" onclick="_auSetFilter('${v}')">${l}</button>`).join('')}</div>
    ${rows.length ? `<div class="table-wrap"><table><thead><tr>
      <th>${t('common.date')}</th><th>${t('security.rules.rule')}</th><th>${t('automation.col_result')}</th><th>${t('security.rules.col_detail')}</th><th></th>
    </tr></thead><tbody>${rows.map(h => { const s = _auHistState(h); return `<tr>
      <td style="font-size:11px;white-space:nowrap">${fmtDate(h.fired_at)}</td>
      <td style="font-size:12px">${esc(h.rule_name || h.rule_id)}</td>
      <td><span class="tag ${tag[s]}" style="font-size:10px">${t(label[s])}</span></td>
      <td style="font-size:11px;color:var(--text2)">${s === 'silenced' ? t('automation.silenced_hint') : s === 'pending' ? t('automation.pending_hint') : esc(h.error || h.detail || '')}</td>
      <td>${s === 'err' ? `<button class="btn btn-ghost btn-sm" onclick="_auReplay(${h.id},this)">${t('automation.replay')}</button>` : ''}</td></tr>`; }).join('')}</tbody></table></div>`
      : `<div class="empty"><p>${t('security.rules.no_history')}</p></div>`}`;
}

window._auReplay = async function(id, btn) {
  btn.disabled = true;
  btn.textContent = t('common.loading');
  try {
    await api('POST', `/rules-engine/history/${id}/replay`);
    toast(t('automation.replayed'), 'success');
    pages['automation-history']();
  } catch (e) {
    toast(e.message, 'error');
    btn.disabled = false;
    btn.textContent = t('automation.replay');
  }
};

// ── PAGE: Silences & maintenance ─────────────────────────────────────────────
// Suspend l'exécution des actions du moteur de règles sur une fenêtre de temps,
// pour toutes les règles ou une liste choisie (POST/DELETE /rules-engine/silences).

function _asFmt(iso) {
  try { return fmtDate(iso); } catch { return iso; }
}

pages['automation-silences'] = async function() {
  const content = document.getElementById('content');
  document.getElementById('topbar-actions').innerHTML =
    `<button class="btn btn-primary btn-sm" onclick="_asOpenModal()">${t('automation.new_silence')}</button>`;
  content.innerHTML = `<p style="color:var(--text2)">${t('common.loading')}</p>`;
  try {
    const [silences, rules, alertRules] = await Promise.all([
      api('GET', '/rules-engine/silences'),
      api('GET', '/rules-engine/rules').catch(() => []),
      api('GET', '/alert-rules').catch(() => []),
    ]);
    window._asSilences = silences || [];
    window._asRules = rules || [];
    window._asAlertRules = alertRules || [];
  } catch (e) { toast(e.message, 'error'); window._asSilences = []; window._asRules = []; window._asAlertRules = []; }
  _asRender();
};

function _asRender() {
  const now = new Date();
  const rows = (window._asSilences || []).slice().sort((a, b) => new Date(b.starts_at) - new Date(a.starts_at));
  const ruleName = id => (window._asRules || []).find(r => r.id === id)?.name
    || (window._asAlertRules || []).find(r => r.id === id)?.name || id;
  document.getElementById('content').innerHTML = `
    <p style="margin:0 0 14px;font-size:13px;color:var(--text2)">${t('automation.silences_hint')}</p>
    ${rows.length ? `<div style="display:flex;flex-direction:column;gap:10px">${rows.map(s => {
      const starts = new Date(s.starts_at), ends = new Date(s.ends_at);
      const state = now < starts ? 'pending' : (now > ends ? 'past' : 'active');
      const tag = { active: 'tag-green', pending: 'tag-accent', past: 'tag-neutral' }[state];
      const label = { active: t('automation.silence_active'), pending: t('automation.silence_pending'), past: t('automation.silence_past') }[state];
      const scope = (s.rule_ids && s.rule_ids.length) ? s.rule_ids.map(ruleName).join(', ') : t('automation.silence_all_rules');
      return `<div class="card blueprint" style="padding:14px 16px;display:flex;align-items:flex-start;gap:12px">
        <div style="flex:1;min-width:0">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
            <span style="font-weight:600;font-size:13.5px">${esc(s.name)}</span>
            <span class="tag ${tag}" style="font-size:10px">${label}</span>
          </div>
          <div style="font-size:11.5px;color:var(--text2);margin-top:6px">${_asFmt(s.starts_at)} → ${_asFmt(s.ends_at)}</div>
          <div style="font-size:11.5px;color:var(--text3);margin-top:2px">${t('automation.silence_scope')}: ${esc(scope)}</div>
        </div>
        <button class="btn btn-ghost btn-sm" style="color:var(--red)" onclick="_asDelete('${esc(s.id)}','${esc(s.name)}')" title="${t('common.delete')}">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6"/><path d="M10 11v6M14 11v6"/></svg>
        </button>
      </div>`;
    }).join('')}</div>` : `<div class="empty"><p>${t('automation.no_silences')}</p></div>`}`;
}

window._asOpenModal = function() {
  const rules = window._asRules || [];
  const alertRules = window._asAlertRules || [];
  const pad = n => String(n).padStart(2, '0');
  const toLocal = d => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  const now = new Date();
  const in1h = new Date(now.getTime() + 3600e3);
  const modal = document.createElement('div');
  modal.className = 'modal-overlay';
  modal.innerHTML = `
    <div class="modal" style="max-width:480px;width:100%">
      <div class="modal-header">
        <span class="modal-title">${t('automation.new_silence')}</span>
        <button class="btn-close" onclick="this.closest('.modal-overlay').remove()">✕</button>
      </div>
      <div class="modal-body" style="display:flex;flex-direction:column;gap:12px">
        <div class="field" style="margin:0">
          <label class="field-label">${t('common.name')}</label>
          <input id="as-name" class="input" placeholder="${t('automation.silence_name_ph')}">
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
          <div class="field" style="margin:0"><label class="field-label">${t('automation.starts_at')}</label>
            <input id="as-starts" type="datetime-local" class="input" value="${toLocal(now)}"></div>
          <div class="field" style="margin:0"><label class="field-label">${t('automation.ends_at')}</label>
            <input id="as-ends" type="datetime-local" class="input" value="${toLocal(in1h)}"></div>
        </div>
        <div class="field" style="margin:0">
          <label class="field-label">${t('automation.silence_scope')}</label>
          <select id="as-scope" class="input" style="height:32px" onchange="document.getElementById('as-rules-wrap').style.display=this.value==='rules'?'block':'none'">
            <option value="all">${t('automation.silence_all_rules')}</option>
            <option value="rules">${t('automation.silence_pick_rules')}</option>
          </select>
        </div>
        <div id="as-rules-wrap" style="display:none;max-height:220px;overflow:auto;border:1px solid var(--border);border-radius:8px;padding:8px">
          ${(rules.length ? `<div style="font-size:10.5px;text-transform:uppercase;letter-spacing:.06em;color:var(--text3);margin:2px 0 4px">${t('automation.silence_group_rules')}</div>
          ${rules.map(r => `<label style="display:flex;align-items:center;gap:8px;font-size:12.5px;padding:3px 0">
            <input type="checkbox" class="as-rule" value="${esc(r.id)}"> ${esc(r.name)}</label>`).join('')}` : '')}
          ${(alertRules.length ? `<div style="font-size:10.5px;text-transform:uppercase;letter-spacing:.06em;color:var(--text3);margin:8px 0 4px">${t('automation.silence_group_alert_rules')}</div>
          ${alertRules.map(r => `<label style="display:flex;align-items:center;gap:8px;font-size:12.5px;padding:3px 0">
            <input type="checkbox" class="as-rule" value="${esc(r.id)}"> ${esc(r.name)}</label>`).join('')}` : '')}
          ${(!rules.length && !alertRules.length) ? `<span style="font-size:12px;color:var(--text3)">${t('security.rules.no_rules')}</span>` : ''}
        </div>
      </div>
      <div class="modal-footer">
        <button class="btn btn-ghost" onclick="this.closest('.modal-overlay').remove()">${t('common.cancel')}</button>
        <button class="btn btn-primary" onclick="_asSave()">${t('common.save')}</button>
      </div>
    </div>`;
  document.body.appendChild(modal);
};

window._asSave = async function() {
  const name = document.getElementById('as-name')?.value?.trim();
  const starts = document.getElementById('as-starts')?.value;
  const ends = document.getElementById('as-ends')?.value;
  if (!name || !starts || !ends) { toast(t('automation.silence_fields_required'), 'error'); return; }
  if (new Date(ends) <= new Date(starts)) { toast(t('automation.silence_bad_range'), 'error'); return; }
  const scope = document.getElementById('as-scope')?.value;
  const ruleIds = scope === 'rules'
    ? [...document.querySelectorAll('.as-rule:checked')].map(c => c.value)
    : [];
  try {
    await api('POST', '/rules-engine/silences', {
      name, starts_at: new Date(starts).toISOString(), ends_at: new Date(ends).toISOString(), rule_ids: ruleIds,
    });
    document.querySelector('.modal-overlay')?.remove();
    toast(t('common.saved'), 'success');
    pages['automation-silences']();
  } catch (e) { toast(e.message, 'error'); }
};

window._asDelete = async function(id, name) {
  if (!confirm(t('security.rules.delete_confirm', { name }))) return;
  try {
    await api('DELETE', `/rules-engine/silences/${id}`);
    toast(t('security.rules.deleted'), 'success');
    pages['automation-silences']();
  } catch (e) { toast(e.message, 'error'); }
};
