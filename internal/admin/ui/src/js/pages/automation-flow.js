// ── PAGE: Éditeur de flux — une règle (condition → action) vue comme un flux.
// Réutilise les champs et la collecte de security.js (ids re-*) pour rester
// strictement équivalent à la fenêtre d'édition des règles.

pages['automation-flow'] = async function() {
  const content = document.getElementById('content');
  document.getElementById('topbar-actions').innerHTML = '';
  content.innerHTML = `<p style="color:var(--text2)">${t('common.loading')}</p>`;
  try { window._reRules = await api('GET', '/rules-engine/rules') || []; }
  catch (e) { toast(e.message, 'error'); window._reRules = []; }
  if (!window._flowSel || (window._flowSel !== 'new' && !window._reRules.some(r => r.id === window._flowSel))) {
    window._flowSel = window._reRules[0]?.id || 'new';
  }
  _flowRender();
};

function _flowCurrent() {
  if (window._flowSel === 'new') {
    return { id: '', name: '', description: '', enabled: true, condition: { type: 'ban_spike' }, action: { type: 'notify' }, cooldown_sec: 300 };
  }
  return window._reRules.find(r => r.id === window._flowSel);
}

function _flowRender() {
  const r = _flowCurrent();
  const isNew = window._flowSel === 'new';
  const sel = (list, cur, id, fn) => `<select id="${id}" class="input" style="height:32px;width:100%" onchange="${fn}(this.value)">${list.map(o =>
    `<option value="${o.value}"${o.value === cur ? ' selected' : ''}>${o.label}</option>`).join('')}</select>`;
  document.getElementById('content').innerHTML = `
    <p style="margin:0 0 14px;font-size:13px;color:var(--text2)">${t('automation.flow_hint')}</p>
    <div class="fl-head">
      <select class="input" style="height:32px;max-width:280px" onchange="_flowSelect(this.value)">
        ${window._reRules.map(x => `<option value="${esc(x.id)}"${x.id === window._flowSel ? ' selected' : ''}>${esc(x.name)}</option>`).join('')}
        <option value="new"${isNew ? ' selected' : ''}>+ ${t('automation.new_rule')}</option>
      </select>
      <input id="re-name" class="input" style="height:32px;flex:1;min-width:200px" value="${esc(r.name)}" placeholder="${t('security.rules.name_ph')}">
      <label style="display:flex;align-items:center;gap:6px;font-size:12.5px"><input type="checkbox" id="re-enabled" ${r.enabled ? 'checked' : ''}>${t('security.rules.enabled')}</label>
      <button class="btn btn-ghost btn-sm" id="flow-sim" ${isNew ? `disabled title="${esc(t('automation.save_first'))}"` : ''} onclick="_flowSimulate()">▶ ${t('automation.simulate')}</button>
      <button class="btn btn-primary btn-sm" onclick="_flowSave()">${t('common.save')}</button>
      ${isNew ? '' : `<button class="btn btn-ghost btn-sm" onclick="_flowVersions()">${t('automation.versions')}</button>`}
      ${isNew ? '' : `<button class="btn btn-ghost btn-sm" style="color:var(--red)" onclick="_flowDelete()">${t('common.delete')}</button>`}
    </div>
    <div class="fl-canvas" id="flow-canvas">
      <div class="fl-node t"><div class="fl-k">${t('automation.node_trigger')}</div>
        ${sel(_COND_TYPES, r.condition?.type, 're-cond-type', '_reUpdateCondFields')}
        <div id="re-cond-fields" style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:10px">${_reCondFieldsHTML(r.condition?.type || 'ban_spike', r.condition || {})}</div></div>
      <div class="fl-wire"></div>
      <div class="fl-node g"><div class="fl-k">${t('automation.node_guard')}</div>
        <label class="field-label">${t('security.rules.cooldown')} <span style="font-weight:400;color:var(--text3)">(${t('automation.seconds')})</span></label>
        <input id="re-cooldown" type="number" class="input" min="60" value="${r.cooldown_sec || 300}"></div>
      <div class="fl-wire"></div>
      <div class="fl-node a"><div class="fl-k">${t('automation.node_action')}</div>
        ${sel(_ACTION_TYPES, r.action?.type, 're-act-type', '_reUpdateActFields')}
        <div id="re-act-fields" style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:10px">${_reActFieldsHTML(r.action?.type || 'notify', r.action || {})}</div></div>
      <div class="fl-wire"></div>
      <div class="fl-node n"><div class="fl-k">${t('automation.node_notify')}</div>
        <p style="margin:0 0 8px;font-size:12.5px;color:var(--text2)">${t('automation.node_notify_hint')}</p>
        <button class="btn btn-ghost btn-sm" onclick="navigate('alerts')">${t('automation.edit_routing')}</button></div>
      <div class="fl-console" id="flow-console" hidden></div>
    </div>
    <input id="re-desc" type="hidden" value="${esc(r.description || '')}">`;
}

window._flowSelect = function(id) {
  window._flowSel = id;
  _flowRender();
};

window._flowSave = async function() {
  const payload = _reCollectRule();
  if (!payload) return;
  try {
    if (window._flowSel === 'new') {
      const res = await api('POST', '/rules-engine/rules', payload);
      window._flowSel = res?.id || 'new';
    } else {
      await api('PUT', `/rules-engine/rules/${window._flowSel}`, payload);
    }
    toast(t('common.saved'), 'success');
    pages['automation-flow']();
  } catch (e) { toast(e.message, 'error'); }
};

window._flowDelete = async function() {
  const r = _flowCurrent();
  if (!r || !confirm(t('security.rules.delete_confirm', { name: r.name }))) return;
  try {
    await api('DELETE', `/rules-engine/rules/${r.id}`);
    toast(t('security.rules.deleted'), 'success');
    window._flowSel = '';
    pages['automation-flow']();
  } catch (e) { toast(e.message, 'error'); }
};

// Historique des versions : un instantané par création/modification/restauration
// (20 derniers conservés par règle), avec retour arrière en un clic.
window._flowVersions = async function() {
  const r = _flowCurrent();
  if (!r) return;
  let versions = [];
  try { versions = await api('GET', `/rules-engine/rules/${r.id}/versions`) || []; }
  catch (e) { toast(e.message, 'error'); return; }
  const body = versions.length
    ? `<div style="display:flex;flex-direction:column;gap:8px;max-height:400px;overflow:auto">${versions.map((v, i) => `
        <div class="card" style="padding:10px 12px;display:flex;align-items:center;gap:10px">
          <div style="flex:1;min-width:0">
            <b>v${v.version}</b>${i === 0 ? ` <span class="tag tag-green" style="font-size:10px">${t('automation.version_current')}</span>` : ''}
            <div style="font-size:11.5px;color:var(--text2)">${fmtDate(v.created_at)} · ${esc(v.condition?.type || '')} → ${esc(v.action?.type || '')}</div>
          </div>
          ${i === 0 ? '' : `<button class="btn btn-ghost btn-sm" onclick="_flowRestoreVersion('${esc(r.id)}',${v.version})">${t('automation.restore')}</button>`}
        </div>`).join('')}</div>`
    : `<p style="font-size:12.5px;color:var(--text3)">${t('automation.no_versions')}</p>`;
  modal(t('automation.versions'), body, `<button class="btn btn-secondary" onclick="closeModal()">${t('common.close')}</button>`);
};

window._flowRestoreVersion = async function(ruleId, version) {
  if (!confirm(t('automation.restore_confirm', { v: version }))) return;
  try {
    await api('POST', `/rules-engine/rules/${ruleId}/versions/${version}/restore`);
    closeModal();
    toast(t('automation.restored', { v: version }), 'success');
    pages['automation-flow']();
  } catch (e) { toast(e.message, 'error'); }
};

// Dry-run réel côté moteur : la condition est évaluée, l'action jamais exécutée.
window._flowSimulate = async function() {
  const nodes = [...document.querySelectorAll('#flow-canvas .fl-node')];
  const con = document.getElementById('flow-console');
  const btn = document.getElementById('flow-sim');
  if (!con || btn.disabled) return;
  btn.disabled = true;
  con.hidden = false;
  con.textContent = `$ dry-run (${t('automation.no_effect')})\n`;
  nodes.forEach(n => n.classList.remove('done', 'run'));
  try {
    const res = await api('POST', `/rules-engine/rules/${window._flowSel}/run?dry_run=true`);
    const lines = [
      t('automation.sim_trigger'),
      res.matched ? t('automation.sim_guard_ok') : t('automation.sim_no_match'),
      res.matched ? t('automation.sim_action') : t('automation.sim_skipped'),
      t('automation.sim_notify'),
    ];
    for (let i = 0; i < nodes.length; i++) {
      nodes[i].classList.add('run');
      await new Promise(ok => setTimeout(ok, 450));
      nodes[i].classList.remove('run');
      const reached = res.matched || i === 0;
      if (reached) nodes[i].classList.add('done');
      con.textContent += `${reached ? '✓' : '·'} ${lines[i]}\n`;
    }
    if (res.detail && Object.keys(res.detail).length) con.textContent += JSON.stringify(res.detail, null, 2);
  } catch (e) { con.textContent += '✗ ' + e.message; }
  btn.disabled = false;
};
