// ── PAGE: Observabilité › Alertes et SLO (Admin + Passerelle) ────────────────
// SLO de disponibilité, couverture par les règles d'alerte, alertes récentes.
//   Admin (obs-alerts)            → toutes les passerelles, sélecteur de passerelle
//   Passerelle (edge-obs-alerts)  → node_name verrouillé sur la passerelle sélectionnée
// Les règles et canaux se gèrent dans « Règles d'alertes » (page alerts) ; ici on les lit.

// fired_at arrive en UTC, avec ou sans fuseau selon le pilote SQLite.
function oaTs(v) {
  const s = String(v);
  return new Date(/(?:Z|[+-]\d\d:?\d\d)$/i.test(s) ? s : s.replace(' ', 'T') + 'Z');
}

const OBS_AL_DAYS = [['24h', 1], ['7d', 7], ['30d', 30]];
let _obsAlDays = 7;
let _obsAlTrigger = '';
let _obsAlNode = '';

pages['obs-alerts'] = function() { renderObsAlerts({ node_name: '', lock: false }); };
pages['edge-obs-alerts'] = function() { renderObsAlerts({ node_name: edgePrismNodeName(), lock: true }); };

async function renderObsAlerts(scope) {
  const main = document.getElementById('content');
  const node = scope.lock ? scope.node_name : _obsAlNode;
  const nq = node ? '?node_name=' + encodeURIComponent(node) : '';
  main.innerHTML = `<div class="spinner" style="margin:60px auto"></div>`;

  const ev = new URLSearchParams({ limit: '200', days: String(_obsAlDays) });
  if (node) ev.set('node', node);
  if (_obsAlTrigger) ev.set('trigger', _obsAlTrigger);
  const evAll = new URLSearchParams({ limit: '200', days: String(_obsAlDays) });
  if (node) evAll.set('node', node);

  const allEdges = scope.lock ? [] : ((await api('GET', '/nodes').catch(() => [])) || []).filter(n => n.role === 'edge');
  const [slo, sloCfg, rules, channels, triggers, events, allEvents, perEdge] = await Promise.all([
    api('GET', '/prism/slo' + nq).catch(() => null),
    node ? api('GET', '/prism/slo/config' + nq).catch(() => null) : Promise.resolve(null),
    api('GET', '/alert-rules').catch(() => []),
    api('GET', '/alert-channels').catch(() => []),
    api('GET', '/alert-rules/triggers').catch(() => []),
    api('GET', '/alert-events?' + ev).catch(() => []),
    _obsAlTrigger ? api('GET', '/alert-events?' + evAll).catch(() => []) : null,
    Promise.all((node ? [] : allEdges.slice(0, 12)).map(n => api('GET', '/prism/slo?node_name=' + encodeURIComponent(n.node_name || n.display_name || n.id)).catch(() => null))),
  ]);

  const label = id => (triggers.find(x => x.id === id) || {}).label || id;
  const rulesList = Array.isArray(rules) ? rules : [];
  const chans = (Array.isArray(channels) ? channels : []).filter(c => c.enabled);
  const list = Array.isArray(events) ? events : [];
  const forCounts = Array.isArray(allEvents) ? allEvents : list;
  // Reproduit alerting.matchesScope (engine.go) : une règle dont scope.nodes est vide couvre tous
  // les nœuds ; sinon la passerelle affichée doit y figurer. Sans passerelle sélectionnée (vue flotte),
  // l'événement flotte (node_name="") n'est jamais filtré par scope.nodes côté moteur : toute règle active
  // portant slo_burn couvre alors la flotte, quel que soit son scope.
  const ruleCoversNode = r => !node || !(r.scope?.nodes?.length) || r.scope.nodes.includes(node);
  const covered = rulesList.some(r => r.enabled && (r.triggers || []).includes('slo_burn') && ruleCoversNode(r));

  const counts = {};
  forCounts.forEach(e => { counts[e.trigger] = (counts[e.trigger] || 0) + 1; });
  const firedByRule = {};
  forCounts.forEach(e => { firedByRule[e.rule_id] = (firedByRule[e.rule_id] || 0) + 1; });

  const nodeSel = scope.lock ? '' : `
    <select class="form-input" style="max-width:200px" data-oa="node">
      <option value="">${esc(t('obs.syn.all_edges'))}</option>
      ${allEdges.map(n => { const v = n.node_name || n.display_name || n.id; return `<option value="${esc(v)}" ${v === node ? 'selected' : ''}>${esc(n.display_name || n.node_name || n.id)}</option>`; }).join('')}
    </select>`;

  const banner = covered ? '' : `
    <div class="prism-panel" style="margin-bottom:14px;border-color:var(--yellow)">
      <div class="prism-panel-title" style="color:var(--yellow)">${esc(t('oa.no_rule_title'))}</div>
      <p style="margin:0 0 10px;font-size:13px;color:var(--text2)">${esc(t('oa.no_rule_body'))}</p>
      ${chans.length
        ? `<button type="button" class="btn btn-primary btn-sm" data-oa="mkrule">${esc(t('oa.create_rule'))}</button>`
        : `<button type="button" class="btn btn-secondary btn-sm" data-oa="channels">${esc(t('oa.no_channel'))}</button>`}
    </div>`;

  const fleet = !node && perEdge.length ? `
    <div class="prism-panel" style="margin-bottom:14px">
      <div class="prism-panel-title">${esc(t('oa.per_edge'))}</div>
      <table class="prism-table">
        <thead><tr><th>${esc(t('obs.syn.col_edge'))}</th><th>${esc(t('obs.syn.slo_avail'))}</th><th>${esc(t('obs.syn.slo_budget'))}</th><th>${esc(t('obs.syn.slo_burn'))} 1 h</th><th>${esc(t('obs.syn.col_status'))}</th></tr></thead>
        <tbody>${allEdges.slice(0, 12).map((n, i) => {
          const s = perEdge[i];
          if (!s) return `<tr><td><b>${esc(n.display_name || n.node_name || n.id)}</b></td><td colspan="4" class="prism-muted">—</td></tr>`;
          const left = Math.max(0, Math.min(100, s.budget_left_pct));
          const cls = { ok: 'tag-green', warning: 'tag-yellow', critical: 'tag-red', exhausted: 'tag-red' }[s.state] || 'tag-neutral';
          return `<tr style="cursor:pointer" data-oa="edge" data-i="${i}">
            <td><b>${esc(n.display_name || n.node_name || n.id)}</b></td>
            <td>${s.availability.toFixed(s.availability >= 99.9 ? 3 : 2)}%</td>
            <td><span class="prism-bar-bg" style="display:inline-block;width:80px;vertical-align:middle"><span class="prism-bar-fill" style="width:${left}%;background:${left < 20 ? 'var(--red)' : left < 50 ? 'var(--yellow)' : 'var(--green)'}"></span></span> ${left.toFixed(0)}%</td>
            <td>${s.burn_1h.toFixed(1)}×</td>
            <td><span class="tag ${cls}">${esc(t('obs.syn.slo_state_' + s.state))}</span></td></tr>`;
        }).join('')}</tbody>
      </table>
    </div>` : '';

  // Alertes par heure (30 jours max) : regroupement côté navigateur, l'historique est déjà chargé.
  const unit = _obsAlDays <= 1 ? 'hour' : 'day';
  const buckets = new Map();
  list.forEach(e => {
    const d = oaTs(e.fired_at);
    if (isNaN(d)) return;
    const p = n => String(n).padStart(2, '0');
    const k = unit === 'hour' ? `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:00` : `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
    buckets.set(k, (buckets.get(k) || 0) + 1);
  });
  const pts = [...buckets.entries()].sort().map(([bucket, total]) => ({ bucket, total, warn: 0, error: 0 }));

  const chips = [`<button type="button" class="chip${_obsAlTrigger ? '' : ' active'}" data-oa="trigger" data-v="">${esc(t('oa.all'))}</button>`]
    .concat(Object.entries(counts).sort((a, b) => b[1] - a[1]).map(([id, n]) =>
      `<button type="button" class="chip${_obsAlTrigger === id ? ' active' : ''}" data-oa="trigger" data-v="${esc(id)}">${esc(label(id))} <span class="chip-n">${n}</span></button>`)).join('');

  const rows = list.map((e, i) => {
    const d = e.detail && typeof e.detail === 'object' ? e.detail : {};
    const where = d.node_name || d.node || d.domain || '';
    return `<tr style="cursor:pointer" data-oa="event" data-i="${i}">
      <td class="mono">${esc(fmtDate(oaTs(e.fired_at)))}</td>
      <td><b>${esc(label(e.trigger))}</b></td>
      <td>${esc(e.rule_name || '—')}${e.silenced ? ` <span class="tag tag-neutral" style="font-size:10px">${esc(t('oa.silenced'))}</span>` : ''}</td>
      <td class="mono">${esc(where || '—')}</td>
      <td style="color:var(--text2);max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(e.title || e.message_title || '')}</td></tr>`;
  }).join('');

  const rulesCard = `
    <div class="prism-panel" style="margin-top:14px">
      <div class="prism-panel-title"><span>${esc(t('oa.rules'))}</span><button type="button" class="btn btn-secondary btn-sm" data-oa="manage">${esc(t('oa.manage'))}</button></div>
      ${rulesList.length ? `<table class="prism-table"><thead><tr><th>${esc(t('oa.col_rule'))}</th><th>${esc(t('oa.col_triggers'))}</th><th>${esc(t('oa.col_channels'))}</th><th>${esc(t('oa.col_fired'))}</th><th>${esc(t('oa.col_enabled'))}</th></tr></thead>
        <tbody>${rulesList.map(r => `<tr>
          <td><b>${esc(r.name)}</b></td>
          <td style="font-size:12px">${(r.triggers || []).map(x => esc(label(x))).join(', ') || '—'}</td>
          <td>${(r.channels || []).length}</td>
          <td>${firedByRule[r.id] || 0}</td>
          <td><span class="tag ${r.enabled ? 'tag-green' : 'tag-neutral'}">${esc(t(r.enabled ? 'oa.on' : 'oa.off'))}</span></td></tr>`).join('')}</tbody></table>`
        : `<p class="prism-muted">${esc(t('oa.no_rules'))}</p>`}
    </div>`;

  main.innerHTML = `<div id="obs-al-root">
    <div class="prism-filters">
      <div class="prism-fg">${nodeSel}</div>
      ${nodeSel ? '<div class="prism-fg-sep"></div>' : ''}
      <div class="prism-fg" style="gap:4px">${OBS_AL_DAYS.map(([l, d]) => `<button type="button" class="btn btn-secondary btn-sm${d === _obsAlDays ? ' is-active' : ''}" data-oa="days" data-v="${d}">${l}</button>`).join('')}</div>
    </div>
    ${banner}
    ${obsSloCardHTML(slo, { targetAttr: 'data-oa="slo-target"', resetAttr: 'data-oa="slo-reset"', node, isOverride: !!sloCfg?.is_override })}
    ${fleet}
    <div class="prism-panel">
      <div class="prism-panel-title">${esc(t('oa.recent'))}</div>
      <div class="logs-quick"><div class="logs-quick-g">${chips}</div></div>
      <div id="oa-hist">${gpxHistHTML(pts, unit, { attr: 'data-oa-bucket', title: t('oa.hist_title'), hint: '' })}</div>
      ${list.length ? `<div class="tw"><table class="prism-table"><thead><tr><th>${esc(t('oa.col_time'))}</th><th>${esc(t('oa.col_trigger'))}</th><th>${esc(t('oa.col_rule'))}</th><th>${esc(t('oa.col_where'))}</th><th>${esc(t('oa.col_message'))}</th></tr></thead><tbody>${rows}</tbody></table></div>`
        : `<p class="prism-muted">${esc(t('oa.none'))}</p>`}
    </div>
    ${rulesCard}</div>`;

  const root = document.getElementById('obs-al-root');
  const drawer = e => {
    root.querySelector('#oa-drawer')?.remove();
    const d = document.createElement('aside');
    d.id = 'oa-drawer';
    d.className = 'prism-drawer open';
    const detail = e.detail && Object.keys(e.detail).length ? JSON.stringify(e.detail, null, 2) : '';
    d.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <span class="prism-panel-title" style="margin:0">${esc(t('oa.drawer'))}</span>
        <button type="button" class="btn btn-ghost btn-sm" data-oa="close">✕</button>
      </div>
      <div style="font-size:16px;font-weight:600;margin-bottom:4px">${esc(e.title || label(e.trigger))}${e.silenced ? ` <span class="tag tag-neutral" style="font-size:10px;vertical-align:middle">${esc(t('oa.silenced'))}</span>` : ''}</div>
      <div class="prism-muted" style="margin-bottom:12px">${esc(label(e.trigger))} · ${esc(e.rule_name || '—')} · ${esc(fmtDate(oaTs(e.fired_at)))}</div>
      ${e.silenced ? `<p class="prism-muted" style="margin:0 0 12px">${esc(t('oa.silenced_hint'))}</p>` : ''}
      ${e.body ? `<pre class="mono" style="white-space:pre-wrap;word-break:break-word;background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius);padding:10px;font-size:12px;margin:0 0 12px">${esc(e.body)}</pre>` : ''}
      ${detail ? `<div class="prism-panel-title" style="margin:0 0 6px">${esc(t('oa.detail'))}</div><pre class="mono" style="white-space:pre-wrap;word-break:break-word;background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius);padding:10px;font-size:12px;margin:0 0 12px">${esc(detail)}</pre>` : ''}
      <div class="prism-dstats" style="grid-template-columns:1fr"><div class="prism-dstat"><span>${esc(t('oa.col_channels'))}</span><b>${(e.channels || []).length}</b></div><div class="prism-dstat"><span>${esc(t('oa.priority'))}</span><b>${e.priority || 0}</b></div></div>`;
    root.appendChild(d);
  };

  root.onclick = async ev => {
    const el = ev.target.closest('[data-oa],[data-oa-bucket]');
    if (!el) return;
    const act = el.getAttribute('data-oa');
    if (el.hasAttribute('data-oa-bucket')) return;
    if (act === 'days') { _obsAlDays = parseInt(el.dataset.v, 10) || 7; renderObsAlerts(scope); }
    else if (act === 'trigger') { _obsAlTrigger = el.dataset.v || ''; renderObsAlerts(scope); }
    else if (act === 'event') drawer(list[parseInt(el.dataset.i, 10)]);
    else if (act === 'close') root.querySelector('#oa-drawer')?.remove();
    else if (act === 'manage') navigate('alerts');
    else if (act === 'channels') navigate('alert-channels');
    else if (act === 'edge') { const n = allEdges[parseInt(el.dataset.i, 10)]; if (n) selectEdge(n, 'edge-obs-alerts'); }
    else if (act === 'mkrule') {
      try {
        await api('POST', '/alert-rules', { name: t('oa.rule_name'), scope: {}, triggers: ['slo_burn'], channels: chans.map(c => c.id), cooldown_sec: 3600, priority: 5, enabled: true });
        toast(t('oa.rule_created'), 'success');
        renderObsAlerts(scope);
      } catch (e) { toast(e.message, 'error'); }
    }
    else if (act === 'slo-reset') {
      if (!node) return;
      api('DELETE', '/prism/slo/config?node_name=' + encodeURIComponent(node))
        .catch(err => toast(err.message, 'error'))
        .finally(() => renderObsAlerts(scope));
    }
  };
  root.onchange = e => {
    const nodeEl = e.target.closest('[data-oa="node"]');
    if (nodeEl) { _obsAlNode = nodeEl.value; renderObsAlerts(scope); return; }
    const sl = e.target.closest('[data-oa="slo-target"]');
    if (sl) {
      const nqp = node ? '?node_name=' + encodeURIComponent(node) : '';
      api('PUT', '/prism/slo/config' + nqp, { target: parseFloat(sl.value) })
        .catch(err => toast(err.message, 'error'))
        .finally(() => renderObsAlerts(scope));
    }
  };
}
