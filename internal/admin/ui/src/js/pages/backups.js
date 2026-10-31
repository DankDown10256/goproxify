// ── PAGE: Sauvegardes
// Extrait de pages-all.js — phase 4.

const BK_MAX_SCHEDULES = 5;

function bkWeekdays() {
  return [0, 1, 2, 3, 4, 5, 6].map(v => ({ v, l: t('backups.weekday.' + v) }));
}

function bkMonths() {
  return [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12].map(v => ({ v, l: t('backups.month.' + v) }));
}

function bkFreqOptions() {
  return ['daily', 'weekly', 'monthly', 'yearly'].map(v => ({ v, l: t('backups.freq.' + v) }));
}

const BK_TABS = [
  {
    id: 'snapshots',
    titleKey: 'backups.tab.snapshots.title',
    descKey: 'backups.tab.snapshots.desc',
    icon: '<polyline points="21 8 21 21 3 21 3 8"/><rect x="1" y="3" width="22" height="5"/><line x1="10" y1="12" x2="14" y2="12"/>',
  },
  {
    id: 'schedule',
    titleKey: 'backups.tab.schedule.title',
    descKey: 'backups.tab.schedule.desc',
    icon: '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>',
  },
  {
    id: 'destinations',
    titleKey: 'backups.tab.destinations.title',
    descKey: 'backups.tab.destinations.desc',
    icon: '<path d="M18 10h-1.26A8 8 0 109 20h9a5 5 0 000-10z"/>',
  },
  {
    id: 'key',
    titleKey: 'backups.tab.key.title',
    descKey: 'backups.tab.key.desc',
    icon: '<path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.78 7.78 5.5 5.5 0 017.78-7.78zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>',
  },
];

function bkNewSchedule(partial = {}) {
  return {
    id: partial.id || ('tmp-' + Math.random().toString(36).slice(2, 10)),
    name: partial.name || t('backups.schedule.new_default'),
    enabled: partial.enabled ?? true,
    frequency: partial.frequency || 'daily',
    hour: partial.hour ?? 3,
    minute: partial.minute ?? 0,
    weekday: partial.weekday ?? 1,
    month_day: partial.month_day ?? 1,
    month: partial.month ?? 1,
    cron: partial.cron || '',
    retention: partial.retention ?? 7,
    include_history: !!partial.include_history,
  };
}

function bkPad2(n) { return String(n).padStart(2, '0'); }

function bkFreqLabel(sch) {
  const time = `${bkPad2(sch.hour)}:${bkPad2(sch.minute)}`;
  switch (sch.frequency) {
    case 'weekly': {
      const d = bkWeekdays().find(x => x.v === Number(sch.weekday))?.l || '—';
      return t('backups.freq.weekly_at', { day: d.toLowerCase(), time });
    }
    case 'monthly':
      return t('backups.freq.monthly_at', { day: sch.month_day, time });
    case 'yearly': {
      const m = bkMonths().find(x => x.v === Number(sch.month))?.l || '—';
      return t('backups.freq.yearly_at', { day: sch.month_day, month: m.toLowerCase(), time });
    }
    case 'custom':
      return t('backups.freq.custom_cron', { cron: sch.cron || '—' });
    default:
      return t('backups.freq.daily_at', { time });
  }
}

function bkRetentionHint(sch) {
  return t('backups.freq.retention_hint', {
    summary: bkFreqLabel(sch),
    n: sch.retention ?? 7,
  });
}

// ── PAGE: Sauvegardes ──────────────────────────────────────────────────────
pages.backups = async function() {
  const content = document.getElementById('content');
  content.innerHTML = '<p style="color:var(--text2)">' + t('common.loading') + '</p>';

  let activeTab = 'snapshots'; // snapshots | schedule | destinations
  let draftSchedules = [];

  function setTopbar() {
    const actions = document.getElementById('topbar-actions');
    if (activeTab === 'snapshots') {
      actions.innerHTML = `
        <button class="btn btn-primary btn-sm" onclick="createSnapshot()">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-1px;margin-right:5px"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="16"/><line x1="8" y1="12" x2="16" y2="12"/></svg>
          ${t('backups.create_snapshot')}
        </button>
        <button class="btn btn-secondary btn-sm" onclick="createSnapshot(true)" title="${t('backups.schedule.history_hint')}">${t('backups.create_with_history')}</button>`;
    } else {
      actions.innerHTML = '';
    }
  }

  function authDownload(url, filename) {
    fetch(url, {headers:{'Authorization':'Bearer '+state.token}})
      .then(r => r.blob())
      .then(blob => {
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = filename;
        a.click();
        URL.revokeObjectURL(a.href);
        toast(t('common.download_started'), 'success');
      }).catch(e => toast(t('common.error_msg', { msg: e.message }), 'error'));
  }

  function navHtml() {
    return `
      <div class="page-nav" role="tablist" aria-label="${t('backups.nav_aria')}">
        ${BK_TABS.map(tab => `
          <button type="button" role="tab" class="page-nav-item${activeTab===tab.id?' active':''}"
            aria-selected="${activeTab===tab.id}" onclick="window._bkTab('${tab.id}')">
            <span class="page-nav-icon" aria-hidden="true">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${tab.icon}</svg>
            </span>
            <span>
              <div class="page-nav-title">${t(tab.titleKey)}</div>
              <div class="page-nav-desc">${t(tab.descKey)}</div>
            </span>
          </button>`).join('')}
      </div>`;
  }

  async function render() {
    setTopbar();
    const needsSched = activeTab === 'snapshots' || activeTab === 'schedule';
    const needsSnaps = activeTab === 'snapshots';

    const [status, dests, hosts] = await Promise.all([
      activeTab === 'snapshots' ? api('GET', '/backups/status').catch(() => null) : Promise.resolve(null),
      activeTab === 'destinations' ? api('GET', '/backups/destinations').catch(() => []) : Promise.resolve([]),
      activeTab === 'snapshots' ? api('GET', '/hosts').catch(() => []) : Promise.resolve([]),
    ]);
    const keyStatus = activeTab === 'key' ? await api('GET', '/backups/key').catch(() => null) : null;
    window._bkDests = dests;
    const [cfg, snaps] = await Promise.all([
      needsSched
        ? api('GET', '/backups/schedule').catch(() => ({schedules:[], max: BK_MAX_SCHEDULES}))
        : Promise.resolve({schedules: draftSchedules, max: BK_MAX_SCHEDULES}),
      needsSnaps
        ? api('GET', '/backups/snapshots').catch(() => [])
        : Promise.resolve([]),
    ]);

    if (needsSched && !draftSchedules.length && Array.isArray(cfg.schedules)) {
      draftSchedules = cfg.schedules.map(s => bkNewSchedule(s));
    }

    let body = '';
    if (activeTab === 'snapshots') body = runningBanner(status && status.running) + statusBanner(status) + snapshotsTab(snaps, draftSchedules) + rebuildCard(status, hosts);
    else if (activeTab === 'destinations') body = destinationsTab(dests);
    else if (activeTab === 'key') body = keyTab(keyStatus);
    else body = scheduleTab(draftSchedules);

    content.innerHTML = `${navHtml()}<div id="bk-body">${body}</div>`;

    // Sauvegarde en cours : bouton neutralisé et rafraîchissement automatique tant qu'elle tourne.
    clearTimeout(window._bkPollTimer);
    const run = status && status.running;
    document.querySelectorAll('#topbar-actions button').forEach(b => { b.disabled = !!(run && run.name); });
    if (activeTab === 'snapshots' && run) {
      window._bkPollTimer = setTimeout(() => { if (document.getElementById('bk-body')) render(); }, 2000);
    }
  }

  window._bkTab = function(tab) {
    if (activeTab === 'schedule') readDraftFromDom();
    activeTab = tab;
    render();
  };

  function readDraftFromDom() {
    const cards = [...document.querySelectorAll('[data-bk-sched]')];
    if (!cards.length) return;
    draftSchedules = cards.map(card => {
      const id = card.getAttribute('data-bk-sched');
      const prev = draftSchedules.find(s => s.id === id) || {};
      const freq = card.querySelector('.bk-freq')?.value || 'daily';
      return bkNewSchedule({
        ...prev,
        id,
        name: card.querySelector('.bk-name')?.value.trim() || t('backups.schedule.default_name'),
        enabled: card.querySelector('.bk-enabled')?.checked || false,
        frequency: freq,
        hour: parseInt(card.querySelector('.bk-hour')?.value, 10) || 0,
        minute: parseInt(card.querySelector('.bk-minute')?.value, 10) || 0,
        weekday: parseInt(card.querySelector('.bk-weekday')?.value, 10) || 0,
        month_day: parseInt(card.querySelector('.bk-monthday')?.value, 10) || 1,
        month: parseInt(card.querySelector('.bk-month')?.value, 10) || 1,
        cron: card.querySelector('.bk-cron')?.value.trim() || '',
        retention: parseInt(card.querySelector('.bk-retention')?.value, 10) || 0,
        include_history: card.querySelector('.bk-history')?.checked || false,
      });
    });
  }

  // ── Onglet Snapshots ──────────────────────────────────────────────────────
  function snapshotsTab(snaps, schedules) {
    const enabledN = (schedules || []).filter(s => s.enabled).length;
    const countLabel = snaps.length === 1
      ? t('backups.snapshot_count', { n: snaps.length })
      : t('backups.snapshot_count_n', { n: snaps.length });
    const schedHint = enabledN
      ? (enabledN === 1
        ? t('backups.schedules_active', { n: enabledN })
        : t('backups.schedules_active_n', { n: enabledN }))
      : t('backups.no_schedule_hint');
    return `
      <div class="card blueprint">
        <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:16px;flex-wrap:wrap;margin-bottom:16px">
          <div>
            <div class="card-kicker">${t('backups.kicker.admin')}</div>
            <div class="card-title">${countLabel}</div>
            <p style="color:var(--text2);font-size:13px;margin:8px 0 0;line-height:1.5;max-width:520px">
              ${t('backups.snapshots_desc')}
              ${schedHint}
            </p>
          </div>
        </div>
        ${snapshotsTable(snaps, schedules)}
        <p style="color:var(--text2);font-size:12px;margin:14px 0 0">
          ${t('backups.restore_modal.from_file')}
          <a href="#" onclick="navigate('import');return false">${t('backups.restore_modal.from_file_link')}</a>
        </p>
      </div>`;
  }

  // Reconstruire l'Admin sur une machine neuve (ADR 0019, étape 9) : la commande du launcher, prête à copier. Elle ne contient
  // jamais la clé de sauvegarde, que l'Admin ne montre qu'au superadmin et sur demande.
  function rebuildCard(st, hosts) {
    const list = Array.isArray(hosts) ? hosts : [];
    window._bkRebuildImage = (st && st.launcher_image) || 'ghcr.io/vincamok/goproxify/launcher:preview';
    const hostField = list.length
      ? `<select id="bk-rb-host" class="input" onchange="bkRebuildCmd(true)">${list.map(h => `<option value="${esc(h.name)}" data-addr="${esc(h.addr)}">${esc(h.name)} (${esc(h.addr)})</option>`).join('')}</select>`
      : `<input id="bk-rb-host" class="input" placeholder="${t('backups.rebuild.host_ph')}" oninput="bkRebuildCmd()">`;
    const noKey = st && !st.key_set
      ? `<div style="border-left:3px solid var(--warning,#c80);padding:6px 10px;margin:10px 0;font-size:13px">${t('backups.rebuild.no_key')} <a href="#" onclick="window._bkTab('key');return false">${t('backups.rebuild.key_link')}</a></div>`
      : '';
    setTimeout(() => window.bkRebuildCmd && window.bkRebuildCmd(true), 0);
    return `
      <div class="card" id="bk-rebuild" style="margin-top:12px">
        <div class="card-kicker">${t('backups.rebuild.kicker')}</div>
        <div class="card-title">${t('backups.rebuild.title')}</div>
        <p style="color:var(--text2);font-size:13px;margin:8px 0 0;line-height:1.5;max-width:640px">${t('backups.rebuild.desc')}</p>
        ${noKey}
        <ol style="font-size:13px;line-height:1.6;padding-left:20px;margin:12px 0">
          <li>${t('backups.rebuild.s1')}</li>
          <li>${t('backups.rebuild.s2')}</li>
        </ol>
        <div style="display:flex;gap:12px;flex-wrap:wrap;margin:8px 0">
          <label style="display:flex;flex-direction:column;gap:4px;font-size:12px;color:var(--text2)">${t('backups.rebuild.host')}${hostField}</label>
          <label style="display:flex;flex-direction:column;gap:4px;font-size:12px;color:var(--text2)">${t('backups.rebuild.addr')}
            <input id="bk-rb-addr" class="input" placeholder="192.168.1.50" oninput="bkRebuildCmd()"></label>
        </div>
        <pre id="bk-rb-cmd" style="white-space:pre-wrap;word-break:break-all;font-size:12px;margin:8px 0"></pre>
        <button class="btn btn-secondary btn-sm" onclick="copyText(document.getElementById('bk-rb-cmd').textContent, t('backups.rebuild.copied'))">${t('backups.rebuild.copy')}</button>
        <ol start="3" style="font-size:13px;line-height:1.6;padding-left:20px;margin:12px 0 0">
          <li>${t('backups.rebuild.s3')}</li>
        </ol>
        <p style="color:var(--text2);font-size:12px;margin:10px 0 0">${t('backups.rebuild.or_ui')}</p>
      </div>`;
  }

  window.bkRebuildCmd = function(hostChanged) {
    const host = document.getElementById('bk-rb-host');
    const addr = document.getElementById('bk-rb-addr');
    const out = document.getElementById('bk-rb-cmd');
    if (!host || !out) return;
    const picked = host.selectedOptions && host.selectedOptions[0];
    if (addr && picked && picked.dataset.addr) addr.placeholder = picked.dataset.addr;
    const name = (host.value || '').trim() || '<host>';
    const a = ((addr && addr.value) || '').trim();
    out.textContent = 'docker run --rm \\\n  -v /var/run/docker.sock:/var/run/docker.sock \\\n  -v "$PWD/<file>:/backup/snapshot:ro" \\\n  ' +
      window._bkRebuildImage + ' \\\n  --restore /backup/snapshot --name ' + name + (a ? ' --addr ' + a : '') + ' --backup-key <backup key>';
  };

  function snapshotsTable(snaps, schedules) {
    const nameById = Object.fromEntries((schedules||[]).map(s => [s.id, s.name]));
    if (!snaps.length) return `
      <div class="empty">
        <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="21 8 21 21 3 21 3 8"/><rect x="1" y="3" width="22" height="5"/><line x1="10" y1="12" x2="14" y2="12"/></svg>
        <p>${t('backups.empty_snapshots')}</p>
      </div>`;
    return `<div class="table-wrap"><table>
      <thead><tr><th>${t('common.name')}</th><th>${t('backups.col.schedule')}</th><th>${t('common.size')}</th><th>${t('common.date')}</th><th>${t('backups.col.integrity')}</th><th style="text-align:right">${t('common.actions')}</th></tr></thead>
      <tbody>${snaps.map(s => {
        const ts = new Date(s.created_at).toISOString().slice(0,10);
        const fname = `goproxify-backup-${ts}.gpx-admin-backup`;
        const plan = s.schedule_id ? (nameById[s.schedule_id] || '—') : t('common.manual');
        return `<tr>
          <td style="font-weight:600">${esc(s.name)}</td>
          <td style="color:var(--text2);font-size:12px">${esc(plan)}</td>
          <td style="color:var(--text2);white-space:nowrap">${fmtBytes(s.size_bytes)}</td>
          <td style="font-size:12px;white-space:nowrap">${fmtDate(s.created_at)}</td>
          <td style="font-size:12px">${integrityCell(s)}</td>
          <td style="display:flex;gap:4px;justify-content:flex-end;align-items:center">
            <button class="btn btn-ghost btn-icon" onclick="bkVerify('${s.id}')" title="${t('backups.verify')}">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
            </button>
            <button class="btn btn-ghost btn-icon" onclick="bkDownload('${s.id}','${esc(fname)}')" title="${t('common.download')}">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
            </button>
            <button class="btn btn-ghost btn-icon" onclick="restoreSnapshot('${s.id}','${esc(s.name)}')" title="${t('common.restore')}" style="color:var(--accent)">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 102.13-9.36L1 10"/></svg>
            </button>
            <button class="btn btn-ghost btn-icon" onclick="deleteSnapshot('${s.id}','${esc(s.name)}')" title="${t('common.delete')}" style="color:var(--danger,#c44)">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18"/><path d="M8 6V4a2 2 0 012-2h4a2 2 0 012 2v2"/><path d="M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6"/></svg>
            </button>
          </td>
        </tr>`;
      }).join('')}</tbody>
    </table></div>`;
  }

  function integrityCell(s) {
    const ok = s.verified_at
      ? '<span style="color:var(--success,#2a8)" title="' + esc(s.sha256 || '') + '">✓ ' + t('backups.verified') + '</span>'
      : '<span style="color:var(--warning,#c80)">' + t('backups.not_verified') + '</span>';
    const copies = (s.deliveries || []).map(d => d.ok
      ? '<span style="color:var(--success,#2a8)" title="' + esc(d.at) + '">☁ ' + esc(d.destination) + '</span>'
      : '<span style="color:var(--danger,#c44)" title="' + esc(d.error) + '">☁ ' + esc(d.destination) + ' ✗</span>').join('<br>');
    return ok + (copies ? '<br>' + copies : '');
  }

  function runningBanner(run) {
    if (!run) return '';
    const spin = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" style="flex:none"><path d="M12 2a10 10 0 0110 10"><animateTransform attributeName="transform" type="rotate" from="0 12 12" to="360 12 12" dur="0.9s" repeatCount="indefinite"/></path></svg>';
    const lines = [];
    if (run.name) {
      const secs = run.started_at ? Math.max(0, Math.round((Date.now() - new Date(run.started_at).getTime()) / 1000)) : 0;
      lines.push(t('backups.run.snapshot', { name: esc(run.name), phase: t('backups.run.phase.' + run.phase), secs }));
    }
    if ((run.delivering || []).length) lines.push(t('backups.run.delivering', { names: run.delivering.map(esc).join(', ') }));
    return '<div class="card" role="status" style="margin-bottom:12px;display:flex;gap:10px;align-items:flex-start;border-left:3px solid var(--accent);font-size:13px">' + spin +
      '<div style="line-height:1.6">' + lines.join('<br>') + '</div></div>';
  }

  function statusBanner(st) {
    if (!st) return '';
    const warns = [];
    if (!st.key_set) warns.push(t('backups.warn.no_key'));
    (st.stale || []).forEach(n => warns.push(t('backups.warn.stale', { name: esc(n) })));
    if (st.last_run && !st.last_run.ok && !st.running) warns.push(t('backups.warn.last_failed', { name: esc(st.last_run.name), err: esc(st.last_run.error || '') }));
    const enabled = (st.destinations || []).filter(d => d.enabled);
    if (!enabled.length) warns.push(t('backups.warn.no_destination'));
    enabled.filter(d => d.last_error).forEach(d => warns.push(t('backups.warn.dest_failed', { name: esc(d.name), err: esc(d.last_error) })));
    if (!warns.length) return '<div class="card" style="margin-bottom:12px;color:var(--success,#2a8);font-size:13px">✓ ' + t('backups.status.ok') + '</div>';
    return '<div class="card" style="margin-bottom:12px;border-left:3px solid var(--warning,#c80);font-size:13px"><ul style="margin:0;padding-left:18px;line-height:1.7">' +
      warns.map(w => '<li>' + w + '</li>').join('') + '</ul></div>';
  }

  window.bkVerify = async function(id) {
    try {
      const r = await api('POST', '/backups/snapshots/' + id + '/verify', {});
      if (r.ok) toast(t('backups.verify_ok'), 'success');
      else toast(t('backups.verify_failed', { msg: r.error }), 'error');
      render();
    } catch (e) { toast(e.message, 'error'); }
  };

  // ── Onglet Destinations ───────────────────────────────────────────────────
  function destinationsTab(dests) {
    const rows = dests.length ? dests.map(d => '<tr>' +
      '<td style="font-weight:600">' + esc(d.name) + '</td>' +
      '<td style="color:var(--text2)">' + esc(t('backups.dest.type.' + d.type)) + '</td>' +
      '<td style="color:var(--text2);font-size:12px">' + esc(d.config.path || d.config.url || d.config.endpoint || '') + '</td>' +
      '<td>' + (d.enabled ? t('common.enabled') : t('common.disabled')) + '</td>' +
      '<td>' + (d.retention || '∞') + '</td>' +
      '<td style="display:flex;gap:4px;justify-content:flex-end"><button class="btn btn-ghost btn-sm" onclick="bkDestTest(\'' + d.id + '\')">' + t('backups.dest.test') + '</button>' +
      '<button class="btn btn-ghost btn-sm" onclick="bkDestEdit(\'' + d.id + '\')">' + t('common.edit') + '</button>' +
      '<button class="btn btn-ghost btn-sm" style="color:var(--danger,#c44)" onclick="bkDestDelete(\'' + d.id + '\')">' + t('common.delete') + '</button></td></tr>').join('')
      : '<tr><td colspan="6" style="color:var(--text2)">' + t('backups.dest.empty') + '</td></tr>';
    return '<div class="card blueprint"><div class="card-kicker">' + t('backups.dest.kicker') + '</div>' +
      '<div class="card-title">' + t('backups.tab.destinations.title') + '</div>' +
      '<p style="color:var(--text2);font-size:13px;margin:12px 0;line-height:1.6;max-width:680px">' + t('backups.dest.intro') + '</p>' +
      '<div class="table-wrap"><table><thead><tr><th>' + t('common.name') + '</th><th>' + t('backups.dest.col_type') + '</th><th>' + t('backups.dest.target') + '</th><th>' + t('backups.dest.col_status') + '</th><th>' + t('backups.dest.retention') + '</th><th></th></tr></thead><tbody>' + rows + '</tbody></table></div>' +
      '<div style="margin-top:14px"><button class="btn btn-primary btn-sm" onclick="bkDestEdit(\'\')">' + t('backups.dest.add') + '</button></div></div>';
  }

  window.bkDestEdit = function(id) {
    const d = (window._bkDests || []).find(x => x.id === id) || { type: 'dir', enabled: true, config: {}, retention: 14 };
    const c = d.config || {};
    const f = (key, label, val, type, ph) => '<div class="field"><label>' + label + '</label><input class="input" id="bkd-' + key + '" type="' + (type || 'text') + '" value="' + esc(val || '') + '" placeholder="' + esc(ph || '') + '"></div>';
    const secretPh = k => c[k + '_set'] ? t('backups.dest.secret_kept') : '';
    modal(d.id ? t('backups.dest.edit') : t('backups.dest.add'),
      f('name', t('common.name'), d.name) +
      '<div class="field"><label>' + t('backups.dest.col_type') + '</label><select class="input" id="bkd-type" onchange="bkDestType()">' +
        ['dir', 'webdav', 's3'].map(x => '<option value="' + x + '"' + (d.type === x ? ' selected' : '') + '>' + t('backups.dest.type.' + x) + '</option>').join('') + '</select></div>' +
      '<div data-t="dir">' + f('path', t('backups.dest.path'), c.path, 'text', '/mnt/backup') + '</div>' +
      '<div data-t="webdav">' + f('url', 'URL', c.url, 'text', 'https://cloud.example.com/remote.php/dav/files/me/gpx') + f('username', t('backups.dest.username'), c.username) + f('password', t('backups.dest.password'), '', 'password', secretPh('password')) + '</div>' +
      '<div data-t="s3">' + f('endpoint', 'Endpoint', c.endpoint, 'text', 'https://s3.fr-par.scw.cloud') + f('region', t('backups.dest.region'), c.region, 'text', 'fr-par') + f('bucket', 'Bucket', c.bucket) + f('prefix', t('backups.dest.prefix'), c.prefix) + f('access_key', t('backups.dest.access_key'), c.access_key) + f('secret_key', t('backups.dest.secret_key'), '', 'password', secretPh('secret_key')) + '</div>' +
      f('retention', t('backups.dest.retention_label'), d.retention, 'number') +
      '<label style="display:flex;gap:8px;align-items:center;font-size:13px"><input type="checkbox" id="bkd-enabled"' + (d.enabled ? ' checked' : '') + '> ' + t('common.enable') + '</label>' +
      '<input type="hidden" id="bkd-id" value="' + esc(d.id || '') + '">',
      '<button class="btn btn-secondary btn-sm" onclick="closeModal()">' + t('common.cancel') + '</button><button class="btn btn-primary btn-sm" onclick="bkDestSave()">' + t('common.save') + '</button>');
    bkDestType();
  };

  window.bkDestType = function() {
    const ty = document.getElementById('bkd-type').value;
    document.querySelectorAll('[data-t]').forEach(el => { el.style.display = el.getAttribute('data-t') === ty ? '' : 'none'; });
  };

  window.bkDestSave = async function() {
    const v = k => document.getElementById('bkd-' + k)?.value.trim() || '';
    const type = v('type');
    const keys = { dir: ['path'], webdav: ['url', 'username', 'password'], s3: ['endpoint', 'region', 'bucket', 'prefix', 'access_key', 'secret_key'] }[type];
    const config = {};
    keys.forEach(k => { config[k] = v(k); });
    const id = v('id');
    const body = { name: v('name'), type, enabled: document.getElementById('bkd-enabled').checked, retention: parseInt(v('retention'), 10) || 0, config };
    try {
      await api(id ? 'PUT' : 'POST', '/backups/destinations' + (id ? '/' + id : ''), body);
      closeModal();
      toast(t('backups.dest.saved'), 'success');
      render();
    } catch (e) { toast(e.message, 'error'); }
  };

  window.bkDestTest = async function(id) {
    try {
      const r = await api('POST', '/backups/destinations/' + id + '/test', {});
      toast(r.ok ? t('backups.dest.test_ok') : t('backups.dest.test_failed', { msg: r.error }), r.ok ? 'success' : 'error');
    } catch (e) { toast(e.message, 'error'); }
  };

  window.bkDestDelete = async function(id) {
    if (!confirm(t('backups.dest.delete_confirm'))) return;
    try { await api('DELETE', '/backups/destinations/' + id); render(); } catch (e) { toast(e.message, 'error'); }
  };

  // ── Onglet Clé de chiffrement ─────────────────────────────────────────────
  function keyTab(st) {
    if (!st) return '<div class="card">' + t('backups.key.unavailable') + '</div>';
    const src = t('backups.key.source.' + st.source);
    const fp = st.fingerprint ? '<code>' + esc(st.fingerprint) + '</code>' : '—';
    const env = st.source === 'env';
    const btn = (label, fn, cls) => '<button class="btn ' + (cls || 'btn-secondary') + ' btn-sm" onclick="' + fn + '">' + label + '</button>';
    const retired = (st.retired || []).map(r => '<tr><td><code>' + esc(r.fingerprint) + '</code></td><td style="font-size:12px">' + esc(fmtDate(r.retired_at)) + '</td>' +
      '<td style="display:flex;gap:4px;justify-content:flex-end">' + btn(t('backups.key.reveal'), "bkKeyReveal('" + esc(r.fingerprint) + "')", 'btn-ghost') +
      btn(t('backups.key.forget'), "bkKeyForget('" + esc(r.fingerprint) + "')", 'btn-ghost') + '</td></tr>').join('');
    return '<div class="card blueprint"><div class="card-kicker">' + t('backups.key.kicker') + '</div>' +
      '<div class="card-title">' + t('backups.tab.key.title') + '</div>' +
      '<p style="color:var(--text2);font-size:13px;margin:12px 0;line-height:1.6;max-width:720px">' + t('backups.key.intro') + '</p>' +
      '<div style="display:flex;gap:24px;flex-wrap:wrap;margin:8px 0 14px;font-size:13px"><div><div style="color:var(--text2);font-size:12px">' + t('backups.key.source') + '</div><b>' + src + '</b></div>' +
      '<div><div style="color:var(--text2);font-size:12px">' + t('backups.key.fingerprint') + '</div><b>' + fp + '</b></div></div>' +
      (env ? '<p style="font-size:13px;color:var(--text2)">' + t('backups.key.env_note') + '</p>' : '') +
      '<div style="display:flex;gap:8px;flex-wrap:wrap">' +
        (!env ? btn(st.source === 'file' ? t('backups.key.rotate') : t('backups.key.generate'), 'bkKeyGenerate()', 'btn-primary') : '') +
        (!env ? btn(t('backups.key.enter'), 'bkKeyEnter()') : '') +
        (st.source === 'file' ? btn(t('backups.key.reveal'), "bkKeyReveal('')") : '') +
        (st.source === 'file' ? btn(t('backups.key.deactivate'), 'bkKeyDeactivate()', 'btn-ghost') : '') +
      '</div>' +
      '<div class="bk-sec-t" style="margin-top:22px">' + t('backups.key.retired_title') + '</div>' +
      '<p style="color:var(--text2);font-size:12px;margin:4px 0 8px">' + t('backups.key.retired_desc') + '</p>' +
      '<div class="table-wrap"><table><thead><tr><th>' + t('backups.key.fingerprint') + '</th><th>' + t('backups.key.retired_at') + '</th><th></th></tr></thead><tbody>' +
        (retired || '<tr><td colspan="3" style="color:var(--text2)">' + t('backups.key.retired_none') + '</td></tr>') + '</tbody></table></div>' +
      '<div style="margin-top:10px">' + btn(t('backups.key.add_retired'), 'bkKeyAddRetired()', 'btn-ghost') + '</div></div>';
  }

  function keyShownModal(title, key, fp) {
    modal(title,
      '<p style="font-size:13px;line-height:1.6">' + t('backups.key.shown_warn') + '</p>' +
      '<div style="display:flex;gap:8px;align-items:center;margin:10px 0"><input class="input" id="bkk-shown" readonly value="' + esc(key) + '" style="font-family:monospace">' +
      '<button class="btn btn-secondary btn-sm" onclick="navigator.clipboard.writeText(document.getElementById(\'bkk-shown\').value);toast(t(\'backups.key.copied\'),\'success\')">' + t('backups.key.copy') + '</button></div>' +
      '<div style="font-size:12px;color:var(--text2)">' + t('backups.key.fingerprint') + ' : <code>' + esc(fp) + '</code></div>' +
      '<label style="display:flex;gap:8px;align-items:center;font-size:13px;margin-top:14px"><input type="checkbox" id="bkk-saved" onchange="document.getElementById(\'bkk-close\').disabled=!this.checked"> ' + t('backups.key.saved') + '</label>',
      '<button class="btn btn-primary btn-sm" id="bkk-close" disabled onclick="closeModal();pages.backups()">' + t('common.close') + '</button>');
  }

  window.bkKeyGenerate = async function() {
    if (!confirm(t('backups.key.rotate_confirm'))) return;
    try {
      const r = await api('POST', '/backups/key', { action: 'generate' });
      keyShownModal(t('backups.key.new_title'), r.key, r.fingerprint);
    } catch (e) { toast(e.message, 'error'); }
  };

  window.bkKeyEnter = function() {
    modal(t('backups.key.enter'),
      '<div class="field"><label>' + t('backups.key.key_label') + '</label><input class="input" id="bkk-new" type="password" autocomplete="off" style="font-family:monospace"></div>' +
      '<p style="font-size:12px;color:var(--text2)">' + t('backups.key.min_len') + '</p>',
      '<button class="btn btn-secondary btn-sm" onclick="closeModal()">' + t('common.cancel') + '</button><button class="btn btn-primary btn-sm" onclick="bkKeySave()">' + t('common.save') + '</button>');
  };

  window.bkKeySave = async function() {
    try {
      const r = await api('PUT', '/backups/key', { key: document.getElementById('bkk-new').value });
      closeModal();
      toast(r.rotated ? t('backups.key.rotated') : t('backups.key.saved_ok'), 'success');
      render();
    } catch (e) { toast(e.message, 'error'); }
  };

  window.bkKeyReveal = function(fp) {
    modal(t('backups.key.reveal'),
      '<p style="font-size:13px">' + t('backups.key.reveal_desc') + '</p>' +
      '<div class="field"><label>' + t('backups.dest.password') + '</label><input class="input" id="bkk-pw" type="password" autocomplete="current-password"></div>' +
      '<input type="hidden" id="bkk-fp" value="' + esc(fp) + '">',
      '<button class="btn btn-secondary btn-sm" onclick="closeModal()">' + t('common.cancel') + '</button><button class="btn btn-primary btn-sm" onclick="bkKeyRevealDo()">' + t('backups.key.reveal') + '</button>');
  };

  window.bkKeyRevealDo = async function() {
    try {
      const r = await api('POST', '/backups/key/reveal', { password: document.getElementById('bkk-pw').value, fingerprint: document.getElementById('bkk-fp').value });
      closeModal();
      keyShownModal(t('backups.key.reveal'), r.key, r.fingerprint);
    } catch (e) { toast(e.message, 'error'); }
  };

  window.bkKeyDeactivate = async function() {
    if (!confirm(t('backups.key.deactivate_confirm'))) return;
    try { await api('DELETE', '/backups/key'); render(); } catch (e) { toast(e.message, 'error'); }
  };

  window.bkKeyAddRetired = function() {
    modal(t('backups.key.add_retired'),
      '<p style="font-size:13px">' + t('backups.key.add_retired_desc') + '</p>' +
      '<div class="field"><label>' + t('backups.key.key_label') + '</label><input class="input" id="bkk-old" type="password" autocomplete="off" style="font-family:monospace"></div>',
      '<button class="btn btn-secondary btn-sm" onclick="closeModal()">' + t('common.cancel') + '</button><button class="btn btn-primary btn-sm" onclick="bkKeyAddRetiredDo()">' + t('common.save') + '</button>');
  };

  window.bkKeyAddRetiredDo = async function() {
    try {
      await api('POST', '/backups/key/retired', { key: document.getElementById('bkk-old').value });
      closeModal();
      render();
    } catch (e) { toast(e.message, 'error'); }
  };

  window.bkKeyForget = async function(fp) {
    if (!confirm(t('backups.key.forget_confirm'))) return;
    try { await api('DELETE', '/backups/key/retired/' + fp); render(); } catch (e) { toast(e.message, 'error'); }
  };

  window.bkDownload = function(id, filename) {
    authDownload(`/api/v1/backups/snapshots/${id}`, filename);
  };

  // ── Onglet Planification ──────────────────────────────────────────────────
  function scheduleTab(schedules) {
    const canAdd = schedules.length < BK_MAX_SCHEDULES;
    return `
      <div class="card blueprint">
        <div class="card-kicker">${t('backups.kicker.auto')}</div>
        <div class="card-title">${t('backups.schedule.title')}</div>
        <p style="color:var(--text2);font-size:13px;margin:12px 0 0;line-height:1.6;max-width:640px">
          ${t('backups.schedule.intro', { max: BK_MAX_SCHEDULES })}
        </p>

        <div id="bk-sched-list" style="display:flex;flex-direction:column;gap:14px;margin-top:18px">
          ${schedules.length ? schedules.map((s, i) => scheduleCard(s, i)).join('') : `
            <div class="empty" style="padding:24px">
              <p style="margin:0">${t('backups.schedule.empty')}</p>
            </div>`}
        </div>

        <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:16px">
          <button type="button" class="btn btn-secondary btn-sm" ${canAdd?'':'disabled'} onclick="bkAddSchedule()">
            ${t('backups.schedule.add')}
          </button>
          <span style="color:var(--text2);font-size:12px">${t('backups.schedule.counter', { n: schedules.length, max: BK_MAX_SCHEDULES })}</span>
          <button type="button" class="btn btn-primary btn-sm" style="margin-left:auto" onclick="saveSchedules()">
            ${t('common.save')}
          </button>
        </div>
      </div>`;
  }

  function scheduleCard(sch) {
    const freq = sch.frequency || 'daily';
    const weekdays = bkWeekdays();
    const months = bkMonths();
    const hourOpts = Array.from({length:24}, (_, h) =>
      `<option value="${h}" ${Number(sch.hour)===h?'selected':''}>${bkPad2(h)}</option>`).join('');
    const minOpts = [0,15,30,45].concat(Number(sch.minute) % 15 !== 0 ? [Number(sch.minute)] : [])
      .filter((v,i,a) => a.indexOf(v)===i).sort((a,b)=>a-b)
      .map(m => `<option value="${m}" ${Number(sch.minute)===m?'selected':''}>${bkPad2(m)}</option>`).join('');
    const dayOpts = Array.from({length:28}, (_, i) => i+1)
      .map(d => `<option value="${d}" ${Number(sch.month_day)===d?'selected':''}>${d}</option>`).join('');

    return `
      <div class="bk-sched-card" data-bk-sched="${esc(sch.id)}" style="border:1px solid var(--border);border-radius:8px;padding:14px 16px;background:var(--bg2,transparent)">
        <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:12px">
          <label style="display:flex;align-items:center;gap:8px;font-size:13px;cursor:pointer;margin:0">
            <input type="checkbox" class="bk-enabled" ${sch.enabled?'checked':''}> ${t('common.enable')}
          </label>
          <div class="field" style="margin:0;flex:1;min-width:160px">
            <label>${t('common.name')}</label>
            <input class="input bk-name" value="${esc(sch.name)}" placeholder="${t('backups.schedule.name_ph')}">
          </div>
          <button type="button" class="btn btn-ghost btn-icon" title="${t('common.delete')}" onclick="bkRemoveSchedule('${esc(sch.id)}')" style="margin-left:auto;color:var(--danger,#c44)">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18"/><path d="M8 6V4a2 2 0 012-2h4a2 2 0 012 2v2"/><path d="M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6"/></svg>
          </button>
        </div>

        <div style="display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end">
          <div class="field" style="margin:0;min-width:180px">
            <label>${t('backups.schedule.freq')}</label>
            <select class="input bk-freq" onchange="bkOnFreqChange('${esc(sch.id)}')">
              ${bkFreqOptions().map(f => `<option value="${f.v}" ${freq===f.v?'selected':''}>${f.l}</option>`).join('')}
              ${freq==='custom' ? `<option value="custom" selected>${t('backups.freq.custom')}</option>` : ''}
            </select>
          </div>

          <div class="field bk-when-weekly" style="margin:0;${freq==='weekly'?'':'display:none'}">
            <label>${t('backups.schedule.day')}</label>
            <select class="input bk-weekday">
              ${weekdays.map(d => `<option value="${d.v}" ${Number(sch.weekday)===d.v?'selected':''}>${d.l}</option>`).join('')}
            </select>
          </div>

          <div class="field bk-when-monthly" style="margin:0;${freq==='monthly'||freq==='yearly'?'':'display:none'}">
            <label>${t('backups.schedule.month_day')}</label>
            <select class="input bk-monthday">${dayOpts}</select>
          </div>

          <div class="field bk-when-yearly" style="margin:0;${freq==='yearly'?'':'display:none'}">
            <label>${t('backups.schedule.month')}</label>
            <select class="input bk-month">
              ${months.map(m => `<option value="${m.v}" ${Number(sch.month)===m.v?'selected':''}>${m.l}</option>`).join('')}
            </select>
          </div>

          <div class="field" style="margin:0;${freq==='custom'?'display:none':''}">
            <label>${t('backups.schedule.hour')}</label>
            <div style="display:flex;align-items:center;gap:4px">
              <select class="input bk-hour" style="width:72px">${hourOpts}</select>
              <span style="color:var(--text2)">:</span>
              <select class="input bk-minute" style="width:72px">${minOpts}</select>
            </div>
          </div>

          <div class="field bk-when-custom" style="margin:0;${freq==='custom'?'':'display:none'};min-width:180px">
            <label>${t('backups.schedule.cron')}</label>
            <input class="input bk-cron" value="${esc(sch.cron||'')}" placeholder="0 3 * * *">
          </div>

          <div class="field" style="margin:0">
            <label>${t('backups.schedule.retention')}</label>
            <input type="number" class="input bk-retention" value="${sch.retention ?? 7}" min="1" max="365" style="width:90px" title="${t('backups.schedule.retention_title')}">
          </div>
        </div>

        <label style="display:flex;align-items:center;gap:8px;font-size:13px;margin:12px 0 0;cursor:pointer" title="${t('backups.schedule.history_hint')}">
          <input type="checkbox" class="bk-history" ${sch.include_history ? 'checked' : ''}> ${t('backups.schedule.history')}
        </label>

        <p class="bk-hint" style="color:var(--text2);font-size:12px;margin:10px 0 0">
          ${esc(bkRetentionHint(sch))}
        </p>
      </div>`;
  }

  window.bkOnFreqChange = function(id) {
    readDraftFromDom();
    const card = document.querySelector(`[data-bk-sched="${CSS.escape(id)}"]`);
    if (!card) return;
    const freq = card.querySelector('.bk-freq')?.value || 'daily';
    const sch = draftSchedules.find(s => s.id === id);
    if (sch) sch.frequency = freq;
    card.querySelectorAll('.bk-when-weekly').forEach(el => el.style.display = freq==='weekly' ? '' : 'none');
    card.querySelectorAll('.bk-when-monthly').forEach(el => el.style.display = (freq==='monthly'||freq==='yearly') ? '' : 'none');
    card.querySelectorAll('.bk-when-yearly').forEach(el => el.style.display = freq==='yearly' ? '' : 'none');
    card.querySelectorAll('.bk-when-custom').forEach(el => el.style.display = freq==='custom' ? '' : 'none');
    const timeField = card.querySelector('.bk-hour')?.closest('.field');
    if (timeField) timeField.style.display = freq==='custom' ? 'none' : '';
    const hint = card.querySelector('.bk-hint');
    if (hint && sch) hint.textContent = bkRetentionHint(sch);
  };

  window.bkAddSchedule = function() {
    readDraftFromDom();
    if (draftSchedules.length >= BK_MAX_SCHEDULES) {
      toast(t('backups.max_schedules', { n: BK_MAX_SCHEDULES }), 'error');
      return;
    }
    const presets = [
      {name: t('backups.preset.daily'), frequency:'daily', hour:3, minute:0, retention:7},
      {name: t('backups.preset.monthly'), frequency:'monthly', hour:4, minute:0, month_day:1, retention:12},
      {name: t('backups.preset.yearly'), frequency:'yearly', hour:5, minute:0, month_day:1, month:1, retention:5},
      {name: t('backups.preset.weekly'), frequency:'weekly', hour:2, minute:0, weekday:0, retention:4},
    ];
    const used = new Set(draftSchedules.map(s => s.frequency));
    const preset = presets.find(p => !used.has(p.frequency)) || {name: t('backups.schedule.default_name'), frequency:'daily', hour:3, retention:7};
    draftSchedules.push(bkNewSchedule(preset));
    render();
  };

  window.bkRemoveSchedule = function(id) {
    readDraftFromDom();
    draftSchedules = draftSchedules.filter(s => s.id !== id);
    render();
  };

  await render();

  window.saveSchedules = async function() {
    readDraftFromDom();
    if (draftSchedules.length > BK_MAX_SCHEDULES) {
      toast(t('backups.max_schedules', { n: BK_MAX_SCHEDULES }), 'error');
      return;
    }
    const schedules = draftSchedules.map(s => ({
      id: s.id.startsWith('tmp-') ? undefined : s.id,
      name: s.name,
      enabled: !!s.enabled,
      frequency: s.frequency || 'daily',
      hour: Number(s.hour) || 0,
      minute: Number(s.minute) || 0,
      weekday: Number(s.weekday) || 0,
      month_day: Number(s.month_day) || 1,
      month: Number(s.month) || 1,
      cron: s.cron || '',
      retention: Number(s.retention) || 0,
      include_history: !!s.include_history,
    }));
    try {
      await api('PUT', '/backups/schedule', {schedules});
      toast(t('backups.schedules_saved'), 'success');
      draftSchedules = [];
      await render();
    } catch(err) { toast(err.message, 'error'); }
  };
};

window.createSnapshot = async function(history) {
  try {
    // La sauvegarde tourne en arrière-plan (202) : le bandeau « en cours » suit son avancement.
    await api('POST', '/backups/snapshots', history === true ? { history: true } : {});
    toast(t('backups.snapshot_started'), 'success');
    pages.backups();
  } catch(e) { toast(e.message, 'error'); }
};

let _bkRestoreId = null;
let _bkRestoreCtx = null;

function bkNodeKey(n) { return n.id || (n.role + ':' + n.name); }

// Sélecteur de proxies : restaurer tous les proxies, quelques-uns ou un seul.
function bkProxyPicker(snapProxies, curProxies) {
  const existing = new Set(curProxies.map(p => p.id));
  const rows = snapProxies.map(p => `
    <label class="bk-px-row" data-q="${esc((String(p.name || '') + ' ' + String(p.host || '')).toLowerCase())}" style="display:flex;align-items:center;gap:8px;padding:4px 2px;font-size:13px">
      <input type="checkbox" class="bk-px-cb" value="${esc(p.id)}" checked onchange="bkRestoreRefresh()">
      <span style="font-weight:600">${esc(p.name || p.host || p.id)}</span>
      <span style="color:var(--text2);font-size:12px">${esc(p.host || '')}</span>
      <span style="margin-left:auto;font-size:11px;color:var(--text2)">${existing.has(p.id) ? t('backups.restore_modal.px_exists') : t('backups.restore_modal.px_new')}</span>
      <button type="button" class="btn btn-ghost btn-sm" onclick="event.preventDefault();bkOnlyProxy('${esc(p.id)}')">${t('backups.restore_modal.px_only')}</button>
    </label>`).join('');
  return `
    <div id="bk-px" style="margin-top:12px">
      <div class="bk-sec-t" style="display:flex;align-items:center;gap:10px">
        <span>${t('backups.restore_modal.px_title')}</span>
        <input class="input" id="bk-px-q" placeholder="${t('backups.restore_modal.px_search')}" oninput="bkProxyFilter()" style="max-width:220px;margin-left:auto">
        <a href="#" onclick="bkProxyAll(true);return false">${t('backups.restore_modal.px_all')}</a>
        <a href="#" onclick="bkProxyAll(false);return false">${t('backups.restore_modal.px_none')}</a>
      </div>
      <div style="max-height:190px;overflow:auto;border:1px solid var(--border);border-radius:8px;padding:6px 10px">${rows}</div>
    </div>`;
}

// null = pas de sélecteur (tous) ; sinon l'ensemble des identifiants cochés.
function bkPickedProxies() {
  const cbs = [...document.querySelectorAll('.bk-px-cb')];
  if (!cbs.length) return null;
  return new Set(cbs.filter(c => c.checked).map(c => c.value));
}

function bkProxyIds(proxiesOn) {
  if (!proxiesOn) return [''];
  const cbs = [...document.querySelectorAll('.bk-px-cb')];
  const ids = cbs.filter(c => c.checked).map(c => c.value);
  if (!cbs.length || ids.length === cbs.length) return []; // vide = tous
  return ids.length ? ids : ['']; // [''] = aucun
}

window.bkProxyAll = function(on) {
  document.querySelectorAll('.bk-px-cb').forEach(c => { if (c.closest('.bk-px-row').style.display !== 'none') c.checked = on; });
  bkRenderImplications();
};

window.bkProxyFilter = function() {
  const q = (document.getElementById('bk-px-q')?.value || '').toLowerCase();
  document.querySelectorAll('.bk-px-row').forEach(r => { r.style.display = !q || r.dataset.q.includes(q) ? 'flex' : 'none'; });
};

// « Seul celui-ci » : décoche tout le reste (autres entités, autres proxies).
window.bkOnlyProxy = function(id) {
  document.querySelectorAll('.bk-chip input').forEach(c => { c.checked = c.id === 'bk-rs-proxies'; });
  document.querySelectorAll('.bk-px-cb').forEach(c => { c.checked = c.value === id; });
  bkRenderImplications();
};

// Ce que la restauration implique pour l'infrastructure, selon les cases cochées. Chaque élément :
// niveau (danger | warn | info), titre, explication. Rien n'est supprimé par une restauration :
// ce qui existe maintenant et n'est pas dans le snapshot reste en place.
function bkImplications(c, sel) {
  const s = c.summary || {};
  const out = [];
  const add = (level, key, vars) => out.push({ level, title: t('backups.impl.' + key + '.t', vars), text: t('backups.impl.' + key + '.d', vars) });
  const overwrite = sel.mode === 'overwrite';

  if (sel.proxies) {
    const picked = bkPickedProxies();
    const snap = c.snapProxies.filter(p => !picked || picked.has(p.key));
    const cur = new Set(c.curProxies.map(p => p.key));
    const created = snap.filter(p => !cur.has(p.key)).length;
    const over = snap.filter(p => cur.has(p.key)).length;
    const snapKeys = new Set(c.snapProxies.map(p => p.key));
    const extra = c.curProxies.filter(p => !snapKeys.has(p.key)).length;
    if (created) add('info', 'px_create', { n: created });
    if (over && overwrite) add('warn', 'px_over', { n: over });
    if (over && !overwrite) add('info', 'px_skip', { n: over });
    if (extra) add('info', 'px_extra', { n: extra });
  }

  if (sel.nodes) {
    const cur = new Set(c.curNodes.map(n => n.key));
    const created = c.snapNodes.filter(n => !cur.has(n.key));
    const over = c.snapNodes.filter(n => cur.has(n.key)).length;
    if (created.length) add('warn', 'nodes_create', { n: created.length, names: created.slice(0, 6).map(n => n.name || n.key).join(', ') + (created.length > 6 ? '…' : '') });
    if (over && overwrite) add('info', 'nodes_over', { n: over });
    const snapKeys = new Set(c.snapNodes.map(n => n.key));
    const extra = c.curNodes.filter(n => !snapKeys.has(n.key)).length;
    if (extra) add('info', 'nodes_extra', { n: extra });
  }

  if (sel.config && s.config_row_count) {
    add(overwrite ? 'warn' : 'info', overwrite ? 'config_over' : 'config_skip', { n: s.config_row_count });
  }
  if (sel.users) add('info', sel.secrets ? 'users_secrets' : 'users', { n: s.user_count || 0 });
  if (sel.tokens && !sel.secrets && s.token_count) add('warn', 'tokens', { n: s.token_count });

  if (sel.secrets) {
    const d = s.secrets_detail;
    if (s.secrets_locked) {
      add('danger', 'secrets_locked', {});
    } else {
      add('danger', 'secrets', {});
      if (d && d.gateways && d.gateways.length) add('danger', 'gateways', { n: d.gateways.length, names: d.gateways.join(', ') });
      if (d && d.config_files && d.config_files.length) add('info', 'ha_config', { files: d.config_files.join(', ') });
      add('warn', 'restart_admin', {});
    }
  }
  if (sel.history) add(s.history_locked ? 'danger' : 'info', s.history_locked ? 'history_locked' : 'history', {});
  if (out.length && overwrite) add('info', 'safety', {});
  const rank = { danger: 0, warn: 1, info: 2 };
  return out.sort((a, b) => rank[a.level] - rank[b.level]);
}

function bkImplicationsHtml(c) {
  const checked = id => document.getElementById('bk-rs-' + id)?.checked ?? false;
  const sel = {
    proxies: checked('proxies'), nodes: checked('nodes'), config: checked('config'), users: checked('users'),
    tokens: checked('tokens'), secrets: checked('secrets'), history: checked('history'),
    mode: document.getElementById('bk-rs-conflict')?.value || 'overwrite',
  };
  const items = bkImplications(c, sel);
  if (!items.length) return '';
  const color = { danger: 'var(--danger,#c44)', warn: 'var(--warning,#c80)', info: 'var(--text2)' };
  return `
    <div class="bk-sec-t" style="margin-top:14px">${t('backups.impl.title')}</div>
    <p style="color:var(--text2);font-size:12px;margin:2px 0 8px">${t('backups.impl.intro')}</p>
    <div style="display:flex;flex-direction:column;gap:6px">
      ${items.map(i => `
        <div style="border-left:3px solid ${color[i.level]};padding:4px 10px;font-size:13px;line-height:1.5">
          <b>${esc(i.title)}</b><div style="color:var(--text2);font-size:12px">${esc(i.text)}</div>
        </div>`).join('')}
    </div>`;
}

// Recalcule le panneau « Ce que cela implique » après chaque changement de case, de proxy ou de mode.
function bkRenderImplications() {
  const c = _bkRestoreCtx;
  const el = document.getElementById('bk-impl');
  if (!c || !el) return;
  el.innerHTML = bkImplicationsHtml(c);
}

window.bkRestoreRefresh = bkRenderImplications;

window.restoreSnapshot = async function(id, name) {
  let s, curNodes, curProxies;
  try {
    [s, curNodes, curProxies] = await Promise.all([
      api('GET', `/backups/snapshots/${id}/summary`),
      api('GET', '/declared-nodes').catch(() => []),
      api('GET', '/proxies').catch(() => []),
    ]);
  } catch(e) { toast(e.message, 'error'); return; }

  const entities = [
    ['proxies',  t('trafic.proxies'),          (s.proxies?.length) || 0],
    ['nodes',    t('backups.restore_modal.nodes'), (s.declared_nodes?.length) || 0],
    ['users',    t('import.entity.users'),    s.user_count   || 0],
    ['tokens',   t('import.entity.tokens'),   s.token_count  || 0],
    ['pats',     t('import.entity.pats'),     s.pat_count    || 0],
    ['snippets', t('import.entity.snippets'), s.snippet_count|| 0],
    ['channels', t('import.entity.channels'), s.channel_count|| 0],
    ['rules',    t('import.entity.rules'),    s.rule_count   || 0],
    ['config',   t('import.entity.config'),   s.config_row_count || 0],
    ['secrets',  t('import.entity.secrets'),  s.has_secrets ? '🔒' : 0],
    ['history',  t('import.entity.history'),  s.has_history ? '🔒' : 0],
  ].filter(([,, n]) => n);

  const nodeOf = n => ({ key: bkNodeKey(n), role: n.role || '?', name: n.name, sub: [n.region, n.environment].filter(Boolean).join(' · ') });
  const proxyOf = p => ({ key: p.id, role: 'proxy', name: p.name || p.host || p.id, sub: p.host || '' });
  _bkRestoreId = id;
  _bkRestoreCtx = {
    curNodes: (curNodes || []).filter(n => !String(n.id || '').startsWith('cfg:')).map(nodeOf),
    snapNodes: (s.declared_nodes || []).map(nodeOf),
    curProxies: (curProxies || []).map(proxyOf),
    snapProxies: (s.proxies || []).map(proxyOf),
    summary: s,
  };
  const when = s.created_at ? new Date(s.created_at).toLocaleString() : '';

  const body = entities.length ? `
    <div class="bk-rs-banner">
      <div class="bk-rs-ic"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 1 0 3-6.7"/><path d="M3 4v5h5"/><path d="M12 8v4l3 2"/></svg></div>
      <div><b>${esc(name)}</b><span>${esc(when)}</span></div>
    </div>
    <div id="bk-impl"></div>
    <div class="bk-sec-t">${t('backups.restore_modal.what')}</div>
    <div class="bk-chips">
      ${entities.map(([eid, label, n]) => `
        <label class="bk-chip">
          <input type="checkbox" id="bk-rs-${eid}" ${eid === 'secrets' || eid === 'history' ? '' : 'checked'} onchange="bkRestoreRefresh()">
          <span>${esc(label)}</span><b>${n}</b>
        </label>`).join('')}
    </div>
    ${(s.proxies || []).length ? bkProxyPicker(s.proxies, curProxies || []) : ''}
    <div class="field" style="margin:14px 0 8px">
      <label class="field-label">${t('import.conflict')}</label>
      <select id="bk-rs-conflict" class="input" style="max-width:260px" onchange="bkRestoreRefresh()">
        <option value="overwrite">${t('trafic.overwrite')}</option>
        <option value="skip">${t('trafic.skip_keep')}</option>
      </select>
    </div>
    <p class="bk-note">${t('backups.restore_modal.additive')} ${t('backups.restore_modal.safety')}</p>`
    : `<p style="color:var(--text2);font-size:13px;margin:0">${t('backups.restore_modal.empty')}</p>`;

  modal(
    t('backups.restore_modal.title', { name: esc(name) }),
    body,
    `<button class="btn btn-secondary btn-sm" onclick="closeModal()">${t('common.cancel')}</button>` +
      (entities.length ? `<button class="btn btn-primary btn-sm" id="bk-rs-apply" onclick="applySnapshotRestore()">${t('common.restore')}</button>` : ''),
    true
  );
  bkRenderImplications();
};

window.applySnapshotRestore = async function() {
  const checked = id => document.getElementById('bk-rs-' + id)?.checked ?? false;
  const btn = document.getElementById('bk-rs-apply');
  const selection = {
    // proxy_ids vide = importer tous ; [''] = ID invalide → importer aucun
    proxy_ids:             bkProxyIds(checked('proxies')),
    skip_nodes:            !checked('nodes'),
    import_users:          checked('users'),
    import_tokens:         checked('tokens'),
    import_pats:           checked('pats'),
    import_snippets:       checked('snippets'),
    import_alert_channels: checked('channels'),
    import_alert_rules:    checked('rules'),
    import_config:         checked('config'),
    import_secrets:        checked('secrets'),
    import_history:        checked('history'),
    on_conflict:           document.getElementById('bk-rs-conflict')?.value || 'overwrite',
  };
  if (btn) btn.disabled = true;
  try {
    const res = await api('POST', `/backups/snapshots/${_bkRestoreId}/restore`, { selection });
    closeModal();
    toast(t('backups.restore_result', { proxies: res.proxies||0, users: res.users||0, config: res.config||0 }), 'success');
    const gws = res.gateways || [];
    gws.filter(g => g.error).forEach(g => toast(t('backups.gateway_failed', { name: g.gateway, msg: g.error }), 'error'));
    const need = gws.filter(g => !g.error && g.restart_required).map(g => g.gateway);
    if (need.length) toast(t('backups.gateway_restart', { names: need.join(', ') }), 'info');
    if (res.secrets_error) toast(t('backups.secrets_failed', { msg: res.secrets_error }), 'error');
    if (res.history_error) toast(t('backups.history_failed', { msg: res.history_error }), 'error');
    if (res.secret_files > 0) toast(t('backups.restart_admin'), 'info');
    pages.backups();
  } catch(e) {
    toast(e.message, 'error');
    if (btn) btn.disabled = false;
  }
};

window.deleteSnapshot = async function(id, name) {
  if (!confirm(t('backups.delete_confirm', { name }))) return;
  try {
    await api('DELETE', `/backups/snapshots/${id}`);
    toast(t('backups.snapshot_deleted'), 'success');
    pages.backups();
  } catch(e) { toast(e.message, 'error'); }
};

window.restoreProxyVersion = async function(versionID, proxyName, date) {
  if (!confirm(t('backups.proxy_restore_confirm', { date, name: proxyName }))) return;
  try {
    const res = await api('POST', `/backups/proxy-history/${versionID}/restore`);
    toast(t('backups.proxy_restored', { id: esc(res.proxy_id) }), 'success');
  } catch(e) { toast(e.message, 'error'); }
};
