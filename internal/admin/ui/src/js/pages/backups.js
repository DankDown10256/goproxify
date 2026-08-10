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
    id: 'routing',
    titleKey: 'backups.tab.routing.title',
    descKey: 'backups.tab.routing.desc',
    icon: '<circle cx="12" cy="12" r="2"/><path d="M16.24 7.76a6 6 0 010 8.49"/><path d="M7.76 16.24a6 6 0 010-8.49"/><path d="M19.07 4.93a10 10 0 010 14.14"/><path d="M4.93 19.07a10 10 0 010-14.14"/>',
  },
  {
    id: 'history',
    titleKey: 'backups.tab.history.title',
    descKey: 'backups.tab.history.desc',
    icon: '<polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 102.13-9.36L1 10"/>',
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

  let activeTab = 'snapshots'; // snapshots | schedule | routing | history
  let allProxies = null;
  let draftSchedules = [];
  let histProxyId = '';

  function setTopbar() {
    const actions = document.getElementById('topbar-actions');
    if (activeTab === 'snapshots') {
      actions.innerHTML = `
        <button class="btn btn-primary btn-sm" onclick="createSnapshot()">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-1px;margin-right:5px"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="16"/><line x1="8" y1="12" x2="16" y2="12"/></svg>
          ${t('backups.create_snapshot')}
        </button>`;
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
    if (activeTab === 'snapshots') body = snapshotsTab(snaps, draftSchedules);
    else if (activeTab === 'schedule') body = scheduleTab(draftSchedules);
    else if (activeTab === 'routing') body = routingTab();
    else body = await historyTab();

    content.innerHTML = `${navHtml()}<div id="bk-body">${body}</div>`;

    if (activeTab === 'history' && histProxyId) {
      const sel = document.getElementById('bk-hist-proxy');
      if (sel) sel.value = histProxyId;
      await window.bkLoadHistory(histProxyId);
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
      </div>`;
  }

  function snapshotsTable(snaps, schedules) {
    const nameById = Object.fromEntries((schedules||[]).map(s => [s.id, s.name]));
    if (!snaps.length) return `
      <div class="empty">
        <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="21 8 21 21 3 21 3 8"/><rect x="1" y="3" width="22" height="5"/><line x1="10" y1="12" x2="14" y2="12"/></svg>
        <p>${t('backups.empty_snapshots')}</p>
      </div>`;
    return `<div class="table-wrap"><table>
      <thead><tr><th>${t('common.name')}</th><th>${t('backups.col.schedule')}</th><th>${t('common.size')}</th><th>${t('common.date')}</th><th style="text-align:right">${t('common.actions')}</th></tr></thead>
      <tbody>${snaps.map(s => {
        const ts = new Date(s.created_at).toISOString().slice(0,10);
        const fname = `goproxify-backup-${ts}.gpx-admin-backup`;
        const plan = s.schedule_id ? (nameById[s.schedule_id] || '—') : t('common.manual');
        return `<tr>
          <td style="font-weight:600">${esc(s.name)}</td>
          <td style="color:var(--text2);font-size:12px">${esc(plan)}</td>
          <td style="color:var(--text2);white-space:nowrap">${fmtBytes(s.size_bytes)}</td>
          <td style="font-size:12px;white-space:nowrap">${fmtDate(s.created_at)}</td>
          <td style="display:flex;gap:4px;justify-content:flex-end">
            <button class="btn btn-ghost btn-sm" onclick="bkDownload('${s.id}','${esc(fname)}')" title="${t('common.download')}">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
            </button>
            <button class="btn btn-secondary btn-sm" onclick="restoreSnapshot('${s.id}','${esc(s.name)}')">${t('common.restore')}</button>
            <button class="btn btn-danger btn-sm" onclick="deleteSnapshot('${s.id}','${esc(s.name)}')">${t('common.delete')}</button>
          </td>
        </tr>`;
      }).join('')}</tbody>
    </table></div>`;
  }

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
          <button type="button" class="btn btn-ghost btn-sm" title="${t('common.delete')}" onclick="bkRemoveSchedule('${esc(sch.id)}')" style="margin-left:auto;color:var(--danger,#c44)">
            ${t('common.delete')}
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

  // ── Onglet Routage ────────────────────────────────────────────────────────
  function routingTab() {
    return `
      <div class="card blueprint" style="max-width:560px">
        <div class="card-kicker">${t('backups.kicker.routing')}</div>
        <div class="card-title">${t('backups.routing.title')}</div>
        <p style="color:var(--text2);font-size:13px;margin:12px 0 20px;line-height:1.6">
          ${t('backups.routing.desc')}
        </p>
        <button class="btn btn-primary" onclick="bkDownloadCore()">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-2px;margin-right:5px"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
          ${t('backups.routing.download')}
        </button>
      </div>`;
  }

  window.bkDownloadCore = function() {
    const ts = new Date().toISOString().slice(0,10);
    authDownload('/api/v1/backups/core', `goproxify-routing-${ts}.gpx-core-backup`);
  };

  // ── Onglet Historique ─────────────────────────────────────────────────────
  async function historyTab() {
    if (!allProxies) allProxies = await api('GET', '/proxies').catch(() => []);
    const proxyOpts = allProxies.map(p =>
      `<option value="${esc(p.id)}" ${histProxyId===p.id?'selected':''}>${esc(p.name||p.id)}</option>`).join('');
    return `
      <div class="card blueprint">
        <div class="card-kicker">${t('backups.kicker.versioning')}</div>
        <div class="card-title">${t('backups.history.title')}</div>
        <p style="color:var(--text2);font-size:13px;margin:12px 0 0;line-height:1.5;max-width:520px">
          ${t('backups.history.desc')}
        </p>
        ${allProxies.length ? `
          <div class="field" style="max-width:360px;margin:16px 0 0">
            <label>${t('backups.history.proxy')}</label>
            <select id="bk-hist-proxy" class="input" onchange="bkLoadHistory(this.value)">
              <option value="">${t('backups.history.select_proxy')}</option>
              ${proxyOpts}
            </select>
          </div>
          <div id="bk-hist-body" style="margin-top:16px"></div>
        ` : `<div class="empty"><p>${t('backups.history.no_proxies')}</p></div>`}
      </div>`;
  }

  window.bkLoadHistory = async function(proxyId) {
    histProxyId = proxyId || '';
    const el = document.getElementById('bk-hist-body');
    if (!el || !proxyId) {
      if (el && !proxyId) el.innerHTML = '';
      return;
    }
    el.innerHTML = '<p style="color:var(--text2);font-size:13px">' + t('common.loading') + '</p>';
    const versions = await api('GET', `/backups/proxy-history/${proxyId}`).catch(() => []);
    if (!versions.length) {
      el.innerHTML = '<p style="color:var(--text2);font-size:13px;margin:0">' + t('backups.history.no_versions') + '</p>';
      return;
    }
    const proxy = allProxies.find(p => p.id === proxyId);
    const pName = proxy ? esc(proxy.name||proxy.id) : esc(proxyId);
    el.innerHTML = `<div class="table-wrap"><table>
      <thead><tr><th>${t('common.date')}</th><th>${t('common.note')}</th><th style="text-align:right"></th></tr></thead>
      <tbody>${versions.map(v => `<tr>
        <td style="font-size:12px;white-space:nowrap">${fmtDate(v.created_at)}</td>
        <td style="color:var(--text2);font-size:12px">${esc(v.note||'—')}</td>
        <td style="text-align:right">
          <button class="btn btn-secondary btn-sm" onclick="restoreProxyVersion('${v.id}','${pName}','${fmtDate(v.created_at)}')">${t('common.restore')}</button>
        </td>
      </tr>`).join('')}</tbody>
    </table></div>`;
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
    }));
    try {
      await api('PUT', '/backups/schedule', {schedules});
      toast(t('backups.schedules_saved'), 'success');
      draftSchedules = [];
      await render();
    } catch(err) { toast(err.message, 'error'); }
  };
};

window.createSnapshot = async function() {
  try {
    await api('POST', '/backups/snapshots', {});
    toast(t('backups.snapshot_created'), 'success');
    pages.backups();
  } catch(e) { toast(e.message, 'error'); }
};

window.restoreSnapshot = async function(id, name) {
  if (!confirm(t('backups.restore_confirm', { name }))) return;
  try {
    const res = await api('POST', `/backups/snapshots/${id}/restore`);
    toast(t('backups.restore_result', { proxies: res.proxies||0, users: res.users||0 }), 'success');
    pages.backups();
  } catch(e) { toast(e.message, 'error'); }
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
