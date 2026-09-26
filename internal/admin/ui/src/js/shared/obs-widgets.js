// ── Widgets d'observabilité partagés (Prism, Synthèse) ───────────────────────
// Rendu HTML pur : les données viennent des endpoints /prism/*, les actions
// passent par des attributs data-prism="…" interprétés par la page hôte.

function obsNum(n) {
  if (n == null) return '0';
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(1) + 'k';
  return String(n);
}

function obsBytes(b) {
  if (!b) return '0 B';
  if (b >= 1e9) return (b / 1e9).toFixed(1) + ' GB';
  if (b >= 1e6) return (b / 1e6).toFixed(1) + ' MB';
  if (b >= 1e3) return (b / 1e3).toFixed(1) + ' KB';
  return b + ' B';
}

function obsKpisHtml(k, timeline) {
  if (!k || typeof k !== 'object' || Array.isArray(k)) return '';
  const delta = (v, inv) => {
    const n = Number(v) || 0;
    if (n === 0) return `<span class="prism-kpi-delta neu">—</span>`;
    const cls = (n > 0) === !inv ? 'up' : 'down';
    return `<span class="prism-kpi-delta ${cls}">${n > 0 ? '↑' : '↓'} ${Math.abs(n).toFixed(1)}%</span>`;
  };
  const uniqueVal = (Number(k.unique_ips) > 0) ? obsNum(k.unique_ips) : '…';
  const errRate = Number(k.error_rate) || 0;
  const avgLat = Number(k.avg_latency_ms) || 0;
  const botShare = Number(k.bot_share) || 0;
  const icoReq = `<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>`;
  const icoBw  = `<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>`;
  const icoErr = `<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
  const icoIp  = `<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87"/><path d="M16 3.13a4 4 0 010 7.75"/></svg>`;
  const icoLat = `<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>`;
  const icoBot = `<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="2" x2="9" y2="4"/><line x1="15" y1="2" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="22"/><line x1="15" y1="20" x2="15" y2="22"/><line x1="20" y1="9" x2="22" y2="9"/><line x1="20" y1="14" x2="22" y2="14"/><line x1="2" y1="9" x2="4" y2="9"/><line x1="2" y1="14" x2="4" y2="14"/></svg>`;
  const tl = timeline || [];
  const spark = (vals, color) => {
    if (vals.length < 3) return '';
    const mx = Math.max(...vals), mn = Math.min(...vals), rng = (mx - mn) || 1;
    const pts = vals.map((v, i) => `${(i / (vals.length - 1) * 100).toFixed(1)},${(34 - (v - mn) / rng * 28).toFixed(1)}`).join(' ');
    return `<svg class="prism-spark" viewBox="0 0 100 38" preserveAspectRatio="none"><polygon points="0,38 ${pts} 100,38" fill="${color}" opacity=".12"/><polyline points="${pts}" fill="none" stroke="${color}" stroke-width="1.4" vector-effect="non-scaling-stroke"/></svg>`;
  };
  const sparkReq = spark(tl.map(p => p.requests || 0), 'var(--accent)');
  const sparkErr = spark(tl.map(p => p.requests ? (p.errors || 0) / p.requests * 100 : 0), 'var(--red)');
  const card = (icon, label, val, foot, sp = '') => `
    <div class="prism-kpi">${sp}
      <div class="prism-kpi-top">
        <span class="prism-kpi-ico">${icon}</span>
        <span class="prism-kpi-label">${label}</span>
      </div>
      <div class="prism-kpi-val">${val}</div>
      <div class="prism-kpi-foot">${foot}</div>
    </div>`;
  return `<div class="prism-kpis">
    ${card(icoReq, t('prism.requests'), obsNum(k.requests), delta(k.requests_delta, false), sparkReq)}
    ${card(icoBw, t('prism.bandwidth'), obsBytes(k.bandwidth), delta(k.bandwidth_delta, false))}
    ${card(icoErr, t('prism.error_rate'), errRate.toFixed(1) + '%', delta(k.error_rate_delta, true), sparkErr)}
    ${card(icoIp, t('prism.unique_ips'), `<span id="prism-kpi-unique-ips">${uniqueVal}</span>`, '')}
    ${card(icoLat, t('prism.latency'), avgLat.toFixed(0) + ' ms', '')}
    ${card(icoBot, t('prism.bot_share'), botShare.toFixed(1) + '%', '')}
  </div>`;
}

function obsTimelineHtml(pts, opts = {}) {
  const bucketLabel = opts.live ? 'minute' : 'heure';
  if (!pts || pts.length === 0) return `<div class="prism-panel-title">${t('prism.requests_per', { bucket: bucketLabel })}</div><p style="color:var(--text3);font-size:13px">${opts.live ? t('prism.wait_traffic') : t('prism.no_period')}</p>`;

  const rawMax = Math.max(...pts.map(p => p.requests), 1);
  const niceMax = (() => {
    const mag = Math.pow(10, Math.floor(Math.log10(rawMax)));
    const steps = [1, 2, 2.5, 5, 10];
    for (const s of steps) { const v = s * mag; if (v >= rawMax) return v; }
    return rawMax;
  })();

  const W = 900, H = 150, padX = 52, padY = 10, padB = 30;
  const chartW = W - padX - 6;
  const chartH = H - padY;
  const toX = i => padX + (pts.length > 1 ? (i / (pts.length - 1)) * chartW : chartW);
  const toY = v => padY + (1 - v / niceMax) * chartH;

  const fmtLabel = v => v >= 1000 ? (v / 1000).toFixed(v % 1000 === 0 ? 0 : 1) + 'k' : String(v);
  const gridVals = [0.33, 0.67, 1].map(f => Math.round(niceMax * f));
  const gridLines = gridVals.map(v => {
    const y = toY(v).toFixed(1);
    return `<line x1="${padX}" y1="${y}" x2="${W - 6}" y2="${y}" stroke="var(--border)" stroke-width="1"/>
      <text x="${padX - 6}" y="${parseFloat(y) + 3.5}" text-anchor="end" font-size="10" fill="var(--text3)" font-family="system-ui,sans-serif">${fmtLabel(v)}</text>`;
  }).join('');
  const baseline = toY(0).toFixed(1);
  const baselineLine = `<line x1="${padX}" y1="${baseline}" x2="${W - 6}" y2="${baseline}" stroke="var(--border)" stroke-width="1.5"/>`;

  function bezier(data, field) {
    if (data.length < 2) return data.map((p, i) => `${i === 0 ? 'M' : 'L'}${toX(i).toFixed(1)},${toY(p[field]).toFixed(1)}`).join(' ');
    let d = `M${toX(0).toFixed(1)},${toY(data[0][field]).toFixed(1)}`;
    for (let i = 0; i < data.length - 1; i++) {
      const x1 = toX(i), y1 = toY(data[i][field]);
      const x2 = toX(i + 1), y2 = toY(data[i + 1][field]);
      const cp = (x2 - x1) * 0.3;
      d += ` C${(x1 + cp).toFixed(1)},${y1.toFixed(1)} ${(x2 - cp).toFixed(1)},${y2.toFixed(1)} ${x2.toFixed(1)},${y2.toFixed(1)}`;
    }
    return d;
  }

  const reqLine = bezier(pts, 'requests');
  const errLine = pts.length > 1 ? bezier(pts, 'errors') : '';
  const area = reqLine + ` L${toX(pts.length - 1).toFixed(1)},${baseline} L${padX},${baseline} Z`;

  const step = Math.ceil(pts.length / 7);
  const xLabels = pts.reduce((acc, p, i) => {
    if (i % step === 0 || i === pts.length - 1) {
      const label = p.bucket.includes('T') ? p.bucket.split('T')[1].slice(0, 5) : p.bucket.slice(5);
      acc.push(`<text x="${toX(i).toFixed(1)}" y="${H + padB - 8}" text-anchor="middle" font-size="10" fill="var(--text3)" font-family="system-ui,sans-serif">${esc(label)}</text>`);
    }
    return acc;
  }, []);

  /* marqueurs visibles sur la ligne principale */
  const showDots = pts.length <= 48;
  const markers = showDots ? pts.map((p, i) => {
    const x = toX(i).toFixed(1), y = toY(p.requests).toFixed(1);
    return `<circle cx="${x}" cy="${y}" r="3" fill="var(--bg2)" stroke="var(--accent)" stroke-width="1.5" pointer-events="none"/>`;
  }).join('') : '';

  /* zones cliquables invisibles par-dessus */
  const hitTargets = pts.map((p, i) => {
    const x = toX(i).toFixed(1), y = toY(p.requests).toFixed(1);
    return `<circle cx="${x}" cy="${y}" r="0" fill="transparent" stroke="transparent" stroke-width="20" style="cursor:pointer"
      data-prism="bucket" data-bucket="${esc(p.bucket)}" title="${esc(p.bucket)} — ${p.requests} req"/>`;
  }).join('');

  const uid = 'pg' + Math.random().toString(36).slice(2, 7);
  return `
    <div class="prism-panel-title">${t('prism.requests_per', { bucket: bucketLabel })} <span style="font-weight:400;color:var(--text3);font-size:11px">· ${t('prism.click_zoom')}</span></div>
    <svg class="prism-svg" viewBox="0 0 ${W} ${H + padB}" preserveAspectRatio="none">
      <defs>
        <linearGradient id="${uid}" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%"   stop-color="var(--accent)" stop-opacity=".12"/>
          <stop offset="60%"  stop-color="var(--accent)" stop-opacity=".04"/>
          <stop offset="100%" stop-color="var(--accent)" stop-opacity="0"/>
        </linearGradient>
        <clipPath id="${uid}c"><rect x="${padX}" y="${padY - 4}" width="${chartW}" height="${chartH + 4}"/></clipPath>
      </defs>
      ${gridLines}
      ${baselineLine}
      <g clip-path="url(#${uid}c)">
        <path d="${area}" fill="url(#${uid})"/>
        <path d="${reqLine}" fill="none" stroke="var(--accent)" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
        ${errLine ? `<path d="${errLine}" fill="none" stroke="var(--red)" stroke-width="1.5" stroke-dasharray="5,4" stroke-linecap="round"/>` : ''}
      </g>
      ${markers}
      ${hitTargets}
      ${xLabels.join('')}
    </svg>
    <div style="display:flex;gap:20px;font-size:11px;color:var(--text3);margin-top:6px">
      <span style="display:flex;align-items:center;gap:6px"><span style="width:16px;height:1.5px;background:var(--accent);border-radius:2px;display:inline-block"></span>Requêtes</span>
      ${errLine ? `<span style="display:flex;align-items:center;gap:6px"><span style="width:16px;height:0;border-top:1.5px dashed var(--red);display:inline-block"></span>${t('prism.errors')}</span>` : ''}
    </div>`;
}

function obsStatusHtml(groups) {
  if (!groups || groups.length === 0) return `<div class="prism-panel-title">${t('prism.http_codes')}</div><p style="color:var(--text3);font-size:13px">${t('prism.no_data')}</p>`;
  const colors = {'2xx':'var(--green)','3xx':'#60a5fa','4xx':'#f59e0b','5xx':'var(--red)'};
  const byGroup = Object.fromEntries(groups.map(g => [g.group, g]));
  const leftGroups = ['4xx', '5xx'].map(key => byGroup[key]).filter(Boolean);
  const rightGroups = ['2xx', '3xx'].map(key => byGroup[key]).filter(Boolean);
  const total = groups.reduce((s, g) => s + g.count, 0);
  const R = 52, CX = 64, CY = 64, sw = 20, circum = 2 * Math.PI * R;
  let offset = 0;
  const arcs = groups.map(g => {
    const pct = total > 0 ? g.count / total : 0;
    const a = {g: g.group, pct, offset, color: colors[g.group] || '#999'}; offset += pct; return a;
  }).filter(a => a.pct > 0).map(a => {
    const dash = a.pct * circum, gap = circum - dash, rot = a.offset * 360 - 90;
    return `<circle cx="${CX}" cy="${CY}" r="${R}" fill="none" stroke="${a.color}" stroke-width="${sw}" stroke-dasharray="${dash.toFixed(2)} ${gap.toFixed(2)}" transform="rotate(${rot.toFixed(2)} ${CX} ${CY})"/>`;
  });
  const okPct = total > 0 ? ((byGroup['2xx']?.count || 0) / total * 100).toFixed(0) : 0;
  const legendCol = (list) => `
    <div class="prism-donut-legend">
      ${list.map(g => `
        <div style="display:flex;align-items:center;gap:6px">
          <div class="prism-legend-dot" style="background:${colors[g.group] || '#999'}"></div>
          <button type="button" class="log-filter-link" data-prism="to-logs-status" data-status="${esc(g.group)}" title="Voir dans les logs"><b style="color:var(--text)">${g.group}</b></button>
          <span style="color:var(--text3)">${obsNum(g.count)} <span style="font-size:10px">(${g.pct.toFixed(1)}%)</span></span>
        </div>
        ${(g.breakdown || []).slice(0, 4).map(b => `<div style="padding-left:16px;font-size:11px;color:var(--text3)">
          <button type="button" class="log-filter-link" data-prism="to-logs-status" data-status="${b.code}" title="${esc(t('prism.filter_logs'))}">${b.code}</button> — ${obsNum(b.count)}
        </div>`).join('')}`).join('')}
    </div>`;
  return `
    <div class="prism-panel-title">Codes HTTP</div>
    <div class="prism-donut">
      ${legendCol(leftGroups)}
      <svg width="128" height="128" viewBox="0 0 128 128" style="flex-shrink:0">
        <circle cx="${CX}" cy="${CY}" r="${R}" fill="none" stroke="var(--bg3)" stroke-width="${sw}"/>
        ${arcs.join('')}
        <text x="${CX}" y="${CY - 4}" text-anchor="middle" font-size="22" font-weight="700" fill="var(--text)">${okPct}%</text>
        <text x="${CX}" y="${CY + 12}" text-anchor="middle" font-size="9" fill="var(--text3)">succès 2xx</text>
        <text x="${CX}" y="${CY + 24}" text-anchor="middle" font-size="9" fill="var(--text3)">${obsNum(total)} req</text>
      </svg>
      ${legendCol(rightGroups)}
    </div>`;
}


// Anomalies détectées côté serveur (/prism/anomalies) → lignes affichables.
function obsAnomalyRows(list) {
  const pl = n => obsNum(n);
  const sub = a => t('pz.an_err_sub', { rate: a.value.toFixed(1), n: pl(a.count) });
  return (list || []).map(a => {
    switch (a.kind) {
      case 'error_spike':
        return { lvl: 'r', ico: '!', title: t('pz.an_spike'), sub: t('pz.an_spike_sub', { n: pl(a.value), at: esc(String(a.subject).replace('T', ' ').slice(5, 16)), avg: a.baseline.toFixed(0) }), act: `data-prism="bucket" data-bucket="${esc(a.subject)}"`, actLabel: t('pz.a_zoom') };
      case 'dominant_ip':
        return { lvl: 'y', ico: '⚑', title: t('pz.an_ip', { ip: esc(a.subject) }), sub: t('pz.an_ip_sub', { pct: a.value.toFixed(0), n: pl(a.count) }), act: a.banned ? '' : `data-prism="ban" data-ip="${esc(a.subject)}"`, actLabel: t('pz.ban_btn') };
      case 'country_errors':
        return { lvl: 'y', ico: '◎', title: t('pz.an_country', { name: esc(a.label) }), sub: sub(a), act: `data-prism="country" data-cc="${esc(a.subject)}"`, actLabel: t('pz.a_detail') };
      case 'backend_errors':
        return { lvl: 'r', ico: '⛌', title: t('pz.an_backend', { name: esc(a.subject || a.label) }), sub: sub(a), act: `data-prism="filter-proxy" data-proxy="${esc(a.subject)}"`, actLabel: t('pz.a_filter') };
      case 'bot_share':
        return { lvl: 'y', ico: '🤖', title: t('pz.an_bots'), sub: t('pz.an_bots_sub', { pct: a.value.toFixed(0) }), act: 'data-prism="tab" data-tab="sources"', actLabel: t('pz.a_see') };
      default:
        return null;
    }
  }).filter(Boolean);
}

function obsAnomaliesHtml(list, opts = {}) {
  const rows = obsAnomalyRows(list).slice(0, opts.limit || 5);
  if (!rows.length) return `<p class="prism-muted">${t('pz.an_none')}</p>`;
  return rows.map(i => `
    <div class="prism-ins">
      <span class="prism-ins-ico ${i.lvl}">${i.ico}</span>
      <div class="prism-ins-txt"><b>${i.title}</b><span>${i.sub}</span></div>
      ${i.act ? `<button type="button" class="btn btn-ghost btn-sm" ${i.act}>${i.actLabel}</button>` : ''}
    </div>`).join('');
}
