// Page Ephor : trois onglets (vue d'ensemble, détections, listes et exceptions) et un tiroir de réglages
// qui laisse la page visible pendant l'édition.

const SENT_TABS = ['overview', 'detections', 'lists'];
const SENT_TAB_LABELS = { overview: "Vue d'ensemble", detections: 'Détections', lists: 'Listes et exceptions' };
const SENT_TAB_KEY = 'gpx_ephor_tab';

const SENT_SECTIONS = [
  { id: 'general',    label: 'Général' },
  { id: 'detection',  label: 'Détection' },
  { id: 'behavior',   label: 'Comportement' },
  { id: 'ddos',       label: 'Anti-DDoS' },
  { id: 'riposte',    label: 'Riposte' },
  { id: 'lists',      label: 'Listes' },
  { id: 'exceptions', label: 'Exceptions' },
];

const _sent = { mode: 'admin', edgeCtx: null, cfg: {}, active: [], history: [], tab: 'overview', refs: null, sugg: null };

// Signaux de comportement de la note commune (ADR 0011) : points, et ce qu'ils regardent. Tout signal naît en detect.
const SENT_BEHAVIOR = [
  { key: 'high_4xx_rate', points: '4', what: 'plus de 40 % de 4xx sur la fenêtre' },
  { key: 'path_scanning', points: '3', what: '15 chemins distincts ou plus' },
  { key: 'waf_score_accumulation', points: '3 à 5', what: 'règles WAF déclenchées requête après requête' },
  { key: 'ua_rotation', points: '3', what: '3 User-Agents différents ou plus' },
  { key: 'request_burst', points: '4', what: '30 requêtes en 10 secondes' },
  { key: 'high_post_ratio', points: '2', what: 'plus de 70 % d\'écritures' },
  { key: 'high_path_entropy', points: '2', what: 'chemins presque tous différents' },
  { key: 'distributed_scan', points: '5 à 8', what: '5 IP ou plus du même /24 (/48 IPv6)' },
  { key: 'ua_tls_mismatch', points: '4', what: 'User-Agent de navigateur, suites TLS d\'un client programmatique' },
  { key: 'no_assets', points: '2', what: '25 pages HTML sans image, style ni script' },
  { key: 'regular_interval', points: '2', what: 'requêtes à intervalles presque identiques' },
  { key: 'scan_breadth', points: '3', what: 'chemins distincts en erreur, rapportés au volume' },
  { key: 'asn_aggregate', points: '4', what: 'plusieurs IP du même opérateur (ASN) qui échouent' },
  { key: 'rate_deviation', points: '3', what: 'débit de l\'IP au-dessus du normal appris pour la route et l\'heure' },
  { key: 'fail2ban', points: '5', what: 'décision de Fail2Ban prise en entrée' },
  { key: 'crowdsec', points: '5', what: 'décision de CrowdSec prise en entrée' },
  { key: 'surface_violation', points: '3', what: 'requête hors de la politique de surface du proxy, refusée par le backend' },
];
const SENT_NEW_SIGNALS = new Set(['ua_tls_mismatch', 'no_assets', 'regular_interval', 'scan_breadth', 'asn_aggregate', 'rate_deviation']);

function sentSignalMode(cfg, key) {
  const b = cfg.behavior || {};
  return (b.signals && b.signals[key]) || b.mode || 'detect';
}

function sentDetections(cfg) {
  const lists = cfg.lists || {};
  const custom = cfg.custom_lists || {};
  const wl = cfg.whitelist || {};
  const nCustom = k => (custom[k] || []).length;
  const plural = n => `${n} entrée${n > 1 ? 's' : ''} inline`;
  const rateBanN = cfg.rate_ban_threshold || 1;
  return [
    { key: 'ip', label: 'IP malveillante', section: 'lists', on: !!lists.ip_enabled, score: 5, effect: 'ban', detail: 'Listes de réputation IP', wl: (wl.ips || []).length },
    { key: 'custom_ip', label: 'IP personnalisée', section: 'lists', on: nCustom('ips') > 0, score: 5, effect: 'ban', detail: plural(nCustom('ips')) },
    { key: 'ua', label: 'User-Agent suspect', section: 'lists', on: !!lists.ua_enabled, score: 3, effect: 'ban', detail: 'Scanners et bots connus', wl: (wl.uas || []).length },
    { key: 'custom_ua', label: 'User-Agent personnalisé', section: 'lists', on: nCustom('uas') > 0, score: 3, effect: 'ban', detail: plural(nCustom('uas')) },
    { key: 'path', label: 'Path suspect', section: 'lists', on: !!lists.path_enabled, score: 2, effect: 'ban', detail: 'Chemins sensibles (.env, wp-admin…)', wl: (wl.paths || []).length },
    { key: 'custom_path', label: 'Path personnalisé', section: 'lists', on: nCustom('paths') > 0, score: 2, effect: 'ban', detail: plural(nCustom('paths')) },
    { key: 'rate', label: 'Débit par IP', section: 'detection', on: (cfg.rate_limit || 0) > 0, score: 4, effect: rateBanN > 1 ? `ban après ${rateBanN}` : 'ban',
      detail: `${cfg.rate_limit || 0} req/s sur ${cfg.rate_window || '1s'}` },
    { key: 'error4xx', label: 'Erreurs 4xx répétées', section: 'detection', on: (cfg.error_threshold || 0) > 0, effect: 'ban',
      detail: `${cfg.error_threshold || 0} erreurs sur ${cfg.error_window || '10s'}` },
    { key: 'waf', label: 'Comportement WAF suspect', section: 'waf', on: null, effect: 'ban', detail: 'Score WAF cumulé par IP (profil WAF du proxy)' },
    { key: 'global', label: 'Limite globale', section: 'ddos', on: (cfg.global_rps || 0) > 0, effect: '503', detail: `${cfg.global_rps || 0} req/s toutes IPs (anti-DDoS)` },
  ];
}

// Les bans Ephor portent le motif de la détection (« threat: ua », « waf: comportement suspect »…).
function sentDetectionKey(reason) {
  const r = reason || '';
  if (/^waf:/.test(r)) return 'waf';
  if (/rate/.test(r)) return 'rate';
  if (/4xx/.test(r)) return 'error4xx';
  const m = /^threat:\s*(\w+)$/.exec(r);
  return m ? m[1] : 'other';
}

function sentBanIsActive(b, activeIds) { return activeIds.has(b.id); }

function sentAgo(iso) {
  const ts = new Date(iso).getTime();
  if (!ts) return '—';
  const s = Math.max(0, Math.round((Date.now() - ts) / 1000));
  if (s < 60) return "à l'instant";
  if (s < 3600) return `il y a ${Math.floor(s / 60)} min`;
  if (s < 86400) return `il y a ${Math.floor(s / 3600)} h`;
  return `il y a ${Math.floor(s / 86400)} j`;
}

function sentStats() {
  const activeIds = new Set(_sent.active.map(b => b.id));
  const labels = Object.fromEntries(sentDetections(_sent.cfg).map(d => [d.key, d.label]));
  const dayAgo = Date.now() - 86400000;
  const perIP = {};
  const perKey = {};
  let last24 = 0;
  for (const b of _sent.history) {
    perIP[b.ip] = (perIP[b.ip] || 0) + 1;
    const k = sentDetectionKey(b.reason);
    perKey[k] = (perKey[k] || 0) + 1;
    if (new Date(b.created_at).getTime() >= dayAgo) last24++;
  }
  const activeKey = {};
  for (const b of _sent.active) { const k = sentDetectionKey(b.reason); activeKey[k] = (activeKey[k] || 0) + 1; }
  const repeat = Object.entries(perIP).filter(([, n]) => n > 1).sort((a, b) => b[1] - a[1]);
  const topKey = Object.entries(perKey).sort((a, b) => b[1] - a[1])[0];
  return { activeIds, labels, last24, perIP, perKey, activeKey, repeat, topKey };
}

function sentTile(label, value, sub, color) {
  return `<div class="sec-tile"><div class="sec-tile-label">${label}</div>
    <div class="sec-tile-value" style="${color ? `color:${color};` : ''}${String(value).length > 6 ? 'font-size:18px;line-height:1.3' : ''}">${value}</div>
    ${sub ? `<div style="font-size:11px;color:var(--text3);margin-top:2px">${sub}</div>` : ''}</div>`;
}

function sentCard(title, body, action) {
  return `<div class="card blueprint" style="margin-bottom:16px">
    <div class="card-header"><span class="card-title">${title}</span>${action || ''}</div>
    <div style="padding:0 16px 16px">${body}</div></div>`;
}

const sentNoData = `<p style="color:var(--text2);font-size:13px;padding-top:8px">Aucune donnée</p>`;

function sentChip(label, value, section) {
  return `<button type="button" class="sent-chip" onclick="openEphorSettings('${section}')"><span>${label}</span><b>${value}</b></button>`;
}

function sentViewOverview() {
  const cfg = _sent.cfg;
  const s = sentStats();
  const noBan = (cfg.mode || 'block') !== 'block';
  const tarpitOn = !!cfg.tarpit?.enabled;
  const recent = _sent.history.slice(0, 12);
  const top = s.repeat.slice(0, 8);

  return `
    <div class="sec-grid" style="grid-template-columns:repeat(4,1fr);margin-bottom:16px">
      ${sentTile('Bans actifs', _sent.active.length, 'posés par Ephor', _sent.active.length ? 'var(--red)' : 'var(--green)')}
      ${sentTile('Bans sur 24 h', s.last24, 'nouveaux', s.last24 ? 'var(--yellow)' : 'var(--green)')}
      ${sentTile('IP récidivistes', s.repeat.length, 'bannies plusieurs fois', s.repeat.length ? 'var(--yellow)' : 'var(--green)')}
      ${sentTile('Détection principale', s.topKey ? esc(s.labels[s.topKey[0]] || 'Autres motifs') : '—', s.topKey ? `${s.topKey[1]} ban${s.topKey[1] > 1 ? 's' : ''} au total` : 'aucun ban')}
    </div>
    ${noBan ? '<p style="font-size:12px;color:var(--yellow);margin:0 0 14px">Mode detect : les signaux sont journalisés, aucune IP n\'est bannie ni rejetée.</p>' : ''}
    <div class="sent-chips">
      ${sentChip('Mode', (cfg.mode || 'block') === 'block' ? 'Block' : 'Detect', 'general')}
      ${sentChip('Score seuil', cfg.score_threshold || 0, 'general')}
      ${sentChip('Durée du ban', esc(cfg.ban_duration || '24h') + (cfg.escalation?.enabled ? ` ×${cfg.escalation.factor || 2} par récidive` : ''), 'general')}
      ${sentChip('Débit par IP', cfg.rate_limit > 0 ? `${cfg.rate_limit} req/s` : '—', 'detection')}
      ${sentChip('Erreurs 4xx', `${cfg.error_threshold || 0} / ${esc(cfg.error_window || '10s')}`, 'detection')}
      ${sentChip('Score par IP', cfg.ip_score?.enabled ? `ban à ${cfg.ip_score.ban_threshold || 10}, demi-vie ${esc(cfg.ip_score.half_life || '10m')}` : 'Off', 'detection')}
      ${sentChip('Limite globale', cfg.global_rps > 0 ? `${cfg.global_rps} req/s` : '—', 'ddos')}
      ${sentChip('Tarpit', tarpitOn ? `${(cfg.tarpit.delay_ms || 5000) / 1000} s` : 'Off', 'riposte')}
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:8px" class="sent-two">
      ${sentCard('Décisions récentes', recent.length === 0 ? sentNoData :
        `<div style="display:flex;flex-direction:column;gap:5px;margin-top:8px">${recent.map(b => {
          const on = sentBanIsActive(b, s.activeIds);
          const label = s.labels[sentDetectionKey(b.reason)] || esc(b.reason || 'Autre motif');
          return `<div style="display:flex;align-items:center;gap:8px;font-size:12px;padding:5px 8px;border-radius:6px;background:var(--bg2)" title="${esc(banSignalsText(b.signals))}">
            <span class="tag ${on ? 'tag-red' : 'tag-neutral'}" style="min-width:52px;text-align:center;font-size:10px">${on ? 'ACTIF' : 'EXPIRÉ'}</span>
            <span style="font-family:monospace;color:var(--text1)">${esc(b.ip)}</span>${trBtn(b.ip)}
            <span style="color:var(--text2);flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${label}</span>
            <span style="color:var(--text3);font-size:11px;white-space:nowrap">${sentAgo(b.created_at)}</span></div>`;
        }).join('')}</div>`)}
      ${sentCard('IP récidivistes', top.length === 0 ? sentNoData :
        `<table style="width:100%;border-collapse:collapse;font-size:13px"><thead><tr>
          <th style="text-align:left;padding:8px 6px;border-bottom:1px solid var(--border)">IP</th>
          <th style="text-align:right;padding:8px 6px;border-bottom:1px solid var(--border)">Bans</th>
          <th style="text-align:right;padding:8px 6px;border-bottom:1px solid var(--border)">Statut</th></tr></thead>
          <tbody>${top.map(([ip, n]) => {
            const on = _sent.active.some(b => b.ip === ip);
            return `<tr style="border-bottom:1px solid var(--border)">
              <td style="padding:6px;font-family:monospace;font-size:12px">${esc(ip)}</td>
              <td style="text-align:right;padding:6px"><span class="tag tag-yellow">${n}</span></td>
              <td style="text-align:right;padding:6px">${on ? '<span class="tag tag-red">Banni</span>' : '<span class="tag tag-neutral">Libre</span>'}</td></tr>`;
          }).join('')}</tbody></table>`)}
    </div>
    <div style="text-align:right;margin-bottom:20px">
      <button class="btn btn-ghost btn-sm" onclick="navigate('${securityPageId('bans', _sent.mode)}')">${t('security.view_all_bans') || 'Voir tous les bans'} &rarr;</button>
    </div>`;
}

function sentViewBehavior() {
  const cfg = _sent.cfg;
  const rows = SENT_BEHAVIOR.map(sg => {
    const mode = sentSignalMode(cfg, sg.key);
    const tag = mode === 'block' ? 'tag-red' : mode === 'off' ? 'tag-neutral' : 'tag-yellow';
    return `<tr style="border-bottom:1px solid var(--border);${mode === 'off' ? 'opacity:.55' : ''}">
      <td style="padding:8px 6px"><b>${esc(banSignalLabel(sg.key))}</b> <span style="font-family:monospace;font-size:11px;color:var(--text3)">${sg.key}</span>${SENT_NEW_SIGNALS.has(sg.key) ? ' <span class="tag tag-yellow" style="font-size:10px">nouveau</span>' : ''}</td>
      <td style="padding:8px 6px;font-size:12px;color:var(--text2)">${esc(sg.what)}</td>
      <td style="text-align:right;padding:8px 6px;color:var(--text2)">${sg.points}</td>
      <td style="text-align:right;padding:8px 6px"><span class="tag ${tag}">${mode}</span></td></tr>`;
  }).join('');
  return sentCard('Signaux de comportement', `
    <p style="font-size:12px;color:var(--text2);margin:8px 0 0">La note commune d'une IP additionne son score cumulé et les signaux en <b>block</b> ; ceux en <b>detect</b> sont affichés dans les bans et comptés en note fantôme (<code>gpx_threat_shadow_bans_total</code>).</p>
    <div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:13px;margin-top:8px">
      <thead><tr><th style="text-align:left;padding:8px 6px;border-bottom:1px solid var(--border)">Signal</th><th style="text-align:left;padding:8px 6px;border-bottom:1px solid var(--border)">Ce qu'il regarde</th>
      <th style="text-align:right;padding:8px 6px;border-bottom:1px solid var(--border)">Points</th><th style="text-align:right;padding:8px 6px;border-bottom:1px solid var(--border)">Mode</th></tr></thead>
      <tbody>${rows}</tbody></table></div>`, `<button class="btn btn-ghost btn-sm" onclick="openEphorSettings('behavior')">Régler</button>`);
}

// Ce que chaque passerelle a appris : débit normal par IP, route par route et heure par heure ; base ASN.
function sentViewReferences() {
  const r = _sent.refs;
  if (r === null) return sentCard('Références apprises', '<div class="spinner" style="margin:12px 0"></div>');
  if (r === false) return sentCard('Références apprises', '<p style="font-size:12px;color:var(--text2);margin:8px 0 0">Les passerelles n\'ont pas répondu.</p>');
  const gws = (r.gateways || []);
  if (!gws.length) return sentCard('Références apprises', '<p style="font-size:12px;color:var(--text2);margin:8px 0 0">Aucune passerelle ne répond.</p>');
  const body = gws.map(g => {
    const refs = g.references || [];
    const asn = g.asn?.version ? `base ASN <span class="tr-mono">${esc(g.asn.version)}</span> (${(g.asn.v4_ranges || 0).toLocaleString()} plages IPv4, ${(g.asn.v6_ranges || 0).toLocaleString()} IPv6)` : 'pas de base ASN (installez-la dans Sécurité › ASN : l\'agrégat par ASN reste muet sans elle)';
    const rows = refs.map(x => `<tr style="border-bottom:1px solid var(--border)">
      <td style="padding:6px">${esc(x.route)}</td><td style="padding:6px;text-align:right">${String(x.hour).padStart(2, '0')} h UTC</td>
      <td style="padding:6px;text-align:right">${x.median}</td><td style="padding:6px;text-align:right">${x.threshold}</td>
      <td style="padding:6px;text-align:right">${x.samples}</td>
      <td style="padding:6px;text-align:right"><span class="tag ${x.ready ? 'tag-green' : 'tag-yellow'}" title="${esc('depuis ' + (x.since || '') + ', mise à jour ' + (x.updated || ''))}">${x.ready ? 'fiable' : 'apprentissage'}</span></td></tr>`).join('');
    return `<div style="margin-top:12px"><div style="font-size:12.5px"><b>${esc(g.node_name)}</b> · ${g.profiles || 0} profil${(g.profiles || 0) > 1 ? 's' : ''} en cours · ${asn}</div>
      ${refs.length ? `<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:12.5px;margin-top:6px"><thead><tr style="color:var(--text3)">
        <th style="text-align:left;padding:6px">Route</th><th style="text-align:right;padding:6px">Heure</th><th style="text-align:right;padding:6px" title="requêtes par minute et par IP, 90ᵉ centile des IP sans signal">Médiane</th>
        <th style="text-align:right;padding:6px" title="au-delà, rate_deviation se déclenche">Seuil</th><th style="text-align:right;padding:6px" title="minutes observées pour cette heure">Minutes</th><th style="text-align:right;padding:6px">État</th></tr></thead><tbody>${rows}</tbody></table></div>`
      : '<p style="font-size:12px;color:var(--text2);margin:6px 0 0">Rien d\'appris encore : une référence naît après quelques minutes de trafic sur une route et ne devient fiable qu\'après 24 h.</p>'}</div>`;
  }).join('');
  return sentCard('Références apprises', `<p style="font-size:12px;color:var(--text2);margin:8px 0 0">Débit normal par IP, estimé par médiane et écart absolu médian sur les IP sans signal, borné dans sa dérive. Il ne contient aucune IP.</p>${body}`);
}

async function sentLoadReferences() {
  if (_sent.loadingRefs) return;
  _sent.loadingRefs = true;
  if (_sent.refs === null) {
    try { _sent.refs = await api('GET', `/security/threat-references${window._secEdgeQ || ''}`); } catch { _sent.refs = false; }
  }
  if (_sent.sugg === null) {
    try { _sent.sugg = await api('GET', `/security/threat-config/suggestions${window._secEdgeQ || ''}`); } catch { _sent.sugg = false; }
  }
  _sent.loadingRefs = false;
  if (_sent.tab === 'detections') sentDrawTab();
}

// Seuils proposés à partir des cumuls par minute (sans IP) : l'administrateur accepte, rien n'est appliqué d'office.
function sentViewSuggestions() {
  const s = _sent.sugg;
  if (s === null) return sentCard('Seuils proposés', '<div class="spinner" style="margin:12px 0"></div>');
  const list = (s && s.suggestions) || [];
  if (!list.length) return sentCard('Seuils proposés', '<p style="font-size:12px;color:var(--text2);margin:8px 0 0">Pas encore de trafic agrégé : les passerelles envoient leurs cumuls par minute, une proposition apparaît avec quelques heures de trafic.</p>');
  const cur = _sent.cfg.global_rps || 0;
  const rows = list.map(x => `<tr style="border-bottom:1px solid var(--border)">
    <td style="padding:6px">${esc(x.node_name || '—')}</td>
    <td style="padding:6px;text-align:right" title="médiane / p99 / p99,9 / max, en requêtes par seconde">${x.rps_median} / ${x.rps_p99} / ${x.rps_p999} / ${x.rps_max}</td>
    <td style="padding:6px;text-align:right">${x.error_share} %</td>
    <td style="padding:6px;text-align:right">${x.current_global_rps || '—'}</td>
    <td style="padding:6px;text-align:right">${x.ready ? `<b>${x.suggested_global_rps}</b> req/s` : `<span style="color:var(--text3)">${esc(x.why || '')}</span>`}</td>
    <td style="padding:6px;text-align:right">${x.ready && x.suggested_global_rps !== cur ? `<button class="btn btn-ghost btn-sm" onclick="sentApplySuggestion(${x.suggested_global_rps})">Appliquer</button>` : ''}</td></tr>`).join('');
  return sentCard('Seuils proposés', `<p style="font-size:12px;color:var(--text2);margin:8px 0 0">${esc((s && s.note) || '')}</p>
    <div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:12.5px;margin-top:6px"><thead><tr style="color:var(--text3)">
      <th style="text-align:left;padding:6px">Passerelle</th><th style="text-align:right;padding:6px">Débit normal (req/s)</th><th style="text-align:right;padding:6px">Erreurs</th>
      <th style="text-align:right;padding:6px">Limite globale actuelle</th><th style="text-align:right;padding:6px">Proposée</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`);
}

// « Appliquer » ne fait que remplir le formulaire de réglages : l'administrateur relit, simule et enregistre.
window.sentApplySuggestion = function(rps) {
  const input = document.getElementById('threat-global-rps');
  if (input) input.value = rps;
  window.openEphorSettings('ddos');
};

function sentViewDetections() {
  const cfg = _sent.cfg;
  const s = sentStats();
  const total = _sent.active.length || 1;
  const rows = sentDetections(cfg).map(d => {
    const n = s.activeKey[d.key] || 0;
    const dot = d.on === null ? 'var(--text3)' : d.on ? 'var(--green)' : 'var(--border)';
    const action = d.section === 'waf'
      ? (_sent.mode === 'edge' ? `<button class="btn btn-ghost btn-sm" onclick="navigate('edge-security-waf-profiles')">Profils WAF &rarr;</button>` : '')
      : `<button class="btn btn-ghost btn-sm" onclick="openEphorSettings('${d.section}')">Régler</button>`;
    return `<tr style="border-bottom:1px solid var(--border);${d.on === false ? 'opacity:.55' : ''}">
      <td style="padding:8px 6px"><span class="sent-dot" style="background:${dot}"></span>${d.label} <span style="font-family:monospace;font-size:11px;color:var(--text3)">${d.key}</span></td>
      <td style="padding:8px 6px;font-size:12px;color:var(--text2)">${d.on === false ? 'Désactivée' : d.detail}${d.wl ? ` · ${d.wl} en whitelist` : ''}</td>
      <td style="text-align:right;padding:8px 6px;color:var(--text2)">${d.score ?? '—'}</td>
      <td style="text-align:right;padding:8px 6px"><span class="tag ${d.effect === '503' ? 'tag-yellow' : 'tag-red'}">${d.effect === '503' ? 'rejet 503' : d.effect}</span></td>
      <td style="padding:8px 6px;min-width:110px">${n > 0
        ? `<div style="display:flex;align-items:center;gap:6px"><div class="sent-bar"><i style="width:${Math.round(n / total * 100)}%"></i></div><span class="tag tag-red">${n}</span></div>`
        : '<span style="color:var(--text3)">—</span>'}</td>
      <td style="text-align:right;padding:8px 6px">${action}</td></tr>`;
  }).join('');
  const other = s.activeKey.other ? `<tr><td style="padding:6px;color:var(--text2)" colspan="4">Autres motifs</td>
    <td style="padding:6px"><span class="tag tag-red">${s.activeKey.other}</span></td><td></td></tr>` : '';
  const noBan = (cfg.mode || 'block') !== 'block';
  return sentCard('Détections', `
    ${noBan ? '<p style="font-size:12px;color:var(--yellow);margin:8px 0 0">Mode detect : les signaux sont journalisés, aucune IP n\'est bannie ni rejetée.</p>' : ''}
    <div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:13px;margin-top:8px">
      <thead><tr>
        <th style="text-align:left;padding:8px 6px;border-bottom:1px solid var(--border)">Détection</th>
        <th style="text-align:left;padding:8px 6px;border-bottom:1px solid var(--border)">Configuration</th>
        <th style="text-align:right;padding:8px 6px;border-bottom:1px solid var(--border)" title="Poids dans le score de la requête (seuil : ${cfg.score_threshold || 0})">Score</th>
        <th style="text-align:right;padding:8px 6px;border-bottom:1px solid var(--border)">Effet</th>
        <th style="text-align:left;padding:8px 6px;border-bottom:1px solid var(--border)">Bans actifs</th>
        <th></th></tr></thead>
      <tbody>${rows}${other}</tbody></table></div>`) + sentViewBehavior() + sentViewReferences() + sentViewSuggestions();
}

function sentChips(list, max = 8) {
  if (!list.length) return '<span style="color:var(--text3);font-size:12px">Aucune entrée</span>';
  const shown = list.slice(0, max).map(v => `<span class="sent-entry">${esc(v)}</span>`).join('');
  return shown + (list.length > max ? `<span class="sent-entry" style="opacity:.6">+${list.length - max}</span>` : '');
}

function sentViewLists() {
  const cfg = _sent.cfg;
  const lists = cfg.lists || {};
  const custom = cfg.custom_lists || {};
  const wl = cfg.whitelist || {};
  const group = _sent.edgeCtx?.group;
  const edit = section => `<button class="btn btn-ghost btn-sm" onclick="openEphorSettings('${section}')">Modifier</button>`;
  const ref = [
    ['IP connues', 'Firehol L1', lists.ip_enabled],
    ['User-Agents malveillants', 'scanners et bots', lists.ua_enabled],
    ['Paths suspects', 'chemins de scan', lists.path_enabled],
  ];
  const three = (a, b, c) => `<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:14px" class="sent-two">${[a, b, c].map(([label, items]) =>
    `<div><div style="font-size:12px;font-weight:600;color:var(--text2);margin:10px 0 6px">${label} <span style="color:var(--text3);font-weight:400">(${items.length})</span></div>
      <div style="display:flex;flex-wrap:wrap;gap:4px">${sentChips(items)}</div></div>`).join('')}</div>`;
  return `
    ${sentCard('Listes de référence', `
      <div style="margin-top:8px">${ref.map(([label, sub, on]) => `<div class="sent-row">
        <span class="sent-dot" style="background:${on ? 'var(--green)' : 'var(--border)'}"></span>
        <span>${label}</span><span style="color:var(--text3);font-size:12px">${sub}</span>
        <span class="tag ${on ? 'tag-green' : 'tag-neutral'}" style="margin-left:auto">${on ? 'Activée' : 'Désactivée'}</span></div>`).join('')}</div>
      <p style="font-size:12px;color:var(--text2);margin:10px 0 0">Rafraîchies toutes les <b>${esc(lists.refresh_interval || '6h')}</b>.${group
        ? ` Dans le groupe HA <b>${esc(group.name)}</b>, les listes sont échangées entre passerelles : la plus récente l'emporte.` : ''}</p>`, edit('lists'))}
    ${sentCard('Listes personnalisées', three(['IPs / CIDRs bloqués', custom.ips || []], ['User-Agents bloqués', custom.uas || []], ['Paths bloqués', custom.paths || []]), edit('lists'))}
    ${sentCard('Exceptions (liste blanche)', three(['IPs / CIDRs de confiance', wl.ips || []], ['User-Agents autorisés', wl.uas || []], ['Paths exclus', wl.paths || []]), edit('exceptions'))}
    ${_sent.mode === 'edge' ? sentCard('Profil WAF', `<p style="font-size:12px;color:var(--text2);margin:8px 0 10px">Le score WAF cumulé par IP alimente la détection « comportement WAF suspect ».</p>
      <button class="btn btn-ghost btn-sm" onclick="navigate('edge-security-waf-profiles')">Voir les profils WAF &rarr;</button>`) : ''}`;
}

function sentDrawerForm(cfg) {
  const mode = cfg.mode || 'block';
  const lists = cfg.lists || {};
  const custom = cfg.custom_lists || {};
  const wl = cfg.whitelist || {};
  const fld = (label, hint, input) => `<div class="field" style="margin:0 0 10px"><label class="field-label">${label}${hint ? ` <span style="font-weight:400;color:var(--text3)">${hint}</span>` : ''}</label>${input}</div>`;
  const sec = (id, title, body) => `<section id="sent-sec-${id}" class="sent-sec"><h4>${title}</h4>${body}</section>`;
  const chk = (id, on, label) => `<label style="display:flex;align-items:center;gap:6px;font-size:12.5px;margin-bottom:6px"><input type="checkbox" id="${id}" ${on ? 'checked' : ''}>${label}</label>`;
  const ta = (id, rows, ph, arr) => `<textarea id="${id}" class="input" rows="${rows}" placeholder="${ph}">${esc((arr || []).join('\n'))}</textarea>`;
  return `
    ${sec('general', 'Général', `
      ${fld('Mode', '', `<select id="threat-mode" class="input" style="height:32px"><option value="block" ${mode === 'block' ? 'selected' : ''}>Block — bannir</option><option value="detect" ${mode === 'detect' ? 'selected' : ''}>Detect — journaliser</option></select>`)}
      ${fld('Score seuil', '(0 = premier signal)', `<input id="threat-score" type="number" class="input" value="${cfg.score_threshold || 0}" min="0" placeholder="0">`)}
      ${fld(t('security.threat.ban_duration'), '', `<input id="threat-dur" class="input" value="${esc(cfg.ban_duration || '24h')}" placeholder="24h">`)}
      <p style="font-size:12px;color:var(--text2);margin:10px 0">Bans graduels : une IP déjà bannie par Ephor récemment l'est plus longtemps (durée × facteur à chaque récidive). Un déban manuel remet le compteur à zéro.</p>
      ${chk('threat-esc-on', cfg.escalation?.enabled, 'Activer les bans graduels')}
      ${fld('Facteur par récidive', '(défaut 2 : 24 h, 48 h, 96 h…)', `<input id="threat-esc-factor" type="number" class="input" value="${cfg.escalation?.factor || ''}" min="1.1" step="0.1" placeholder="2">`)}
      ${fld('Fenêtre de récidive', '(défaut 168h = 7 jours, max 720h)', `<input id="threat-esc-window" class="input" value="${esc(cfg.escalation?.window || '')}" placeholder="168h">`)}
      ${fld('Durée maximale d\'un ban', '(défaut 720h = 30 jours)', `<input id="threat-esc-max" class="input" value="${esc(cfg.escalation?.max_duration || '')}" placeholder="720h">`)}`)}
    ${sec('detection', 'Détection', `
      ${fld(t('security.threat.rate_limit'), '(req/s par IP, 0 = désactivé)', `<input id="threat-rate" type="number" class="input" value="${cfg.rate_limit || 0}" min="0" step="0.5" placeholder="0 = désactivé">`)}
      ${fld('Fenêtre rate', '(ex : 1s)', `<input id="threat-rate-window" class="input" value="${esc(cfg.rate_window || '1s')}" placeholder="1s">`)}
      ${fld('Ban auto rate — seuil', '(déclenchements avant ban, 1 = immédiat)', `<input id="threat-rate-ban-threshold" type="number" class="input" value="${cfg.rate_ban_threshold || 1}" min="1" placeholder="1">`)}
      ${fld('Ban auto rate — fenêtre', '(ex : 10s)', `<input id="threat-rate-ban-window" class="input" value="${esc(cfg.rate_ban_window || '')}" placeholder="= fenêtre rate">`)}
      ${fld(t('security.threat.error_threshold'), '', `<input id="threat-errs" type="number" class="input" value="${cfg.error_threshold || 20}" min="1">`)}
      ${fld(t('security.threat.error_window'), '', `<input id="threat-ewin" class="input" value="${esc(cfg.error_window || '10s')}" placeholder="10s">`)}
      <p style="font-size:12px;color:var(--text2);margin:10px 0">Score cumulé par IP : chaque signal ajoute des points (chemin sensible 2, User-Agent suspect 3, débit 4) qui s'estompent avec le temps. L'IP n'est bannie qu'au seuil ; les IP des listes de menaces le sont tout de suite. Remplace le ban auto rate ci-dessus.</p>
      ${chk('threat-score-on', cfg.ip_score?.enabled, 'Activer le score cumulé par IP')}
      ${fld('Score — seuil de ban', '(défaut 10)', `<input id="threat-score-ban" type="number" class="input" value="${cfg.ip_score?.ban_threshold || ''}" min="1" step="1" placeholder="10">`)}
      ${fld('Score — demi-vie', '(le score est divisé par deux à chaque demi-vie, défaut 10m)', `<input id="threat-score-halflife" class="input" value="${esc(cfg.ip_score?.half_life || '')}" placeholder="10m">`)}
      <p style="font-size:12px;color:var(--text2);margin:10px 0">Erreurs 4xx pondérées : chaque 4xx ajoute des points au score (400, 405 : 1 ; 404 et autres : 0,5). 401, 403 et 429 ne comptent pas. Remplace le seuil d'erreurs 4xx ci-dessus. Nécessite le score cumulé.</p>
      ${chk('threat-err-on', cfg.ip_score?.errors?.enabled, 'Verser les erreurs 4xx au score')}
      ${fld('Poids par code', '(un par ligne : 404=0.5 ; 0 ignore le code)', ta('threat-err-weights', 3, '404=0.5&#10;400=1&#10;403=0', Object.entries(cfg.ip_score?.errors?.weights || {}).map(([k, v]) => `${k}=${v}`)))}
      ${fld('Poids par route', '(un par ligne : /login=3 ; préfixe de chemin, 0 ignore la route)', ta('threat-err-routes', 3, '/login=3&#10;/api/=0.5', (cfg.ip_score?.errors?.routes || []).map(r => `${r.prefix}=${r.factor}`)))}`)}
    ${sec('behavior', 'Comportement — note commune', `
      <p style="font-size:12px;color:var(--text2);margin:0 0 10px">Ephor verse chaque requête dans un magasin commun avec le WAF, Fail2Ban et CrowdSec, et en tire des signaux de comportement. Un signal naît en <b>detect</b> : calculé, expliqué dans le ban qu'il aurait provoqué, compté en « note fantôme », jamais décisif. Passez-le en <b>block</b> après avoir lu la simulation (faux positifs). Les signaux ne comptent que si le score cumulé est activé.</p>
      ${fld('Mode par défaut', '(signaux non réglés ci-dessous ; off : plus rien n\'est versé au magasin)', `<select id="threat-bh-mode" class="input" style="height:32px">${['detect', 'block', 'off'].map(m => `<option value="${m}" ${(cfg.behavior?.mode || 'detect') === m ? 'selected' : ''}>${m}</option>`).join('')}</select>`)}
      ${SENT_BEHAVIOR.map(sg => `<div style="display:flex;align-items:center;gap:8px;margin:0 0 6px;font-size:12.5px">
        <span style="flex:1;min-width:0"><b>${esc(banSignalLabel(sg.key))}</b>${SENT_NEW_SIGNALS.has(sg.key) ? ' <span class="tag tag-yellow" style="font-size:10px">nouveau</span>' : ''}<br><span style="color:var(--text3);font-size:11px">${esc(sg.what)} · ${sg.points} pts</span></span>
        <select id="threat-bh-sig-${sg.key}" class="input" style="height:30px;width:auto"><option value="">défaut</option>${['off', 'detect', 'block'].map(m => `<option value="${m}" ${cfg.behavior?.signals?.[sg.key] === m ? 'selected' : ''}>${m}</option>`).join('')}</select></div>`).join('')}
      ${chk('threat-bh-notrust', cfg.behavior?.no_trust, 'Couper le bonus de confiance (sinon : +1 au seuil de ban par centaine de requêtes propres et par jour d\'historique sans signal, jusqu\'à +8)')}
      ${fld('Familles TLS', '(une par ligne : famille=empreinte JA4 « b » à 12 caractères ; complète la table livrée, famille chromium)', ta('threat-bh-tls', 2, 'chromium=8daaf6152771', Object.entries(cfg.behavior?.tls_families || {}).flatMap(([f, hs]) => (hs || []).map(h => `${f}=${h}`))))}
      ${fld('Ancienneté minimale des références', '(défaut 24h : avant, le signal rate_deviation reste en detect)', `<input id="threat-bh-minage" class="input" value="${esc(cfg.behavior?.reference_min_age || '')}" placeholder="24h">`)}`)}
    ${sec('ddos', 'Anti-DDoS', `
      ${fld('Global req/s max', '(toutes IPs, 0 = désactivé)', `<input id="threat-global-rps" type="number" class="input" value="${cfg.global_rps || 0}" min="0" step="10" placeholder="0 = désactivé">`)}
      ${fld('Global burst', '(0 = 2× global req/s)', `<input id="threat-global-burst" type="number" class="input" value="${cfg.global_burst || 0}" min="0" step="10" placeholder="0 = 2×RPS">`)}`)}
    ${sec('riposte', 'Riposte — tarpit', `
      <p style="font-size:12px;color:var(--text2);margin:0 0 10px">Retient la réponse aux IP bloquées au lieu de refuser aussitôt, ce qui ralentit les bots.</p>
      ${chk('threat-tarpit', cfg.tarpit?.enabled, 'Activer le tarpit')}
      ${fld('Délai', '(ms, défaut 5000, max 30000)', `<input id="threat-tarpit-delay" type="number" class="input" value="${cfg.tarpit?.delay_ms || ''}" min="0" max="30000" placeholder="5000">`)}
      ${fld('Requêtes retenues max', '(défaut 200 ; au-delà, refus immédiat)', `<input id="threat-tarpit-max" type="number" class="input" value="${cfg.tarpit?.max_concurrent || ''}" min="0" placeholder="200">`)}`)}
    ${sec('lists', 'Listes', `
      ${chk('threat-ua', lists.ua_enabled, t('security.threat.list_ua'))}
      ${chk('threat-path', lists.path_enabled, t('security.threat.list_path'))}
      ${chk('threat-ip', lists.ip_enabled, t('security.threat.list_ip'))}
      ${fld(t('security.threat.refresh'), '', `<input id="threat-refresh" class="input" value="${esc(lists.refresh_interval || '6h')}" placeholder="6h">`)}
      ${fld('IPs / CIDRs bloqués', '', ta('threat-custom-ips', 3, '192.168.1.0/24&#10;1.2.3.4', custom.ips))}
      ${fld('User-Agents bloqués', '', ta('threat-custom-uas', 3, 'badbot&#10;scrapy', custom.uas))}
      ${fld('Paths bloqués (préfixes)', '', ta('threat-custom-paths', 3, '/admin/secret&#10;/phpmyadmin', custom.paths))}
      ${fld('Empreintes TLS bloquées', '(JA3 MD5 ou JA4, une par ligne ; TLS uniquement)', ta('threat-custom-tls', 3, 'e7d705a3286e19ea42f587b344ee6865&#10;t13d1516h2_8daaf6152771_02713d6af862', custom.tls_fingerprints))}`)}
    ${sec('exceptions', 'Exceptions', `
      ${fld(t('security.threat.wl_ips'), '', ta('threat-wl-ips', 2, '10.0.0.0/8&#10;203.0.113.1', wl.ips))}
      ${fld(t('security.threat.wl_uas'), '', ta('threat-wl-uas', 2, 'mon-crawler&#10;pingdom', wl.uas))}
      ${fld(t('security.threat.wl_paths'), '', ta('threat-wl-paths', 2, '/healthz&#10;/.well-known/', wl.paths))}`)}`;
}

function sentDrawerHTML(cfg) {
  const enabled = !!cfg.enabled;
  const group = _sent.edgeCtx?.group;
  return `
    <div id="sent-drawer" class="sent-drawer" aria-hidden="true">
      <div class="sent-drawer-head">
        <div style="display:flex;align-items:center;gap:10px">
          <b style="font-size:14px">Réglages Ephor</b>
          <label class="toggle" title="Activer Ephor"><input type="checkbox" id="threat-enabled" ${enabled ? 'checked' : ''} onchange="saveThreatConfig(null,true)"><span class="toggle-slider"></span></label>
          <button class="btn btn-ghost btn-sm" style="margin-left:auto;padding:4px 8px;font-size:16px;line-height:1" onclick="closeEphorSettings()" aria-label="Fermer">&#x2715;</button>
        </div>
        ${group ? `<div style="font-size:11px;color:var(--text2);margin-top:6px">Ces réglages sont partagés par le groupe HA <b>${esc(group.name)}</b> et appliqués à tous ses membres.</div>` : ''}
        <div class="sent-drawer-nav">${SENT_SECTIONS.map(s => `<button type="button" onclick="sentGoSection('${s.id}')">${s.label}</button>`).join('')}</div>
      </div>
      <form id="sent-form" onsubmit="saveThreatConfig(event)" class="sent-drawer-body">${sentDrawerForm(cfg)}
        <div id="sent-sim-result"></div>
      </form>
      <div class="sent-drawer-foot">
        <select id="sent-sim-hours" class="input" style="height:32px;width:auto" title="Fenêtre de logs rejouée">
          <option value="1">1 h</option><option value="6" selected>6 h</option><option value="24">24 h</option></select>
        <button type="button" class="btn btn-ghost btn-sm" onclick="simulateEphor()">Simuler</button>
        <button type="submit" form="sent-form" class="btn btn-primary btn-sm" style="margin-left:auto">${t('common.save')}</button>
      </div>
    </div>`;
}

function sentDrawSummary(sim) {
  const cur = sim.current || {}, cand = sim.candidate || {}, d = sim.delta || {};
  const sign = n => (n > 0 ? `+${n}` : `${n}`);
  const row = (label, a, b, delta, warn) => `<tr><td style="padding:4px 0;color:var(--text2)">${label}</td><td style="text-align:right">${a}</td><td style="text-align:right">${b}</td>
    <td style="text-align:right;${warn && delta > 0 ? 'color:var(--red)' : ''}">${sign(delta)}</td></tr>`;
  const tops = (cand.top_ips || []).slice(0, 5).map(i => `<div style="display:flex;gap:8px;font-size:11px;padding:2px 0">
    <span style="font-family:monospace">${esc(i.ip)}</span><span style="color:var(--text3)">${i.blocked} bloquées${i.legit_blocked ? ` · ${i.legit_blocked} légitimes` : ''}</span></div>`).join('');
  return `<div class="sent-sim">
    <div style="font-size:12px;font-weight:600;margin-bottom:6px">Simulation sur ${sim.window_hours} h — ${sim.events_replayed} requêtes rejouées${sim.truncated ? ' (tronqué)' : ''}</div>
    <table style="width:100%;font-size:12px;border-collapse:collapse"><thead><tr style="color:var(--text3)"><th></th><th style="text-align:right;font-weight:400">Actuelle</th><th style="text-align:right;font-weight:400">Candidate</th><th style="text-align:right;font-weight:400">Écart</th></tr></thead><tbody>
      ${row('Requêtes bloquées', cur.blocked || 0, cand.blocked || 0, d.blocked || 0)}
      ${row('Faux positifs probables', cur.legit_blocked || 0, cand.legit_blocked || 0, d.legit_blocked || 0, true)}
      ${row('IP bloquées', cur.blocked_ips || 0, cand.blocked_ips || 0, d.blocked_ips || 0)}
      ${row('Bans', (cur.bans || []).length, (cand.bans || []).length, d.bans || 0)}</tbody></table>
    ${tops ? `<div style="margin-top:8px;font-size:11px;color:var(--text2)">IP les plus touchées</div>${tops}` : ''}
    <div style="font-size:11px;color:var(--text3);margin-top:8px">Non simulé : listes par défaut, limite globale, règles WAF et agrégat par ASN. « Faux positifs » = requêtes bloquées qui avaient abouti.</div></div>`;
}

function sentDrawTab() {
  const body = document.getElementById('sent-body');
  if (!body) return;
  document.querySelectorAll('#sent-root [data-sent-tab]').forEach(b => {
    const on = b.dataset.sentTab === _sent.tab;
    b.classList.toggle('active', on);
    b.setAttribute('aria-selected', on);
  });
  body.innerHTML = _sent.tab === 'detections' ? sentViewDetections() : _sent.tab === 'lists' ? sentViewLists() : sentViewOverview();
  if (_sent.tab === 'detections') sentLoadReferences();
}

window.sentSetTab = function(tab) {
  if (!SENT_TABS.includes(tab)) return;
  _sent.tab = tab;
  try { localStorage.setItem(SENT_TAB_KEY, tab); } catch {}
  sentDrawTab();
};

window.sentGoSection = function(id) {
  document.getElementById('sent-sec-' + id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
};

window.openEphorSettings = function(section) {
  const d = document.getElementById('sent-drawer');
  if (!d) return;
  d.classList.add('open');
  d.setAttribute('aria-hidden', 'false');
  document.getElementById('sent-root')?.classList.add('sent-shifted');
  if (section) setTimeout(() => window.sentGoSection(section), 50);
};

window.closeEphorSettings = function() {
  const d = document.getElementById('sent-drawer');
  if (!d) return;
  d.classList.remove('open');
  d.setAttribute('aria-hidden', 'true');
  document.getElementById('sent-root')?.classList.remove('sent-shifted');
};

document.addEventListener('keydown', e => { if (e.key === 'Escape') window.closeEphorSettings(); });

function sentCollectConfig(enabled) {
  const $ = id => document.getElementById(id);
  const num = (id, def, float) => (float ? parseFloat($(id)?.value || def) : parseInt($(id)?.value || def, 10)) || 0;
  const lines = id => ($(id)?.value || '').split('\n').map(s => s.trim()).filter(Boolean);
  // « clé=nombre » par ligne ; les lignes invalides sont ignorées.
  const kv = id => lines(id).filter(l => l.includes('=')).map(l => { const i = l.lastIndexOf('='); return [l.slice(0, i).trim(), parseFloat(l.slice(i + 1))]; })
    .filter(([k, v]) => k && Number.isFinite(v) && v >= 0);
  return {
    enabled,
    mode: $('threat-mode')?.value || 'block',
    score_threshold: num('threat-score', '0'),
    tarpit: {
      enabled: $('threat-tarpit')?.checked ?? false,
      delay_ms: num('threat-tarpit-delay', '0'),
      max_concurrent: num('threat-tarpit-max', '0'),
    },
    rate_limit: num('threat-rate', '0', true),
    rate_window: $('threat-rate-window')?.value || '1s',
    rate_ban_threshold: num('threat-rate-ban-threshold', '1') || 1,
    rate_ban_window: $('threat-rate-ban-window')?.value || '',
    global_rps: num('threat-global-rps', '0', true),
    global_burst: num('threat-global-burst', '0'),
    escalation: {
      enabled: $('threat-esc-on')?.checked ?? false,
      factor: num('threat-esc-factor', '0', true),
      window: $('threat-esc-window')?.value || '',
      max_duration: $('threat-esc-max')?.value || '',
    },
    ip_score: {
      enabled: $('threat-score-on')?.checked ?? false,
      ban_threshold: num('threat-score-ban', '0', true),
      half_life: $('threat-score-halflife')?.value || '',
      errors: {
        enabled: $('threat-err-on')?.checked ?? false,
        weights: Object.fromEntries(kv('threat-err-weights').map(([k, v]) => [k, v])),
        routes: kv('threat-err-routes').map(([k, v]) => ({ prefix: k, factor: v })),
      },
    },
    behavior: sentCollectBehavior(),
    error_threshold: parseInt($('threat-errs')?.value || '20', 10),
    error_window: $('threat-ewin')?.value || '10s',
    ban_duration: $('threat-dur')?.value || '24h',
    lists: {
      refresh_interval: $('threat-refresh')?.value || '6h',
      ua_enabled: $('threat-ua')?.checked ?? false,
      path_enabled: $('threat-path')?.checked ?? false,
      ip_enabled: $('threat-ip')?.checked ?? false,
    },
    custom_lists: { ips: lines('threat-custom-ips'), uas: lines('threat-custom-uas'), paths: lines('threat-custom-paths'), tls_fingerprints: lines('threat-custom-tls') },
    whitelist: { ips: lines('threat-wl-ips'), uas: lines('threat-wl-uas'), paths: lines('threat-wl-paths') },
  };
}

function sentCollectBehavior() {
  const $ = id => document.getElementById(id);
  if (!$('threat-bh-mode')) return window._threatCfg?.behavior || undefined;
  const signals = {};
  SENT_BEHAVIOR.forEach(sg => { const v = $('threat-bh-sig-' + sg.key)?.value; if (v) signals[sg.key] = v; });
  const fam = {};
  ($('threat-bh-tls')?.value || '').split('\n').map(s => s.trim()).filter(l => l.includes('=')).forEach(l => {
    const i = l.indexOf('=');
    const f = l.slice(0, i).trim().toLowerCase(), h = l.slice(i + 1).trim();
    if (f && h) (fam[f] = fam[f] || []).push(h);
  });
  const b = { mode: $('threat-bh-mode').value };
  if (b.mode === 'detect') delete b.mode;
  if (Object.keys(signals).length) b.signals = signals;
  if (Object.keys(fam).length) b.tls_families = fam;
  if ($('threat-bh-notrust')?.checked) b.no_trust = true;
  const age = ($('threat-bh-minage')?.value || '').trim();
  if (age) b.reference_min_age = age;
  return Object.keys(b).length ? b : undefined;
}

window.saveThreatConfig = async function(e, keepOpen) {
  if (e) e.preventDefault();
  const cfg = sentCollectConfig(document.getElementById('threat-enabled')?.checked ?? false);
  try {
    await api('PUT', `/security/threat-config${window._secEdgeQ || ''}`, cfg);
    window._threatCfg = cfg;
    toast(t('security.threat.saved'), 'success');
    if (!keepOpen) window.closeEphorSettings();
    _sent.cfg = cfg;
    await sentReload(keepOpen);
  } catch (err) { toast(err.message, 'error'); }
};

window.simulateEphor = async function() {
  const out = document.getElementById('sent-sim-result');
  if (!out) return;
  out.innerHTML = '<div class="sent-sim"><div class="spinner"></div></div>';
  try {
    const hours = parseInt(document.getElementById('sent-sim-hours')?.value || '6', 10);
    const sim = await api('POST', `/security/threat-config/simulate${window._secEdgeQ || ''}`,
      { config: sentCollectConfig(document.getElementById('threat-enabled')?.checked ?? false), hours });
    out.innerHTML = sentDrawSummary(sim);
  } catch (err) {
    out.innerHTML = '';
    toast(err.message, 'error');
  }
};

async function sentLoad(mode) {
  const edgeCtx = await resolveSecurityEdgeCtx(mode);
  if (mode === 'edge' && edgeCtx?.missing) return { edgeCtx };
  const edgeQ = edgeCtx?.edgeRef ? `?edge=${encodeURIComponent(edgeCtx.edgeRef)}` : '';
  window._secEdgeQ = edgeQ;
  const extra = edgeQ ? '&' + edgeQ.slice(1) : '';
  const [active, history, cfg] = await Promise.all([
    api('GET', `/security/bans?active=true&source=threat${extra}`).catch(() => []),
    api('GET', `/security/bans?source=threat${extra}`).catch(() => []),
    api('GET', `/security/threat-config${edgeQ}`).catch(() => null),
  ]);
  return {
    edgeCtx,
    active: filterSecBans(active || [], edgeCtx),
    history: filterSecBans(history || [], edgeCtx),
    cfg: cfg || {},
  };
}

function sentPageHTML() {
  const cfg = _sent.cfg;
  const on = !!cfg.enabled;
  const isBlock = (cfg.mode || 'block') === 'block';
  return `${securityEdgeBanner(_sent.edgeCtx)}
    <div id="sent-root">
      <div class="page-header" style="display:flex;align-items:center;gap:10px;margin-bottom:16px;flex-wrap:wrap">
        <h1 class="page-title" style="margin:0;display:flex;align-items:center;gap:8px"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><ellipse cx="12" cy="12" rx="10" ry="6"/><circle cx="12" cy="12" r="3"/><circle cx="12" cy="12" r="1" fill="currentColor" stroke="none"/></svg> Ephor</h1>
        <span class="tag ${on ? 'tag-green' : 'tag-neutral'}">${on ? t('common.active') || 'Actif' : t('common.inactive') || 'Inactif'}</span>
        <span class="tag ${isBlock ? 'tag-red' : 'tag-yellow'}">${isBlock ? 'Block' : 'Detect'}</span>
        ${_sent.edgeCtx?.group ? `<span class="tag tag-neutral" title="Réglages partagés par le groupe HA">Groupe ${esc(_sent.edgeCtx.group.name)}</span>` : ''}
        <button class="btn btn-ghost btn-sm" style="margin-left:auto" onclick="openEphorSettings()">${t('common.settings') || 'Réglages'}</button>
      </div>
      <div class="tabs" role="tablist">${SENT_TABS.map(k => `<button type="button" role="tab" class="tab" data-sent-tab="${k}" onclick="sentSetTab('${k}')">${SENT_TAB_LABELS[k]}</button>`).join('')}</div>
      <div id="sent-body"></div>
    </div>
    ${sentDrawerHTML(cfg)}`;
}

async function sentReload(keepOpen) {
  const content = document.getElementById('content');
  if (!content || !document.getElementById('sent-root')) return;
  const wasOpen = keepOpen && document.getElementById('sent-drawer')?.classList.contains('open');
  const d = await sentLoad(_sent.mode);
  Object.assign(_sent, d);
  content.innerHTML = sentPageHTML();
  sentDrawTab();
  if (wasOpen) window.openEphorSettings();
}

async function renderEphorDashboard({ mode }) {
  const content = document.getElementById('content');
  content.innerHTML = `<div style="padding:20px 0"><div class="spinner"></div></div>`;
  try {
    _sent.mode = mode;
    _sent.refs = null;
    _sent.sugg = null;
    const d = await sentLoad(mode);
    if (mode === 'edge' && d.edgeCtx?.missing) {
      content.innerHTML = '<p style="color:var(--text2)">' + t('trafic.no_edge') + '</p>';
      return;
    }
    Object.assign(_sent, d);
    window._threatCfg = _sent.cfg;
    let tab = 'overview';
    try { const s = localStorage.getItem(SENT_TAB_KEY); if (SENT_TABS.includes(s)) tab = s; } catch {}
    _sent.tab = tab;
    content.innerHTML = sentPageHTML();
    sentDrawTab();
  } catch (e) { toast(e.message, 'error'); }
}
