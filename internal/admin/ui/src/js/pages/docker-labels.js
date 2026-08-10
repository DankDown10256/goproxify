// ── Modale générateur Labels Docker / Kubernetes
// Ouverte depuis Trafic (tuile proxy), modale proxy, ou assistant Infrastructure.
// Plus de page standalone.

const _LBL_SNIPPET_TYPES = [
  { type: 'headers', labelKey: 'dockerlbl.snip.type.headers' },
  { type: 'tls',     labelKey: 'dockerlbl.snip.type.tls' },
];

const _lblIcoCopy = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>`;

function _lblTabBtn(key, label, icon) {
  return `<div data-ltab="${key}" onclick="switchLblTab('${key}')" class="lbl-mtab">
    ${icon}<span>${label}</span>
  </div>`;
}

function _lblSecCard(title, body) {
  return `<div class="lbl-sec-card">
    <div class="lbl-sec-card-title">${title}</div>
    ${body}
  </div>`;
}

function _lblAuthOptionsHTML(providers) {
  return (Array.isArray(providers) ? providers : []).map(p => {
    const name = p.name || p.id || '';
    const kind = p.provider || p.type || '';
    return `<option value="${esc(name)}">${esc(name)}${kind ? ` (${esc(kind)})` : ''}</option>`;
  }).join('');
}

function _lblSnippetsHTML(snippets) {
  const list = Array.isArray(snippets) ? snippets : [];
  if (!list.length) {
    return `<div class="form-hint">${t('dockerlbl.snippets_empty')} <a href="#" onclick="event.preventDefault();closeModal();navigate('snippets')" style="color:var(--accent)">${t('dockerlbl.snippets_manage')}</a></div>`;
  }
  const byType = {};
  for (const s of list) {
    if (!s?.type || !s?.name) continue;
    (byType[s.type] = byType[s.type] || []).push(s);
  }
  const blocks = _LBL_SNIPPET_TYPES.map(({ type, labelKey }) => {
    const items = byType[type] || [];
    if (!items.length) return '';
    return `<div class="lbl-snip-group">
      <div class="lbl-section-label">${t(labelKey)}</div>
      ${items.map(s => `<div class="lbl-option">
        <span>
          <span class="lbl-option-title">${esc(s.name)}</span>
          <span class="lbl-option-hint">${esc(s.type)}</span>
        </span>
        <label class="toggle"><input type="checkbox" class="lbl-snip-cb" data-name="${esc(s.name)}" onchange="genLabels()"><span class="toggle-slider"></span></label>
      </div>`).join('')}
    </div>`;
  }).filter(Boolean).join('');
  if (!blocks) {
    return `<div class="form-hint">${t('dockerlbl.snippets_empty')} <a href="#" onclick="event.preventDefault();closeModal();navigate('snippets')" style="color:var(--accent)">${t('dockerlbl.snippets_manage')}</a></div>`;
  }
  return blocks + `<div class="form-hint" style="margin-top:6px"><a href="#" onclick="event.preventDefault();closeModal();navigate('snippets')" style="color:var(--accent)">${t('dockerlbl.snippets_manage')}</a></div>`;
}

/** Ouvre la modale générateur. opts: { prefill?, format?, title? } */
window.openDockerLabelsModal = async function(opts = {}) {
  let snippets = [];
  let authProviders = [];
  try {
    const [snipList, authList] = await Promise.all([
      api('GET', '/snippets').catch(() => []),
      api('GET', '/auth-providers').catch(() => []),
    ]);
    snippets = Array.isArray(snipList) ? snipList : [];
    authProviders = Array.isArray(authList) ? authList.filter(p => p.enabled !== false) : [];
  } catch {}
  window._lblSnippets = snippets;
  window._lblAuthProviders = authProviders;
  window._lblType = opts.prefill?.type === 'tcp' || opts.prefill?.type === 'udp' ? opts.prefill.type : 'http';
  window._lblFormat = opts.format || 'docker';

  const icoRoute = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/></svg>`;
  const icoSec = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`;
  const icoSnip = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>`;
  const icoTraffic = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>`;
  const icoUp = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>`;
  const icoPrev = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>`;

  const body = `
    <div class="lbl-modal">
      <aside class="lbl-modal-nav" id="lbl-tabs">
        ${_lblTabBtn('route', t('dockerlbl.tab.route'), icoRoute)}
        ${_lblTabBtn('sec', t('dockerlbl.tab.security'), icoSec)}
        ${_lblTabBtn('snip', t('dockerlbl.tab.snippets'), icoSnip)}
        ${_lblTabBtn('traffic', t('dockerlbl.tab.traffic'), icoTraffic)}
        ${_lblTabBtn('update', t('dockerlbl.tab.update'), icoUp)}
        ${_lblTabBtn('preview', t('dockerlbl.tab.preview'), icoPrev)}
      </aside>
      <div class="lbl-modal-body">

        <div id="ltab-route" class="lbl-mtab-panel">
          <div class="lbl-format-grid" id="lbl-format-tabs" role="tablist">
            <button type="button" class="lbl-format-card active" data-fmt="docker" onclick="setLabelFormat('docker',this)">
              <span class="lbl-format-title">${t('dockerlbl.format.docker')}</span>
              <span class="lbl-format-desc">${t('dockerlbl.format.docker_desc')}</span>
            </button>
            <button type="button" class="lbl-format-card" data-fmt="k8s" onclick="setLabelFormat('k8s',this)">
              <span class="lbl-format-title">${t('dockerlbl.format.k8s')}</span>
              <span class="lbl-format-desc">${t('dockerlbl.format.k8s_desc')}</span>
            </button>
          </div>

          <div id="lbl-type-tabs" class="lbl-section" style="margin-top:14px">
            <div class="lbl-section-label">${t('dockerlbl.protocol')}</div>
            <div class="seg" role="group">
              <label class="seg-opt"><input type="radio" name="lbl-type" value="http" checked onchange="setLabelType('http')">${t('dockerlbl.proto.http')}</label>
              <label class="seg-opt"><input type="radio" name="lbl-type" value="tcp" onchange="setLabelType('tcp')">TCP</label>
              <label class="seg-opt"><input type="radio" name="lbl-type" value="udp" onchange="setLabelType('udp')">UDP</label>
            </div>
          </div>

          <div class="lbl-sec-card" style="margin-top:12px">
            <div class="lbl-sec-card-title">${t('dockerlbl.domain')}</div>
            <div class="form-hint" style="margin-bottom:8px">${t('dockerlbl.domain_hint')}</div>
            <div id="lbl-domains-list"></div>
            <button type="button" class="btn btn-secondary btn-sm" onclick="_lblAddDomain()">${t('dockerlbl.add_alias')}</button>
          </div>

          <div class="field" style="margin-top:12px" id="lbl-port-group">
            <label class="field-label">${t('dockerlbl.port')}</label>
            <input id="lbl-port" class="input" type="number" placeholder="3000" oninput="genLabels()">
            <div class="form-hint">${t('dockerlbl.port_hint')}</div>
          </div>

          <div class="lbl-options" id="lbl-route-toggles" style="margin-top:12px">
            <div class="lbl-option">
              <span><span class="lbl-option-title">TLS</span><span class="lbl-option-hint">${t('dockerlbl.tls_hint')}</span></span>
              <label class="toggle"><input type="checkbox" id="lbl-tls" onchange="genLabels()"><span class="toggle-slider"></span></label>
            </div>
            <div class="lbl-option" id="lbl-https-group">
              <span><span class="lbl-option-title">${t('dockerlbl.https')}</span><span class="lbl-option-hint">${t('dockerlbl.https_hint')}</span></span>
              <label class="toggle"><input type="checkbox" id="lbl-https" onchange="genLabels()"><span class="toggle-slider"></span></label>
            </div>
            <div class="lbl-option" id="lbl-passthrough-group">
              <span><span class="lbl-option-title">${t('dockerlbl.passthrough')}</span><span class="lbl-option-hint">${t('dockerlbl.passthrough_hint')}</span></span>
              <label class="toggle"><input type="checkbox" id="lbl-passthrough" onchange="genLabels()"><span class="toggle-slider"></span></label>
            </div>
            <div class="lbl-option" id="lbl-logs-group">
              <span><span class="lbl-option-title">${t('dockerlbl.log_fwd')}</span><span class="lbl-option-hint">${t('dockerlbl.log_fwd_hint')}</span></span>
              <label class="toggle"><input type="checkbox" id="lbl-logs" onchange="genLabels()"><span class="toggle-slider"></span></label>
            </div>
          </div>
        </div>

        <div id="ltab-sec" class="lbl-mtab-panel" style="display:none">
          <p class="form-hint" style="margin:0 0 12px">${t('dockerlbl.sec_intro')}</p>

          ${_lblSecCard('WAF', `
            <div class="lbl-sec-row">
              <label style="display:flex;align-items:center;gap:8px;cursor:pointer;padding-top:22px;">
                <label class="toggle"><input type="checkbox" id="lbl-waf-enabled" onchange="genLabels();_lblSyncConditional()"><span class="toggle-slider"></span></label>
                <span style="font-size:13px;font-weight:500">${t('dockerlbl.enabled')}</span>
              </label>
              <div class="field" style="margin:0" id="lbl-waf-mode-wrap">
                <label class="field-label" style="font-size:11px">${t('dockerlbl.mode_label')}</label>
                <select id="lbl-waf" class="input" onchange="genLabels()">
                  <option value="block">${t('dockerlbl.waf.block')}</option>
                  <option value="detect">${t('dockerlbl.waf.detect')}</option>
                </select>
              </div>
            </div>
            <div class="form-hint" style="margin-top:8px">${t('dockerlbl.waf_hint')}</div>
          `)}

          ${_lblSecCard(t('dockerlbl.bot_title'), `
            <div class="lbl-sec-row">
              <label style="display:flex;align-items:center;gap:8px;cursor:pointer;padding-top:2px;">
                <label class="toggle"><input type="checkbox" id="lbl-bot" onchange="genLabels()"><span class="toggle-slider"></span></label>
                <span style="font-size:13px;font-weight:500">${t('dockerlbl.enabled')}</span>
              </label>
            </div>
            <div class="form-hint" style="margin-top:8px">${t('dockerlbl.bot_hint')}</div>
          `)}

          ${_lblSecCard(t('dockerlbl.rate_title'), `
            <div class="lbl-sec-row" style="margin-bottom:4px;">
              <label style="display:flex;align-items:center;gap:8px;cursor:pointer;padding-top:22px;">
                <label class="toggle"><input type="checkbox" id="lbl-rl-enabled" onchange="genLabels();_lblSyncConditional()"><span class="toggle-slider"></span></label>
                <span style="font-size:13px;font-weight:500">${t('dockerlbl.enabled')}</span>
              </label>
              <div id="lbl-rl-fields" class="form-row" style="gap:8px;opacity:.45">
                <div class="field" style="margin:0"><label class="field-label" style="font-size:11px">${t('dockerlbl.rate')}</label><input id="lbl-rps" class="input" type="number" min="0" step="0.1" value="10" oninput="genLabels()"></div>
                <div class="field" style="margin:0"><label class="field-label" style="font-size:11px">${t('dockerlbl.rate_burst')}</label><input id="lbl-burst" class="input" type="number" min="0" value="20" oninput="genLabels()"></div>
              </div>
            </div>
          `)}

          ${_lblSecCard(t('dockerlbl.ipf_title'), `
            <div class="lbl-sec-row">
              <label style="display:flex;align-items:center;gap:8px;cursor:pointer;padding-top:22px;">
                <label class="toggle"><input type="checkbox" id="lbl-ipf-enabled" onchange="genLabels();_lblSyncConditional()"><span class="toggle-slider"></span></label>
                <span style="font-size:13px;font-weight:500">CIDR</span>
              </label>
              <div id="lbl-ipf-fields" style="flex:1 1 180px;min-width:0;opacity:.45">
                <div class="field" style="margin:0 0 8px">
                  <label class="field-label" style="font-size:11px">${t('dockerlbl.mode_label')}</label>
                  <select id="lbl-ipf-mode" class="input" onchange="genLabels()">
                    <option value="deny">${t('dockerlbl.mode.deny')}</option>
                    <option value="allow">${t('dockerlbl.mode.allow')}</option>
                  </select>
                </div>
                <div class="field" style="margin:0">
                  <label class="field-label" style="font-size:11px">${t('dockerlbl.ipf_cidrs')}</label>
                  <textarea id="lbl-ipf-cidrs" class="input" rows="3" placeholder="10.0.0.0/8&#10;203.0.113.10/16" oninput="genLabels()"></textarea>
                  <div class="form-hint">${t('dockerlbl.ipf_hint')}</div>
                </div>
              </div>
            </div>
          `)}

          ${_lblSecCard('GeoIP', `
            <div class="lbl-sec-row">
              <label style="display:flex;align-items:center;gap:8px;cursor:pointer;padding-top:22px;">
                <label class="toggle"><input type="checkbox" id="lbl-geo-enabled" onchange="genLabels();_lblSyncConditional()"><span class="toggle-slider"></span></label>
                <span style="font-size:13px;font-weight:500">${t('dockerlbl.enabled')}</span>
              </label>
              <div id="lbl-geo-fields" style="flex:1 1 180px;min-width:0;opacity:.45">
                <div class="field" style="margin:0 0 8px">
                  <label class="field-label" style="font-size:11px">${t('dockerlbl.mode_label')}</label>
                  <select id="lbl-geo-mode" class="input" onchange="genLabels()">
                    <option value="deny">${t('dockerlbl.mode.deny')}</option>
                    <option value="allow">${t('dockerlbl.mode.allow')}</option>
                  </select>
                </div>
                <div class="field" style="margin:0">
                  <label class="field-label" style="font-size:11px">${t('dockerlbl.geo_countries')}</label>
                  <input id="lbl-geo-countries" class="input" placeholder="FR,DE,BE" oninput="genLabels()">
                  <div class="form-hint">${t('dockerlbl.geo_hint')}</div>
                </div>
              </div>
            </div>
          `)}

          ${_lblSecCard('CORS', `
            <div class="lbl-options" style="margin:0">
              <div class="lbl-option" style="background:transparent;border:none;padding:0">
                <span><span class="lbl-option-title">CORS</span><span class="lbl-option-hint">${t('dockerlbl.cors_hint')}</span></span>
                <label class="toggle"><input type="checkbox" id="lbl-cors" onchange="genLabels();_lblSyncConditional()"><span class="toggle-slider"></span></label>
              </div>
            </div>
            <div class="field" id="lbl-cors-origins-wrap" style="display:none;margin-top:10px">
              <label class="field-label" style="font-size:11px">${t('dockerlbl.cors_origins')}</label>
              <input id="lbl-cors-origins" class="input" placeholder="https://app.example.fr" oninput="genLabels()">
              <div class="form-hint">${t('dockerlbl.cors_origins_hint')}</div>
            </div>
          `)}
        </div>

        <div id="ltab-snip" class="lbl-mtab-panel" style="display:none">
          <div class="field" id="lbl-auth-group">
            <label class="field-label">${t('dockerlbl.auth_provider')}</label>
            <select id="lbl-auth" class="input" onchange="genLabels()">
              <option value="">${t('dockerlbl.off')}</option>
              ${_lblAuthOptionsHTML(authProviders)}
            </select>
            <div class="form-hint">${t('dockerlbl.auth_hint')}</div>
          </div>
          <div class="field" id="lbl-snippets-group" style="margin-top:14px">
            <label class="field-label">${t('dockerlbl.snippets')}</label>
            <div class="form-hint">${t('dockerlbl.snippets_hint')}</div>
            <div class="lbl-options" id="lbl-snippets-list" style="margin-top:8px">${_lblSnippetsHTML(snippets)}</div>
          </div>
        </div>

        <div id="ltab-traffic" class="lbl-mtab-panel" style="display:none">
          <div class="lbl-options">
            <div class="lbl-option">
              <span><span class="lbl-option-title">${t('dockerlbl.canary')}</span><span class="lbl-option-hint">${t('dockerlbl.canary_hint')}</span></span>
              <label class="toggle"><input type="checkbox" id="lbl-canary" onchange="genLabels();_lblSyncConditional()"><span class="toggle-slider"></span></label>
            </div>
          </div>
          <div class="field" id="lbl-canary-weight-wrap" style="display:none;margin-top:10px">
            <label class="field-label">${t('dockerlbl.canary_weight')}</label>
            <input id="lbl-canary-weight" class="input" type="number" min="1" max="100" value="10" oninput="genLabels()">
          </div>
          <div class="lbl-options" style="margin-top:10px">
            <div class="lbl-option">
              <span><span class="lbl-option-title">${t('dockerlbl.shadow')}</span><span class="lbl-option-hint">${t('dockerlbl.shadow_hint')}</span></span>
              <label class="toggle"><input type="checkbox" id="lbl-shadow" onchange="genLabels()"><span class="toggle-slider"></span></label>
            </div>
          </div>
        </div>

        <div id="ltab-update" class="lbl-mtab-panel" style="display:none">
          <div class="field" id="lbl-update-group">
            <label class="field-label">${t('dockerlbl.auto_update')}</label>
            <select id="lbl-update" class="input" onchange="genLabels();_lblSyncConditional()">
              <option value="">${t('dockerlbl.off')}</option>
              <option value="true">${t('dockerlbl.automatic')}</option>
              <option value="scheduled">${t('dockerlbl.scheduled')}</option>
            </select>
          </div>
          <div class="field" id="lbl-cron-group" style="display:none;margin-top:10px">
            <label class="field-label">${t('dockerlbl.cron')}</label>
            <input id="lbl-cron" class="input" placeholder="0 3 * * *" oninput="genLabels()">
          </div>
          <div class="lbl-options" id="lbl-prune-group" style="display:none;margin-top:10px">
            <div class="lbl-option">
              <span><span class="lbl-option-title">${t('dockerlbl.prune')}</span><span class="lbl-option-hint">${t('dockerlbl.prune_hint')}</span></span>
              <label class="toggle"><input type="checkbox" id="lbl-prune" onchange="genLabels()"><span class="toggle-slider"></span></label>
            </div>
          </div>
        </div>

        <div id="ltab-preview" class="lbl-mtab-panel" style="display:none">
          <div class="lbl-snippet-head" style="margin-bottom:8px">
            <span class="lbl-file-badge" id="lbl-output-badge">labels</span>
            <button type="button" class="btn btn-ghost btn-sm" onclick="copyLabels()">${_lblIcoCopy} ${t('dockerlbl.copy')}</button>
          </div>
          <div class="label-gen lbl-output" id="lbl-output" style="min-height:120px">${t('dockerlbl.fill_form')}</div>
          <div class="lbl-snippet-head" style="margin:16px 0 8px">
            <span class="lbl-file-badge" id="lbl-snippet-title">docker-compose.yml</span>
            <button type="button" class="btn btn-ghost btn-sm" onclick="copyLabelSnippet()">${_lblIcoCopy} ${t('dockerlbl.copy_snippet')}</button>
          </div>
          <div class="code-block lbl-snippet" id="lbl-compose" style="max-height:220px">…</div>
        </div>

      </div>
    </div>`;

  const title = opts.title || t('page.docker-labels');
  modal(title, body, `
    <button class="btn btn-secondary" onclick="closeModal()">${t('common.cancel')}</button>
    <button class="btn btn-primary" onclick="copyLabels();">${_lblIcoCopy} ${t('dockerlbl.copy')}</button>
  `, true);

  _lblInitDomains(opts.prefill?.host || '');
  if (opts.prefill) applyLabelPrefill(opts.prefill);
  else {
    _syncLabelFormatUI();
    _lblSyncConditional();
    genLabels();
  }
  switchLblTab('route');
};

window.switchLblTab = function(tab) {
  ['route', 'sec', 'snip', 'traffic', 'update', 'preview'].forEach(k => {
    const panel = document.getElementById('ltab-' + k);
    if (panel) panel.style.display = k === tab ? 'flex' : 'none';
  });
  document.querySelectorAll('#lbl-tabs .lbl-mtab').forEach(el => {
    const on = el.dataset.ltab === tab;
    el.classList.toggle('active', on);
  });
  if (tab === 'preview') genLabels();
};

function _lblInitDomains(hostCsv) {
  const list = document.getElementById('lbl-domains-list');
  if (!list) return;
  list.innerHTML = '';
  const hosts = String(hostCsv || '').split(',').map(h => h.trim()).filter(Boolean);
  if (!hosts.length) hosts.push('');
  hosts.forEach((h, i) => _lblAddDomain(h, i === 0));
}

window._lblAddDomain = function(value, isPrimary) {
  const list = document.getElementById('lbl-domains-list');
  if (!list) return;
  const primary = isPrimary === true || list.children.length === 0;
  const row = document.createElement('div');
  row.className = 'lbl-domain-row';
  row.innerHTML = `
    <input class="input lbl-domain-val" placeholder="${primary ? 'app.example.fr' : 'www.example.fr'}" value="${esc(value || '')}" oninput="genLabels()">
    ${primary
      ? `<span class="lbl-domain-tag">${t('dockerlbl.primary')}</span>`
      : `<button type="button" class="btn-icon" title="${esc(t('common.delete'))}" onclick="this.closest('.lbl-domain-row').remove();genLabels()">×</button>`}`;
  list.appendChild(row);
};

function _lblSelectedDomains() {
  return [...document.querySelectorAll('.lbl-domain-val')]
    .map(el => el.value.trim())
    .filter(Boolean);
}

function _lblSelectedSnippetNames() {
  return [...document.querySelectorAll('.lbl-snip-cb:checked')]
    .map(el => (el.dataset.name || '').trim())
    .filter(Boolean);
}

/** Mappe un proxy/stream Trafic vers les champs du générateur. */
function mapProxyToLabelPrefill(p) {
  if (!p) return null;
  let cfg = p.config;
  if (typeof cfg === 'string') {
    try { cfg = JSON.parse(cfg); } catch { cfg = {}; }
  }
  cfg = cfg && typeof cfg === 'object' ? cfg : {};
  const type = String(cfg.type || p.type || 'http').toLowerCase();
  const isL4 = type === 'tcp' || type === 'udp' || type === 'both';
  const backends = cfg.backends || p.backends || [];
  const be0 = backends[0];
  const beUrl = typeof be0 === 'string' ? be0 : (be0?.url || '');
  const portFromBe = (String(beUrl).match(/:(\d+)(?:\/|$)/) || [])[1] || '';
  const listen = cfg.listen_port || p.listen_port;
  const waf = cfg.waf || cfg.security?.waf;
  const bot = cfg.bot || cfg.security?.bot_protection || cfg.security?.bot;
  const rl = cfg.rate_limit || cfg.security?.rate_limit;
  const rps = rl?.rps ?? rl?.requests_per_second ?? 0;
  const burst = rl?.burst ?? 0;
  const geo = cfg.geo_ip || cfg.security?.geo_ip;
  const ipf = cfg.ip_filter || cfg.security?.ip_filter;
  const cors = cfg.cors || cfg.security?.cors;
  const hdr = cfg.headers || {};
  const logging = cfg.logging;
  const logsOn = !!(logging && logging.format !== 'off' && logging.access_log !== false);
  let wafMode = '';
  if (waf?.enabled) wafMode = (waf.mode === 'detect' ? 'detect' : 'block');
  const hostList = [cfg.host || p.host, ...(Array.isArray(cfg.aliases) ? cfg.aliases : [])]
    .map(h => String(h || '').trim())
    .filter(Boolean);
  const uniqHosts = [...new Set(hostList)];
  return {
    type: isL4 ? (type === 'both' ? 'tcp' : type) : 'http',
    host: uniqHosts.join(',') || p.name || '',
    port: isL4 ? String(listen || portFromBe || '') : String(portFromBe || ''),
    tls: !!(cfg.tls_enabled || cfg.tls_passthrough || type === 'https'),
    https: /^https:/i.test(beUrl) || !!cfg.https,
    passthrough: !!cfg.tls_passthrough,
    logs: logsOn,
    rlEnabled: !!(rl && (Number(rps) > 0 || cfg.rate_limit)),
    rps: Number(rps) || 10,
    burst: Number(burst) || 20,
    geoEnabled: !!(geo && (geo.countries || []).length),
    geoMode: geo?.mode || 'deny',
    geoCountries: Array.isArray(geo?.countries) ? geo.countries.join(',') : '',
    ipfEnabled: !!(ipf && (ipf.cidrs || []).length),
    ipfMode: ipf?.mode || 'deny',
    ipfCidrs: Array.isArray(ipf?.cidrs) ? ipf.cidrs.join('\n') : '',
    cors: !!(cors && (cors.allowed_origins || cors.enabled)),
    corsOrigins: Array.isArray(cors?.allowed_origins) && !cors.allowed_origins.includes('*')
      ? cors.allowed_origins.join(',') : '',
    waf: wafMode,
    bot: !!bot?.enabled,
    auth: cfg.auth_provider_id || (typeof cfg.auth === 'string' ? cfg.auth : '') || '',
    canary: !!cfg.canary?.enabled || !!cfg.canary,
    canaryWeight: cfg.canary?.weight || cfg.canary_weight || 10,
    shadow: !!cfg.shadow?.enabled || !!cfg.shadow,
    snippetIds: Array.isArray(cfg.snippet_ids) ? cfg.snippet_ids.slice() : [],
    hsts: !!hdr.hsts,
    hideServer: !!hdr.hide_server,
    xfo: hdr.x_frame_options || '',
  };
}

function applyLabelPrefill(pre) {
  if (!pre || typeof pre !== 'object') return;
  const lblType = pre.type === 'tcp' || pre.type === 'udp' ? pre.type : 'http';
  window.setLabelType(lblType);
  const setVal = (id, v) => { const el = document.getElementById(id); if (el && v != null && v !== '') el.value = v; };
  const setChk = (id, v) => { const el = document.getElementById(id); if (el) el.checked = !!v; };

  _lblInitDomains(pre.host || '');
  setVal('lbl-port', pre.port);
  setChk('lbl-tls', pre.tls);
  setChk('lbl-https', pre.https);
  setChk('lbl-passthrough', pre.passthrough);
  setChk('lbl-logs', pre.logs);

  setChk('lbl-rl-enabled', pre.rlEnabled || pre.rps > 0);
  setVal('lbl-rps', String(pre.rps > 0 ? pre.rps : 10));
  setVal('lbl-burst', String(pre.burst > 0 ? pre.burst : 20));
  setChk('lbl-geo-enabled', pre.geoEnabled || !!(pre.geoMode && pre.geoCountries));
  setVal('lbl-geo-mode', pre.geoMode || 'deny');
  setVal('lbl-geo-countries', pre.geoCountries || '');
  setChk('lbl-ipf-enabled', pre.ipfEnabled || !!(pre.ipfMode && pre.ipfCidrs));
  setVal('lbl-ipf-mode', pre.ipfMode || 'deny');
  setVal('lbl-ipf-cidrs', pre.ipfCidrs || '');
  setChk('lbl-cors', pre.cors);
  setVal('lbl-cors-origins', pre.corsOrigins || '');
  setChk('lbl-waf-enabled', !!pre.waf);
  setVal('lbl-waf', pre.waf || 'block');
  setChk('lbl-bot', pre.bot);
  setChk('lbl-canary', pre.canary);
  setVal('lbl-canary-weight', String(pre.canaryWeight || 10));
  setChk('lbl-shadow', pre.shadow);

  const authEl = document.getElementById('lbl-auth');
  if (authEl && pre.auth) {
    const providers = window._lblAuthProviders || [];
    const match = providers.find(p => p.id === pre.auth || p.name === pre.auth);
    authEl.value = match?.name || pre.auth;
  }

  const snips = window._lblSnippets || [];
  const names = new Set();
  for (const id of (pre.snippetIds || [])) {
    const s = snips.find(x => x.id === id || x.name === id);
    if (s?.name) names.add(s.name);
  }
  for (const n of (pre.snippetNames || [])) {
    if (n) names.add(n);
  }
  document.querySelectorAll('.lbl-snip-cb').forEach(el => {
    el.checked = names.has(el.dataset.name);
  });

  _syncLabelFormatUI();
  _lblSyncConditional();
  genLabels();
}

window.openDockerLabelsFromProxy = async function(proxyId) {
  const all = window._traficAll || window._proxies || [];
  let p = all.find(x => x.id === proxyId);
  if (!p) {
    try { p = await api('GET', `/proxies/${encodeURIComponent(proxyId)}`); } catch {}
  }
  if (!p) {
    if (typeof toast === 'function') toast(t('trafic.no_proxy_sel'), 'error');
    return;
  }
  const host = (() => {
    let cfg = p.config;
    if (typeof cfg === 'string') { try { cfg = JSON.parse(cfg); } catch { cfg = {}; } }
    return cfg?.host || p.host || p.name || proxyId;
  })();
  await openDockerLabelsModal({
    prefill: mapProxyToLabelPrefill(p),
    title: `${t('page.docker-labels')} — ${host}`,
  });
};

function _lblSyncConditional() {
  const rlOn = document.getElementById('lbl-rl-enabled')?.checked;
  const rlFields = document.getElementById('lbl-rl-fields');
  if (rlFields) rlFields.style.opacity = rlOn ? '1' : '0.45';

  const geoOn = document.getElementById('lbl-geo-enabled')?.checked;
  const geoFields = document.getElementById('lbl-geo-fields');
  if (geoFields) geoFields.style.opacity = geoOn ? '1' : '0.45';

  const ipfOn = document.getElementById('lbl-ipf-enabled')?.checked;
  const ipfFields = document.getElementById('lbl-ipf-fields');
  if (ipfFields) ipfFields.style.opacity = ipfOn ? '1' : '0.45';

  const wafOn = document.getElementById('lbl-waf-enabled')?.checked;
  const wafWrap = document.getElementById('lbl-waf-mode-wrap');
  if (wafWrap) wafWrap.style.opacity = wafOn ? '1' : '0.45';

  const corsOn = document.getElementById('lbl-cors')?.checked;
  const corsWrap = document.getElementById('lbl-cors-origins-wrap');
  if (corsWrap) corsWrap.style.display = corsOn ? '' : 'none';

  const canaryOn = document.getElementById('lbl-canary')?.checked;
  const canaryWrap = document.getElementById('lbl-canary-weight-wrap');
  if (canaryWrap) canaryWrap.style.display = canaryOn ? '' : 'none';

  const update = document.getElementById('lbl-update')?.value;
  const cronGroup = document.getElementById('lbl-cron-group');
  const pruneGroup = document.getElementById('lbl-prune-group');
  if (cronGroup) cronGroup.style.display = update === 'scheduled' ? '' : 'none';
  if (pruneGroup) pruneGroup.style.display = update ? '' : 'none';
}

function _syncLabelFormatUI() {
  const isK8s = window._lblFormat === 'k8s';
  document.querySelectorAll('#lbl-format-tabs .lbl-format-card').forEach(el => {
    el.classList.toggle('active', el.dataset.fmt === window._lblFormat);
  });
  ['lbl-https-group', 'lbl-passthrough-group', 'lbl-logs-group', 'lbl-type-tabs'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.style.display = isK8s ? 'none' : '';
  });
  // Tabs sécu / trafic / maj masqués en K8s (discovery limitée)
  document.querySelectorAll('#lbl-tabs .lbl-mtab').forEach(el => {
    const k = el.dataset.ltab;
    if (['sec', 'snip', 'traffic', 'update'].includes(k)) {
      el.style.display = isK8s ? 'none' : '';
    }
  });
  const snipTitle = document.getElementById('lbl-snippet-title');
  const badge = document.getElementById('lbl-output-badge');
  if (snipTitle) snipTitle.textContent = isK8s ? t('dockerlbl.snippet_k8s') : 'docker-compose.yml';
  if (badge) badge.textContent = isK8s ? 'annotations' : 'labels';
  if (isK8s) {
    window._lblType = 'http';
    document.querySelectorAll('input[name="lbl-type"]').forEach(el => {
      el.checked = el.value === 'http';
    });
  } else {
    _lblSyncConditional();
  }
}

window.setLabelFormat = function(fmt, el) {
  window._lblFormat = fmt;
  if (el) {
    document.querySelectorAll('#lbl-format-tabs .lbl-format-card').forEach(c => c.classList.remove('active'));
    el.classList.add('active');
  }
  _syncLabelFormatUI();
  genLabels();
};

window.setLabelType = function(type) {
  window._lblType = type;
  document.querySelectorAll('input[name="lbl-type"]').forEach(el => {
    el.checked = el.value === type;
  });
  genLabels();
};

window.genLabels = function() {
  if (!document.getElementById('lbl-output')) return;
  const format = window._lblFormat || 'docker';
  const type  = window._lblType || 'http';
  const hosts = _lblSelectedDomains();
  const host  = hosts.join(',') || 'app.example.fr';
  const tls   = document.getElementById('lbl-tls')?.checked;
  const https = document.getElementById('lbl-https')?.checked;
  const passthrough = document.getElementById('lbl-passthrough')?.checked;
  const logs  = document.getElementById('lbl-logs')?.checked;
  const rlOn  = document.getElementById('lbl-rl-enabled')?.checked;
  const rps   = parseFloat(document.getElementById('lbl-rps')?.value) || 0;
  const burst = parseInt(document.getElementById('lbl-burst')?.value) || 0;
  const geoOn = document.getElementById('lbl-geo-enabled')?.checked;
  const geoMode = document.getElementById('lbl-geo-mode')?.value || 'deny';
  const geoCountries = (document.getElementById('lbl-geo-countries')?.value || '').trim();
  const ipfOn = document.getElementById('lbl-ipf-enabled')?.checked;
  const ipfMode = document.getElementById('lbl-ipf-mode')?.value || 'deny';
  const ipfCidrs = (document.getElementById('lbl-ipf-cidrs')?.value || '').trim()
    .split(/[\n,]+/).map(s => s.trim()).filter(Boolean).join(',');
  const corsOn = document.getElementById('lbl-cors')?.checked;
  const corsOrigins = (document.getElementById('lbl-cors-origins')?.value || '').trim();
  const snippets = _lblSelectedSnippetNames().join(',');
  const auth = (document.getElementById('lbl-auth')?.value || '').trim();
  const wafOn = document.getElementById('lbl-waf-enabled')?.checked;
  const waf = document.getElementById('lbl-waf')?.value || 'block';
  const bot = document.getElementById('lbl-bot')?.checked;
  const canary = document.getElementById('lbl-canary')?.checked;
  const canaryWeight = parseInt(document.getElementById('lbl-canary-weight')?.value) || 10;
  const shadow = document.getElementById('lbl-shadow')?.checked;
  const port  = document.getElementById('lbl-port')?.value || '3000';
  const update = document.getElementById('lbl-update')?.value;
  const cron  = document.getElementById('lbl-cron')?.value;
  const prune = document.getElementById('lbl-prune')?.checked;

  const isL4 = type === 'tcp' || type === 'udp';
  const svcName = (hosts[0] || 'app').split('.')[0].replace(/[^a-z0-9]/gi, '').toLowerCase() || 'app';

  if (format === 'k8s') {
    const annotations = [
      `    goproxify.host: "${host}"`,
      `    goproxify.port: "${port}"`,
    ];
    if (tls) annotations.push(`    goproxify.tls: "true"`);
    const annBlock = annotations.join('\n');
    const output = [
      'goproxify.enabled: "true"',
      `goproxify.host: "${host}"`,
      `goproxify.port: "${port}"`,
      tls ? 'goproxify.tls: "true"' : null,
    ].filter(Boolean).join('\n');
    const manifest = `apiVersion: v1
kind: Service
metadata:
  name: ${svcName}
  labels:
    goproxify.enabled: "true"
  annotations:
${annBlock}
spec:
  selector:
    app: ${svcName}
  ports:
    - port: 80
      targetPort: ${port}`;
    document.getElementById('lbl-output').textContent = output;
    document.getElementById('lbl-compose').textContent = manifest;
    return;
  }

  const labels = [`goproxify.enable=true`];
  if (isL4) {
    labels.push(`goproxify.type=${type}`);
    labels.push(`goproxify.port=${port}`);
  } else {
    labels.push(`goproxify.host=${host}`);
    labels.push(`goproxify.port=${port}`);
    if (tls) labels.push(`goproxify.tls=true`);
    if (https) labels.push(`goproxify.https=true`);
    if (passthrough) labels.push(`goproxify.passthrough=true`);
  }
  if (logs) labels.push(`goproxify.logs=true`);
  if (rlOn && rps > 0) {
    labels.push(burst > 0 ? `goproxify.rate_limit=${rps}/s:${burst}` : `goproxify.rate_limit=${rps}/s`);
  }
  if (geoOn && geoCountries) {
    labels.push(`goproxify.geo_ip=${geoMode}:${geoCountries.replace(/\s+/g, '')}`);
  }
  if (ipfOn && ipfCidrs) {
    labels.push(`goproxify.ip_filter=${ipfMode}:${ipfCidrs.replace(/\s+/g, '')}`);
  }
  if (corsOn) {
    labels.push(corsOrigins ? `goproxify.cors=${corsOrigins.replace(/\s+/g, '')}` : 'goproxify.cors=true');
  }
  if (snippets) labels.push(`goproxify.snippets=${snippets}`);
  if (auth) labels.push(`goproxify.auth_provider=${auth}`);
  if (wafOn) labels.push(`goproxify.waf=${waf}`);
  if (bot) labels.push(`goproxify.bot=true`);
  if (canary) {
    labels.push('goproxify.canary=true');
    labels.push(`goproxify.canary.weight=${canaryWeight > 0 ? canaryWeight : 10}`);
  }
  if (shadow) labels.push('goproxify.shadow=true');
  if (update === 'true') labels.push('goproxify.update.auto=true');
  if (update === 'scheduled' && cron) labels.push(`goproxify.update.schedule=${cron}`);
  if (update && prune) labels.push('goproxify.update.prune=true');

  document.getElementById('lbl-output').textContent = labels.join('\n');
  const compose = `services:\n  ${svcName}:\n    image: your-image:latest\n    labels:\n${labels.map(l => '      - "' + l + '"').join('\n')}`;
  document.getElementById('lbl-compose').textContent = compose;
};

window.copyLabels = function() {
  const txt = document.getElementById('lbl-output')?.textContent;
  if (txt) copyText(txt, t('dockerlbl.copied'));
};

window.copyLabelSnippet = function() {
  const txt = document.getElementById('lbl-compose')?.textContent;
  if (txt) copyText(txt, t('dockerlbl.copied_snippet'));
};

// Route legacy : ouvre la modale depuis Infrastructure.
pages['docker-labels'] = function() {
  navigate('infrastructure');
  setTimeout(() => openDockerLabelsModal(), 80);
};
