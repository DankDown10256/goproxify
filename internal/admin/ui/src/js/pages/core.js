// ── PAGE: Contexte Core (waf, ipfilter, certs, auth, metrics, cluster…) ─
// Extrait de pages-all.js — phase 3. Trafic Core reste dans trafic.js.

const _stubPage = (label) => function() {
  document.getElementById('content').innerHTML = `
    <div class="empty">
      <svg width="48" height="48" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="3"/><path d="M9 12h6M12 9v6"/></svg>
      <p style="font-size:15px;font-weight:600;margin-top:8px">${esc(label)}</p>
      <p style="font-size:13px;margin-top:4px">${t('corepage.wip_soon')}</p>
    </div>`;
};

// ── PAGE: WAF ──────────────────────────────────────────────────────────────
pages['core-waf'] = async function() {
  const content = document.getElementById('content');
  content.innerHTML = '<p style="color:var(--text2)">' + t('common.loading') + '</p>';
  try {
    const core = state.selectedCore;
    const coreLabel = core?.display_name || core?.node_name || core?.id || '—';
    const snippets = await api('GET', '/snippets').catch(() => []) || [];
    const wafSnippets = snippets.filter(s => s.type === 'waf' || s.profile_type === 'waf');
    const parseCfg = (s) => {
      if (!s) return {};
      if (typeof s.config === 'string') { try { return JSON.parse(s.config); } catch { return {}; } }
      return s.config || {};
    };
    const wafPrimary = parseCfg(wafSnippets[0]);
    let wafMode = wafPrimary.mode || (wafPrimary.enabled === false ? 'off' : (wafPrimary.enabled ? 'block' : 'off'));
    if (wafPrimary.enabled === false) wafMode = 'off';
    if (wafMode !== 'block' && wafMode !== 'detect' && wafMode !== 'off') wafMode = wafPrimary.enabled ? 'block' : 'off';
    const excluded = new Set(Array.isArray(wafPrimary.exclude_categories) ? wafPrimary.exclude_categories : []);
    // Compat : exclude_ids → catégories
    const CAT_IDS = {
      sqli: [942100, 942110, 942120],
      xss: [941100, 941110, 941120],
      traversal: [930100, 930110],
      rce: [932100, 932110],
      php: [933100],
      ssrf: [934100],
      scanner: [913100],
    };
    if (Array.isArray(wafPrimary.exclude_ids) && wafPrimary.exclude_ids.length) {
      const idSet = new Set(wafPrimary.exclude_ids);
      Object.entries(CAT_IDS).forEach(([cat, ids]) => {
        if (ids.every(id => idSet.has(id))) excluded.add(cat);
      });
    }

    const RULES = [
      { id: 'sqli',     name: 'SQL Injection',        category: 'OWASP CRS-4', ids: '942100–942999' },
      { id: 'xss',      name: 'Cross-Site Scripting',  category: 'OWASP CRS-4', ids: '941100–941999' },
      { id: 'traversal',name: 'Path Traversal / LFI',  category: 'OWASP CRS-4', ids: '930100–930999' },
      { id: 'rce',      name: 'Command Injection',     category: 'OWASP CRS-4', ids: '932100–932999' },
      { id: 'php',      name: 'PHP Injection',          category: 'OWASP CRS-4', ids: '933100–933999' },
      { id: 'ssrf',     name: 'SSRF',                  category: 'OWASP CRS-4', ids: '934100–934999' },
      { id: 'scanner',  name: 'Scanner Detection',     category: 'OWASP CRS-4', ids: '913100–913999' },
    ];

    content.innerHTML = `
      <div style="margin-bottom:20px">
        <h1 style="margin:0 0 4px;font-size:28px;font-family:var(--font-heading);font-weight:600;">${t('page.core-waf')}</h1>
        <p style="margin:0;opacity:0.65;font-size:14px;">${t('corepage.waf.subtitle', { core: esc(coreLabel) })}</p>
      </div>
      <div class="card blueprint" style="padding:18px;display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;margin-bottom:20px">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <div>
          <div class="card-kicker">${t('corepage.waf.global_mode')}</div>
          <div class="card-title" style="font-size:16px;" id="waf-mode-label">${t(wafMode==='detect'?'corepage.mode.detect_only':(wafMode==='off'?'common.disabled':'corepage.mode.block'))}</div>
        </div>
        <div class="seg">
          <label class="seg-opt"><input type="radio" name="waf-mode" value="block" ${wafMode==='block'?'checked':''} onchange="updateWafModeLabel(this.value)">${t('corepage.mode.block')}</label>
          <label class="seg-opt"><input type="radio" name="waf-mode" value="detect" ${wafMode==='detect'?'checked':''} onchange="updateWafModeLabel(this.value)">${t('corepage.mode.detect')}</label>
          <label class="seg-opt"><input type="radio" name="waf-mode" value="off" ${wafMode==='off'?'checked':''} onchange="updateWafModeLabel(this.value)">${t('common.disabled')}</label>
        </div>
      </div>
      <div>
        <h6 style="margin:0 0 12px;">${t('corepage.waf.rules_heading')}</h6>
        <div class="card blueprint" style="overflow:hidden;">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          <div class="table-wrap">
          <table class="table">
            <thead><tr><th>${t('corepage.col.rule')}</th><th>${t('corepage.col.category')}</th><th>IDs</th><th>${t('corepage.col.status')}</th><th></th></tr></thead>
            <tbody>
              ${RULES.map(r => {
                const active = !excluded.has(r.id);
                return `<tr>
                <td>${esc(r.name)}</td>
                <td style="opacity:0.7;">${esc(r.category)}</td>
                <td style="font-family:monospace;font-size:12px;opacity:0.65;">${esc(r.ids)}</td>
                <td><span class="tag ${active?'tag-green':'tag-neutral'}" id="waf-status-${r.id}">${active?t('corepage.status.active'):t('trafic.inactive')}</span></td>
                <td style="text-align:right;"><button class="btn btn-ghost" onclick="toggleWafRule('${r.id}')">${active?t('corepage.action.disable'):t('common.enable')}</button></td>
              </tr>`;
              }).join('')}
            </tbody>
          </table>
          </div>
        </div>
      </div>
      <div style="margin-top:16px;display:flex;justify-content:flex-end;">
        <button type="button" class="btn btn-primary" id="core-waf-save" onclick="saveCoreWaf()">${t('common.save')}</button>
      </div>
      ${wafSnippets.length ? `
      <div style="margin-top:20px;">
        <h6 style="margin:0 0 12px;">${t('corepage.waf.profiles_heading')}</h6>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(min(300px,100%),1fr));gap:14px;">
          ${wafSnippets.map(s => `
          <div class="card blueprint" style="padding:14px 16px;">
            <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
            <div class="card-title" style="font-size:13.5px;">${esc(s.name)}</div>
            <div class="card-meta">${esc(s.description||t('corepage.waf.profile_default'))}</div>
          </div>`).join('')}
        </div>
      </div>` : ''}`;

    window._coreWafSnippetId = wafSnippets[0]?.id || null;
    window._coreWafSnippetName = wafSnippets[0]?.name || 'WAF Core';
    window._wafExcluded = excluded;
    window._wafCatIds = CAT_IDS;
    window.updateWafModeLabel = function(val) {
      const labels = { block: t('corepage.mode.block'), detect: t('corepage.mode.detect_only'), off: t('common.disabled') };
      document.getElementById('waf-mode-label').textContent = labels[val] || val;
    };
    window.toggleWafRule = function(id) {
      const el = document.getElementById('waf-status-' + id);
      const btn = el?.closest('tr')?.querySelector('button');
      if (!el) return;
      const active = el.classList.contains('tag-green');
      el.className = active ? 'tag tag-neutral' : 'tag tag-green';
      el.textContent = active ? t('trafic.inactive') : t('corepage.status.active');
      if (btn) btn.textContent = active ? t('common.enable') : t('corepage.action.disable');
      if (active) window._wafExcluded.add(id); else window._wafExcluded.delete(id);
    };
    window.saveCoreWaf = async function() {
      const mode = document.querySelector('input[name="waf-mode"]:checked')?.value || 'off';
      const excludeCategories = [...(window._wafExcluded || [])];
      const excludeIds = excludeCategories.flatMap(cat => (window._wafCatIds?.[cat] || []));
      const config = {
        mode: mode === 'off' ? 'block' : mode,
        enabled: mode !== 'off',
        exclude_categories: excludeCategories,
        exclude_ids: excludeIds,
      };
      const btn = document.getElementById('core-waf-save');
      if (btn) { btn.disabled = true; btn.textContent = t('common.saving') || '…'; }
      try {
        const payload = {
          name: window._coreWafSnippetName || 'WAF Core',
          type: 'waf',
          description: t('corepage.waf.profile_default'),
          config,
        };
        const id = window._coreWafSnippetId;
        if (id) {
          await api('PUT', `/snippets/${encodeURIComponent(id)}`, payload);
        } else {
          const created = await api('POST', '/snippets', payload);
          if (created?.id) {
            window._coreWafSnippetId = created.id;
            window._coreWafSnippetName = created.name || payload.name;
          }
        }
        toast(t('common.saved') || 'WAF enregistré', 'success');
        navigate('core-waf');
      } catch (e) {
        toast(e.message || t('common.error'), 'error');
      } finally {
        if (btn) { btn.disabled = false; btn.textContent = t('common.save'); }
      }
    };
  } catch(e) { content.innerHTML = `<p style="color:var(--red)">${esc(e.message)}</p>`; }
};

// ── PAGE: IP / GeoIP / Bot ─────────────────────────────────────────────────
pages['core-ipfilter'] = async function() {
  const content = document.getElementById('content');
  content.innerHTML = '<p style="color:var(--text2)">' + t('common.loading') + '</p>';
  try {
    const core = state.selectedCore;
    const coreLabel = core?.display_name || core?.node_name || core?.id || '—';
    const snippets = await api('GET', '/snippets').catch(() => []) || [];
    const parseCfg = (s) => {
      if (!s) return {};
      if (typeof s.config === 'string') { try { return JSON.parse(s.config); } catch { return {}; } }
      return s.config || {};
    };
    const ipSnippets = snippets.filter(s => s.type === 'ip_filter' || s.profile_type === 'ip_filter');
    const geoSnippets = snippets.filter(s => s.type === 'geo_ip' || s.profile_type === 'geo_ip');
    const botSnippets = snippets.filter(s => s.type === 'bot' || s.profile_type === 'bot');
    const geoCodes = [...new Set(geoSnippets.flatMap(s => {
      const c = parseCfg(s);
      return [...(c.countries || []), ...(c.blocked_countries || [])];
    }).map(c => String(c).toUpperCase().trim()).filter(Boolean))];
    const geoPrimary = parseCfg(geoSnippets[0]);
    const geoMode = geoPrimary.mode || 'deny';
    const geoDb = geoPrimary.db_path || '';
    const geoDefaultDb = (typeof GPX_GEO_DEFAULT_DB !== 'undefined' && GPX_GEO_DEFAULT_DB) || '/etc/goproxify/geoip/GeoLite2-Country.mmdb';
    const botPrimary = parseCfg(botSnippets[0]);
    let botMode = botPrimary.mode || (botPrimary.enabled ? 'block' : 'off');
    if (botMode === 'log') botMode = 'monitor';
    if (!botPrimary.enabled && botMode !== 'off' && botMode !== 'monitor' && botMode !== 'block') botMode = 'off';
    if (botPrimary.enabled === false) botMode = 'off';
    const botChallenge = !!(botPrimary.js_challenge || botPrimary.challenge);

    content.innerHTML = `
      <div style="margin-bottom:20px">
        <h1 style="margin:0 0 4px;font-size:28px;font-family:var(--font-heading);font-weight:600;">${t('page.core-ipfilter')}</h1>
        <p style="margin:0;opacity:0.65;font-size:14px;">${t('corepage.ipfilter.subtitle', { core: esc(coreLabel) })}</p>
        <p style="margin:4px 0 0;opacity:0.55;font-size:12.5px;">${t('corepage.ipfilter.defaults_hint')}</p>
      </div>

      <div class="card blueprint" style="padding:20px;display:flex;flex-direction:column;gap:14px;margin-bottom:16px;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap;">
          <h6 style="margin:0;">${t('corepage.ipfilter.manual_list')}</h6>
          <button class="btn btn-ghost" onclick="openIpRuleModal()">${t('corepage.ipfilter.new_rule')}</button>
        </div>
        <div class="table-wrap">
        <table class="table">
          <thead><tr><th>${t('corepage.col.cidr')}</th><th>${t('corepage.col.type')}</th><th>${t('common.note')}</th><th></th></tr></thead>
          <tbody id="ip-rules-body"><tr><td colspan="4" class="empty"><p>${t('corepage.ipfilter.no_rules')}</p></td></tr></tbody>
        </table>
        </div>
      </div>

      ${ipSnippets.length ? `
      <div style="margin-bottom:16px;">
        <h6 style="margin:0 0 8px;">${t('corepage.ipfilter.threat_feeds')}</h6>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(min(200px,100%),1fr));gap:12px;">
          ${ipSnippets.map(s => `
          <div class="card blueprint" style="padding:14px 16px;">
            <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
            <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px;">
              <div class="card-title" style="font-size:13.5px;">${esc(s.name)}</div>
              <span class="tag tag-outline" style="font-size:10px;">${s.config?.mode === 'allow' ? 'ALLOW' : 'DENY'}</span>
            </div>
            <div class="card-meta" style="font-size:11px;">${esc(s.description||'')}</div>
          </div>`).join('')}
        </div>
      </div>` : ''}

      <div class="card blueprint" style="padding:20px;display:flex;flex-direction:column;gap:14px;margin-bottom:16px;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <h6 style="margin:0;">${t('corepage.geo.title')}</h6>
        <p style="margin:0;font-size:12.5px;color:var(--text3);">${t('corepage.geo.picker_hint')}</p>
        <div style="display:flex;gap:16px;align-items:flex-start;">
          <div style="display:flex;align-items:center;gap:8px;padding-top:22px;">
            <label class="toggle"><input type="checkbox" id="core-geo-enabled" ${geoCodes.length?'checked':''} onchange="psecGeoToggleEnabled(this.checked)"><span class="toggle-slider"></span></label>
            <span style="font-size:13px;font-weight:500;">${t('corepage.geo.label')}</span>
          </div>
          <div class="field" style="flex:1;margin:0;">
            <label class="field-label" style="font-size:11px">${t('corepage.geo.mode_label')}</label>
            <select id="core-geo-mode" class="input">
              <option value="deny" ${geoMode!=='allow'?'selected':''}>${t('corepage.geo.mode_deny')}</option>
              <option value="allow" ${geoMode==='allow'?'selected':''}>${t('corepage.geo.mode_allow')}</option>
            </select>
          </div>
        </div>
        <div id="core-geo-fields" style="opacity:${geoCodes.length?'1':'0.45'};">
          <div class="field" style="margin:0 0 8px;">
            <label class="field-label" style="font-size:11px">${t('corepage.geo.db_label')}</label>
            <input id="core-geo-db" class="input" placeholder="${esc(geoDefaultDb)}" value="${esc(geoDb)}">
            <div style="font-size:10px;color:var(--text3);margin-top:3px;">${t('corepage.geo.db_hint')}</div>
          </div>
          <div id="core-geo-picker"></div>
        </div>
        ${geoSnippets.length ? `<div style="font-size:11px;color:var(--text3);border-top:1px solid var(--border);padding-top:10px;">
          ${t('corepage.geo.linked_snippets')} ${geoSnippets.map(s => `<code>${esc(s.name||s.id)}</code>`).join(', ')}
        </div>` : ''}
        <div style="display:flex;justify-content:flex-end;gap:8px;border-top:1px solid var(--border);padding-top:12px;margin-top:4px;">
          <button type="button" class="btn btn-primary" id="core-geo-save" onclick="saveCoreGeoIP()">${t('corepage.geo.save')}</button>
        </div>
      </div>

      <div class="card blueprint" style="padding:20px;display:flex;flex-direction:column;gap:14px;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <h6 style="margin:0;">${t('corepage.bot.title')}</h6>
        <div class="seg" style="align-self:flex-start;">
          <label class="seg-opt"><input type="radio" name="bot-mode" value="off" ${botMode==='off'?'checked':''} onchange="updateBotMode(this.value)">${t('common.disabled')}</label>
          <label class="seg-opt"><input type="radio" name="bot-mode" value="monitor" ${botMode==='monitor'?'checked':''} onchange="updateBotMode(this.value)">${t('corepage.bot.mode_monitor')}</label>
          <label class="seg-opt"><input type="radio" name="bot-mode" value="block" ${botMode==='block'?'checked':''} onchange="updateBotMode(this.value)">${t('corepage.bot.mode_block')}</label>
        </div>
        <div style="display:flex;align-items:center;gap:10px;">
          <span style="font-size:13px;opacity:0.75;">${t('corepage.bot.js_challenge')}</span>
          <span class="tag ${botChallenge?'tag-accent':'tag-neutral'}" id="bot-challenge-tag" style="cursor:pointer;" onclick="toggleBotChallenge()">${botChallenge ? t('common.enabled') : t('common.disabled')}</span>
        </div>
        <div style="display:flex;justify-content:flex-end;gap:8px;border-top:1px solid var(--border);padding-top:12px;margin-top:4px;">
          <button type="button" class="btn btn-primary" id="core-bot-save" onclick="saveCoreBot()">${t('corepage.bot.save')}</button>
        </div>
      </div>

      <div id="ip-rule-modal-container"></div>`;

    try { psecGeoInit(geoCodes, 'core-geo-picker'); } catch (e) { console.warn('core geo init', e); }
    window._coreGeoSnippetId = geoSnippets[0]?.id || null;
    window._coreGeoSnippetName = geoSnippets[0]?.name || 'GeoIP Core';
    window.saveCoreGeoIP = async function() {
      const enabled = !!document.getElementById('core-geo-enabled')?.checked;
      const mode = document.getElementById('core-geo-mode')?.value || 'deny';
      const dbPath = (document.getElementById('core-geo-db')?.value || '').trim();
      const countries = enabled ? psecGeoGetSelected() : [];
      if (enabled && !countries.length) {
        toast(t('corepage.geo.toast_select_country'), 'error');
        return;
      }
      const config = {
        mode,
        countries,
        blocked_countries: countries, // alias legacy (page / affichages anciens)
        db_path: dbPath || undefined,
      };
      const id = window._coreGeoSnippetId;
      if (!enabled && !countries.length && !id) {
        toast(t('corepage.geo.toast_already_inactive'), 'info');
        return;
      }
      const btn = document.getElementById('core-geo-save');
      if (btn) { btn.disabled = true; btn.textContent = t('corepage.geo.saving'); }
      try {
        const payload = {
          name: window._coreGeoSnippetName || 'GeoIP Core',
          type: 'geo_ip',
          description: t('corepage.geo_default_desc'),
          config,
        };
        if (id) {
          await api('PUT', `/snippets/${encodeURIComponent(id)}`, payload);
        } else {
          const created = await api('POST', '/snippets', payload);
          if (created?.id) {
            window._coreGeoSnippetId = created.id;
            window._coreGeoSnippetName = created.name || payload.name;
          }
        }
        toast(enabled ? t('corepage.geo.toast_saved', { n: countries.length }) : t('corepage.geo.toast_disabled'), 'success');
        navigate('core-ipfilter');
      } catch (e) {
        toast(e.message || t('corepage.geo.toast_error'), 'error');
      } finally {
        if (btn) { btn.disabled = false; btn.textContent = t('corepage.geo.save'); }
      }
    };
    window._ipRules = [];
    window.renderIpRules = function() {
      const body = document.getElementById('ip-rules-body');
      if (!body) return;
      body.innerHTML = window._ipRules.length ? window._ipRules.map((r,i) => `<tr>
        <td style="font-family:monospace;">${esc(r.cidr)}</td>
        <td><span class="tag ${r.type==='allow'?'tag-green':'tag-red'}">${r.type==='allow'?t('corepage.ipfilter.allow'):t('corepage.ipfilter.deny')}</span></td>
        <td style="opacity:0.7;">${esc(r.note||'')}</td>
        <td style="text-align:right;"><button class="btn btn-ghost btn-icon" onclick="removeIpRule(${i})" title="${t('common.delete')}"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M3 6h18"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/></svg></button></td>
      </tr>`).join('') : '<tr><td colspan="4" class="empty"><p>' + t('corepage.ipfilter.no_rules') + '</p></td></tr>';
    };
    window.openIpRuleModal = function() {
      document.getElementById('ip-rule-modal-container').innerHTML = `
        <div class="dialog-backdrop" style="position:fixed;inset:0;z-index:9999;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,0.55);">
          <div class="dialog blueprint" role="dialog" aria-modal="true">
            <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
            <div class="dialog-title">${t('corepage.ipfilter.modal_title')}</div>
            <div class="dialog-body" style="display:flex;flex-direction:column;gap:14px;">
              <div class="field"><label>${t('corepage.ipfilter.cidr_label')}</label><input class="input" id="nr-cidr" placeholder="${t('corepage.ipfilter.cidr_ph')}"></div>
              <div class="field"><label>${t('corepage.col.type')}</label><div class="seg">
                <label class="seg-opt"><input type="radio" name="nr-type" value="allow" checked>${t('corepage.ipfilter.allow')}</label>
                <label class="seg-opt"><input type="radio" name="nr-type" value="deny">${t('corepage.ipfilter.deny')}</label>
              </div></div>
              <div class="field"><label>${t('common.note')}</label><input class="input" id="nr-note" placeholder="${t('corepage.ipfilter.note_ph')}"></div>
            </div>
            <div class="dialog-actions">
              <button class="btn btn-secondary blueprint" onclick="document.getElementById('ip-rule-modal-container').innerHTML=''"><i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>${t('common.cancel')}</button>
              <button class="btn btn-primary blueprint" onclick="createIpRule()"><i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>${t('corepage.ipfilter.add_rule')}</button>
            </div>
          </div>
        </div>`;
    };
    window.createIpRule = function() {
      const cidr = document.getElementById('nr-cidr')?.value;
      const type = document.querySelector('input[name="nr-type"]:checked')?.value || 'deny';
      const note = document.getElementById('nr-note')?.value;
      if (!cidr) return;
      window._ipRules.push({ cidr, type, note });
      document.getElementById('ip-rule-modal-container').innerHTML = '';
      renderIpRules();
    };
    window.removeIpRule = function(i) { window._ipRules.splice(i,1); renderIpRules(); };
    window._coreBotSnippetId = botSnippets[0]?.id || null;
    window._coreBotSnippetName = botSnippets[0]?.name || 'Bot Core';
    window.updateBotMode = function(val) {
      const tag = document.getElementById('bot-challenge-tag');
      if (!tag) return;
      if (val === 'off') {
        tag.className = 'tag tag-neutral';
        tag.textContent = t('common.disabled');
        tag.style.opacity = '0.45';
        tag.style.pointerEvents = 'none';
      } else {
        tag.style.opacity = '1';
        tag.style.pointerEvents = '';
      }
    };
    window.toggleBotChallenge = function() {
      const el = document.getElementById('bot-challenge-tag');
      if (!el || el.style.pointerEvents === 'none') return;
      const active = el.classList.contains('tag-accent');
      el.className = active ? 'tag tag-neutral' : 'tag tag-accent';
      el.textContent = active ? t('common.disabled') : t('common.enabled');
    };
    window.saveCoreBot = async function() {
      const mode = document.querySelector('input[name="bot-mode"]:checked')?.value || 'off';
      const challenge = !!document.getElementById('bot-challenge-tag')?.classList.contains('tag-accent') && mode !== 'off';
      const config = {
        mode,
        enabled: mode !== 'off',
        js_challenge: challenge,
      };
      const btn = document.getElementById('core-bot-save');
      if (btn) { btn.disabled = true; btn.textContent = t('corepage.bot.saving'); }
      try {
        const payload = {
          name: window._coreBotSnippetName || 'Bot Core',
          type: 'bot',
          description: t('corepage.bot_default_desc'),
          config,
        };
        const id = window._coreBotSnippetId;
        if (id) {
          await api('PUT', `/snippets/${encodeURIComponent(id)}`, payload);
        } else {
          const created = await api('POST', '/snippets', payload);
          if (created?.id) {
            window._coreBotSnippetId = created.id;
            window._coreBotSnippetName = created.name || payload.name;
          }
        }
        const modeLabels = { off: t('corepage.bot.mode_off'), monitor: t('corepage.bot.mode_monitor_short'), block: t('corepage.bot.mode_block_short') };
        const detail = (modeLabels[mode] || mode) + (challenge ? t('corepage.bot.challenge_suffix') : '');
        toast(t('corepage.bot.toast_saved', { detail }), 'success');
        navigate('core-ipfilter');
      } catch (e) {
        toast(e.message || t('corepage.bot.toast_error'), 'error');
      } finally {
        if (btn) { btn.disabled = false; btn.textContent = t('corepage.bot.save'); }
      }
    };
    try { updateBotMode(botMode); } catch (_) {}
  } catch(e) { content.innerHTML = `<p style="color:var(--red)">${esc(e.message)}</p>`; }
};

// Certificats TLS Core → pages['core-certs'] dans domains.js (renderCertsPage)

// ── PAGE: Auth / SSO ───────────────────────────────────────────────────────
pages['core-auth'] = async function() {
  const content = document.getElementById('content');
  content.innerHTML = '<p style="color:var(--text2)">' + t('common.loading') + '</p>';
  try {
    const core = state.selectedCore;
    const coreLabel = core?.display_name || core?.node_name || core?.id || '—';
    const providers = await api('GET', '/auth-providers').catch(() => []) || [];

    const forwardAuth = providers.filter(p => ['authentik','authelia','forward','basic'].includes(p.type));
    const oidc = providers.filter(p => p.type === 'oidc');
    const native = providers.filter(p => ['jwt','mtls','ldap','saml','github_oauth'].includes(p.type));

    function providerCard(p) {
      const active = p.enabled !== false;
      return `<div class="card blueprint" style="display:flex;flex-direction:column;gap:10px;padding:16px 18px;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:10px;">
          <div class="card-title" style="font-size:15px;">${esc(p.name||p.type)}</div>
          <span class="tag ${active?'tag-green':'tag-neutral'}">${active ? t('trafic.active') : t('trafic.inactive')}</span>
        </div>
        <code style="font-size:11px;opacity:0.6;">${esc(p.type)}</code>
        <div class="card-meta">${esc(p.forward_auth_url||p.issuer_url||p.server||p.description||'')}</div>
        <div style="display:flex;align-items:center;gap:8px;margin-top:2px;">
          <button class="btn btn-ghost" onclick="navigate('snippets')">${t('corepage.auth.configure')}</button>
        </div>
      </div>`;
    }

    content.innerHTML = `
      <div style="margin-bottom:20px">
        <h1 style="margin:0 0 4px;font-size:28px;font-family:var(--font-heading);font-weight:600;">${t('page.core-auth')}</h1>
        <p style="margin:0;opacity:0.65;font-size:14px;">${t('corepage.auth.subtitle', { core: esc(coreLabel) })}</p>
      </div>

      <div style="display:flex;flex-direction:column;gap:8px;margin-bottom:20px;">
        <h6 style="margin:0;">${t('corepage.auth.forward_title')}</h6>
        <p style="margin:0 0 4px;opacity:0.6;font-size:12.5px;">${t('corepage.auth.forward_desc')}</p>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(min(220px,100%),1fr));gap:14px;">
          ${forwardAuth.length ? forwardAuth.map(providerCard).join('') : `
          <div class="card blueprint" style="padding:28px;display:flex;flex-direction:column;align-items:center;gap:10px;text-align:center;grid-column:1/-1;">
            <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
            <span class="tag tag-neutral">${t('corepage.auth.no_forward')}</span>
            <p style="margin:0;font-size:12.5px;opacity:0.6;max-width:40ch;">${t('corepage.auth.no_forward_hint')}</p>
            <button class="btn btn-secondary blueprint" onclick="navigate('snippets')"><i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>${t('corepage.auth.manage_snippets')}</button>
          </div>`}
        </div>
      </div>

      ${native.length ? `<div style="display:flex;flex-direction:column;gap:8px;margin-bottom:20px;">
        <h6 style="margin:0;">${t('corepage.auth.native_title')}</h6>
        <p style="margin:0 0 4px;opacity:0.6;font-size:12.5px;">${t('corepage.auth.native_desc')}</p>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(min(220px,100%),1fr));gap:14px;">
          ${native.map(providerCard).join('')}
        </div>
      </div>` : ''}

      ${oidc.length ? `<div style="display:flex;flex-direction:column;gap:8px;margin-bottom:20px;">
        <h6 style="margin:0;">${t('corepage.auth.oidc_title')}</h6>
        <p style="margin:0 0 4px;opacity:0.6;font-size:12.5px;">${t('corepage.auth.oidc_desc')}</p>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(min(220px,100%),1fr));gap:14px;">
          ${oidc.map(providerCard).join('')}
        </div>
      </div>` : ''}

      <div class="card blueprint" style="padding:20px;display:flex;flex-direction:column;gap:14px;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <h6 style="margin:0;">${t('corepage.auth.local_policy')}</h6>
        <div style="display:flex;align-items:center;gap:10px;">
          <span style="font-size:13px;opacity:0.75;">${t('corepage.auth.mfa_label')}</span>
          <span class="tag tag-neutral" id="mfa-tag" style="cursor:pointer;" onclick="toggle2FA()">${t('corepage.auth.mfa_not_required')}</span>
        </div>
        <div class="field" style="max-width:220px;">
          <label for="session-duration">${t('corepage.auth.session_duration')}</label>
          <select class="input" id="session-duration">
            <option value="1h">${t('corepage.auth.session_1h')}</option>
            <option value="8h" selected>${t('corepage.auth.session_8h')}</option>
            <option value="24h">${t('corepage.auth.session_24h')}</option>
            <option value="7d">${t('corepage.auth.session_7d')}</option>
          </select>
        </div>
      </div>`;

    window.toggle2FA = function() {
      const el = document.getElementById('mfa-tag');
      if (!el) return;
      const active = el.classList.contains('tag-accent');
      el.className = active ? 'tag tag-neutral' : 'tag tag-accent';
      el.textContent = active ? t('corepage.auth.mfa_not_required') : t('corepage.auth.mfa_required');
    };
  } catch(e) { content.innerHTML = `<p style="color:var(--red)">${esc(e.message)}</p>`; }
};

// ── PAGE: Métriques ────────────────────────────────────────────────────────
pages['core-metrics'] = async function() {
  const content = document.getElementById('content');
  content.innerHTML = '<p style="color:var(--text2)">' + t('common.loading') + '</p>';
  try {
    const core = state.selectedCore;
    const coreLabel = core?.display_name || core?.node_name || core?.id || '—';

    let health = null;
    if (core?.node_endpoint) {
      health = await api('GET', `/nodes/${core.id}/health`).catch(() => null);
    }

    const cpu = core?.cpu_pct ?? health?.cpu_pct ?? null;
    const mem = core?.mem_pct ?? health?.mem_pct ?? null;
    const rps = health?.requests_per_sec ?? null;
    const latency = health?.latency_p95_ms ?? null;
    const errRate = health?.error_rate_pct ?? null;
    const bw = health?.bandwidth_mbps ?? null;

    const fmtNum = (v, suffix='') => v != null ? `${typeof v === 'number' ? v.toFixed(v < 10 ? 1 : 0) : v}${suffix}` : '—';

    const days = [
      t('corepage.metrics.day_mon'), t('corepage.metrics.day_tue'), t('corepage.metrics.day_wed'),
      t('corepage.metrics.day_thu'), t('corepage.metrics.day_fri'), t('corepage.metrics.day_sat'),
      t('corepage.metrics.day_sun'),
    ];
    const fakeBars = days.map(d => ({ label: d, pct: Math.floor(30 + Math.random()*60) }));

    content.innerHTML = `
      <div style="margin-bottom:20px">
        <h1 style="margin:0 0 4px;font-size:28px;font-family:var(--font-heading);font-weight:600;">${t('page.core-metrics')}</h1>
        <p style="margin:0;opacity:0.65;font-size:14px;">${t('corepage.metrics.subtitle', { core: esc(coreLabel) })}</p>
      </div>
      <div class="gp-stat-grid" style="margin-bottom:20px;">
        <div class="card blueprint">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          <div class="card-kicker">${t('corepage.metrics.rps')}</div>
          <div class="card-title">${fmtNum(rps)}</div>
          <div class="card-meta">${t('corepage.metrics.rps_meta')}</div>
        </div>
        <div class="card blueprint">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          <div class="card-kicker">${t('corepage.metrics.latency_p95')}</div>
          <div class="card-title">${latency != null ? fmtNum(latency,'ms') : '—'}</div>
          <div class="card-meta">${t('corepage.metrics.latency_meta')}</div>
        </div>
        <div class="card blueprint">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          <div class="card-kicker">${t('corepage.metrics.error_rate')}</div>
          <div class="card-title">${errRate != null ? fmtNum(errRate,'%') : '—'}</div>
          <div class="card-meta">${t('corepage.metrics.error_meta')}</div>
        </div>
        <div class="card blueprint">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          <div class="card-kicker">${t('corepage.metrics.cpu')}</div>
          <div class="card-title">${fmtNum(cpu,'%')}</div>
          <div class="card-meta">${t('corepage.metrics.memory', { pct: fmtNum(mem,'%') })}</div>
        </div>
      </div>
      <div class="card blueprint" style="padding:20px;margin-bottom:16px;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <h6 style="margin:0 0 16px;">${t('corepage.metrics.activity_7d')}</h6>
        <div style="display:flex;align-items:flex-end;gap:12px;height:140px;">
          ${fakeBars.map(d => `
          <div style="display:flex;flex-direction:column;align-items:center;gap:6px;flex:1;height:100%;justify-content:flex-end;">
            <div style="width:100%;max-width:36px;background:var(--accent);height:${d.pct}%;"></div>
            <span style="font-size:11px;opacity:0.6;">${d.label}</span>
          </div>`).join('')}
        </div>
      </div>
      <div class="card blueprint" style="padding:20px;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;">
          <h6 style="margin:0;">${t('corepage.metrics.prometheus_title')}</h6>
          <span class="tag tag-accent">${t('trafic.active')}</span>
        </div>
        <p style="margin:0;font-size:13px;opacity:0.7;">
          ${t('corepage.metrics.prometheus_desc')}
        </p>
      </div>`;
  } catch(e) { content.innerHTML = `<p style="color:var(--red)">${esc(e.message)}</p>`; }
};

// ── PAGE: Nœuds / Raft (Cluster) ───────────────────────────────────────────
pages['core-cluster'] = async function() {
  const content = document.getElementById('content');
  content.innerHTML = '<p style="color:var(--text2)">' + t('common.loading') + '</p>';
  try {
    const core = state.selectedCore;
    const coreLabel = core?.display_name || core?.node_name || core?.id || '—';
    const nodes = await api('GET', '/nodes').catch(() => []) || [];
    const coreNodes = nodes.filter(n => n.role === 'core');
    const defaultGroup = t('corepage.cluster.default_group');
    const groupName = core?.group_name || defaultGroup;
    const groupNodes = coreNodes.filter(n => (n.group_name || defaultGroup) === groupName);

    content.innerHTML = `
      <div style="margin-bottom:20px">
        <h1 style="margin:0 0 4px;font-size:28px;font-family:var(--font-heading);font-weight:600;">${t('page.core-cluster')}</h1>
        <p style="margin:0;opacity:0.65;font-size:14px;">${t('corepage.cluster.subtitle', { core: esc(coreLabel) })}</p>
      </div>

      <div class="gp-core-grid" style="margin-bottom:20px;">
        <div class="card blueprint">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          <div class="card-kicker">${t('corepage.cluster.nodes_in_group')}</div>
          <div class="card-title">${groupNodes.filter(n=>n.status==='online').length} / ${groupNodes.length}</div>
          <div class="card-meta">${t('corepage.cluster.group', { name: esc(groupName) })}</div>
        </div>
        <div class="card blueprint">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          <div class="card-kicker">${t('corepage.cluster.raft_state')}</div>
          <div class="card-title">${groupNodes.length > 1 ? t('corepage.cluster.mode_cluster') : t('corepage.cluster.mode_standalone')}</div>
          <div class="card-meta">${groupNodes.length > 1 ? t('corepage.cluster.consensus_active') : t('corepage.cluster.single_node')}</div>
        </div>
        <div class="card blueprint">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          <div class="card-kicker">${t('corepage.cluster.all_groups')}</div>
          <div class="card-title">${[...new Set(coreNodes.map(n=>n.group_name||defaultGroup))].length}</div>
          <div class="card-meta">${t('corepage.cluster.cores_total', { n: coreNodes.length })}</div>
        </div>
      </div>

      <h6 style="margin:0 0 12px;">${t('corepage.cluster.group_members', { name: esc(groupName) })}</h6>
      <div class="card blueprint" style="overflow:hidden;margin-bottom:20px;padding:0;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <div class="table-wrap">
        <table class="table">
          <thead><tr><th>${t('corepage.col.node')}</th><th>${t('corepage.col.address')}</th><th>${t('corepage.col.raft_role')}</th><th>${t('corepage.metrics.cpu')}</th><th>${t('corepage.col.memory')}</th><th>${t('corepage.col.status')}</th></tr></thead>
          <tbody>
            ${groupNodes.length ? groupNodes.map(n => `<tr>
              <td><strong>${esc(n.display_name||n.node_name||n.id)}</strong>${n.id===core?.id?' <span class="tag tag-accent-2" style="font-size:10px;">' + t('corepage.cluster.this_node') + '</span>':''}</td>
              <td style="font-family:monospace;font-size:12px;">${esc(n.node_endpoint||n.api_host||'—')}</td>
              <td><span class="tag tag-neutral">${n.raft_role||'Follower'}</span></td>
              <td>${n.cpu_pct!=null?n.cpu_pct.toFixed(1)+'%':'—'}</td>
              <td>${n.mem_pct!=null?n.mem_pct.toFixed(1)+'%':'—'}</td>
              <td>${n.status==='online'?'<span class="tag tag-green">' + t('corepage.cluster.online') + '</span>':'<span class="tag tag-red">' + t('corepage.cluster.offline') + '</span>'}</td>
            </tr>`).join('') : '<tr><td colspan="6" class="empty"><p>' + t('corepage.cluster.no_nodes') + '</p></td></tr>'}
          </tbody>
        </table>
        </div>
      </div>

      <div class="card blueprint" style="padding:18px;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <h6 style="margin:0 0 8px;">${t('corepage.cluster.raft_arch_title')}</h6>
        <p style="margin:0;font-size:13px;opacity:0.7;">
          ${t('corepage.cluster.raft_arch_desc')}
        </p>
      </div>`;
  } catch(e) { content.innerHTML = `<p style="color:var(--red)">${esc(e.message)}</p>`; }
};

// ── PAGE: Paramètres Core ─────────────────────────────────────────────────
pages['core-settings'] = function() {
  const content = document.getElementById('content');
  const core = state.selectedCore;
  const coreLabel = core?.display_name || core?.node_name || '—';
  const sections = [
    {
      label: t('coresettings.section.security'),
      desc: t('coresettings.section.security_desc'),
      items: [
        { page: 'core-waf',      icon: '<path d="M8 2l5 3v4c0 3-2.5 5.5-5 6.5C5.5 14.5 3 12 3 9V5l5-3z"/><path d="M6 8h4M8 6v4"/>', label: t('coresettings.item.waf'), desc: t('coresettings.item.waf_desc') },
        { page: 'core-ipfilter', icon: '<circle cx="8" cy="8" r="6"/><path d="M5 8h6M8 5v6"/>', label: t('coresettings.item.ipfilter'), desc: t('coresettings.item.ipfilter_desc') },
        { page: 'core-auth',     icon: '<rect x="4" y="8" width="8" height="6" rx="1"/><path d="M6 8V6a2 2 0 014 0v2"/>', label: t('coresettings.item.auth'), desc: t('coresettings.item.auth_desc') },
      ]
    },
    {
      label: t('coresettings.section.tls'),
      desc: t('coresettings.section.tls_desc'),
      items: [
        { page: 'core-certs', icon: '<path d="M12 2H4a1 1 0 00-1 1v10a1 1 0 001 1h8a1 1 0 001-1V3a1 1 0 00-1-1zM9 7H7m2 3H7"/>', label: t('coresettings.item.certs'), desc: t('coresettings.item.certs_desc') },
      ]
    },
    {
      label: t('coresettings.section.routing'),
      desc: t('coresettings.section.routing_desc'),
      items: [
        { page: 'snippets',  icon: '<path d="M4 6l4-4 4 4M4 10l4 4 4-4"/>', label: t('coresettings.item.snippets'), desc: t('coresettings.item.snippets_desc') },
      ]
    },
    {
      label: t('coresettings.section.infra'),
      desc: t('coresettings.section.infra_desc'),
      items: [
        { page: 'core-cluster', icon: '<circle cx="8" cy="8" r="2"/><circle cx="2" cy="4" r="1.5"/><circle cx="14" cy="4" r="1.5"/><circle cx="8" cy="14" r="1.5"/><path d="M3.2 4.8L6.5 7M9.5 7l3.3-2.2M8 9.5V12"/>', label: t('coresettings.item.cluster'), desc: t('coresettings.item.cluster_desc') },
        { page: 'core-portal-catalog', icon: '<rect x="3" y="5" width="10" height="8" rx="1"/><path d="M6 8h6"/>', label: t('coresettings.item.pcatalog'), desc: t('coresettings.item.pcatalog_desc') },
        { page: 'core-portal-users', icon: '<circle cx="8" cy="5" r="2.5"/><path d="M3 13c0-2.2 2.2-4 5-4s5 1.8 5 4"/>', label: t('coresettings.item.pusers'), desc: t('coresettings.item.pusers_desc') },
        { page: 'core-general', icon: '<circle cx="8" cy="8" r="3"/><path d="M8 1v2M8 13v2M1 8h2M13 8h2M3.2 3.2l1.4 1.4M11.4 11.4l1.4 1.4M3.2 12.8l1.4-1.4M11.4 4.6l1.4-1.4"/>', label: t('coresettings.item.general'), desc: t('coresettings.item.general_desc') },
      ]
    },
  ];

  const headerHtml = `
    <div style="margin-bottom:20px">
      <h1 style="margin:0 0 4px;font-size:24px;font-family:var(--font-heading);font-weight:600;">${t('coresettings.title', { core: esc(coreLabel) })}</h1>
      <p style="margin:0;font-size:13px;color:var(--text2);">${t('coresettings.subtitle')}</p>
      <div style="margin-top:10px;display:inline-flex;align-items:center;gap:8px;padding:6px 12px;background:var(--bg2);border:1px solid var(--border);border-radius:8px;font-size:12px;">
        <span style="color:var(--text2)">${t('coresettings.version_banner')}</span>
        <strong style="font-family:monospace;">v${esc(core?.version || '—')}</strong>
      </div>
    </div>`;

  renderSettingsHub({ contentEl: content, sections, headerHtml });
};

pages['core-general'] = async function() {
  const content = document.getElementById('content');
  content.innerHTML = '<p style="color:var(--text2)">' + t('common.loading') + '</p>';
  try {
    const core = state.selectedCore;
    if (!core) { content.innerHTML = '<p style="color:var(--text2)">' + t('corepage.general.no_core') + '</p>'; return; }
    const coreLabel = core.display_name || core.node_name || core.id || '—';

    const statusOnline  = core.status === 'online';
    const statusPending = core.status === 'pending';
    const statusColor   = statusOnline ? 'var(--green)' : statusPending ? 'var(--yellow,#f59e0b)' : 'var(--red)';
    const statusLabel   = statusOnline ? t('corepage.general.status_connected') : statusPending ? t('corepage.general.status_pending') : t('corepage.general.status_offline');
    const lastSeen      = core.last_seen_at ? fmtDate(core.last_seen_at) : '—';
    const tagsVal       = Array.isArray(core.tags) ? core.tags.join(', ') : (core.tags || '');

    const infraCell = (port, label, envVar) => `
      <div style="background:var(--bg2,rgba(128,128,128,0.07));border-radius:6px;padding:10px 14px;">
        <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.07em;opacity:0.45;margin-bottom:5px;">${label}</div>
        <div style="font-family:monospace;font-size:15px;font-weight:700;">:${port}</div>
        <div style="font-size:10px;opacity:0.35;margin-top:3px;font-family:monospace;">${envVar}</div>
      </div>`;

    content.innerHTML = `
      <div style="margin-bottom:20px">
        <button onclick="navigate('core-settings')" style="background:none;border:none;color:var(--text2);cursor:pointer;font-size:12px;padding:0;margin-bottom:8px;">${t('corepage.general.back', { core: esc(coreLabel) })}</button>
        <h1 style="margin:0 0 4px;font-size:24px;font-family:var(--font-heading);font-weight:600;">${t('page.core-general')}</h1>
        <p style="margin:0;font-size:13px;color:var(--text2);">${t('corepage.general.subtitle')}</p>
      </div>
      <div style="display:flex;flex-direction:column;gap:16px;max-width:720px;">

        <!-- Plan de contrôle WebSocket -->
        <div class="card blueprint" style="padding:20px;display:flex;flex-direction:column;gap:14px;">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;">
            <div>
              <h6 style="margin:0 0 3px;font-size:11px;text-transform:uppercase;letter-spacing:0.09em;opacity:0.5;">${t('corepage.general.ws_control')}</h6>
              <div style="font-size:12px;color:var(--text2);">${t('corepage.general.ws_tunnel')}</div>
            </div>
            <div style="display:flex;align-items:center;gap:7px;">
              <span style="width:8px;height:8px;border-radius:50%;background:${statusColor};display:inline-block;flex-shrink:0;${statusOnline?'box-shadow:0 0 0 3px rgba(74,222,128,0.22);':''}"></span>
              <span style="font-size:13px;font-weight:600;color:${statusColor}">${esc(statusLabel)}</span>
            </div>
          </div>
          <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(min(155px,100%),1fr));gap:10px;padding-top:10px;border-top:1px solid var(--border);">
            <div>
              <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.07em;opacity:0.4;margin-bottom:3px;">${t('corepage.general.endpoint')}</div>
              <div style="font-family:monospace;font-size:11px;word-break:break-all;opacity:0.85;">${esc(core.endpoint||'—')}</div>
            </div>
            <div>
              <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.07em;opacity:0.4;margin-bottom:3px;">${t('corepage.general.version')}</div>
              <div style="font-family:monospace;font-size:12px;">${esc(core.version||'—')}</div>
            </div>
            <div>
              <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.07em;opacity:0.4;margin-bottom:3px;">${t('corepage.general.last_seen')}</div>
              <div style="font-size:12px;">${esc(lastSeen)}</div>
            </div>
            <div>
              <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.07em;opacity:0.4;margin-bottom:3px;">${t('corepage.general.cpu_mem')}</div>
              <div style="font-size:12px;font-family:monospace;">${core.cpu_pct != null ? Math.round(core.cpu_pct)+'%' : '—'} / ${core.mem_pct != null ? Math.round(core.mem_pct)+'%' : '—'}</div>
            </div>
          </div>
        </div>

        <!-- Identité — champs modifiables -->
        <div class="card blueprint" style="padding:20px;display:flex;flex-direction:column;gap:16px;">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          <h6 style="margin:0;font-size:11px;text-transform:uppercase;letter-spacing:0.09em;opacity:0.5;">${t('corepage.general.identity')}</h6>
          <div class="gp-split-2" style="gap:10px;">
            <div class="field">
              <label>Node name <span style="font-size:10px;opacity:0.4;font-style:italic;">${t('corepage.general.node_name_ro')}</span></label>
              <input class="input" value="${esc(core.node_name||'')}" readonly tabindex="-1" style="opacity:0.5;cursor:default;">
            </div>
            <div class="field">
              <label for="cs-display">${t('corepage.general.display_name')}</label>
              <input class="input" id="cs-display" value="${esc(core.display_name||'')}" placeholder="${esc(core.node_name||'core-1')}">
            </div>
          </div>
          <div class="gp-split-2" style="gap:10px;">
            <div class="field">
              <label for="cs-region">${t('corepage.general.region')}</label>
              <input class="input" id="cs-region" value="${esc(core.region||'')}" placeholder="eu-west-1">
            </div>
            <div class="field">
              <label for="cs-env">${t('corepage.general.environment')}</label>
              <input class="input" id="cs-env" value="${esc(core.environment||'')}" placeholder="production">
            </div>
          </div>
          <div class="field">
            <label for="cs-tags">Tags <span style="font-size:11px;opacity:0.4;">${t('corepage.general.tags_hint')}</span></label>
            <input class="input" id="cs-tags" value="${esc(tagsVal)}" placeholder="ha, ssl-offload, edge">
          </div>
        </div>

        <!-- Infrastructure — lecture seule -->
        <div class="card blueprint" style="padding:20px;display:flex;flex-direction:column;gap:14px;">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:6px;">
            <h6 style="margin:0;font-size:11px;text-transform:uppercase;letter-spacing:0.09em;opacity:0.5;">${t('corepage.general.infra')}</h6>
            <span style="font-size:10px;opacity:0.35;font-style:italic;">${t('corepage.general.infra_env_only')}</span>
          </div>
          <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(min(160px,100%),1fr));gap:8px;">
            ${infraCell(80,  'HTTP',       'GPX_NETWORK_HTTP_PORT')}
            ${infraCell(443, 'HTTPS',      'GPX_NETWORK_HTTPS_PORT')}
            ${infraCell(8000,'Hub WS / API','GPX_NETWORK_INTERNAL_API_PORT')}
            <div style="background:var(--bg2,rgba(128,128,128,0.07));border-radius:6px;padding:10px 14px;">
              <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.07em;opacity:0.45;margin-bottom:5px;">${t('corepage.general.log_level')}</div>
              <div style="font-family:monospace;font-size:12px;font-weight:600;">GPX_ENGINE_LOG_LEVEL</div>
              <div style="font-size:10px;opacity:0.35;margin-top:3px;">${t('corepage.general.log_default')}</div>
            </div>
          </div>
        </div>

        <button class="btn btn-primary blueprint" style="align-self:flex-start;" onclick="saveCoreGeneral('${esc(core.id||'')}')">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          ${t('common.save')}
        </button>
      </div>`;

    window.saveCoreGeneral = async function(id) {
      if (!id) { toast(t('corepage.general.toast_no_core'),'error'); return; }
      const tagsRaw = document.getElementById('cs-tags')?.value || '';
      const payload = {
        display_name: document.getElementById('cs-display')?.value?.trim() || '',
        region:       document.getElementById('cs-region')?.value?.trim() || '',
        environment:  document.getElementById('cs-env')?.value?.trim() || '',
        tags:         tagsRaw.split(',').map(t => t.trim()).filter(Boolean),
      };
      try {
        await api('PATCH', `/nodes/${id}`, payload);
        toast(t('corepage.general.toast_saved'), 'success');
        if (state.selectedCore) {
          Object.assign(state.selectedCore, payload);
        }
      } catch(e) { toast(t('common.error_msg', { msg: e.message }), 'error'); }
    };
  } catch(e) { content.innerHTML = `<p style="color:var(--red)">${esc(e.message)}</p>`; }
};

