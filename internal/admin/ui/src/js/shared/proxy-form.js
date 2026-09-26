// ── Shared: formulaire / liste / streams proxy ─────────────────────────────
// Chargé avant pages/* (trafic.js dépend de openProxyModal, etc.).
// Extrait de pages-all.js — phase 1 du plan split pages-all.

// ── YAML lite engine ────────────────────────────────────────────────────────
// Sérialiseur/parseur YAML minimal pour l'onglet "YAML brut" de la modale proxy.
// Gère le sous-ensemble produit par le Go proxystore : strings, numbers,
// booleans, null, arrays, objects imbriqués, block literals (|).
const _yaml = (function () {
  const AMBIGUOUS = /^(true|false|null|yes|no|on|off|~)$/i;
  const LOOKS_NUM  = /^[-+]?(\d+\.?\d*|\.\d+)([eE][-+]?\d+)?$|^0[xX][0-9a-fA-F]+$|^0[0-7]+$/;
  const NEEDS_Q    = /^[:{}\[\]#&*!|>'"%@` ]|[ \t]$/;

  function quoteStr(s) {
    if (s.includes('\n')) {
      const lines = s.split('\n');
      if (lines[lines.length - 1] === '') lines.pop();
      return { block: true, lines };
    }
    if (AMBIGUOUS.test(s) || LOOKS_NUM.test(s) || NEEDS_Q.test(s) || s === '')
      return { q: '"' + s.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"' };
    return { q: s };
  }

  function ser(val, indent) {
    const pad = ' '.repeat(indent);
    if (val === null || val === undefined) return 'null';
    if (typeof val === 'boolean') return String(val);
    if (typeof val === 'number')  return String(val);
    if (typeof val === 'string') {
      const q = quoteStr(val);
      if (q.block) return '|\n' + q.lines.map(l => pad + '  ' + l).join('\n') + '\n';
      return q.q;
    }
    if (Array.isArray(val)) {
      if (!val.length) return '[]';
      if (val.every(v => v === null || typeof v !== 'object')) {
        const inline = '[' + val.map(v => ser(v, 0)).join(', ') + ']';
        if (inline.length <= 80) return inline;
      }
      return '\n' + val.map(v => {
        if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
          const inner = ser(v, indent + 2).trimStart();
          return pad + '- ' + inner;
        }
        return pad + '- ' + ser(v, indent + 2);
      }).join('\n');
    }
    if (typeof val === 'object') {
      const keys = Object.keys(val);
      if (!keys.length) return '{}';
      return '\n' + keys.map(k => {
        const v = val[k];
        if (v !== null && typeof v === 'object') return pad + k + ': ' + ser(v, indent + 2);
        if (typeof v === 'string' && v.includes('\n')) return pad + k + ': ' + ser(v, indent);
        return pad + k + ': ' + ser(v, indent + 2);
      }).join('\n');
    }
    return String(val);
  }

  function dump(obj) {
    if (typeof obj !== 'object' || !obj) return String(obj) + '\n';
    return Object.keys(obj).map(k => {
      const v = obj[k];
      if (v !== null && typeof v === 'object') return k + ': ' + ser(v, 2);
      if (typeof v === 'string' && v.includes('\n')) return k + ': ' + ser(v, 0);
      return k + ': ' + ser(v, 2);
    }).join('\n') + '\n';
  }

  // ── parseur ────────────────────────────────────────────────────────────────
  function scalar(s) {
    if (s === 'null' || s === '~') return null;
    if (s === 'true'  || s === 'yes' || s === 'on')  return true;
    if (s === 'false' || s === 'no'  || s === 'off') return false;
    if (s.startsWith('"') && s.endsWith('"'))
      return s.slice(1,-1).replace(/\\"/g,'"').replace(/\\\\/g,'\\');
    if (s.startsWith("'") && s.endsWith("'")) return s.slice(1,-1).replace(/''/g,"'");
    if ((s.startsWith('[') && s.endsWith(']')) || (s.startsWith('{') && s.endsWith('}')))
      { try { return JSON.parse(s); } catch { return s; } }
    const n = Number(s);
    return (s !== '' && !isNaN(n)) ? n : s;
  }

  function nextNE(lines, from) {
    let i = from; while (i < lines.length && !lines[i].trim()) i++; return i;
  }

  function parseBlock(lines, start, base) {
    let i = nextNE(lines, start);
    if (i >= lines.length) return { v: null, i };
    const ind = lines[i].search(/\S/);
    if (ind < base) return { v: null, i };
    return lines[i].trimStart().startsWith('- ')
      ? parseSeq(lines, i, ind) : parseMap(lines, i, ind);
  }

  function parseSeq(lines, start, ind) {
    const arr = []; let i = start;
    while (i < lines.length) {
      const line = lines[i];
      if (!line.trim()) { i++; continue; }
      if (line.search(/\S/) < ind) break;
      if (line.search(/\S/) > ind) { i++; continue; }
      const c = line.trimStart();
      if (!c.startsWith('- ') && c !== '-') break;
      const item = c.startsWith('- ') ? c.slice(2) : '';
      i++; // avancer dès maintenant — évite les boucles infinies
      if (!item.trim()) {
        const s = parseBlock(lines, i, ind+2); arr.push(s.v); i = s.i;
      } else if (item.includes(': ')) {
        // map débutant sur la ligne du tiret : inline k/v + lignes suivantes au même niveau
        const obj = {};
        const ci = item.indexOf(': ');
        const k0 = item.slice(0, ci);
        const v0 = item.slice(ci+2).trim();
        obj[k0] = v0 === '' ? null : scalar(v0);
        // lire les champs suivants au niveau ind+2
        const rest = parseMap(lines, i, ind+2);
        Object.assign(obj, rest.v);
        arr.push(obj);
        i = rest.i;
      } else {
        arr.push(scalar(item.trim()));
      }
    }
    return { v: arr, i };
  }

  function parseMap(lines, start, ind) {
    const obj = {}; let i = start;
    while (i < lines.length) {
      const raw = lines[i];
      if (!raw.trim()) { i++; continue; }
      const li = raw.search(/\S/);
      if (li < ind) break;
      if (li > ind) { i++; continue; }
      const c = raw.trimStart();
      const ci = c.indexOf(': ');
      if (ci === -1 && !c.endsWith(':')) { i++; continue; }
      const key = ci !== -1 ? c.slice(0, ci) : c.slice(0, -1);
      const vs  = ci !== -1 ? c.slice(ci+2).trim() : '';
      if (!vs || vs === '|') {
        i++;
        const ni = nextNE(lines, i);
        if (vs === '|' || (ni < lines.length && lines[ni].trimStart() === '|')) {
          const bl = parseLiteral(lines, vs==='|' ? i : ni+1, ind+2);
          obj[key] = bl.v; i = bl.i;
        } else {
          const s = parseBlock(lines, i, ind+2); obj[key] = s.v; i = s.i;
        }
      } else { obj[key] = scalar(vs); i++; }
    }
    return { v: obj, i };
  }

  function parseLiteral(lines, start, bInd) {
    const parts = []; let i = start;
    while (i < lines.length) {
      const l = lines[i];
      if (!l.trim()) { parts.push(''); i++; continue; }
      if (l.search(/\S/) < bInd) break;
      parts.push(l.slice(bInd)); i++;
    }
    while (parts.length && !parts[parts.length-1]) parts.pop();
    return { v: parts.join('\n') + '\n', i };
  }

  function parse(text) { return parseBlock(text.split('\n'), 0, 0).v; }

  return { dump, parse };
})();

function tryJSON2(s) { if (!s || typeof s === 'object') return s||{}; try { return JSON.parse(s); } catch { return {}; } }

const FWD_HEADER_OPTIONS = ['X-Real-IP', 'X-Forwarded-For', 'X-Forwarded-Proto', 'X-Forwarded-Host'];

/** URL backend depuis string | {url} — évite "[object Object]" sur {} vide. */
function backendURL(b) {
  if (b == null || b === '') return '';
  if (typeof b === 'string') return b;
  if (typeof b === 'object' && typeof b.url === 'string') return b.url;
  return '';
}

/** Cases à cocher : absent = tout coché (défaut nginx) ; liste explicite = sélection. */
function forwardedHeaderChecked(cfg, name) {
  const list = cfg?.headers_manipulation?.forwarded_headers;
  if (list == null) return true;
  const want = String(name).toLowerCase();
  return list.some(h => String(h).toLowerCase() === want);
}

function requestSetHeaderLines(cfg) {
  const m = cfg?.headers_manipulation?.request_set_header || {};
  return Object.entries(m).map(([k, v]) => k + ': ' + v);
}

window.globalToggleProxy = async function(id, currentlyEnabled) {
  try {
    await api('PATCH', `/proxies/${encodeURIComponent(id)}`, { enabled: !currentlyEnabled });
    toast(currentlyEnabled ? 'Proxy désactivé' : 'Proxy activé', 'success');
    await refreshProxies();
  } catch(e) { toast('Erreur : ' + e.message, 'error'); }
};

window.filterProxies = function() {
  const q = (document.getElementById('proxy-search')?.value || '').toLowerCase();
  const af = window._proxyActiveFilters || {};
  const isTable = window._proxyViewMode === 'table';
  function rowMatches(row) {
    if (q && !row.dataset.proxySearch.includes(q)) return false;
    if (af.status === 'active' && row.dataset.proxyEnabled !== 'true') return false;
    if (af.status === 'inactive' && row.dataset.proxyEnabled !== 'false') return false;
    if (af.type && row.dataset.proxyType !== af.type) return false;
    if (af.source && row.dataset.proxySource !== af.source) return false;
    return true;
  }
  if (isTable) {
    document.querySelectorAll('#proxy-groups tr[data-proxy-search]').forEach(row => {
      row.style.display = rowMatches(row) ? '' : 'none';
    });
  } else {
    document.querySelectorAll('#proxy-groups [data-proxy-search]').forEach(tile => {
      tile.style.display = rowMatches(tile) ? '' : 'none';
    });
    document.querySelectorAll('[data-proxy-subsection]').forEach(sub => {
      const tiles = [...sub.querySelectorAll('[data-proxy-search]')];
      if (tiles.length === 0) return;
      sub.style.display = tiles.some(t => t.style.display !== 'none') ? '' : 'none';
    });
    document.querySelectorAll('[data-proxy-section]').forEach(section => {
      const tiles = [...section.querySelectorAll('[data-proxy-search]')];
      if (tiles.length === 0) return; // section vide (placeholder) : toujours visible
      section.style.display = tiles.some(t => t.style.display !== 'none') ? '' : 'none';
    });
  }
};

window.deleteProxy = function(id) {
  if (!id) { toast('ID proxy manquant', 'error'); return; }
  confirm_(`Supprimer le proxy "${id}" ?`, async () => {
    try {
      await api('DELETE', `/proxies/${encodeURIComponent(id)}`);
      toast('Proxy supprimé', 'success');
      refreshProxies();
    } catch(e) { toast(e.message, 'error'); }
  });
};

window.onProxyCheckChange = function() {
  const cbs = document.querySelectorAll('.proxy-select-cb:checked');
  const bar = document.getElementById('proxy-batch-bar');
  const count = document.getElementById('proxy-batch-count');
  if (bar) bar.style.display = cbs.length ? 'flex' : 'none';
  if (count) count.textContent = cbs.length + ' sélectionné(s)';
};

window.toggleGroupProxies = function(groupCb, groupId) {
  document.querySelectorAll('.proxy-select-cb[data-group="'+groupId+'"]').forEach(cb => { cb.checked = groupCb.checked; });
  window.onProxyCheckChange();
};

window.batchToggleProxies = async function(enable) {
  const ids = [...document.querySelectorAll('.proxy-select-cb:checked')].map(cb => cb.dataset.id);
  if (!ids.length) return;
  try {
    await Promise.all(ids.map(id => api('PATCH', '/proxies/'+encodeURIComponent(id), { enabled: enable })));
    toast(ids.length + ' proxy(s) ' + (enable ? 'activé(s)' : 'désactivé(s)'), 'success');
    refreshProxies();
  } catch(e) { toast('Erreur : ' + e.message, 'error'); }
};

window.batchDeleteProxies = function() {
  const ids = [...document.querySelectorAll('.proxy-select-cb:checked')].map(cb => cb.dataset.id);
  if (!ids.length) return;
  confirm_('Supprimer ' + ids.length + ' proxy(s) ?', async () => {
    try {
      await Promise.all(ids.map(id => api('DELETE', '/proxies/'+encodeURIComponent(id))));
      toast(ids.length + ' proxy(s) supprimé(s)', 'success');
      refreshProxies();
    } catch(e) { toast(e.message, 'error'); }
  });
};

window.clearProxySelection = function() {
  document.querySelectorAll('.proxy-select-cb, .proxy-grp-cb').forEach(cb => cb.checked = false);
  const bar = document.getElementById('proxy-batch-bar');
  if (bar) bar.style.display = 'none';
};

window.setProxyView = function(mode) {
  window._proxyViewMode = mode;
  refreshProxies();
};

window.setProxyFilter = function(key, val) {
  if (!window._proxyActiveFilters) window._proxyActiveFilters = { status: '', type: '', source: '' };
  window._proxyActiveFilters[key] = val;
  refreshProxies();
};

window.setProxyGroupBy = function(val) {
  window._proxyGroupBy = val;
  refreshProxies();
};

window.setProxySortBy = function(val) {
  window._proxySortBy = val;
  refreshProxies();
};

window.openProxyImportModal = function() {
  const pim = { step: 1, format: null, text: '', files: [], proxies: [], result: null };
  const close = () => { const c = document.getElementById('proxies-modal-container'); if (c) c.innerHTML = ''; };

  const STEPS = ['Format', 'Configuration', 'Sélection', 'Résultat'];
  const stepsBar = () => STEPS.map((s,i) => {
    const n = i + 1, active = n === pim.step, done = n < pim.step;
    return `<div style="display:flex;align-items:center;gap:6px">
      <span style="width:22px;height:22px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:700;flex-shrink:0;
        background:${done?'var(--green)':active?'var(--accent)':'var(--bg3)'};
        color:${done||active?'#fff':'var(--text3)'};
        border:1.5px solid ${done?'var(--green)':active?'var(--accent)':'var(--border)'};">${done?'✓':n}</span>
      <span style="font-size:11px;font-weight:600;${active?'color:var(--text)':'color:var(--text3)'}">${s}</span>
      ${i < STEPS.length-1 ? '<span style="width:18px;height:1px;background:var(--border);flex-shrink:0"></span>' : ''}
    </div>`;
  }).join('');

  const render = () => {
    const body = (() => {
      // ── Step 1 : Format ────────────────────────────────────────────────────
      if (pim.step === 1) return `
        <p style="font-size:13px;color:var(--text2);margin:0 0 16px">Choisissez le format de votre configuration source.</p>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(min(120px,100%),1fr));gap:10px;margin-bottom:8px">
          ${configFormatPickerHtml(pim.format, id => `window._pim.format='${id}';window._pim_render()`)}
        </div>`;

      // ── Step 2 : Configuration ─────────────────────────────────────────────
      if (pim.step === 2) {
        const fmt = CONFIG_FORMATS.find(f => f.id === pim.format) || {};
        const fmtSvg = configFormatMeta(pim.format, 20);
        const fileList = pim.files || [];
        return `
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:16px;padding:10px 14px;background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius)">
          <div style="width:32px;height:32px;border-radius:8px;display:flex;align-items:center;justify-content:center;background:${fmtSvg.color}18;color:${fmtSvg.color};flex-shrink:0">
            ${fmtSvg.svg}
          </div>
          <div>
            <div style="font-size:13px;font-weight:700">${esc(fmt.label||pim.format)}</div>
            <div style="font-size:11px;color:var(--text3)">${esc(fmt.hint||'')}</div>
          </div>
          <button onclick="window._pim.step=1;window._pim_render()" style="margin-left:auto;background:none;border:none;cursor:pointer;color:var(--text3);font-size:11px;padding:4px 8px;border-radius:var(--radius)">Changer →</button>
        </div>
        <div id="pim-dropzone" style="border:2px dashed var(--border);border-radius:var(--radius);padding:20px;text-align:center;cursor:pointer;margin-bottom:12px;transition:border-color .2s"
          onclick="document.getElementById('pim-file').click()"
          ondragover="event.preventDefault();this.style.borderColor='var(--accent)'"
          ondragleave="this.style.borderColor='var(--border)'"
          ondrop="event.preventDefault();this.style.borderColor='var(--border)';window._pimLoadFiles(event.dataTransfer.files)">
          <svg width="24" height="24" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24" style="opacity:.45;margin-bottom:8px"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
          <p style="font-size:12px;color:var(--text3);margin:0">Glisser-déposer un ou plusieurs fichiers ou <span style="color:var(--accent);text-decoration:underline">parcourir</span></p>
          <input type="file" id="pim-file" style="display:none" accept=".conf,.yaml,.yml,.toml,.json,.txt,.caddyfile" multiple
            onchange="window._pimLoadFiles(this.files)">
        </div>
        ${fileList.length ? `<div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px">${fileList.map((f,i)=>`<span style="display:inline-flex;align-items:center;gap:5px;padding:3px 8px;background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius);font-size:12px">
          <svg width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M13 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V9z"/><polyline points="13 2 13 9 20 9"/></svg>
          ${esc(f.name)}
          <button onclick="window._pimRemoveFile(${i})" style="background:none;border:none;cursor:pointer;color:var(--text3);padding:0;font-size:14px;line-height:1" title="Retirer">×</button>
        </span>`).join('')}</div>` : ''}
        <div class="field" style="margin-bottom:0">
          <label class="field-label">— ou coller le contenu —</label>
          <textarea id="pim-text" class="input" rows="${fileList.length ? 5 : 10}" placeholder="Collez ici votre configuration ${fmt.label||''}…" style="font-family:monospace;font-size:12px;resize:vertical">${esc(pim.text)}</textarea>
        </div>`;
      }

      // ── Step 3 : Sélection ─────────────────────────────────────────────────
      if (pim.step === 3) {
        if (!pim.proxies.length) return `
          <div style="text-align:center;padding:36px 0">
            <div style="width:56px;height:56px;border-radius:14px;background:rgba(251,146,60,.1);border:1px solid rgba(251,146,60,.25);display:flex;align-items:center;justify-content:center;margin:0 auto 14px">
              <svg width="24" height="24" fill="none" stroke="#fb923c" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            </div>
            <div style="font-size:16px;font-weight:700;margin-bottom:8px">Aucun proxy détecté</div>
            <p style="color:var(--text2);font-size:13px">Vérifiez le format sélectionné et le contenu collé.</p>
          </div>`;
        return `
        <div style="display:flex;align-items:center;gap:8px;padding:8px 4px;border-bottom:1px solid var(--border);margin-bottom:4px;font-size:12px">
          <label style="display:flex;align-items:center;gap:6px;cursor:pointer">
            <input type="checkbox" id="pim-all" checked onchange="document.querySelectorAll('.pim-cb').forEach(c=>{c.checked=this.checked;window._pim.proxies[+c.dataset.i]._sel=this.checked})">
            <b>Tout sélectionner</b>
          </label>
          <span style="color:var(--text3);margin-left:auto">${pim.proxies.length} proxy${pim.proxies.length>1?'s':''} détecté${pim.proxies.length>1?'s':''}</span>
        </div>
        <div style="background:var(--bg3);border-radius:var(--radius);max-height:280px;overflow-y:auto;border:1px solid var(--border)">
          ${pim.proxies.map((p,i) => `
            <label style="display:flex;align-items:flex-start;gap:10px;padding:9px 12px;border-bottom:1px solid var(--border);cursor:pointer;font-size:12px">
              <input type="checkbox" class="pim-cb" data-i="${i}" ${p._sel!==false?'checked':''} style="margin-top:2px"
                onchange="window._pim.proxies[${i}]._sel=this.checked;document.getElementById('pim-all').indeterminate=window._pim.proxies.some(x=>!x._sel)&&window._pim.proxies.some(x=>x._sel!==false)">
              <div style="flex:1;min-width:0">
                <div style="font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(p.host||p.name||'—')}</div>
                <div style="color:var(--text3);margin-top:2px;font-size:11px">${(p.backends||[]).map(b=>`<span class="chip" style="font-size:10px">${esc(typeof b==='string'?b:b.url||'')}</span>`).join(' ')||'—'}</div>
              </div>
              <div style="display:flex;gap:4px;flex-shrink:0">
                ${p.tls?'<span class="tag tag-green" style="font-size:10px">TLS</span>':''}
                ${p.source?`<span class="tag tag-neutral" style="font-size:10px">${esc(p.source)}</span>`:''}
              </div>
            </label>`).join('')}
        </div>
        <div style="margin-top:14px;display:flex;align-items:center;gap:10px">
          <span style="font-size:12px;color:var(--text2);white-space:nowrap">En cas de conflit</span>
          <select id="pim-conflict" class="input" style="max-width:220px">
            <option value="skip">Ignorer (conserver l'existant)</option>
            <option value="overwrite">Écraser</option>
          </select>
        </div>`;
      }

      // ── Step 4 : Résultat ──────────────────────────────────────────────────
      const r = pim.result || {};
      const hasErrors = (r.errors||0) > 0;
      return `
        <div style="text-align:center;padding:32px 16px">
          <div style="width:64px;height:64px;border-radius:16px;display:flex;align-items:center;justify-content:center;margin:0 auto 18px;
            background:${hasErrors?'rgba(251,146,60,.1)':'rgba(34,197,94,.1)'};
            border:1.5px solid ${hasErrors?'rgba(251,146,60,.3)':'rgba(34,197,94,.3)'}">
            <svg width="28" height="28" fill="none" stroke="${hasErrors?'#fb923c':'var(--green)'}" stroke-width="2.5" viewBox="0 0 24 24">${hasErrors?'<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>':'<polyline points="20 6 9 17 4 12"/>'}</svg>
          </div>
          <div style="font-size:17px;font-weight:700;margin-bottom:6px">${hasErrors?'Import terminé avec erreurs':'Import réussi !'}</div>
          <div style="display:flex;justify-content:center;gap:32px;margin:20px auto">
            <div style="text-align:center"><div style="font-size:28px;font-weight:700;color:var(--green)">${r.imported||0}</div><div style="color:var(--text2);font-size:12px">Importés</div></div>
            <div style="text-align:center"><div style="font-size:28px;font-weight:700;color:var(--text3)">${r.skipped||0}</div><div style="color:var(--text2);font-size:12px">Ignorés</div></div>
            ${hasErrors?`<div style="text-align:center"><div style="font-size:28px;font-weight:700;color:var(--red)">${r.errors}</div><div style="color:var(--text2);font-size:12px">Erreurs</div></div>`:''}
          </div>
          <p style="color:var(--text2);font-size:13px;margin-bottom:0">Vos proxies sont disponibles dans la liste ci-dessous.</p>
        </div>`;
    })();

    const actions = (() => {
      if (pim.step === 1) return `
        <button class="btn btn-secondary" onclick="window._pimClose()">Annuler</button>
        <button class="btn btn-primary" onclick="window._pimNext()" ${pim.format?'':'disabled'}>Suivant →</button>`;
      if (pim.step === 2) return `
        <button class="btn btn-secondary" onclick="window._pimClose()">Annuler</button>
        <button class="btn btn-secondary" onclick="window._pim.step=1;window._pim_render()">← Retour</button>
        <button id="pim-btn-parse" class="btn btn-primary" onclick="window._pimParse()">Analyser →</button>`;
      if (pim.step === 3) return `
        <button class="btn btn-secondary" onclick="window._pimClose()">Annuler</button>
        <button class="btn btn-secondary" onclick="window._pim.step=2;window._pim_render()">← Retour</button>
        <button class="btn btn-primary" onclick="window._pimApply()">Importer →</button>`;
      return `
        <button class="btn btn-secondary" onclick="window._pim.step=1;window._pim.format=null;window._pim.text='';window._pim.files=[];window._pim.proxies=[];window._pim_render()">Nouvel import</button>
        <button class="btn btn-primary" onclick="window._pimClose();refreshProxies()">Voir les proxies →</button>`;
    })();

    const mc = document.getElementById('proxies-modal-container');
    if (!mc) return;
    mc.innerHTML = `
      <div class="dialog-backdrop" style="position:fixed;inset:0;z-index:9999;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,0.6);" onclick="if(event.target===this)window._pimClose()">
        <div class="dialog blueprint" role="dialog" aria-modal="true" style="width:min(700px,96vw);max-height:90vh;display:flex;flex-direction:column">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          <div class="dialog-title" style="display:flex;align-items:center;gap:12px;flex-shrink:0">
            <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
            Importer des proxies
            <div style="display:flex;align-items:center;gap:4px;margin-left:auto">${stepsBar()}</div>
          </div>
          <div class="dialog-body" style="flex:1;overflow-y:auto;padding:20px 24px">${body}</div>
          <div class="dialog-actions" style="flex-shrink:0">${actions}</div>
        </div>
      </div>`;
  };

  window._pim = pim;
  window._pim_render = render;
  window._pimClose = close;

  window._pimLoadFiles = (fileList) => {
    if (!fileList || !fileList.length) return;
    const extMap = { yaml: 'traefik-yaml', yml: 'traefik-yaml', toml: 'traefik-toml', conf: 'nginx' };
    if (!pim.files) pim.files = [];
    const files = Array.from(fileList);
    const ext = files[0].name.split('.').pop().toLowerCase();
    if (extMap[ext] && !pim.format) pim.format = extMap[ext];
    let pending = files.length;
    const newContents = new Array(files.length);
    files.forEach((file, i) => {
      if (pim.files.some(f => f.name === file.name)) { pending--; if (!pending) render(); return; }
      pim.files.push({ name: file.name });
      const reader = new FileReader();
      reader.onload = e => {
        newContents[i] = e.target.result;
        pending--;
        if (!pending) { pim.text += (pim.text ? '\n\n' : '') + newContents.filter(Boolean).join('\n\n'); render(); }
      };
      reader.readAsText(file);
    });
  };

  window._pimRemoveFile = (idx) => {
    if (!pim.files) return;
    pim.files.splice(idx, 1);
    if (!pim.files.length) pim.text = '';
    render();
  };

  window._pimNext = () => { pim.step = 2; render(); };

  window._pimParse = async () => {
    pim.text = document.getElementById('pim-text')?.value || '';
    if (!pim.text.trim()) { toast('Aucune configuration saisie', 'error'); return; }
    const btn = document.getElementById('pim-btn-parse');
    if (btn) { btn.disabled = true; btn.textContent = 'Analyse…'; }
    try {
      const res = await api('POST', '/import/config/parse', { format: pim.format, content: pim.text });
      pim.proxies = (res?.proxies || []).map(p => ({ ...p, _sel: true }));
      pim.step = 3;
      render();
    } catch(e) {
      toast('Erreur d\'analyse : ' + e.message, 'error');
      if (btn) { btn.disabled = false; btn.textContent = 'Analyser →'; }
    }
  };

  window._pimApply = async () => {
    const selected = pim.proxies.filter(p => p._sel !== false);
    if (!selected.length) { toast('Aucun proxy sélectionné', 'error'); return; }
    const onConflict = document.getElementById('pim-conflict')?.value || 'skip';
    try {
      const res = await api('POST', '/import/config/apply', { proxies: selected, on_conflict: onConflict });
      pim.result = res;
      pim.step = 4;
      render();
    } catch(e) { toast('Erreur import : ' + e.message, 'error'); }
  };

  render();
};

window.setProxyTileCols = function(n) {
  const prev = window._proxyTileCols || 3;
  window._proxyTileCols = n;
  document.querySelectorAll('[data-cols]').forEach(btn => {
    const active = +btn.dataset.cols === n;
    btn.style.borderColor = active ? 'var(--accent)' : 'var(--border)';
    btn.style.background = active ? 'var(--accent)' : 'var(--bg)';
  });
  const grid = document.getElementById('proxy-groups');
  if (grid && window._proxyViewMode !== 'table') {
    const dx = n > prev ? -40 : 40;
    grid.style.transition = 'none';
    grid.style.transform = `translateX(${dx}px)`;
    grid.style.opacity = '0';
    document.querySelectorAll('.proxy-section-grid').forEach(g => g.style.gridTemplateColumns = `repeat(${n},1fr)`);
    requestAnimationFrame(() => requestAnimationFrame(() => {
      grid.style.transition = 'transform .22s cubic-bezier(.4,0,.2,1), opacity .18s';
      grid.style.transform = 'translateX(0)';
      grid.style.opacity = '1';
    }));
  } else {
    refreshProxies();
  }
};

window.showContainerLabels = function(encoded) {
  let data;
  try { data = JSON.parse(atob(encoded)); } catch { return; }
  const { host, backends, tls, source } = data;
  const lines = [
    'goproxify.enable: "true"',
    `goproxify.host: "${host}"`,
    tls ? 'goproxify.tls: "true"' : null,
    ...(backends||[]).map(b => `goproxify.backend: "${b}"`),
  ].filter(Boolean);
  const yaml = 'labels:\n' + lines.map(l => '  ' + l).join('\n');
  const bodyHtml = `
    <p style="font-size:12px;color:var(--text2);margin:0 0 12px">Labels ${source === 'k8s' ? 'Kubernetes' : 'Docker'} correspondant à ce conteneur :</p>
    <pre id="container-labels-pre" style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:14px 16px;font-size:12px;line-height:1.6;margin:0;overflow-x:auto">${esc(yaml)}</pre>`;
  const footerHtml = `
    <button class="btn btn-secondary" onclick="closeModal()">Fermer</button>
    <button class="btn btn-primary" onclick="navigator.clipboard.writeText(document.getElementById('container-labels-pre').textContent).then(()=>toast('Copié','success'))">Copier</button>`;
  modal(source === 'k8s' ? 'Labels Kubernetes' : 'Labels Docker', bodyHtml, footerHtml);
};

window.exportProxies = function(fmt) {
  const allProxies = window._proxies || [];
  const af = window._proxyActiveFilters || {};
  const q = (document.getElementById('proxy-search')?.value || '').toLowerCase();

  // Build normalized rows for export (proxies + streams)
  const rows = [];
  for (const p of allProxies) {
    const cfg = tryJSON2(p.config);
    const type = cfg?.type || p.type || 'http';
    const isStream = type === 'tcp' || type === 'udp' || type === 'both';
    const host = cfg?.host || p.host || p.id || '';
    const enabled = p.enabled !== false;
    const isDocker = (p.id||'').startsWith('docker:');
    const isK8s = (p.id||'').startsWith('k8s:');
    const source = isDocker ? 'docker' : isK8s ? 'k8s' : 'managed';
    const backends = (cfg?.backends || p.backends || []).map(b => typeof b === 'string' ? b : (b.url || '')).filter(Boolean);
    const aliases = (cfg?.aliases || []).filter(Boolean);
    const allDomains = isStream ? [host] : [host, ...aliases];
    const searchKey = [...allDomains, ...backends].join(' ').toLowerCase();

    if (q && !searchKey.includes(q)) continue;
    if (af.status === 'active' && !enabled) continue;
    if (af.status === 'inactive' && enabled) continue;
    if (af.type && type !== af.type) continue;
    if (af.source && source !== af.source) continue;

    rows.push({
      id: p.id || '',
      nom: host,
      type,
      actif: enabled,
      domaine: isStream ? '' : host,
      aliases: isStream ? '' : aliases.join(';'),
      port_ecoute: isStream ? (cfg?.listen_port || p.listen_port || '') : '',
      backends: backends.join(';'),
      tls: !!(cfg?.tls_enabled || p.tls_enabled),
      source,
      created_at: p.created_at || '',
      // raw config for JSON export
      _cfg: cfg,
      _raw: p,
    });
  }

  if (fmt === 'json') {
    const proxies = rows.filter(r => r.type !== 'tcp' && r.type !== 'udp' && r.type !== 'both')
      .map(r => ({ ...r._cfg, id: r.id, enabled: r.actif, source: r.source, created_at: r.created_at }));
    const streams = rows.filter(r => r.type === 'tcp' || r.type === 'udp' || r.type === 'both')
      .map(r => ({ ...r._cfg, id: r.id, enabled: r.actif, source: r.source, created_at: r.created_at }));
    const payload = { exported_at: new Date().toISOString(), proxies, streams };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'goproxify-export.json'; a.click();
  } else {
    const csvEsc = v => '"' + String(v ?? '').replace(/"/g, '""') + '"';
    const cols = ['id','nom','type','actif','domaine','aliases','port_ecoute','backends','tls','source','created_at'];
    const csvRows = rows.map(r => cols.map(c => csvEsc(r[c])).join(','));
    const blob = new Blob([[cols.join(','), ...csvRows].join('\n')], { type: 'text/csv;charset=utf-8;' });
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'goproxify-export.csv'; a.click();
  }
};

window.openProxyModal = async function(id, initialTab, secTab) {
  let existing = null;
  if (id) {
    try { existing = await api('GET', `/proxies/${encodeURIComponent(id)}`); } catch {}
  }
  const cfg = existing ? (typeof existing.config==='string'?tryJSON(existing.config):existing.config||existing) : {};
  window._openProxyCfg = cfg;
  try {
    window._errorPageTemplates = await api('GET', '/error-page-templates') || [];
  } catch {
    window._errorPageTemplates = [];
  }
  const type = cfg.type || 'http';
  const isHTTP = type === 'http' || type === 'https';

  // Bandeau « ce qui est actif » + compteurs d'onglets — calculés sur la config enregistrée.
  const on = v => (Array.isArray(v) ? v.length > 0 : !!v);
  const active = [
    ['TLS', '#a78bfa', 'general', cfg.tls_enabled || cfg.tls_passthrough],
    ['SSO', '#f472b6', 'auth', cfg.sso?.enabled || cfg.sso?.provider],
    ['JWT', '#60a5fa', 'protection', cfg.jwt?.enabled],
    ['mTLS', '#c084fc', 'protection', cfg.mtls?.enabled],
    ['WAF', '#fb923c', 'protection', cfg.waf?.enabled],
    ['Bots', '#f472b6', 'protection', cfg.bot?.enabled],
    ['Rate limit', '#f59e0b', 'protection', cfg.rate_limit],
    ['IP filter', '#38bdf8', 'protection', cfg.ip_filter?.cidrs],
    ['GeoIP', '#22d3ee', 'protection', cfg.geo_ip?.countries],
    ['HSTS', '#34d399', 'protection', cfg.headers?.hsts],
    ['Snippets', '#a3e635', 'protection', cfg.snippet_ids],
    ['Retry', '#34d399', 'resilience', cfg.retry_policy],
    ['Circuit breaker', '#34d399', 'resilience', cfg.circuit_breaker],
    ['Canary', '#fbbf24', 'resilience', cfg.canary?.backend],
    ['Cache', '#94a3b8', 'avance', cfg.cache],
  ].filter(f => on(f[3]));
  const tabCount = tab => active.filter(f => f[2] === tab).length;
  const score = typeof computeProxyHeaderScore === 'function' && id ? computeProxyHeaderScore(cfg) : null;
  const gradeColor = !score ? '' : score.grade.startsWith('A') ? '#34d399' : score.grade === 'B' ? '#4ade80' : score.grade === 'C' ? '#f59e0b' : score.grade === 'D' ? '#f97316' : '#ef4444';
  const summaryHtml = active.length || score ? `<div class="pm-summary">
      <span class="pm-summary-lbl">Actif</span>
      ${active.map(([label, color, tab]) => `<button type="button" class="pm-chip" style="--c:${color}" onclick="switchProxyTab('${tab}')">${esc(label)}</button>`).join('')}
      ${score ? `<button type="button" class="pm-chip pm-score" style="--c:${gradeColor}" title="Score des en-têtes de sécurité" onclick="switchProxyTab('protection','recap')">Score ${esc(score.grade)}</button>` : ''}
    </div>` : '';
  const tabDefs = [
    ['general', 'Général'], ['entetes', 'En-têtes'], ['auth', 'Auth / SSO'], ['protection', 'Protection'],
    ['resilience', 'Résilience'], ['avance', 'Avancé'], ['yaml', 'YAML'],
  ];
  const tabsHtml = tabDefs.map(([key, label], i) => {
    const n = tabCount(key);
    return `<button type="button" class="pm-tab${i === 0 ? ' active' : ''}" data-tab="${key}" onclick="switchProxyTab('${key}')">${label}${n ? `<span class="pm-cnt">${n}</span>` : ''}</button>`;
  }).join('');

  const body = `
    <div class="pm-shell">
      ${summaryHtml}
      <div id="proxy-tabs" class="pm-tabs">${tabsHtml}</div>

      <!-- Content panels -->
      <div class="pm-content">

        <!-- Panel Général -->
        <div id="ptab-general" style="padding:16px 20px;display:flex;flex-direction:column;gap:14px;">

          <div class="gp-split-2" style="gap:14px;align-items:start;">

            <!-- Colonne gauche : Client → Proxy -->
            <div style="display:flex;flex-direction:column;gap:10px;">
              <div style="font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);">← Client → Proxy</div>

              <!-- Domaines -->
              <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:12px 14px;">
                <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin-bottom:8px;">Domaines</div>
                <div id="p-domains-list">
                  <div class="p-domain-row" style="display:flex;gap:6px;margin-bottom:6px;align-items:center;">
                    <input class="input p-domain-val" style="flex:1;" placeholder="app.example.fr" value="${esc(cfg.host||'')}" title="Domaine principal">
                    <span style="font-size:11px;color:var(--text3);white-space:nowrap;padding:0 4px;min-width:52px;">principal</span>
                  </div>
                  ${(cfg.aliases||[]).map(a=>`
                  <div class="p-domain-row" style="display:flex;gap:6px;margin-bottom:6px;align-items:center;">
                    <input class="input p-domain-val" style="flex:1;" placeholder="www.example.fr" value="${esc(a)}" title="Alias">
                    <button type="button" class="btn-icon" title="Supprimer" onclick="this.closest('.p-domain-row').remove()">×</button>
                  </div>`).join('')}
                </div>
                <button type="button" class="btn btn-secondary btn-sm" onclick="window._addDomainRow()">+ Alias</button>
              </div>

              <!-- HTTPS + Certificat -->
              <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:12px 14px;display:flex;flex-direction:column;gap:10px;">
                <label style="display:flex;align-items:center;gap:10px;cursor:pointer;">
                  <label class="toggle"><input type="checkbox" id="p-https" ${(type==='https'||cfg.tls_enabled)?'checked':''} onchange="updateProxyForm()"><span class="toggle-slider"></span></label>
                  <div><div style="font-size:13px;font-weight:500;">HTTPS entrant</div><div style="font-size:11px;color:var(--text3);">TLS sur ce domaine</div></div>
                </label>
                <div>
                  <div style="font-size:11px;color:var(--text3);margin-bottom:4px;">Certificat</div>
                  <select id="p-cert" class="input" style="appearance:auto"><option value="">✦ Automatique / Let's Encrypt</option></select>
                </div>
              </div>
            </div>

            <!-- Colonne droite : Proxy → Backend -->
            <div style="display:flex;flex-direction:column;gap:10px;">
              <div style="font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);">Proxy → Backend →</div>

              <!-- Backends -->
              <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:12px 14px;">
                <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin-bottom:8px;">Backends</div>
                <div id="p-backends-list">
                  ${((cfg.backends||[]).length ? cfg.backends : [{}]).map((b)=>`
                  <div class="p-backend-row" style="display:flex;gap:6px;margin-bottom:6px;align-items:center">
                    <input class="input p-backend-url" style="flex:1" placeholder="http://10.0.0.5:3000"
                      value="${esc(backendURL(b))}"
                      oninput="this.setCustomValidity(this.value&&!/^https?:\/\/.+/.test(this.value.trim())?'URL invalide (doit commencer par http:// ou https://)':'')"
                      title="URL du backend">
                    <input class="input p-backend-weight" style="width:64px" type="number" min="1" max="100" placeholder="Poids" title="Poids (load balancing)" value="${(b&&typeof b==='object'&&b.weight)||''}">
                    <button type="button" class="btn-icon" title="Supprimer" onclick="this.closest('.p-backend-row').remove();if(!document.querySelectorAll('.p-backend-row').length)window._addBackendRow()">×</button>
                  </div>`).join('')}
                </div>
                <button type="button" class="btn btn-secondary btn-sm" style="margin-top:6px;" onclick="window._addBackendRow()">+ Backend</button>
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:12px;">
                  <div>
                    <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--text3);margin-bottom:4px;">Load balancing</div>
                    <select id="p-lb" class="input" style="width:100%;">
                      <option value="round_robin" ${(!cfg.lb||cfg.lb==='round_robin')?'selected':''}>Round Robin</option>
                      <option value="weighted" ${cfg.lb==='weighted'?'selected':''}>Weighted</option>
                      <option value="adaptive" ${cfg.lb==='adaptive'?'selected':''}>Adaptatif</option>
                    </select>
                  </div>
                  <div>
                    <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--text3);margin-bottom:4px;">HTTP backend</div>
                    <select id="p-http-version" class="input" style="width:100%;">
                      <option value="auto" ${(cfg.http_version||'auto')==='auto'?'selected':''}>Auto</option>
                      <option value="1.1" ${cfg.http_version==='1.1'?'selected':''}>HTTP/1.1</option>
                      <option value="2" ${cfg.http_version==='2'?'selected':''}>HTTP/2</option>
                    </select>
                  </div>
                </div>
              </div>

              <!-- Options backend HTTPS -->
              <div style="background:var(--bg2);border:1px solid var(--border);border-left:3px solid color-mix(in srgb,var(--accent) 60%,transparent);border-radius:10px;padding:12px 14px;display:flex;flex-direction:column;gap:10px;">
                <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);">Vers le backend</div>
                <label style="display:flex;align-items:center;gap:10px;cursor:pointer;">
                  <label class="toggle"><input type="checkbox" id="p-preserve-host" ${cfg.preserve_host!==false?'checked':''}><span class="toggle-slider"></span></label>
                  <div><div style="font-size:13px;font-weight:500;">Conserver le Host</div><div style="font-size:11px;color:var(--text3);">Comme nginx <code>proxy_set_header Host $host</code></div></div>
                </label>
                <label style="display:flex;align-items:center;gap:10px;cursor:pointer;">
                  <label class="toggle"><input type="checkbox" id="p-skip-verify" ${cfg.tls_skip_verify?'checked':''}><span class="toggle-slider"></span></label>
                  <div><div style="font-size:13px;font-weight:500;">Ignorer le certificat backend</div><div style="font-size:11px;color:var(--text3);">Auto-signé, Proxmox…</div></div>
                </label>
                <label style="display:flex;align-items:center;gap:10px;cursor:pointer;">
                  <label class="toggle"><input type="checkbox" id="p-passthrough" ${cfg.tls_passthrough?'checked':''}><span class="toggle-slider"></span></label>
                  <span style="font-size:13px;font-weight:500;">SSL Passthrough</span>
                </label>
              </div>
            </div>
          </div>

          <!-- Protocoles (pleine largeur) -->
          <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:12px 14px;">
            <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin-bottom:10px;">Protocoles</div>
            <div style="display:flex;gap:20px;flex-wrap:wrap;align-items:center;">
              <label style="display:flex;align-items:center;gap:8px;cursor:pointer;">
                <label class="toggle"><input type="checkbox" id="p-ws" ${cfg.websocket!==false?'checked':''}><span class="toggle-slider"></span></label>
                <span style="font-size:13px;">WebSocket</span>
              </label>
              <label style="display:flex;align-items:center;gap:8px;cursor:pointer;">
                <label class="toggle"><input type="checkbox" id="p-http3" ${cfg.protocols?.http3_quic?.enabled?'checked':''}><span class="toggle-slider"></span></label>
                <span style="font-size:13px;">HTTP/3 QUIC</span>
              </label>
              <label style="display:flex;align-items:center;gap:8px;cursor:pointer;">
                <label class="toggle"><input type="checkbox" id="p-grpc" ${cfg.protocols?.grpc?.enabled?'checked':''}><span class="toggle-slider"></span></label>
                <span style="font-size:13px;">gRPC</span>
              </label>
              <div style="display:flex;align-items:center;gap:8px;flex:1;min-width:160px;">
                <span style="font-size:13px;white-space:nowrap;color:var(--text2);">Tags</span>
                <input id="p-tags" class="input" style="flex:1;" placeholder="prod, frontend" value="${esc((cfg.tags||[]).join(', '))}">
              </div>
            </div>
          </div>

          <!-- Locations (pleine largeur) — pas de display:contents (casse closest/querySelector) -->
          <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:12px 14px;">
            <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin-bottom:10px;">Locations — routage par chemin</div>
            <div style="display:grid;grid-template-columns:1.4fr 0.7fr 2.5fr 28px;gap:4px 6px;align-items:center;margin-bottom:4px;">
              <span style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--text3);padding:0 2px;">Chemin</span>
              <span style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--text3);padding:0 2px;">Type</span>
              <span style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--text3);padding:0 2px;">Backend</span>
              <span></span>
            </div>
            <div id="p-locations-list" style="display:flex;flex-direction:column;gap:4px;">
              ${(cfg.locations||[]).map((loc,i)=>`
              <div id="ploc-${i}" class="p-loc-row" style="display:flex;flex-direction:column;gap:3px;">
                <div style="display:grid;grid-template-columns:1.4fr 0.7fr 2.5fr 28px;gap:4px 6px;align-items:center;">
                  <input id="p-loc-path-${i}" class="input p-loc-path" placeholder="/api" value="${esc(loc.path||'')}" style="margin:0;">
                  <select id="p-loc-pathtype-${i}" class="input p-loc-pathtype" style="margin:0;" onchange="toggleLocRewrite(this)">${['prefix','exact','regex'].map(t=>`<option${(loc.path_type||'prefix')===t?' selected':''}>${t}</option>`).join('')}</select>
                  <input id="p-loc-dest-${i}" class="input p-loc-dest" placeholder="http://backend:8080" value="${esc(backendURL((loc.backends&&loc.backends[0])||''))}" style="margin:0;">
                  <button type="button" class="btn-icon" title="Supprimer" onclick="this.closest('.p-loc-row').remove()" style="opacity:.55;"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/></svg></button>
                </div>
                <div class="p-loc-rewrite-row" style="display:${(loc.path_type||'prefix')==='regex'?'grid':'none'};grid-template-columns:80px 1fr;gap:6px;align-items:center;padding-left:2px;">
                  <span style="font-size:10.5px;color:var(--text3);white-space:nowrap;">Réécriture</span>
                  <input class="input p-loc-rewrite" placeholder="/new/$1" value="${esc(loc.path_rewrite||'')}" style="margin:0;font-family:monospace;font-size:12px;">
                </div>
              </div>`).join('')}
            </div>
            <button class="btn btn-secondary btn-sm" style="margin-top:6px;" onclick="addLocationRow()">+ Location</button>
          </div>

          <!-- Routage conditionnel -->
          <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:12px 14px;">
            <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin-bottom:10px;">Routage conditionnel — par header / cookie / query</div>
            <div id="p-conditions-list" style="display:flex;flex-direction:column;gap:6px;">
              ${(cfg.conditions||[]).map((c,i)=>`
              <div class="p-cond-row" style="display:grid;grid-template-columns:minmax(90px,0.9fr) minmax(70px,1fr) minmax(70px,1.2fr) minmax(120px,1.8fr) 28px;gap:6px;align-items:center;" id="pcond-${i}">
                <select id="p-cond-type-${i}" class="input" style="margin:0;">${['header','cookie','query','method'].map(t=>`<option${c.type===t?' selected':''}>${t}</option>`).join('')}</select>
                <input id="p-cond-name-${i}" class="input" placeholder="Nom" value="${esc(c.name||'')}" style="margin:0;">
                <input id="p-cond-val-${i}" class="input" placeholder="Valeur" value="${esc(c.value||'')}" style="margin:0;">
                <input id="p-cond-bk-${i}" class="input" placeholder="http://backend:port" value="${esc(c.backend||'')}" style="margin:0;">
                <button type="button" class="btn-icon" title="Supprimer" onclick="this.closest('.p-cond-row').remove()" style="opacity:.55;">×</button>
              </div>`).join('')}
            </div>
            <button class="btn btn-secondary btn-sm" onclick="addConditionRow()">+ Condition</button>
          </div>

          <!-- Proxy Redirect -->
          <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:12px 14px;">
            <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin-bottom:4px;">Réécriture Location — proxy_redirect</div>
            <div style="font-size:11px;color:var(--text3);margin-bottom:10px;">Réécrit le header <code>Location</code> des redirections 3xx venant du backend. Ex : remplacer <code>http://backend:8080/</code> par <code>https://app.example.fr/</code>.</div>
            <div style="display:grid;grid-template-columns:24px 1fr 1fr 28px;gap:4px 6px;align-items:center;margin-bottom:4px;">
              <span style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--text3);">Rx</span>
              <span style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--text3);">De (from)</span>
              <span style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--text3);">Vers (to)</span>
              <span></span>
            </div>
            <div id="p-redirects-list" style="display:flex;flex-direction:column;gap:4px;">
              ${(cfg.proxy_redirects||[]).map((r,i)=>`
              <div class="p-redirect-row" style="display:grid;grid-template-columns:24px 1fr 1fr 28px;gap:4px 6px;align-items:center;">
                <input type="checkbox" class="p-rd-regex" title="Regex" ${r.regex?'checked':''}>
                <input class="input p-rd-from" placeholder="http://backend:8080/" value="${esc(r.from||'')}" style="margin:0;font-family:monospace;font-size:12px;">
                <input class="input p-rd-to" placeholder="https://app.example.fr/" value="${esc(r.to||'')}" style="margin:0;font-family:monospace;font-size:12px;">
                <button type="button" class="btn-icon" title="Supprimer" onclick="this.closest('.p-redirect-row').remove()" style="opacity:.55;">×</button>
              </div>`).join('')}
            </div>
            <button class="btn btn-secondary btn-sm" style="margin-top:6px;" onclick="addRedirectRow()">+ Règle</button>
          </div>

          <!-- Cookie Domain / Path rewrite -->
          <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:12px 14px;">
            <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin-bottom:4px;">Cookies — proxy_cookie_domain / proxy_cookie_path</div>
            <div style="font-size:11px;color:var(--text3);margin-bottom:10px;">Réécrit les attributs <code>Domain=</code> et <code>Path=</code> des <code>Set-Cookie</code> du backend.</div>
            <div style="display:grid;grid-template-columns:60px 24px 1fr 1fr 28px;gap:4px 6px;align-items:center;margin-bottom:4px;">
              <span style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--text3);">Attribut</span>
              <span style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--text3);">Rx</span>
              <span style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--text3);">De</span>
              <span style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--text3);">Vers</span>
              <span></span>
            </div>
            <div id="p-cookie-rewrites-list" style="display:flex;flex-direction:column;gap:4px;">
              ${[...(cfg.cookie_domains||[]).map(r=>({...r,attr:'domain'})), ...(cfg.cookie_paths||[]).map(r=>({...r,attr:'path'}))].map((r,i)=>`
              <div class="p-cookie-row" style="display:grid;grid-template-columns:60px 24px 1fr 1fr 28px;gap:4px 6px;align-items:center;">
                <select class="input p-ck-attr" style="margin:0;font-size:11px;padding:3px 4px;">
                  <option${r.attr==='domain'?' selected':''}>domain</option>
                  <option${r.attr==='path'?' selected':''}>path</option>
                </select>
                <input type="checkbox" class="p-ck-regex" title="Regex" ${r.regex?'checked':''}>
                <input class="input p-ck-from" placeholder="backend.internal" value="${esc(r.from||'')}" style="margin:0;font-family:monospace;font-size:12px;">
                <input class="input p-ck-to" placeholder="app.example.fr" value="${esc(r.to||'')}" style="margin:0;font-family:monospace;font-size:12px;">
                <button type="button" class="btn-icon" title="Supprimer" onclick="this.closest('.p-cookie-row').remove()" style="opacity:.55;">×</button>
              </div>`).join('')}
            </div>
            <button class="btn btn-secondary btn-sm" style="margin-top:6px;" onclick="addCookieRewriteRow()">+ Règle</button>
          </div>

          <!-- sub_filter — réécriture du body -->
          <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:12px 14px;">
            <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin-bottom:4px;">Réécriture du corps — sub_filter</div>
            <div style="font-size:11px;color:var(--text3);margin-bottom:10px;">Remplace des chaînes ou regex dans le body des réponses <code>text/*</code> et <code>application/json</code>. Gzip décompressé automatiquement.</div>
            <div style="display:grid;grid-template-columns:24px 1fr 1fr 28px;gap:4px 6px;align-items:center;margin-bottom:4px;">
              <span style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--text3);">Rx</span>
              <span style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--text3);">Rechercher</span>
              <span style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--text3);">Remplacer par</span>
              <span></span>
            </div>
            <div id="p-subfilters-list" style="display:flex;flex-direction:column;gap:4px;">
              ${(cfg.sub_filters||[]).map((f,i)=>`
              <div class="p-sf-row" style="display:grid;grid-template-columns:24px 1fr 1fr 28px;gap:4px 6px;align-items:center;">
                <input type="checkbox" class="p-sf-regex" title="Regex" ${f.regex?'checked':''}>
                <input class="input p-sf-from" value="${esc(f.from||'')}" style="margin:0;font-family:monospace;font-size:12px;">
                <input class="input p-sf-to" value="${esc(f.to||'')}" style="margin:0;font-family:monospace;font-size:12px;">
                <button type="button" class="btn-icon" title="Supprimer" onclick="this.closest('.p-sf-row').remove()" style="opacity:.55;">×</button>
              </div>`).join('')}
            </div>
            <button class="btn btn-secondary btn-sm" style="margin-top:6px;" onclick="addSubFilterRow()">+ Règle</button>
          </div>

          <!-- Variables de requête — map {} -->
          <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:12px 14px;">
            <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin-bottom:4px;">Variables de requête — map {}</div>
            <div style="font-size:11px;color:var(--text3);margin-bottom:10px;">Dérive des variables depuis les attributs de la requête (header, cookie, query, method, path, remote_ip). Utilisables dans <code>request_set_header</code> via <code>${"{"}nom{"}"}</code>.</div>
            <div id="p-reqvars-list" style="display:flex;flex-direction:column;gap:6px;">
              ${(cfg.request_vars||[]).map((v,i)=>`
              <div class="p-rv-row" style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:8px 10px;display:flex;flex-direction:column;gap:6px;">
                <div style="display:grid;grid-template-columns:1fr 1fr 1fr 28px;gap:4px 6px;align-items:center;">
                  <input class="input p-rv-name" placeholder="nom (ex: country)" style="font-size:12px;padding:4px 6px;" value="${esc(v.name||'')}">
                  <select class="input p-rv-source" style="font-size:12px;padding:4px 6px;" onchange="toggleRvKey(this)">
                    ${['header','cookie','query','method','remote_ip','path'].map(s=>`<option value="${s}" ${v.source===s?'selected':''}>${s}</option>`).join('')}
                  </select>
                  <input class="input p-rv-key" placeholder="clé header/cookie/query" style="font-size:12px;padding:4px 6px;display:${['header','cookie','query'].includes(v.source)?'':'none'};" value="${esc(v.key||'')}">
                  <span></span>
                  <button onclick="this.closest('.p-rv-row').remove()" style="background:none;border:none;color:var(--text3);cursor:pointer;font-size:15px;grid-column:4;grid-row:1;" title="Supprimer">✕</button>
                </div>
                <div style="font-size:10px;color:var(--text3);margin-bottom:2px;">Cas (pattern → valeur) :</div>
                <div class="p-rv-cases" style="display:flex;flex-direction:column;gap:3px;">
                  ${(v.cases||[]).map(c=>`
                  <div class="p-rvc-row" style="display:grid;grid-template-columns:24px 1fr 1fr 28px;gap:3px 5px;align-items:center;">
                    <input type="checkbox" class="p-rvc-regex" title="Regex" ${c.regex?'checked':''}>
                    <input class="input p-rvc-pattern" placeholder="pattern" style="font-size:12px;padding:3px 5px;" value="${esc(c.pattern||'')}">
                    <input class="input p-rvc-value" placeholder="valeur" style="font-size:12px;padding:3px 5px;" value="${esc(c.value||'')}">
                    <button onclick="this.closest('.p-rvc-row').remove()" style="background:none;border:none;color:var(--text3);cursor:pointer;font-size:13px;" title="Supprimer">✕</button>
                  </div>`).join('')}
                </div>
                <div style="display:flex;align-items:center;gap:8px;">
                  <button onclick="addRvCaseRow(this)" style="font-size:11px;" class="btn btn-sm">+ Cas</button>
                  <span style="font-size:11px;color:var(--text3);">Défaut :</span>
                  <input class="input p-rv-default" placeholder="valeur par défaut" style="font-size:12px;padding:3px 5px;flex:1;" value="${esc(v.default||'')}">
                </div>
              </div>`).join('')}
            </div>
            <button onclick="addReqVarRow()" style="margin-top:8px;font-size:11px;padding:3px 10px;" class="btn btn-sm">+ Variable</button>
          </div>
        </div>

        <!-- Panel Protection (monté par _psecMount) -->
        <div id="ptab-protection" style="display:none;height:100%;"><div style="padding:24px;font-size:12.5px;color:var(--text3);">Chargement…</div></div>

        <!-- Panel En-têtes -->
        <div id="ptab-entetes" style="display:none;padding:16px 20px;flex-direction:column;gap:14px;">
          <div style="font-size:11px;color:var(--text3);padding:8px 12px;background:var(--bg2);border:1px solid var(--border);border-radius:8px;">
            HSTS, X-Frame-Options, « Masquer Server », WAF, limites et filtres se règlent dans l'onglet <b>Protection</b>.
          </div>
          <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:14px 16px;">
            <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin-bottom:6px;">En-têtes transmis au backend</div>
            <div style="font-size:11px;color:var(--text3);margin-bottom:10px;">Équivalent nginx <code>proxy_set_header</code> — décocher pour ne pas injecter.</div>
            <div style="display:flex;flex-direction:column;gap:8px;">
              ${FWD_HEADER_OPTIONS.map(name => {
                const checked = forwardedHeaderChecked(cfg, name);
                const id = 'p-fwd-' + name.toLowerCase().replace(/[^a-z0-9]+/g, '-');
                return `<label style="display:flex;align-items:center;gap:10px;cursor:pointer;">
                  <input type="checkbox" class="p-fwd-header" data-header="${esc(name)}" id="${id}" ${checked?'checked':''}>
                  <span style="font-size:12px;font-weight:600;font-family:ui-monospace,monospace;">${esc(name)}</span>
                </label>`;
              }).join('')}
            </div>
            <label style="display:flex;align-items:center;gap:10px;cursor:pointer;margin-top:12px;">
              <label class="toggle"><input type="checkbox" id="p-request-id" ${cfg.request_id!==false?'checked':''}><span class="toggle-slider"></span></label>
              <div><div style="font-size:12px;font-weight:600;">X-Request-ID</div><div style="font-size:11px;color:var(--text3);">Générer / propager vers le client et le backend</div></div>
            </label>
          </div>
          <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:14px 16px;">
            <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin-bottom:10px;">En-têtes ajoutés à la requête backend</div>
            <textarea id="p-req-set-headers" class="input" rows="3" placeholder="X-Custom: valeur&#10;Authorization: Bearer …">${esc(requestSetHeaderLines(cfg).join('\n'))}</textarea>
            <div style="font-size:10px;color:var(--text3);margin-top:4px;">Format <code>Nom: valeur</code> — écrase la valeur reçue du client.</div>
            <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin:12px 0 8px;">En-têtes retirés avant le backend</div>
            <textarea id="p-req-hide-headers" class="input" rows="2" placeholder="Cookie&#10;Authorization">${esc((cfg.headers_manipulation?.request_hide_header||[]).join('\n'))}</textarea>
            <div style="font-size:10px;color:var(--text3);margin-top:4px;">Un nom d'en-tête par ligne.</div>
          </div>
          <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:14px 16px;">
            <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin-bottom:10px;">En-têtes ajoutés à la réponse</div>
            <textarea id="p-resp-headers" class="input" rows="4" placeholder="X-Custom-Header: valeur&#10;Content-Security-Policy: default-src 'self'">${esc(customHeadersToLines(cfg).join('\n'))}</textarea>
            <div style="font-size:10px;color:var(--text3);margin-top:4px;">Stockés dans <code>headers.custom</code> (appliqués par la passerelle). HSTS / X-Frame-Options : section ci-dessus.</div>
          </div>
          <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:14px 16px;">
            <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin-bottom:10px;">Pages d'erreur rapides</div>
            <div class="form-row" style="gap:8px">
              <div class="field" style="flex:1"><label class="field-label" style="font-size:11px">Page 404</label><input id="p-err-404" class="input" placeholder="https://..." value="${esc(cfg.timeouts_and_resilience?.error_handling?.['404']||'')}"></div>
              <div class="field" style="flex:1"><label class="field-label" style="font-size:11px">Page 502/503</label><input id="p-err-502" class="input" placeholder="https://..." value="${esc(cfg.timeouts_and_resilience?.error_handling?.['502']||cfg.timeouts_and_resilience?.error_handling?.['503']||'')}"></div>
            </div>
          </div>
        </div>

        <!-- Panel Auth / SSO -->
        <div id="ptab-auth" style="display:none;padding:16px 20px;flex-direction:column;gap:14px;">
          <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:14px 16px;">
            <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin-bottom:10px;">Authentification SSO / OIDC</div>
            <div class="field">
              <label class="field-label" style="font-size:11px">Provider</label>
              <select id="p-sso-provider" class="input" onchange="updateSSOForm()">
                <option value="">Désactivé</option>
                <option value="basic" ${cfg.sso?.provider==='basic'?'selected':''}>Basic Auth</option>
                <option value="authentik" ${cfg.sso?.provider==='authentik'?'selected':''}>Authentik</option>
                <option value="authelia" ${cfg.sso?.provider==='authelia'?'selected':''}>Authelia</option>
                <option value="forward" ${cfg.sso?.provider==='forward'?'selected':''}>Forward Auth générique</option>
                <option value="pocket_id" ${cfg.sso?.provider==='pocket_id'?'selected':''}>Pocket ID (OIDC)</option>
                <option value="oidc" ${cfg.sso?.provider==='oidc'?'selected':''}>OIDC générique</option>
              </select>
            </div>
            <div id="p-sso-fwd-fields" style="display:none;margin-top:10px">
              <div class="field"><label class="field-label" style="font-size:11px">Forward Auth URL</label><input id="p-sso-fwd-url" class="input" placeholder="http://auth.example.com/outpost.goauthentik.io/auth/nginx" value="${esc(cfg.sso?.forward_auth_url||'')}"></div>
            </div>
            <div id="p-sso-oidc-fields" style="display:none;margin-top:10px;flex-direction:column;gap:10px">
              <div class="form-row" style="gap:8px">
                <div class="field" style="flex:1"><label class="field-label" style="font-size:11px">Issuer URL</label><input id="p-oidc-issuer" class="input" placeholder="https://id.example.com" value="${esc(cfg.sso?.oidc?.issuer_url||'')}"></div>
                <div class="field" style="flex:1"><label class="field-label" style="font-size:11px">Client ID</label><input id="p-oidc-client-id" class="input" value="${esc(cfg.sso?.oidc?.client_id||'')}"></div>
              </div>
              <div class="form-row" style="gap:8px">
                <div class="field" style="flex:1"><label class="field-label" style="font-size:11px">Client Secret</label><input id="p-oidc-secret" class="input" type="password" value="${esc(cfg.sso?.oidc?.client_secret||'')}"></div>
                <div class="field" style="flex:1"><label class="field-label" style="font-size:11px">Redirect URL</label><input id="p-oidc-redirect" class="input" placeholder="https://app.example.com/_gpx/oidc/callback" value="${esc(cfg.sso?.oidc?.redirect_url||'')}"></div>
              </div>
              <div class="form-row" style="gap:8px">
                <div class="field" style="flex:1"><label class="field-label" style="font-size:11px">Session Secret</label><input id="p-oidc-sess-secret" class="input" type="password" value="${esc(cfg.sso?.oidc?.session_secret||'')}"></div>
                <div class="field" style="flex:1"><label class="field-label" style="font-size:11px">Username claim</label><input id="p-oidc-claim" class="input" placeholder="preferred_username" value="${esc(cfg.sso?.oidc?.username_claim||'')}"></div>
              </div>
            </div>
          </div>
        </div>

        <!-- Panel Résilience -->
        <div id="ptab-resilience" style="display:none;padding:16px 20px;flex-direction:column;gap:14px;">
          <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:14px 16px;">
            <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin-bottom:10px;">Health Check</div>
            <div class="form-row" style="gap:8px">
              <div class="field" style="flex:2"><label class="field-label" style="font-size:11px">Chemin</label><input id="p-hc-path" class="input" placeholder="/health" value="${esc(cfg.health_check?.path||'')}"></div>
              <div class="field" style="flex:1"><label class="field-label" style="font-size:11px">Intervalle</label><input id="p-hc-interval" class="input" placeholder="30s" value="${esc(cfg.health_check?.interval||'')}"></div>
              <div class="field" style="flex:1"><label class="field-label" style="font-size:11px">Timeout</label><input id="p-hc-timeout" class="input" placeholder="5s" value="${esc(cfg.health_check?.timeout||'')}"></div>
            </div>
            <div class="form-row" style="gap:8px;margin-top:6px">
              <div class="field" style="flex:1"><label class="field-label" style="font-size:11px">Seuil sain</label><input id="p-hc-healthy" class="input" type="number" placeholder="2" value="${cfg.health_check?.healthy_threshold||''}"></div>
              <div class="field" style="flex:1"><label class="field-label" style="font-size:11px">Seuil défaillant</label><input id="p-hc-unhealthy" class="input" type="number" placeholder="3" value="${cfg.health_check?.unhealthy_threshold||''}"></div>
              <div style="flex:2"></div>
            </div>
          </div>
          <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:14px 16px;">
            <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin-bottom:12px;">Circuit Breaker</div>
            <div style="display:flex;gap:16px;align-items:flex-start;">
              <label style="display:flex;align-items:center;gap:8px;cursor:pointer;padding-top:22px;">
                <label class="toggle"><input type="checkbox" id="p-cb-enabled" ${cfg.circuit_breaker?.enabled?'checked':''}><span class="toggle-slider"></span></label>
                <span style="font-size:13px;font-weight:500;">Activé</span>
              </label>
              <div class="field" style="flex:1;margin:0;"><label class="field-label" style="font-size:11px">Seuil erreurs (%)</label><input id="p-cb-threshold" class="input" type="number" placeholder="50" value="${cfg.circuit_breaker?.threshold||''}"></div>
              <div class="field" style="flex:1;margin:0;"><label class="field-label" style="font-size:11px">Timeout réinit.</label><input id="p-cb-timeout" class="input" placeholder="30s" value="${esc(cfg.circuit_breaker?.timeout||'')}"></div>
            </div>
          </div>
          <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:14px 16px;">
            <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin-bottom:10px;">Retry</div>
            <div class="form-row" style="gap:8px">
              <div class="field" style="flex:1"><label class="field-label" style="font-size:11px">Max tentatives</label><input id="p-retry-max" class="input" type="number" placeholder="3" value="${cfg.retry_policy?.max_attempts||''}"></div>
              <div class="field" style="flex:1"><label class="field-label" style="font-size:11px">Délai</label><input id="p-retry-delay" class="input" placeholder="500ms" value="${esc(cfg.retry_policy?.retry_delay||'')}"></div>
              <div class="field" style="flex:2"><label class="field-label" style="font-size:11px">Retry si</label><input id="p-retry-on" class="input" placeholder="error, timeout, 5xx" value="${esc((cfg.retry_policy?.retry_on||[]).join(', '))}"></div>
            </div>
          </div>
          <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:14px 16px;">
            <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin-bottom:6px;">Sticky session</div>
            <div style="font-size:11px;color:var(--text3);margin-bottom:10px;">Affinité client → backend via cookie (load balancing).</div>
            <div class="field" style="max-width:280px;margin:0;">
              <label class="field-label" style="font-size:11px">Nom du cookie</label>
              <input id="p-sticky-cookie" class="input" placeholder="GOPROXIFY_STICKY" value="${esc(cfg.sticky_cookie||'')}">
            </div>
          </div>
          <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:14px 16px;">
            <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin-bottom:6px;">Slow-start</div>
            <div style="font-size:11px;color:var(--text3);margin-bottom:10px;">Un backend nouvellement ajouté ou revenu après une panne monte en charge progressivement (de ~5 % à 100 % de sa part) pendant cette durée. 0 = désactivé.</div>
            <div class="field" style="max-width:200px;margin:0;">
              <label class="field-label" style="font-size:11px">Durée (secondes)</label>
              <input id="p-slow-start" class="input" type="number" min="0" placeholder="0" value="${cfg.slow_start_sec || ''}">
            </div>
          </div>
          <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:14px 16px;">
            <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin-bottom:10px;">Canary</div>
            <div class="form-row" style="gap:8px">
              <div class="field" style="flex:2"><label class="field-label" style="font-size:11px">URL backend canary</label><input id="p-canary-backend" class="input" placeholder="http://10.0.0.6:3000" value="${esc(cfg.canary?.backend||'')}"></div>
              <div class="field" style="flex:1"><label class="field-label" style="font-size:11px">% trafic</label><input id="p-canary-weight" class="input" type="number" min="0" max="100" placeholder="10" value="${cfg.canary?.weight||''}"></div>
            </div>
            <div class="form-row" style="gap:8px;margin-top:6px">
              <div class="field" style="flex:1"><label class="field-label" style="font-size:11px">Header</label><input id="p-canary-header" class="input" placeholder="X-Canary" value="${esc(cfg.canary?.header||'')}"></div>
              <div class="field" style="flex:1"><label class="field-label" style="font-size:11px">Valeur</label><input id="p-canary-hval" class="input" placeholder="true" value="${esc(cfg.canary?.header_value||'')}"></div>
              <div class="field" style="flex:1"><label class="field-label" style="font-size:11px">Cookie</label><input id="p-canary-cookie" class="input" placeholder="canary" value="${esc(cfg.canary?.cookie_name||'')}"></div>
            </div>
            <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin:12px 0 8px;">Shadow Mirror</div>
            <div class="field"><label class="field-label" style="font-size:11px">URL miroir (copie silencieuse)</label><input id="p-shadow-backend" class="input" placeholder="http://10.0.0.7:3000" value="${esc(cfg.shadow?.backend||'')}"></div>
          </div>
        </div>

        <!-- Panel Avancé -->
        <div id="ptab-avance" style="display:none;padding:16px 20px;flex-direction:column;gap:14px;">
          <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:14px 16px;">
            <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin-bottom:10px;">Performance</div>
            <div class="gp-split-2" style="gap:10px;">
              <label style="display:flex;align-items:center;gap:8px;cursor:pointer;">
                <label class="toggle"><input type="checkbox" id="p-cache-enabled" ${cfg.performance?.cache_proxy?.enabled?'checked':''}><span class="toggle-slider"></span></label>
                <span style="font-size:13px;font-weight:500;">Cache proxy</span>
              </label>
              <div class="field" style="margin:0;"><label class="field-label" style="font-size:11px">TTL cache</label><input id="p-cache-ttl" class="input" placeholder="1h" value="${esc(cfg.performance?.cache_proxy?.ttl||'')}"></div>
              <label style="display:flex;align-items:center;gap:8px;cursor:pointer;">
                <label class="toggle"><input type="checkbox" id="p-gzip-enabled" ${cfg.performance?.compression_gzip?.enabled?'checked':''}><span class="toggle-slider"></span></label>
                <span style="font-size:13px;font-weight:500;">Compression gzip</span>
              </label>
              <div class="field" style="margin:0;"><label class="field-label" style="font-size:11px">Min size (octets)</label><input id="p-gzip-minsize" class="input" type="number" placeholder="1024" value="${cfg.performance?.compression_gzip?.min_length||''}"></div>
            </div>
            <div class="field" style="margin-top:10px;max-width:50%;"><label class="field-label" style="font-size:11px">Max body client (Mo)</label><input id="p-body-size" class="input" type="number" min="1" placeholder="100" value="${cfg.max_body_size ? Math.round(cfg.max_body_size/1048576) : ''}"></div>
          </div>
          <!-- Cache avancé -->
          <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:14px 16px;">
            <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin-bottom:4px;">Cache avancé — proxy_cache_valid</div>
            <div style="font-size:11px;color:var(--text3);margin-bottom:10px;">Règles TTL par code HTTP. Si aucune règle n'est définie, le TTL ci-dessus (Cache-Control max-age) s'applique. Bypass : contourner le cache si un header ou cookie est présent.</div>
            <div style="display:grid;grid-template-columns:1fr 140px 28px;gap:4px 6px;align-items:center;margin-bottom:4px;">
              <span style="font-size:10px;color:var(--text3)">Codes HTTP (ex: 200 ou vide=tous)</span>
              <span style="font-size:10px;color:var(--text3)">TTL (ex: 10m)</span>
              <span></span>
            </div>
            <div id="p-cache-rules-list" style="display:flex;flex-direction:column;gap:4px;">
              ${(cfg.cache?.valid_rules||[]).map((r,i)=>`
              <div class="p-cache-rule-row" style="display:grid;grid-template-columns:1fr 140px 28px;gap:4px 6px;align-items:center;">
                <input class="input p-cr-codes" style="font-size:12px;padding:4px 6px;" placeholder="200 404" value="${esc((r.status_codes||[]).join(' '))}">
                <input class="input p-cr-ttl" style="font-size:12px;padding:4px 6px;" placeholder="1h" value="${esc(r.ttl||'')}">
                <button onclick="this.closest('.p-cache-rule-row').remove()" style="background:none;border:none;color:var(--text3);cursor:pointer;font-size:15px;" title="Supprimer">✕</button>
              </div>`).join('')}
            </div>
            <button onclick="addCacheRuleRow()" style="margin-top:8px;font-size:11px;padding:3px 10px;" class="btn btn-sm">+ Règle</button>
            <div style="margin-top:12px;display:flex;flex-wrap:wrap;gap:10px;">
              <div class="field" style="flex:1;min-width:180px;margin:0;"><label class="field-label" style="font-size:11px">Bypass si header présent (un par ligne)</label><textarea id="p-cache-bypass-headers" class="input" style="font-size:12px;min-height:48px;" placeholder="X-No-Cache">${esc((cfg.cache?.bypass_headers||[]).join('\n'))}</textarea></div>
              <div class="field" style="flex:1;min-width:180px;margin:0;"><label class="field-label" style="font-size:11px">Bypass si cookie présent (un par ligne)</label><textarea id="p-cache-bypass-cookies" class="input" style="font-size:12px;min-height:48px;" placeholder="session">${esc((cfg.cache?.bypass_cookies||[]).join('\n'))}</textarea></div>
            </div>
          </div>
          <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:14px 16px;">
            <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin-bottom:10px;">Timeouts backend (secondes)</div>
            <div class="form-row" style="gap:8px">
              <div class="field" style="flex:1"><label class="field-label" style="font-size:11px">Connexion</label><input id="p-connect-timeout" class="input" type="number" min="1" placeholder="10" value="${cfg.connect_timeout ? Math.round(cfg.connect_timeout/1e9) : ''}"></div>
              <div class="field" style="flex:1"><label class="field-label" style="font-size:11px">Réponse (read)</label><input id="p-response-timeout" class="input" type="number" min="1" placeholder="30" value="${cfg.response_timeout ? Math.round(cfg.response_timeout/1e9) : ''}"></div>
              <div class="field" style="flex:1"><label class="field-label" style="font-size:11px">Envoi (write)</label><input id="p-send-timeout" class="input" type="number" min="1" placeholder="30" value="${cfg.send_timeout ? Math.round(cfg.send_timeout/1e9) : ''}"></div>
              <div class="field" style="flex:1"><label class="field-label" style="font-size:11px">Buffer (octets)</label><input id="p-buffer-size" class="input" type="number" min="512" placeholder="4096" value="${cfg.buffer_size || ''}"></div>
            </div>
          </div>
          <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:14px 16px;">
            <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin-bottom:6px;">Connexions simultanées — limit_conn</div>
            <div style="font-size:11px;color:var(--text3);margin-bottom:10px;">Limite le nombre de connexions actives par IP. Dépasse = 503. 0 = désactivé.</div>
            <div class="field" style="max-width:160px;margin:0;">
              <label class="field-label" style="font-size:11px">Max connexions / IP</label>
              <input id="p-limit-conn" class="input" type="number" min="0" placeholder="0" value="${cfg.limit_conn?.max_per_ip || ''}">
            </div>
          </div>
          <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:14px 16px;">
            <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin-bottom:6px;">Backpressure — protection des backends</div>
            <div style="font-size:11px;color:var(--text3);margin-bottom:10px;">Plafonne les requêtes simultanées de la route. Les excédentaires attendent dans une file bornée, puis 503 + Retry-After. 0 = désactivé. Les WebSocket sont exclus.</div>
            <div style="display:flex;gap:12px;flex-wrap:wrap;">
              <div class="field" style="flex:1;margin:0;"><label class="field-label" style="font-size:11px">Max requêtes simultanées</label><input id="p-bp-max" class="input" type="number" min="0" placeholder="0" value="${cfg.backpressure?.max_inflight || ''}"></div>
              <div class="field" style="flex:1;margin:0;"><label class="field-label" style="font-size:11px">Taille de la file</label><input id="p-bp-queue" class="input" type="number" min="0" placeholder="0" value="${cfg.backpressure?.queue || ''}"></div>
              <div class="field" style="flex:1;margin:0;"><label class="field-label" style="font-size:11px">Attente max en file (ms)</label><input id="p-bp-timeout" class="input" type="number" min="0" placeholder="1000" value="${cfg.backpressure?.queue_timeout_ms || ''}"></div>
            </div>
          </div>
          <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:14px 16px;">
            <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin-bottom:12px;">Journalisation par route</div>
            <div style="display:flex;gap:16px;align-items:flex-end;flex-wrap:wrap;">
              <label style="display:flex;align-items:center;gap:8px;cursor:pointer;padding-bottom:2px;">
                <label class="toggle"><input type="checkbox" id="p-log-enabled" ${cfg.logging?.access_log!==false?'checked':''}><span class="toggle-slider"></span></label>
                <span style="font-size:13px;font-weight:500;">Access log</span>
              </label>
              <div class="field" style="flex:1;min-width:120px;margin:0;"><label class="field-label" style="font-size:11px">Format</label><select id="p-log-format" class="input"><option value="combined" ${(cfg.logging?.format||'combined')==='combined'?'selected':''}>Combined</option><option value="json" ${cfg.logging?.format==='json'?'selected':''}>JSON</option><option value="minimal" ${cfg.logging?.format==='minimal'?'selected':''}>Minimal</option><option value="off" ${cfg.logging?.format==='off'?'selected':''}>Désactivé</option></select></div>
              <div class="field" style="flex:1;min-width:120px;margin:0;"><label class="field-label" style="font-size:11px">Niveau erreurs</label><select id="p-log-level" class="input"><option value="warn" ${(cfg.logging?.level||'warn')==='warn'?'selected':''}>Warn</option><option value="info" ${cfg.logging?.level==='info'?'selected':''}>Info</option><option value="error" ${cfg.logging?.level==='error'?'selected':''}>Error</option><option value="debug" ${cfg.logging?.level==='debug'?'selected':''}>Debug</option></select></div>
              <label style="display:flex;align-items:center;gap:8px;cursor:pointer;padding-bottom:2px;">
                <label class="toggle"><input type="checkbox" id="p-prom-enabled" ${cfg.observability?.metrics?.prometheus?.enabled?'checked':''}><span class="toggle-slider"></span></label>
                <span style="font-size:13px;font-weight:500;">Prometheus</span>
              </label>
            </div>
          </div>
          <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:14px 16px;">
            <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin-bottom:6px;">Pages d'erreur personnalisées</div>
            <div style="font-size:11px;color:var(--text3);margin-bottom:10px;">Choisir un template de la bibliothèque (adaptatif) ou une URL de redirection. Clés : 400, 403, 404, 502, 503, 504 ou 4xx / 5xx.</div>
            <div id="p-error-pages-list">
              ${renderErrorPageRows(cfg)}
            </div>
            <button type="button" class="btn btn-secondary btn-sm" onclick="window._addErrorPageRow()">+ Ajouter</button>
            ${(Object.entries(cfg.error_pages?.pages||{}).some(([_,v])=>v && !/^https?:\/\//.test(v))) ? `
            <div style="margin-top:10px;font-size:11px;color:var(--text3);padding:8px;background:var(--bg);border-radius:6px">
              HTML inline legacy détecté — migrez vers un template de la bibliothèque (Paramètres → Pages d'erreur).
            </div>` : ''}
          </div>
        </div>

        <!-- Panel YAML brut -->
        <div id="ptab-yaml" style="padding:16px 20px;display:none;flex-direction:column;gap:10px;height:100%;box-sizing:border-box;">
          <div style="display:flex;align-items:center;justify-content:space-between;">
            <div>
              <div style="font-size:13px;font-weight:600;">Config YAML brute</div>
              <div style="font-size:11px;color:var(--text3);margin-top:2px;">Édition directe — les autres onglets sont ignorés à la sauvegarde depuis cet onglet.</div>
            </div>
            <button type="button" class="btn btn-secondary btn-sm" onclick="window._refreshYamlTab()" title="Recharger depuis les autres onglets" style="display:flex;align-items:center;gap:5px;">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 .49-3.51"/></svg>
              Sync
            </button>
          </div>
          <div id="p-yaml-error" style="display:none;background:color-mix(in srgb,var(--error,#e53e3e) 10%,transparent);border:1px solid color-mix(in srgb,var(--error,#e53e3e) 30%,transparent);border-radius:6px;padding:8px 12px;font-size:12px;color:var(--error,#e53e3e);"></div>
          <textarea id="p-yaml-editor"
            spellcheck="false"
            style="flex:1;min-height:340px;font-family:ui-monospace,'Fira Code',monospace;font-size:12.5px;line-height:1.6;resize:none;background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:12px;color:var(--text);tab-size:2;outline:none;transition:border-color .15s;"
            onfocus="this.style.borderColor='var(--accent)'" onblur="this.style.borderColor='var(--border)'"
            oninput="document.getElementById('p-yaml-error').style.display='none'"
            placeholder="# Config YAML du proxy&#10;host: app.example.fr&#10;backends:&#10;  - url: http://10.0.0.1:8080"></textarea>
        </div>

      </div><!-- end content area -->

    </div><!-- end flex container -->`;

  const footer = `
    ${id ? `<div style="margin-right:auto;display:flex;align-items:center;gap:4px;">
      <button class="btn btn-ghost" style="display:flex;align-items:center;gap:6px;" onclick="closeModal();setTimeout(()=>openDockerLabelsFromProxy('${esc(id)}'),30)"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="2" y="8" width="20" height="10" rx="2"/><path d="M6 8V6h3v2M11 8V5h3v3M16 8V6h3v2"/></svg>Labels</button>
    </div>` : ''}
    <button class="btn btn-secondary" onclick="closeModal()">Annuler</button>
    <button class="btn btn-primary" onclick="saveProxy('${esc(id||'')}')">Enregistrer</button>`;

  const headerRight = `<label style="display:flex;align-items:center;gap:8px;font-size:13px;font-weight:400;cursor:pointer;">
    <label class="toggle"><input type="checkbox" id="p-enabled" ${existing?.enabled!==false?'checked':''}><span class="toggle-slider"></span></label>
    <span style="color:var(--text2);">Activé</span>
  </label>`;
  modal(id ? 'Modifier le proxy' : 'Nouveau proxy', body, footer, true, headerRight);
  document.querySelector('#modal-overlay .dialog')?.classList.add('pm-dialog');
  if (initialTab) switchProxyTab(initialTab);
  updateProxyForm();
  // Peupler le sélecteur de certificats
  const certSel = document.getElementById('p-cert');
  if (certSel) {
    api('GET', '/certs').then(certs => {
      if (!Array.isArray(certs)) return;
      const current = cfg.cert_name || '';
      // Construire la liste : wildcard en priorité puis apex
      const added = new Set();
      certs.forEach(c => {
        // Wildcard *.domain
        const wild = '*.' + c.domain;
        if (!added.has(wild)) {
          added.add(wild);
          const opt = document.createElement('option');
          opt.value = wild;
          opt.textContent = wild + ' (exp. ' + c.expires_at?.slice(0,10) + ')';
          if (wild === current) opt.selected = true;
          certSel.appendChild(opt);
        }
        // Apex domain
        if (!added.has(c.domain)) {
          added.add(c.domain);
          const opt = document.createElement('option');
          opt.value = c.domain;
          opt.textContent = c.domain + ' (exp. ' + c.expires_at?.slice(0,10) + ')';
          if (c.domain === current) opt.selected = true;
          certSel.appendChild(opt);
        }
      });
      // Si la valeur actuelle n'est pas dans la liste (cert importé manuellement), l'ajouter
      if (current && !added.has(current)) {
        const opt = document.createElement('option');
        opt.value = current;
        opt.textContent = current;
        opt.selected = true;
        certSel.appendChild(opt);
      }
      // Pas de valeur actuelle → "Automatique" déjà sélectionné (option value="")
    }).catch(() => {
      // Fallback texte libre si l'API échoue
      const val = cfg.cert_name || '';
      certSel.outerHTML = `<input id="p-cert" class="input" placeholder="cert-name" value="${esc(val)}">`;
    });
  }
  await _psecMount(id || '', secTab || (id ? 'recap' : 'params'), document.getElementById('ptab-protection'));
};

window.updateProxyForm = function() {
  updateSSOForm();
};

window.switchProxyTab = function(tab, secTab) {
  ['general','entetes','auth','protection','resilience','avance','yaml'].forEach(t => {
    const panel = document.getElementById('ptab-' + t);
    if (panel) panel.style.display = t === tab ? (t === 'protection' ? 'block' : 'flex') : 'none';
  });
  document.querySelectorAll('#proxy-tabs [data-tab]').forEach(el => {
    el.classList.toggle('active', el.dataset.tab === tab);
  });
  if (tab === 'protection' && secTab && typeof switchSecTab === 'function') switchSecTab(secTab);
  if (tab === 'yaml') window._refreshYamlTab();
};

// Collecte la config depuis les autres onglets et l'affiche en YAML dans la textarea.
window._refreshYamlTab = function() {
  const ta = document.getElementById('p-yaml-editor');
  if (!ta) return;
  const cfg = window._collectProxyConfig();
  if (!cfg) return;
  try { ta.value = _yaml.dump(cfg); } catch(e) { ta.value = '# erreur: ' + e.message; }
};

// Collecte la config courante du formulaire sans déclencher la sauvegarde.
// Réutilise la logique de saveProxy() — extrait dans une fonction partagée.
window._collectProxyConfig = function() {
  try {
    const isHTTPS = document.getElementById('p-https')?.checked;
    const type = isHTTPS ? 'https' : 'http';
    const backends = [...document.querySelectorAll('.p-backend-row')].map(row => {
      const url = row.querySelector('.p-backend-url')?.value.trim();
      const weight = parseInt(row.querySelector('.p-backend-weight')?.value||'0')||0;
      return url ? (weight > 0 ? { url, weight } : { url }) : null;
    }).filter(Boolean);
    const domainVals = [...document.querySelectorAll('.p-domain-val')].map(i=>i.value.trim()).filter(Boolean);
    const host = domainVals[0] || '';
    const aliases = domainVals.slice(1);
    const collected = {
      type, host, ...(aliases.length ? { aliases } : {}),
      tls_enabled: isHTTPS || false,
      backends,
      lb: document.getElementById('p-lb')?.value || 'round_robin',
      // on inclut la config complète telle que connue
      ...window._openProxyCfg,
      // on écrase les champs édités dans le formulaire
      type, host, ...(aliases.length ? { aliases } : { aliases: undefined }),
      tls_enabled: isHTTPS || false, backends,
    };
    return document.getElementById('psec-tabs') ? _psecBuildConfig(collected) : collected;
  } catch { return window._openProxyCfg || {}; }
};

window.updateSSOForm = function() {
  const prov = document.getElementById('p-sso-provider')?.value || '';
  const isFwd = ['authentik','authelia','forward'].includes(prov);
  const isOIDC = ['pocket_id','oidc'].includes(prov);
  const fwdFields = document.getElementById('p-sso-fwd-fields');
  const oidcFields = document.getElementById('p-sso-oidc-fields');
  if (fwdFields) fwdFields.style.display = isFwd ? '' : 'none';
  if (oidcFields) oidcFields.style.display = isOIDC ? '' : 'none';
};

let locationCounter = 200;

window.toggleLocRewrite = function(select) {
  const row = select.closest('.p-loc-row');
  if (!row) return;
  const rewriteRow = row.querySelector('.p-loc-rewrite-row');
  if (!rewriteRow) return;
  rewriteRow.style.display = select.value === 'regex' ? 'grid' : 'none';
};
window.addLocationRow = function() {
  const i = locationCounter++;
  const list = document.getElementById('p-locations-list');
  if (!list) return;
  const div = document.createElement('div');
  div.id = 'ploc-' + i;
  div.className = 'p-loc-row';
  div.style.cssText = 'display:flex;flex-direction:column;gap:3px;';
  div.innerHTML = `
    <div style="display:grid;grid-template-columns:1.4fr 0.7fr 2.5fr 28px;gap:4px 6px;align-items:center;">
      <input id="p-loc-path-${i}" class="input p-loc-path" placeholder="/api" style="margin:0;">
      <select id="p-loc-pathtype-${i}" class="input p-loc-pathtype" style="margin:0;" onchange="toggleLocRewrite(this)">
        ${['prefix','exact','regex'].map(t=>`<option>${t}</option>`).join('')}
      </select>
      <input id="p-loc-dest-${i}" class="input p-loc-dest" placeholder="http://backend:8080" style="margin:0;">
      <button type="button" class="btn-icon" title="Supprimer" onclick="this.closest('.p-loc-row').remove()" style="opacity:.55;"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/></svg></button>
    </div>
    <div class="p-loc-rewrite-row" style="display:none;grid-template-columns:80px 1fr;gap:6px;align-items:center;padding-left:2px;">
      <span style="font-size:10.5px;color:var(--text3);white-space:nowrap;">Réécriture</span>
      <input class="input p-loc-rewrite" placeholder="/new/$1" style="margin:0;font-family:monospace;font-size:12px;">
    </div>`;
  list.appendChild(div);
  div.querySelector('.p-loc-path')?.focus();
};

window.addCacheRuleRow = function() {
  const list = document.getElementById('p-cache-rules-list');
  if (!list) return;
  const div = document.createElement('div');
  div.className = 'p-cache-rule-row';
  div.style.cssText = 'display:grid;grid-template-columns:1fr 140px 28px;gap:4px 6px;align-items:center;';
  div.innerHTML = `<input class="input p-cr-codes" style="font-size:12px;padding:4px 6px;" placeholder="200 404">
    <input class="input p-cr-ttl" style="font-size:12px;padding:4px 6px;" placeholder="1h">
    <button onclick="this.closest('.p-cache-rule-row').remove()" style="background:none;border:none;color:var(--text3);cursor:pointer;font-size:15px;" title="Supprimer">✕</button>`;
  list.appendChild(div);
};

let subFilterCounter = 500;
window.addSubFilterRow = function() {
  const list = document.getElementById('p-subfilters-list');
  if (!list) return;
  const div = document.createElement('div');
  div.className = 'p-sf-row';
  div.style.cssText = 'display:grid;grid-template-columns:24px 1fr 1fr 28px;gap:4px 6px;align-items:center;';
  div.innerHTML = `
    <input type="checkbox" class="p-sf-regex" title="Regex">
    <input class="input p-sf-from" placeholder="http://backend" style="margin:0;font-family:monospace;font-size:12px;">
    <input class="input p-sf-to" placeholder="https://app.example.fr" style="margin:0;font-family:monospace;font-size:12px;">
    <button type="button" class="btn-icon" title="Supprimer" onclick="this.closest('.p-sf-row').remove()" style="opacity:.55;">×</button>`;
  list.appendChild(div);
  div.querySelector('.p-sf-from')?.focus();
};

window.toggleRvKey = function(sel) {
  const row = sel.closest('.p-rv-row');
  const keyInput = row?.querySelector('.p-rv-key');
  if (!keyInput) return;
  keyInput.style.display = ['header','cookie','query'].includes(sel.value) ? '' : 'none';
};

window.addRvCaseRow = function(btn) {
  const caseList = btn.closest('.p-rv-row')?.querySelector('.p-rv-cases');
  if (!caseList) return;
  const div = document.createElement('div');
  div.className = 'p-rvc-row';
  div.style.cssText = 'display:grid;grid-template-columns:24px 1fr 1fr 28px;gap:3px 5px;align-items:center;';
  div.innerHTML = `<input type="checkbox" class="p-rvc-regex" title="Regex">
    <input class="input p-rvc-pattern" placeholder="pattern" style="font-size:12px;padding:3px 5px;">
    <input class="input p-rvc-value" placeholder="valeur" style="font-size:12px;padding:3px 5px;">
    <button onclick="this.closest('.p-rvc-row').remove()" style="background:none;border:none;color:var(--text3);cursor:pointer;font-size:13px;" title="Supprimer">✕</button>`;
  caseList.appendChild(div);
};

window.addReqVarRow = function() {
  const list = document.getElementById('p-reqvars-list');
  if (!list) return;
  const div = document.createElement('div');
  div.className = 'p-rv-row';
  div.style.cssText = 'background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:8px 10px;display:flex;flex-direction:column;gap:6px;';
  div.innerHTML = `
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr 28px;gap:4px 6px;align-items:center;">
      <input class="input p-rv-name" placeholder="nom (ex: country)" style="font-size:12px;padding:4px 6px;">
      <select class="input p-rv-source" style="font-size:12px;padding:4px 6px;" onchange="toggleRvKey(this)">
        ${['header','cookie','query','method','remote_ip','path'].map(s=>`<option value="${s}">${s}</option>`).join('')}
      </select>
      <input class="input p-rv-key" placeholder="clé header/cookie/query" style="font-size:12px;padding:4px 6px;">
      <button onclick="this.closest('.p-rv-row').remove()" style="background:none;border:none;color:var(--text3);cursor:pointer;font-size:15px;grid-column:4;grid-row:1;" title="Supprimer">✕</button>
    </div>
    <div style="font-size:10px;color:var(--text3);margin-bottom:2px;">Cas (pattern → valeur) :</div>
    <div class="p-rv-cases" style="display:flex;flex-direction:column;gap:3px;"></div>
    <div style="display:flex;align-items:center;gap:8px;">
      <button onclick="addRvCaseRow(this)" style="font-size:11px;" class="btn btn-sm">+ Cas</button>
      <span style="font-size:11px;color:var(--text3);">Défaut :</span>
      <input class="input p-rv-default" placeholder="valeur par défaut" style="font-size:12px;padding:3px 5px;flex:1;">
    </div>`;
  list.appendChild(div);
  div.querySelector('.p-rv-name')?.focus();
};

let cookieRewriteCounter = 400;
window.addCookieRewriteRow = function() {
  const list = document.getElementById('p-cookie-rewrites-list');
  if (!list) return;
  const div = document.createElement('div');
  div.className = 'p-cookie-row';
  div.style.cssText = 'display:grid;grid-template-columns:60px 24px 1fr 1fr 28px;gap:4px 6px;align-items:center;';
  div.innerHTML = `
    <select class="input p-ck-attr" style="margin:0;font-size:11px;padding:3px 4px;">
      <option>domain</option><option>path</option>
    </select>
    <input type="checkbox" class="p-ck-regex" title="Regex">
    <input class="input p-ck-from" placeholder="backend.internal" style="margin:0;font-family:monospace;font-size:12px;">
    <input class="input p-ck-to" placeholder="app.example.fr" style="margin:0;font-family:monospace;font-size:12px;">
    <button type="button" class="btn-icon" title="Supprimer" onclick="this.closest('.p-cookie-row').remove()" style="opacity:.55;">×</button>`;
  list.appendChild(div);
  div.querySelector('.p-ck-from')?.focus();
};

let redirectCounter = 300;
window.addRedirectRow = function() {
  const i = redirectCounter++;
  const list = document.getElementById('p-redirects-list');
  if (!list) return;
  const div = document.createElement('div');
  div.className = 'p-redirect-row';
  div.style.cssText = 'display:grid;grid-template-columns:24px 1fr 1fr 28px;gap:4px 6px;align-items:center;';
  div.innerHTML = `
    <input type="checkbox" class="p-rd-regex" title="Regex">
    <input class="input p-rd-from" placeholder="http://backend:8080/" style="margin:0;font-family:monospace;font-size:12px;">
    <input class="input p-rd-to" placeholder="https://app.example.fr/" style="margin:0;font-family:monospace;font-size:12px;">
    <button type="button" class="btn-icon" title="Supprimer" onclick="this.closest('.p-redirect-row').remove()" style="opacity:.55;">×</button>`;
  list.appendChild(div);
  div.querySelector('.p-rd-from')?.focus();
};

let conditionCounter = 100;
window.addConditionRow = function() {
  const i = conditionCounter++;
  const list = document.getElementById('p-conditions-list');
  if (!list) return;
  const div = document.createElement('div');
  div.className = 'p-cond-row';
  div.style.cssText = 'display:grid;grid-template-columns:minmax(90px,0.9fr) minmax(70px,1fr) minmax(70px,1.2fr) minmax(120px,1.8fr) 28px;gap:6px;align-items:center;';
  div.id = 'pcond-' + i;
  div.innerHTML = `
    <select id="p-cond-type-${i}" class="input" style="margin:0;">
      ${['header','cookie','query','method'].map(t=>`<option>${t}</option>`).join('')}
    </select>
    <input id="p-cond-name-${i}" class="input" placeholder="Nom" style="margin:0;">
    <input id="p-cond-val-${i}" class="input" placeholder="Valeur" style="margin:0;">
    <input id="p-cond-bk-${i}" class="input" placeholder="http://backend:port" style="margin:0;">
    <button type="button" class="btn-icon" title="Supprimer" onclick="this.closest('.p-cond-row').remove()" style="opacity:.55;">×</button>`;
  list.appendChild(div);
};

window._addDomainRow = function() {
  const list = document.getElementById('p-domains-list');
  if (!list) return;
  const row = document.createElement('div');
  row.className = 'p-domain-row';
  row.style.cssText = 'display:flex;gap:6px;margin-bottom:6px;align-items:center;';
  row.innerHTML = `<input class="input p-domain-val" style="flex:1;" placeholder="alias.example.fr" title="Alias">
    <button type="button" class="btn-icon" title="Supprimer" onclick="this.closest('.p-domain-row').remove()">×</button>`;
  list.appendChild(row);
  row.querySelector('.p-domain-val').focus();
};

window._addBackendRow = function() {
  const list = document.getElementById('p-backends-list');
  if (!list) return;
  const row = document.createElement('div');
  row.className = 'p-backend-row';
  row.style.cssText = 'display:flex;gap:6px;margin-bottom:6px;align-items:center';
  row.innerHTML = `
    <input class="input p-backend-url" style="flex:1" placeholder="http://10.0.0.5:3000"
      oninput="this.setCustomValidity(this.value&&!/^https?:\\/\\/.+/.test(this.value.trim())?'URL invalide (doit commencer par http:// ou https://)':'')"
      title="URL du backend">
    <input class="input p-backend-weight" style="width:64px" type="number" min="1" max="100" placeholder="Poids" title="Poids (load balancing)">
    <button type="button" class="btn-icon" title="Supprimer" onclick="this.closest('.p-backend-row').remove();if(!document.querySelectorAll('.p-backend-row').length)window._addBackendRow()">×</button>`;
  list.appendChild(row);
  row.querySelector('.p-backend-url').focus();
};

window._errorPageTemplates = [];

function renderErrorPageRows(cfg) {
  const tpls = window._errorPageTemplates || [];
  const tplOpts = tpls.map(t => `<option value="${esc(t.id)}">${esc(t.name)}</option>`).join('');
  const rows = [];
  const templates = cfg.error_pages?.templates || {};
  const pages = cfg.error_pages?.pages || {};
  const codes = new Set([...Object.keys(templates), ...Object.keys(pages)]);
  for (const code of codes) {
    const tplId = templates[code] || '';
    const pageVal = pages[code] || '';
    const isRedirect = /^https?:\/\//.test(pageVal);
    const mode = tplId ? 'template' : (isRedirect ? 'redirect' : (pageVal ? 'legacy' : 'template'));
    rows.push(errorPageRowHTML(code, mode, tplId, isRedirect ? pageVal : '', pageVal && !isRedirect ? pageVal : '', tplOpts));
  }
  return rows.join('');
}

function errorPageRowHTML(code, mode, tplId, redirectURL, legacyHTML, tplOpts) {
  const opts = tplOpts || (window._errorPageTemplates || []).map(t =>
    `<option value="${esc(t.id)}" ${t.id===tplId?'selected':''}>${esc(t.name)}</option>`
  ).join('');
  return `<div class="p-error-page-row" style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:8px;align-items:center">
    <input class="input p-error-code" style="width:64px" placeholder="502" value="${esc(code||'')}">
    <select class="input p-error-mode" style="width:120px" onchange="window._onErrorPageModeChange(this)">
      <option value="template" ${mode==='template'?'selected':''}>Template</option>
      <option value="redirect" ${mode==='redirect'?'selected':''}>Redirect URL</option>
      ${mode==='legacy' ? '<option value="legacy" selected>HTML legacy</option>' : ''}
    </select>
    <select class="input p-error-tpl" style="flex:1;min-width:140px;${mode!=='template'?'display:none':''}">
      <option value="">— Choisir —</option>
      ${(window._errorPageTemplates||[]).map(t=>`<option value="${esc(t.id)}" ${t.id===tplId?'selected':''}>${esc(t.name)}</option>`).join('') || opts}
    </select>
    <input class="input p-error-redirect" style="flex:1;min-width:140px;${mode!=='redirect'?'display:none':''}" placeholder="https://…" value="${esc(redirectURL||'')}">
    ${mode==='legacy' ? `<input class="input p-error-legacy" style="flex:1;min-width:140px" readonly value="${esc(legacyHTML||'')}" title="Migrez vers un template">` : ''}
    <button type="button" class="btn-icon" title="Supprimer" onclick="this.closest('.p-error-page-row').remove()">×</button>
  </div>`;
}

window._onErrorPageModeChange = function(sel) {
  const row = sel.closest('.p-error-page-row');
  if (!row) return;
  const mode = sel.value;
  const tpl = row.querySelector('.p-error-tpl');
  const redir = row.querySelector('.p-error-redirect');
  const leg = row.querySelector('.p-error-legacy');
  if (tpl) tpl.style.display = mode === 'template' ? '' : 'none';
  if (redir) redir.style.display = mode === 'redirect' ? '' : 'none';
  if (leg) leg.style.display = mode === 'legacy' ? '' : 'none';
};

window._addErrorPageRow = function() {
  const list = document.getElementById('p-error-pages-list');
  if (!list) return;
  list.insertAdjacentHTML('beforeend', errorPageRowHTML('', 'template', '', '', '', ''));
  list.lastElementChild?.querySelector('.p-error-code')?.focus();
};

window.saveProxy = async function(id, opts = {}) {
  // ── Mode YAML brut : la textarea prime sur tous les autres onglets ──
  const yamlPanel = document.getElementById('ptab-yaml');
  const yamlActive = yamlPanel && yamlPanel.style.display !== 'none';
  if (yamlActive) {
    const ta = document.getElementById('p-yaml-editor');
    const errEl = document.getElementById('p-yaml-error');
    if (!ta) return;
    let config;
    try {
      config = _yaml.parse(ta.value);
      if (!config || typeof config !== 'object') throw new Error('La config doit être un objet YAML.');
      if (!config.backends?.length) throw new Error('Au moins un backend est requis.');
    } catch(e) {
      if (errEl) { errEl.textContent = e.message; errEl.style.display = ''; }
      return;
    }
    if (errEl) errEl.style.display = 'none';
    const payload = { config, enabled: document.getElementById('p-enabled')?.checked !== false };
    try {
      if (id) {
        await api('PUT', `/proxies/${encodeURIComponent(id)}`, payload);
        toast('Proxy mis à jour', 'success');
      } else {
        await api('POST', '/proxies', payload);
        toast('Proxy créé', 'success');
      }
      if (!opts.keepOpen) { closeModal(); navigate(state.page); }
      return true;
    } catch(e) { toast(e.message, 'error'); }
    return false;
  }

  const isHTTPS = document.getElementById('p-https')?.checked;
  const type = isHTTPS ? 'https' : 'http';
  const isL4 = false;
  const backendRows = [...document.querySelectorAll('.p-backend-row')];
  const backends = backendRows.map(row => {
    const url = row.querySelector('.p-backend-url')?.value.trim();
    const weight = parseInt(row.querySelector('.p-backend-weight')?.value||'0')||0;
    return url ? (weight > 0 ? { url, weight } : { url }) : null;
  }).filter(Boolean);
  if (!backends.length) { toast('Au moins un backend est requis', 'error'); return; }
  const invalid = backends.find(b => !/^https?:\/\/.+/.test(b.url));
  if (invalid) { toast(`URL invalide : ${invalid.url}`, 'error'); return; }
  // Canary config
  const canaryBk = document.getElementById('p-canary-backend')?.value.trim();
  const canaryWeight = parseInt(document.getElementById('p-canary-weight')?.value||'0');
  const canary = canaryBk ? {
    backend: canaryBk,
    weight: canaryWeight,
    header: document.getElementById('p-canary-header')?.value.trim()||undefined,
    header_value: document.getElementById('p-canary-hval')?.value.trim()||undefined,
    cookie_name: document.getElementById('p-canary-cookie')?.value.trim()||undefined,
  } : undefined;

  // Shadow config
  const shadowBk = document.getElementById('p-shadow-backend')?.value.trim();
  const shadow = shadowBk ? { backend: shadowBk } : undefined;

  // Conditions
  const condRows = document.querySelectorAll('[id^="pcond-"]');
  const conditions = Array.from(condRows).map(row => ({
    type: row.querySelector('[id^="p-cond-type"]')?.value||'header',
    name: row.querySelector('[id^="p-cond-name"]')?.value.trim()||undefined,
    value: row.querySelector('[id^="p-cond-val"]')?.value.trim()||'',
    backend: row.querySelector('[id^="p-cond-bk"]')?.value.trim()||'',
  })).filter(c => c.value && c.backend);

  // SSO config
  const ssoProvider = document.getElementById('p-sso-provider')?.value||'';
  let sso = undefined;
  if (ssoProvider) {
    if (['pocket_id','oidc'].includes(ssoProvider)) {
      sso = {
        provider: ssoProvider,
        oidc: {
          issuer_url: document.getElementById('p-oidc-issuer')?.value.trim()||'',
          client_id: document.getElementById('p-oidc-client-id')?.value.trim()||'',
          client_secret: document.getElementById('p-oidc-secret')?.value.trim()||'',
          redirect_url: document.getElementById('p-oidc-redirect')?.value.trim()||'',
          session_secret: document.getElementById('p-oidc-sess-secret')?.value.trim()||'',
          username_claim: document.getElementById('p-oidc-claim')?.value.trim()||'preferred_username',
        },
      };
    } else {
      sso = {
        provider: ssoProvider,
        forward_auth_url: document.getElementById('p-sso-fwd-url')?.value.trim()||'',
      };
    }
  }

  // Locations — collecte par ligne (.p-loc-row), normalise le slash initial (hors regex)
  const locations = Array.from(document.querySelectorAll('#p-locations-list .p-loc-row')).map(row => {
    let path = row.querySelector('.p-loc-path')?.value.trim()||'';
    const pathType = row.querySelector('.p-loc-pathtype')?.value||'prefix';
    const dest = row.querySelector('.p-loc-dest')?.value.trim()||'';
    if (!path) return null;
    if (pathType !== 'regex' && !path.startsWith('/')) path = '/' + path;
    const entry = { path, path_type: pathType };
    if (dest) entry.backends = [{ url: dest }];
    if (pathType === 'regex') {
      const rewrite = row.querySelector('.p-loc-rewrite')?.value.trim() || '';
      if (rewrite) entry.path_rewrite = rewrite;
    }
    return entry;
  }).filter(Boolean);

  // Sub filters
  const sub_filters = Array.from(document.querySelectorAll('#p-subfilters-list .p-sf-row')).map(row => {
    const from = row.querySelector('.p-sf-from')?.value || '';
    const to = row.querySelector('.p-sf-to')?.value || '';
    if (!from) return null;
    const entry = { from, to };
    if (row.querySelector('.p-sf-regex')?.checked) entry.regex = true;
    return entry;
  }).filter(Boolean);

  // Request vars (map {})
  const request_vars = Array.from(document.querySelectorAll('#p-reqvars-list .p-rv-row')).map(row => {
    const name = row.querySelector('.p-rv-name')?.value.trim() || '';
    if (!name) return null;
    const source = row.querySelector('.p-rv-source')?.value || 'header';
    const key = row.querySelector('.p-rv-key')?.value.trim() || '';
    const def = row.querySelector('.p-rv-default')?.value || '';
    const cases = Array.from(row.querySelectorAll('.p-rvc-row')).map(cr => {
      const pattern = cr.querySelector('.p-rvc-pattern')?.value || '';
      const value = cr.querySelector('.p-rvc-value')?.value || '';
      if (!pattern) return null;
      const c = { pattern, value };
      if (cr.querySelector('.p-rvc-regex')?.checked) c.regex = true;
      return c;
    }).filter(Boolean);
    const v = { name, source };
    if (key) v.key = key;
    if (def) v.default = def;
    if (cases.length) v.cases = cases;
    return v;
  }).filter(Boolean);

  // limit_conn
  const limitConnMax = parseInt(document.getElementById('p-limit-conn')?.value || '0');
  const bpMax = parseInt(document.getElementById('p-bp-max')?.value || '0');
  const bpQueue = parseInt(document.getElementById('p-bp-queue')?.value || '0');
  const bpTimeout = parseInt(document.getElementById('p-bp-timeout')?.value || '0');

  // Cookie domain/path rewrites
  const cookie_domains = [], cookie_paths = [];
  document.querySelectorAll('#p-cookie-rewrites-list .p-cookie-row').forEach(row => {
    const attr = row.querySelector('.p-ck-attr')?.value || 'domain';
    const from = row.querySelector('.p-ck-from')?.value.trim() || '';
    const to = row.querySelector('.p-ck-to')?.value.trim() || '';
    if (!from || !to) return;
    const entry = { from, to };
    if (row.querySelector('.p-ck-regex')?.checked) entry.regex = true;
    (attr === 'path' ? cookie_paths : cookie_domains).push(entry);
  });

  // Proxy redirects
  const proxy_redirects = Array.from(document.querySelectorAll('#p-redirects-list .p-redirect-row')).map(row => {
    const from = row.querySelector('.p-rd-from')?.value.trim() || '';
    const to = row.querySelector('.p-rd-to')?.value.trim() || '';
    if (!from || !to) return null;
    const entry = { from, to };
    if (row.querySelector('.p-rd-regex')?.checked) entry.regex = true;
    return entry;
  }).filter(Boolean);

  // Health check
  const hcPath = document.getElementById('p-hc-path')?.value.trim();
  const health_check = hcPath ? {
    path: hcPath,
    interval: document.getElementById('p-hc-interval')?.value.trim()||undefined,
    timeout: document.getElementById('p-hc-timeout')?.value.trim()||undefined,
    healthy_threshold: parseInt(document.getElementById('p-hc-healthy')?.value||'0')||undefined,
    unhealthy_threshold: parseInt(document.getElementById('p-hc-unhealthy')?.value||'0')||undefined,
  } : undefined;

  // Circuit breaker
  const cbEnabled = document.getElementById('p-cb-enabled')?.checked;
  const cbThreshold = parseInt(document.getElementById('p-cb-threshold')?.value||'0');
  const circuit_breaker = (cbEnabled || cbThreshold) ? {
    enabled: cbEnabled,
    threshold: cbThreshold||undefined,
    timeout: document.getElementById('p-cb-timeout')?.value.trim()||undefined,
  } : undefined;

  // Retry
  const retryMax = parseInt(document.getElementById('p-retry-max')?.value||'0');
  const retryOn = (document.getElementById('p-retry-on')?.value||'').split(',').map(s=>s.trim()).filter(Boolean);
  const retry_policy = retryMax ? {
    max_attempts: retryMax,
    retry_delay: document.getElementById('p-retry-delay')?.value.trim()||undefined,
    retry_on: retryOn.length ? retryOn : undefined,
  } : undefined;

  // En-têtes de sécurité natifs (HeadersConfig) + custom (Phase B)
  const hstsEnabled = document.getElementById('p-hsts')?.checked;
  const hstsMaxAge = parseInt(document.getElementById('p-hsts-maxage')?.value||'0') || 31536000;
  const hideServer = document.getElementById('p-hide-server')?.checked;
  const xfo = document.getElementById('p-xfo')?.value || '';
  const respHdrLines = (document.getElementById('p-resp-headers')?.value||'').split('\n').map(s=>s.trim()).filter(Boolean);
  const customFromText = {};
  for (const [n, v] of Object.entries(parseResponseAddHeader(respHdrLines))) {
    const k = n.toLowerCase();
    if (k === 'strict-transport-security' || k === 'x-frame-options') continue;
    customFromText[n] = v;
  }
  const headers = (hstsEnabled || hideServer || xfo || Object.keys(customFromText).length) ? {
    hsts: hstsEnabled || false,
    hsts_max_age: hstsEnabled ? hstsMaxAge : undefined,
    hide_server: hideServer || false,
    x_frame_options: xfo || undefined,
    ...(Object.keys(customFromText).length ? { custom: customFromText } : {}),
  } : undefined;

  // Headers manipulation — forwarded + request set/hide
  const fwdHdrs = [...document.querySelectorAll('.p-fwd-header:checked')]
    .map(el => el.dataset.header)
    .filter(Boolean);
  const reqSetLines = (document.getElementById('p-req-set-headers')?.value||'').split('\n').map(s=>s.trim()).filter(Boolean);
  const request_set_header = parseResponseAddHeader(reqSetLines);
  const request_hide_header = (document.getElementById('p-req-hide-headers')?.value||'').split('\n').map(s=>s.trim()).filter(Boolean);
  const headers_manipulation = {
    forwarded_headers: fwdHdrs,
    ...(Object.keys(request_set_header).length ? { request_set_header } : {}),
    ...(request_hide_header.length ? { request_hide_header } : {}),
  };

  const stickyCookie = (document.getElementById('p-sticky-cookie')?.value||'').trim();
  const slowStart = parseInt(document.getElementById('p-slow-start')?.value || '0');
  const requestID = document.getElementById('p-request-id')?.checked !== false;

  // Performance
  const cacheEnabled = document.getElementById('p-cache-enabled')?.checked;
  const cacheTtl = document.getElementById('p-cache-ttl')?.value.trim();
  const gzipEnabled = document.getElementById('p-gzip-enabled')?.checked;
  const gzipMin = parseInt(document.getElementById('p-gzip-minsize')?.value||'0');
  const bodySizeMB = parseInt(document.getElementById('p-body-size')?.value||'0');
  const performance = (cacheEnabled || gzipEnabled) ? {
    ...(cacheEnabled || cacheTtl ? { cache_proxy: { enabled: cacheEnabled, ttl: cacheTtl||undefined } } : {}),
    ...(gzipEnabled || gzipMin ? { compression_gzip: { enabled: gzipEnabled, min_length: gzipMin||undefined } } : {}),
  } : undefined;

  // Cache avancé
  const cacheRules = Array.from(document.querySelectorAll('#p-cache-rules-list .p-cache-rule-row')).map(row => {
    const codesRaw = (row.querySelector('.p-cr-codes')?.value||'').trim();
    const ttl = (row.querySelector('.p-cr-ttl')?.value||'').trim();
    if (!ttl) return null;
    const status_codes = codesRaw ? codesRaw.split(/\s+/).map(Number).filter(n=>n>0) : [];
    return { status_codes, ttl };
  }).filter(Boolean);
  const cacheBypassHeaders = (document.getElementById('p-cache-bypass-headers')?.value||'').split('\n').map(s=>s.trim()).filter(Boolean);
  const cacheBypassCookies = (document.getElementById('p-cache-bypass-cookies')?.value||'').split('\n').map(s=>s.trim()).filter(Boolean);
  const cacheAdvanced = (cacheEnabled && (cacheRules.length || cacheBypassHeaders.length || cacheBypassCookies.length)) ? {
    enabled: true,
    valid_rules: cacheRules.length ? cacheRules : undefined,
    bypass_headers: cacheBypassHeaders.length ? cacheBypassHeaders : undefined,
    bypass_cookies: cacheBypassCookies.length ? cacheBypassCookies : undefined,
  } : null;

  // Timeouts backend natifs (stockés en nanosecondes pour time.Duration Go)
  const connectTimeoutS = parseInt(document.getElementById('p-connect-timeout')?.value||'0');
  const responseTimeoutS = parseInt(document.getElementById('p-response-timeout')?.value||'0');
  const sendTimeoutS = parseInt(document.getElementById('p-send-timeout')?.value||'0');
  const bufferSizeB = parseInt(document.getElementById('p-buffer-size')?.value||'0');

  // Protocols
  const http3 = document.getElementById('p-http3')?.checked;
  const grpc = document.getElementById('p-grpc')?.checked;
  const protocols = (http3 || grpc) ? {
    ...(http3 ? { http3_quic: { enabled: true } } : {}),
    ...(grpc ? { grpc: { enabled: true } } : {}),
  } : undefined;

  // Timeouts & error pages
  const timeoutProfile = document.getElementById('p-timeout-profile')?.value.trim();
  const err404 = document.getElementById('p-err-404')?.value.trim();
  const err502 = document.getElementById('p-err-502')?.value.trim();
  const timeouts_and_resilience = (timeoutProfile || err404 || err502) ? {
    use_timeout_profile: timeoutProfile||undefined,
    error_handling: (err404 || err502) ? { ...(err404?{'404':err404}:{}), ...(err502?{'502':err502,'503':err502}:{}) } : undefined,
  } : undefined;

  // Security (géré via le modal dédié — on préserve la config existante des chemins canoniques)
  const security = window._openProxyCfg?.security || undefined;
  const existingWaf = window._openProxyCfg?.waf || undefined;
  const existingBot = window._openProxyCfg?.bot || undefined;
  const existingJwt = window._openProxyCfg?.jwt || undefined;

  // Logging par route (natif)
  const logEnabled = document.getElementById('p-log-enabled')?.checked;
  const logFormat = document.getElementById('p-log-format')?.value || 'combined';
  const logLevel = document.getElementById('p-log-level')?.value || 'warn';
  const logging = { access_log: logEnabled, format: logFormat, level: logLevel };

  // Error pages — templates bibliothèque + redirects (+ legacy HTML conservé)
  const errorPageRows = [...document.querySelectorAll('.p-error-page-row')];
  const errorPagesMap = {};
  const errorTemplatesMap = {};
  errorPageRows.forEach(row => {
    const code = row.querySelector('.p-error-code')?.value.trim();
    if (!code) return;
    const mode = row.querySelector('.p-error-mode')?.value || 'template';
    if (mode === 'template') {
      const tid = row.querySelector('.p-error-tpl')?.value.trim();
      if (tid) errorTemplatesMap[code] = tid;
    } else if (mode === 'redirect') {
      const url = row.querySelector('.p-error-redirect')?.value.trim();
      if (url) errorPagesMap[code] = url;
    } else if (mode === 'legacy') {
      const html = row.querySelector('.p-error-legacy')?.value;
      if (html) errorPagesMap[code] = html;
    }
  });
  const error_pages = (Object.keys(errorPagesMap).length || Object.keys(errorTemplatesMap).length)
    ? {
        ...(Object.keys(errorPagesMap).length ? { pages: errorPagesMap } : {}),
        ...(Object.keys(errorTemplatesMap).length ? { templates: errorTemplatesMap } : {}),
      }
    : undefined;

  // Observability (Prometheus uniquement — logging géré nativement)
  const promEnabled = document.getElementById('p-prom-enabled')?.checked;
  const observability = promEnabled ? { metrics: { prometheus: { enabled: true } } } : undefined;

  // Domaines (premier = host, suivants = aliases)
  const domainVals = [...document.querySelectorAll('.p-domain-val')].map(i=>i.value.trim()).filter(Boolean);
  const host = domainVals[0] || '';
  const aliases = domainVals.slice(1);
  const tags = (document.getElementById('p-tags')?.value||'').split(',').map(s=>s.trim()).filter(Boolean);

  let config = {
    type,
    backends,
    lb: document.getElementById('p-lb').value,
    http_version: document.getElementById('p-http-version')?.value||'auto',
    websocket: document.getElementById('p-ws')?.checked !== false,
    request_id: requestID,
    tls_enabled: document.getElementById('p-https')?.checked || false,
    tls_mode: !document.getElementById('p-https')?.checked ? 'none' : (document.getElementById('p-cert').value.trim() ? 'manual' : 'le'),
    tls_passthrough: document.getElementById('p-passthrough').checked,
    tls_skip_verify: document.getElementById('p-skip-verify')?.checked || false,
    preserve_host: document.getElementById('p-preserve-host')?.checked !== false,
    cert_name: document.getElementById('p-cert').value.trim(),
    host,
    ...(aliases.length ? { aliases } : {}),
    ...(tags.length ? { tags } : {}),
    ...(stickyCookie ? { sticky_cookie: stickyCookie } : {}),
    ...(slowStart > 0 ? { slow_start_sec: slowStart } : {}),
    locations,
    ...(health_check ? { health_check } : {}),
    ...(canary ? { canary } : {}),
    ...(shadow ? { shadow } : {}),
    ...(conditions.length ? { conditions } : {}),
    ...(proxy_redirects.length ? { proxy_redirects } : {}),
    ...(cookie_domains.length ? { cookie_domains } : {}),
    ...(cookie_paths.length ? { cookie_paths } : {}),
    ...(sub_filters.length ? { sub_filters } : {}),
    ...(limitConnMax > 0 ? { limit_conn: { max_per_ip: limitConnMax } } : {}),
    ...(bpMax > 0 ? { backpressure: { max_inflight: bpMax, ...(bpQueue > 0 ? { queue: bpQueue } : {}), ...(bpTimeout > 0 ? { queue_timeout_ms: bpTimeout } : {}) } } : {}),
    ...(cacheAdvanced ? { cache: cacheAdvanced } : {}),
    ...(request_vars.length ? { request_vars } : {}),
    ...(circuit_breaker ? { circuit_breaker } : {}),
    ...(retry_policy ? { retry_policy } : {}),
    ...(headers ? { headers } : {}),
    headers_manipulation,
    ...(performance ? { performance } : {}),
    ...(protocols ? { protocols } : {}),
    ...(bodySizeMB > 0 ? { max_body_size: bodySizeMB * 1048576 } : {}),
    ...(connectTimeoutS > 0 ? { connect_timeout: connectTimeoutS * 1e9 } : {}),
    ...(responseTimeoutS > 0 ? { response_timeout: responseTimeoutS * 1e9 } : {}),
    ...(sendTimeoutS > 0 ? { send_timeout: sendTimeoutS * 1e9 } : {}),
    ...(bufferSizeB > 0 ? { buffer_size: bufferSizeB } : {}),
    ...(timeouts_and_resilience ? { timeouts_and_resilience } : {}),
    ...(existingWaf ? { waf: existingWaf } : {}),
    ...(existingBot ? { bot: existingBot } : {}),
    ...(existingJwt ? { jwt: existingJwt } : {}),
    ...(security ? { security } : {}),
    ...(sso ? { sso } : {}),
    ...(observability ? { observability } : {}),
    logging,
    ...(error_pages ? { error_pages } : {}),
  };
  // Onglet Protection monté : il fait foi. Sinon on conserve ce que le formulaire ne gère pas.
  if (document.getElementById('psec-tabs')) {
    config = _psecBuildConfig(config);
  } else {
    const prev = window._openProxyCfg || {};
    for (const k of ['rate_limit', 'ip_filter', 'geo_ip', 'snippet_ids', 'sentinel_whitelist']) {
      if (prev[k] !== undefined) config[k] = prev[k];
    }
    const typed = ['hsts', 'hsts_max_age', 'hide_server', 'x_frame_options'].filter(k => prev.headers?.[k] !== undefined);
    if (typed.length) config.headers = { ...(config.headers || {}), ...Object.fromEntries(typed.map(k => [k, prev.headers[k]])) };
  }
  const payload = { config, enabled: document.getElementById('p-enabled').checked };
  try {
    if (id) {
      await api('PUT', `/proxies/${encodeURIComponent(id)}`, payload);
      toast('Proxy mis à jour', 'success');
    } else {
      await api('POST', '/proxies', payload);
      toast('Proxy créé', 'success');
    }
    if (!opts.keepOpen) { closeModal(); navigate(state.page); }
    return true;
  } catch(e) { toast(e.message, 'error'); }
  return false;
};


function _buildStreamModalHtml(cfg, enabled, editing) {
  const proto = cfg.type || 'tcp';
  const backends = (cfg.backends||[]).length ? cfg.backends : [{}];
  const backendsHtml = backends.map((b, i) => `
    <div class="sp-backend-row" style="display:flex;gap:6px;align-items:center;margin-bottom:6px">
      <input class="input sp-backend-url" style="flex:1" placeholder="10.0.0.5:6379" value="${esc(backendURL(b))}">
      <button type="button" class="btn-icon" title="Supprimer" onclick="this.closest('.sp-backend-row').remove();if(!document.querySelectorAll('.sp-backend-row').length)_addStreamBackend()">×</button>
    </div>`).join('');
  return `
    <div style="display:flex;flex-direction:column;gap:16px;padding-top:4px;">
      <div class="field">
        <label class="field-label">Nom</label>
        <input class="input" id="sp-name" placeholder="Redis cache, DNS, …" value="${esc(cfg.host||'')}">
      </div>
      <div class="form-row" style="gap:12px;">
        <div class="field" style="flex:1;">
          <label class="field-label">Port d'écoute</label>
          <input class="input" id="sp-port" type="number" min="1" max="65535" placeholder="6379" value="${cfg.listen_port||''}">
        </div>
        <div class="field" style="flex:1;">
          <label class="field-label">Protocole</label>
          <div class="seg" style="margin-top:2px;">
            <label class="seg-opt"><input type="radio" name="sp-proto" value="tcp" ${proto==='tcp'?'checked':''}>TCP</label>
            <label class="seg-opt"><input type="radio" name="sp-proto" value="udp" ${proto==='udp'?'checked':''}>UDP</label>
            ${!editing ? `<label class="seg-opt"><input type="radio" name="sp-proto" value="both" ${proto==='both'?'checked':''}>Les deux</label>` : ''}
          </div>
        </div>
      </div>
      <div class="field">
        <label class="field-label">Backends</label>
        <div id="sp-backends-list">${backendsHtml}</div>
        <button type="button" class="btn btn-secondary" style="margin-top:2px;height:28px;padding:0 10px;font-size:12px" onclick="_addStreamBackend()">+ Ajouter un backend</button>
      </div>
      <label style="display:flex;align-items:center;gap:10px;font-size:13px;cursor:pointer;padding:10px 14px;background:var(--bg3);border-radius:var(--radius);border:1px solid var(--border);">
        <label class="toggle"><input type="checkbox" id="sp-enabled" ${enabled!==false?'checked':''}><span class="toggle-slider"></span></label>
        <span style="font-weight:500">Actif</span>
      </label>
    </div>`;
}

window._addStreamBackend = function() {
  const list = document.getElementById('sp-backends-list');
  if (!list) return;
  const row = document.createElement('div');
  row.className = 'sp-backend-row';
  row.style.cssText = 'display:flex;gap:6px;align-items:center;margin-bottom:6px';
  row.innerHTML = '<input class="input sp-backend-url" style="flex:1" placeholder="10.0.0.5:6379"><button type="button" class="btn-icon" title="Supprimer" onclick="this.closest(\'.sp-backend-row\').remove();if(!document.querySelectorAll(\'.sp-backend-row\').length)_addStreamBackend()">×</button>';
  list.appendChild(row);
  row.querySelector('input')?.focus();
};

window.openStreamProxyModal = function() {
  const bodyHtml = _buildStreamModalHtml({}, true, false);
  const footerHtml = `
    <button class="btn btn-secondary" onclick="closeModal()">Annuler</button>
    <button class="btn btn-primary" onclick="saveStreamProxy()">Créer le flux</button>`;
  modal('Nouveau flux TCP/UDP', bodyHtml, footerHtml);
  setTimeout(() => document.getElementById('sp-name')?.focus(), 50);
};

window.openStreamEditModal = async function(id) {
  let existing;
  try { existing = await api('GET', `/proxies/${encodeURIComponent(id)}`); } catch(e) { toast(e.message,'error'); return; }
  const cfg = typeof existing.config === 'string' ? tryJSON2(existing.config) : (existing.config || {});
  const bodyHtml = _buildStreamModalHtml(cfg, existing.enabled !== false, true);
  const footerHtml = `
    <button class="btn btn-sm" style="background:var(--red);color:#fff;border:none;border-radius:var(--radius);padding:0 12px;height:30px;font-size:12px;cursor:pointer;margin-right:auto"
      onclick="confirm_('Supprimer ce flux ?',async()=>{try{await api('DELETE','/proxies/${esc(id)}');closeModal();toast('Flux supprimé','success');refreshProxies();}catch(e){toast(e.message,'error');}})">Supprimer</button>
    <button class="btn btn-secondary" onclick="closeModal()">Annuler</button>
    <button class="btn btn-primary" onclick="saveStreamEdit('${esc(id)}')">Enregistrer</button>`;
  modal('Modifier le flux', bodyHtml, footerHtml);
  setTimeout(() => document.getElementById('sp-name')?.focus(), 50);
};

function _collectStreamForm() {
  const name   = (document.getElementById('sp-name')?.value || '').trim();
  const port   = parseInt(document.getElementById('sp-port')?.value || '0');
  const proto  = document.querySelector('input[name="sp-proto"]:checked')?.value || 'tcp';
  const enabled = document.getElementById('sp-enabled')?.checked !== false;
  const backends = [...document.querySelectorAll('.sp-backend-url')]
    .map(i => i.value.trim()).filter(Boolean).map(url => ({ url }));
  return { name, port, proto, enabled, backends };
}

window.saveStreamProxy = async function() {
  const { name, port, proto, enabled, backends } = _collectStreamForm();
  if (!port || port < 1 || port > 65535) { toast("Port d'écoute invalide", 'error'); return; }
  if (!backends.length) { toast('Au moins un backend requis', 'error'); return; }
  const protos = proto === 'both' ? ['tcp', 'udp'] : [proto];
  try {
    for (const p of protos) {
      const config = { type: p, host: name || (p + '_' + port), listen_port: port, backends };
      await api('POST', '/proxies', { config, enabled });
    }
    toast(protos.length > 1 ? `${protos.length} flux créés` : 'Flux créé', 'success');
    closeModal();
    await refreshProxies();
  } catch(e) { toast(e.message || 'Erreur', 'error'); }
};

window.saveStreamEdit = async function(id) {
  const { name, port, proto, enabled, backends } = _collectStreamForm();
  if (!port || port < 1 || port > 65535) { toast("Port d'écoute invalide", 'error'); return; }
  if (!backends.length) { toast('Au moins un backend requis', 'error'); return; }
  const config = { type: proto, host: name || (proto + '_' + port), listen_port: port, backends };
  try {
    await api('PUT', `/proxies/${encodeURIComponent(id)}`, { config, enabled });
    toast('Flux mis à jour', 'success');
    closeModal();
    refreshProxies();
  } catch(e) { toast(e.message || 'Erreur', 'error'); }
};
