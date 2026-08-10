// ── Thème clair / sombre ───────────────────────────────────────────────────
function updateThemeLabel() {
  const dark = document.documentElement.dataset.theme !== 'light';
  const lbl = document.getElementById('theme-label');
  if (lbl) lbl.textContent = dark ? 'Thème clair' : 'Thème sombre';
  const icon = document.getElementById('theme-icon');
  if (icon) {
    icon.innerHTML = dark
      ? '<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>'
      : '<circle cx="7.5" cy="7.5" r="3.5"/><path d="M7.5 1v1.5M7.5 12v1.5M1 7.5h1.5M12 7.5h1.5M3.2 3.2l1.1 1.1M10.2 10.2l1.1 1.1M3.2 11.8l1.1-1.1M10.2 4.8l1.1-1.1"/>';
  }
}

function _getThemeMode() {
  return localStorage.getItem('gpx_theme') || 'auto';
}

function _applyThemeMode(mode) {
  if (mode === 'auto') {
    document.documentElement.dataset.theme =
      window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  } else {
    document.documentElement.dataset.theme = mode;
  }
  updateThemeIcon();
}

function updateThemeIcon() {
  const icon = document.getElementById('theme-icon');
  if (!icon) return;
  const mode = _getThemeMode();
  if (mode === 'dark') {
    icon.innerHTML = '<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>';
  } else if (mode === 'light') {
    icon.innerHTML = '<circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>';
  } else {
    icon.innerHTML = '<rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>';
  }
}

function setTheme(mode) {
  localStorage.setItem('gpx_theme', mode);
  _applyThemeMode(mode);
  document.getElementById('theme-picker-panel')?.remove();
}

function closeAllPickers(except) {
  if (except !== 'theme') document.getElementById('theme-picker-panel')?.remove();
  if (except !== 'color') document.getElementById('color-picker-panel')?.remove();
  if (except !== 'lang')  document.getElementById('lang-picker-panel')?.remove();
}

function _showPicker(panel, btnId) {
  const btn = document.getElementById(btnId);
  document.body.appendChild(panel);
  const r = btn.getBoundingClientRect();
  panel.style.left = r.left + 'px';
  panel.style.bottom = (window.innerHeight - r.top + 6) + 'px';
  requestAnimationFrame(() => {
    const pr = panel.getBoundingClientRect();
    const vw = window.innerWidth;
    if (pr.right > vw - 8) { panel.style.left = 'auto'; panel.style.right = (vw - r.right) + 'px'; }
    if (pr.left < 8) { panel.style.left = '8px'; panel.style.right = 'auto'; }
  });
  setTimeout(() => document.addEventListener('click', function _c(e) {
    if (!panel.contains(e.target) && !e.target.closest('#' + btnId)) {
      panel.remove(); document.removeEventListener('click', _c);
    }
  }), 0);
}

function toggleThemePicker() {
  if (document.getElementById('theme-picker-panel')) { closeAllPickers(); return; }
  closeAllPickers('theme');
  const mode = _getThemeMode();
  const panel = document.createElement('div');
  panel.id = 'theme-picker-panel';
  panel.className = 'footer-picker-panel';
  panel.innerHTML = `
    <button class="footer-picker-opt${mode==='light'?' active':''}" onclick="setTheme('light')">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
      Clair
    </button>
    <button class="footer-picker-opt${mode==='dark'?' active':''}" onclick="setTheme('dark')">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>
      Sombre
    </button>
    <button class="footer-picker-opt${mode==='auto'?' active':''}" onclick="setTheme('auto')">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
      Auto
    </button>`;
  _showPicker(panel, 'theme-picker-btn');
}

// Applique le thème sauvegardé au plus tôt (avant rendu)
(function() {
  document.documentElement.dataset.theme = localStorage.getItem('gpx_theme') || 'light';
})();

// ── Skin ───────────────────────────────────────────────────────────────────
function _getSkinList() {
  return APP_CONFIG.skins || [];
}

function _getActiveSkinId() {
  return localStorage.getItem('gpx_skin') || APP_CONFIG.skin || (_getSkinList()[0] || {}).id || 'flat';
}

function applySkin(id) {
  document.querySelectorAll('link[data-skin]').forEach(el => {
    el.media = el.dataset.skin === id ? '' : 'not all';
  });
  localStorage.setItem('gpx_skin', id);

  document.querySelectorAll('.skin-option').forEach(el =>
    el.classList.toggle('active', el.dataset.skinId === id)
  );

  const skin = _getSkinList().find(s => s.id === id);
  if (skin) {
    const savedAccent = parseInt(localStorage.getItem('gpx_accent_' + id) || '0');
    _renderPaletteSwatches(skin.accents, id);
    _applyAccent(skin.accents, savedAccent, id);
  }
}

function initSkin() {
  applySkin(_getActiveSkinId());
}

// ── Palette d'accent ───────────────────────────────────────────────────────
function _applyAccent(accents, idx, skinId) {
  const a = accents[idx];
  if (!a) return;
  document.documentElement.style.setProperty('--accent', a.color);
  document.documentElement.style.setProperty('--accent-hover', a.hover);
  document.documentElement.style.setProperty('--color-accent', a.color);
  if (skinId) localStorage.setItem('gpx_accent_' + skinId, idx);
  document.querySelectorAll('.palette-swatch').forEach((el, i) =>
    el.classList.toggle('active', i === idx)
  );
}

function applyAccent(idx) {
  const skinId = _getActiveSkinId();
  const skin = _getSkinList().find(s => s.id === skinId);
  const accents = skin ? skin.accents : (APP_CONFIG.accents || []);
  _applyAccent(accents, idx, skinId);
}

function _renderPaletteSwatches(accents, skinId) {
  const container = document.getElementById('palette-swatches');
  if (!container) return;
  const saved = parseInt(localStorage.getItem('gpx_accent_' + skinId) || '0');
  container.innerHTML = accents.map((a, i) =>
    `<button class="palette-swatch${i === saved ? ' active' : ''}" title="${esc(a.name)}"
      style="background:${a.color}" onclick="applyAccent(${i})"></button>`
  ).join('');
}

function initPalette() {
  const skinId = _getActiveSkinId();
  const skin = _getSkinList().find(s => s.id === skinId);
  const accents = skin ? skin.accents : (APP_CONFIG.accents || []);
  const saved = parseInt(localStorage.getItem('gpx_accent_' + skinId) || '0');
  _renderPaletteSwatches(accents, skinId);
  _applyAccent(accents, saved, skinId);
}

// ── Skin picker ────────────────────────────────────────────────────────────
function toggleSkinPicker() {
  let panel = document.getElementById('skin-picker-panel');
  if (panel) { panel.remove(); return; }

  panel = document.createElement('div');
  panel.id = 'skin-picker-panel';
  panel.className = 'skin-picker-panel';

  const skins = _getSkinList();
  const activeSkinId = _getActiveSkinId();
  panel.innerHTML = skins.map(s => `
    <button class="skin-option${s.id === activeSkinId ? ' active' : ''}"
      data-skin-id="${esc(s.id)}" onclick="applySkin('${esc(s.id)}')">
      <span class="skin-option-swatch" style="background:${(s.accents[0]||{}).color||'var(--accent)'}"></span>
      ${esc(s.label)}
    </button>
  `).join('');

  setTimeout(() => document.addEventListener('click', function _close(e) {
    if (!panel.contains(e.target) && !e.target.closest('#skin-picker-btn')) {
      panel.remove();
      document.removeEventListener('click', _close);
    }
  }), 0);

  const btn = document.getElementById('skin-picker-btn');
  if (btn) btn.after(panel);
  else document.body.appendChild(panel);
}

function _buildColorPickerContent(panel) {
  const skins = _getSkinList();
  const activeSkinId = _getActiveSkinId();
  const skin = skins.find(s => s.id === activeSkinId) || skins[0];
  const accents = skin ? skin.accents : [];
  const savedIdx = parseInt(localStorage.getItem('gpx_accent_' + activeSkinId) || '0');
  let html = '';
  if (skins.length > 1) {
    html += `<div class="fp-section-label">Style</div>`;
    html += skins.map(s => `
      <button class="footer-picker-opt${s.id === activeSkinId ? ' active' : ''}" data-skin-id="${esc(s.id)}"
        onclick="applySkin('${esc(s.id)}');_rebuildColorPicker()">
        <span style="width:12px;height:12px;border-radius:50%;background:${(s.accents[0]||{}).color||'var(--accent)'};flex:none;border:1.5px solid rgba(0,0,0,.15);"></span>
        ${esc(s.label)}
      </button>`).join('');
    if (accents.length) html += `<div style="height:1px;background:var(--border);margin:4px 2px;"></div>`;
  }
  if (accents.length) {
    html += `<div class="fp-section-label">Couleur d'accent</div>`;
    html += `<div style="display:flex;flex-wrap:wrap;gap:6px;padding:4px 10px 8px;">` +
      accents.map((a, i) =>
        `<button class="fp-accent-swatch${i === savedIdx ? ' active' : ''}" title="${esc(a.name)}"
          style="background:${a.color}" onclick="applyAccent(${i});_updateColorPickerAccents(${i})"></button>`
      ).join('') + `</div>`;
  }
  panel.innerHTML = html;
}
function _rebuildColorPicker() {
  const panel = document.getElementById('color-picker-panel');
  if (!panel) return;
  const { left, right, bottom } = panel.style;
  _buildColorPickerContent(panel);
  panel.style.left = left; panel.style.right = right; panel.style.bottom = bottom;
}
function _updateColorPickerAccents(idx) {
  document.querySelectorAll('#color-picker-panel .fp-accent-swatch').forEach((el, i) =>
    el.classList.toggle('active', i === idx));
}
function toggleColorPicker() {
  if (document.getElementById('color-picker-panel')) { closeAllPickers(); return; }
  closeAllPickers('color');
  const panel = document.createElement('div');
  panel.id = 'color-picker-panel';
  panel.className = 'footer-picker-panel';
  _buildColorPickerContent(panel);
  _showPicker(panel, 'color-picker-btn');
}

const LANGS = [
  { code: 'en', labelKey: 'lang.en' },
  { code: 'fr', labelKey: 'lang.fr' },
  { code: 'es', labelKey: 'lang.es' },
  { code: 'de', labelKey: 'lang.de' },
];
function _getLang() {
  return (typeof gpxResolveLocale === 'function') ? gpxResolveLocale() : (localStorage.getItem('gpx_locale') || localStorage.getItem('gpx_lang') || 'en');
}
function setLang(code) {
  if (typeof gpxSetLocale === 'function') gpxSetLocale(code);
  else {
    localStorage.setItem('gpx_locale', code);
    localStorage.setItem('gpx_lang', code);
  }
  document.getElementById('lang-picker-panel')?.remove();
  if (typeof gpxRefreshUILocale === 'function') gpxRefreshUILocale();
  else location.reload();
}
function toggleLangPicker() {
  if (document.getElementById('lang-picker-panel')) { closeAllPickers(); return; }
  closeAllPickers('lang');
  const lang = _getLang();
  const panel = document.createElement('div');
  panel.id = 'lang-picker-panel';
  panel.className = 'footer-picker-panel';
  panel.innerHTML = LANGS.map(l => `
    <button class="footer-picker-opt${l.code === lang ? ' active' : ''}" onclick="setLang('${l.code}')">
      ${typeof t === 'function' ? t(l.labelKey) : l.code}
    </button>`).join('');
  _showPicker(panel, 'lang-picker-btn');
}

