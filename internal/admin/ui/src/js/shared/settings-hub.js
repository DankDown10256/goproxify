// ── Hub Paramètres partagé (Admin + Core) ─────────────────────────────────
// sections: [{ label, desc, items: [{ page, icon, label, desc }] }]
// headerHtml / footerHtml : HTML optionnel au-dessus / en-dessous des sections.

function renderSettingsHub({ contentEl, sections, headerHtml, footerHtml }) {
  const el = contentEl || document.getElementById('content');
  if (!el) return;

  const settingCard = (it) => `
    <div onclick="navigate('${it.page}')" style="background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:14px 16px;cursor:pointer;transition:border-color .15s" onmouseover="this.style.borderColor='var(--accent)'" onmouseout="this.style.borderColor='var(--border)'">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
        <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0;color:var(--accent)">${it.icon}</svg>
        <span style="font-weight:600;font-size:13px">${esc(it.label)}</span>
      </div>
      <div style="font-size:12px;color:var(--text2);line-height:1.4">${esc(it.desc)}</div>
    </div>`;

  const sectionsHtml = (sections || []).map(s => `
    <div style="margin-bottom:28px">
      <div style="margin-bottom:12px">
        <div style="font-size:13px;font-weight:600;color:var(--text);margin-bottom:2px">${esc(s.label)}</div>
        <div style="font-size:12px;color:var(--text2)">${esc(s.desc)}</div>
      </div>
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(min(220px,100%),1fr));gap:10px">
        ${(s.items || []).map(settingCard).join('')}
      </div>
    </div>`).join('');

  el.innerHTML = (headerHtml || '') + sectionsHtml + (footerHtml || '');
}
