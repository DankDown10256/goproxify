// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Mode expert : masque les réglages rarement utilisés pour alléger l'interface. Une préférence par navigateur,
// partagée par toute l'interface : la classe `is-expert` du <body> en est la seule source côté CSS, et
// l'évènement `gpx:expert` prévient les vues qui rendent leur liste en JS (modale de proxy).
// Un réglage masqué mais déjà configuré reste visible : c'est à l'appelant de le garantir, le CSS ne le sait pas.
const Expert = (() => {
  const KEY = 'gpx_expert';
  let on = false;
  try { on = localStorage.getItem(KEY) === '1'; } catch {}
  const apply = () => document.body?.classList.toggle('is-expert', on);
  if (document.body) apply(); else document.addEventListener('DOMContentLoaded', apply);

  function set(v) {
    v = !!v;
    if (v === on) return;
    on = v;
    try { localStorage.setItem(KEY, v ? '1' : '0'); } catch {}
    apply();
    document.dispatchEvent(new CustomEvent('gpx:expert', { detail: v }));
  }

  document.addEventListener('change', e => {
    if (e.target.matches?.('[data-expert-switch]')) set(e.target.checked);
  });
  document.addEventListener('gpx:expert', e => {
    document.querySelectorAll('[data-expert-switch]').forEach(i => { i.checked = e.detail; });
  });

  return {
    get on() { return on; },
    set,
    switchHtml: () => `<label class="expert-switch" title="Affiche aussi les réglages rarement utilisés"><label class="toggle"><input type="checkbox" data-expert-switch ${on ? 'checked' : ''}><span class="toggle-slider"></span></label><span>Expert</span></label>`,
  };
})();
window.Expert = Expert;
