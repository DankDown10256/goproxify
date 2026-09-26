// ── PAGE: Enregistrements Access (rejeu des sessions)
// Émulateur volontairement simple : texte, retours chariot, effacement, déplacement du curseur.
// Les applications plein écran (vim, top) s'affichent de façon approximative.
function gpxCastTerm() {
  const rows = [''];
  let r = 0, c = 0;
  const grow = () => { while (rows.length <= r) rows.push(''); };
  const put = (ch) => {
    grow();
    const line = rows[r].padEnd(c, ' ');
    rows[r] = line.slice(0, c) + ch + line.slice(c + 1);
    c++;
  };
  const feed = (s) => {
    for (let i = 0; i < s.length; i++) {
      const ch = s[i];
      if (ch === '\x1b') {
        const n = s[i + 1];
        if (n === '[') {
          let j = i + 2;
          while (j < s.length && !/[@-~]/.test(s[j])) j++;
          const params = s.slice(i + 2, j).replace(/[?>=]/g, '').split(';').map(x => parseInt(x, 10));
          const p0 = Number.isFinite(params[0]) ? params[0] : 0;
          const one = Math.max(1, p0);
          grow();
          switch (s[j]) {
            case 'J':
              if (p0 === 2 || p0 === 3) { rows.length = 0; rows.push(''); r = 0; c = 0; }
              else if (p0 === 0) { rows.length = r + 1; rows[r] = rows[r].slice(0, c); }
              break;
            case 'K':
              rows[r] = p0 === 2 ? '' : p0 === 1 ? ' '.repeat(c) + rows[r].slice(c) : rows[r].slice(0, c);
              break;
            case 'H': case 'f':
              r = Math.max(0, (Number.isFinite(params[0]) ? params[0] : 1) - 1);
              c = Math.max(0, (Number.isFinite(params[1]) ? params[1] : 1) - 1);
              grow();
              break;
            case 'A': r = Math.max(0, r - one); break;
            case 'B': r += one; grow(); break;
            case 'C': c += one; break;
            case 'D': c = Math.max(0, c - one); break;
            case 'G': c = one - 1; break;
            case 'P': rows[r] = rows[r].slice(0, c) + rows[r].slice(c + one); break;
            default: break;
          }
          i = j;
        } else if (n === ']') {
          let j = i + 2;
          while (j < s.length && s[j] !== '\x07' && !(s[j] === '\x1b' && s[j + 1] === '\\')) j++;
          i = s[j] === '\x1b' ? j + 1 : j;
        } else {
          i += 1;
        }
      } else if (ch === '\r') {
        c = 0;
      } else if (ch === '\n') {
        r++; grow();
      } else if (ch === '\b') {
        c = Math.max(0, c - 1);
      } else if (ch === '\t') {
        c = (Math.floor(c / 8) + 1) * 8;
      } else if (ch >= ' ') {
        put(ch);
      }
    }
    if (rows.length > 2000) { rows.splice(0, rows.length - 2000); r = Math.min(r, rows.length - 1); }
  };
  return { feed, text: () => rows.join('\n') };
}

pages['portal-recordings'] = async function() {
  const edgeName = state.selectedEdge?.node_name || '';
  const content = document.getElementById('content');
  document.getElementById('topbar-actions').innerHTML = `<button class="btn btn-secondary" id="prec-refresh">${esc(t('common.refresh') || 'Actualiser')}</button>`;
  if (!edgeName) {
    content.innerHTML = `<div class="empty"><p style="font-size:15px;font-weight:600">${esc(t('portal.need_edge') || 'Sélectionnez une passerelle')}</p></div>`;
    return;
  }
  const q = '?edge=' + encodeURIComponent(edgeName);
  content.innerHTML = `
    <div class="card blueprint" style="padding:16px 18px">
      <div style="font-family:var(--font-heading);font-size:18px;font-weight:700;margin-bottom:4px">Enregistrements de sessions</div>
      <p class="muted" style="font-size:12px;margin:0 0 12px">Ce que l'utilisateur voit dans son terminal (jamais ce qu'il tape), chiffré sur la passerelle. Activez l'enregistrement dans l'onglet Politiques. Chaque lecture est journalisée.</p>
      <div id="prec-list" class="muted" style="font-size:12px">…</div>
    </div>`;

  const dur = (s) => s < 60 ? Math.round(s) + ' s' : Math.floor(s / 60) + ' min ' + Math.round(s % 60) + ' s';
  const size = (b) => b < 1024 ? b + ' o' : b < 1048576 ? Math.round(b / 1024) + ' Kio' : (b / 1048576).toFixed(1) + ' Mio';

  const play = async (m) => {
    const res = await fetch('/api/v1/portal/recordings/' + encodeURIComponent(m.id) + q, {
      headers: { 'Authorization': 'Bearer ' + state.token },
    });
    if (!res.ok) { toast((await res.text().catch(() => '')) || 'Lecture impossible', 'error'); return; }
    const lines = (await res.text()).split('\n').filter(Boolean);
    const events = [];
    let last = 0, adj = 0;
    for (const ln of lines.slice(1)) {
      try {
        const [tt, kind, data] = JSON.parse(ln);
        if (kind !== 'o') continue;
        adj += Math.min(Math.max(0, tt - last), 2);
        last = tt;
        events.push({ t: adj, d: data });
      } catch (_) { /* ligne illisible ignorée */ }
    }
    const total = events.length ? events[events.length - 1].t : 0;
    modal(esc(m.actor) + ' → ' + esc(m.target_id),
      `<pre id="prec-screen" style="background:#0b0d12;color:#d8dce8;font:12px/1.35 var(--font-mono, monospace);padding:12px;border-radius:6px;height:380px;overflow:auto;margin:0;white-space:pre"></pre>
       <div style="display:flex;gap:10px;align-items:center;margin-top:10px;flex-wrap:wrap">
         <button class="btn btn-secondary btn-sm" id="prec-play">Pause</button>
         <input type="range" id="prec-seek" min="0" max="${Math.max(1, Math.round(total * 100))}" value="0" style="flex:1;min-width:140px"/>
         <select class="input" id="prec-speed" style="width:auto"><option value="1">×1</option><option value="2">×2</option><option value="4">×4</option><option value="16">×16</option></select>
         <span class="muted" id="prec-time" style="font-size:11px;min-width:90px;text-align:right"></span>
       </div>
       <p class="muted" style="font-size:11px;margin:8px 0 0">Rejeu simplifié : les pauses longues sont raccourcies et les applications plein écran (vim, top) s'affichent de façon approximative.${m.truncated ? ' Enregistrement tronqué (limite de taille).' : ''}</p>`,
      '', true);

    const screen = document.getElementById('prec-screen');
    const seek = document.getElementById('prec-seek');
    const btn = document.getElementById('prec-play');
    const timeEl = document.getElementById('prec-time');
    let term = gpxCastTerm(), idx = 0, clock = 0, playing = true, prev = performance.now();
    const paint = () => {
      const stick = screen.scrollTop + screen.clientHeight >= screen.scrollHeight - 20;
      screen.textContent = term.text();
      if (stick) screen.scrollTop = screen.scrollHeight;
      seek.value = Math.round(clock * 100);
      timeEl.textContent = dur(clock) + ' / ' + dur(total);
    };
    const advance = (to) => {
      while (idx < events.length && events[idx].t <= to) term.feed(events[idx++].d);
      clock = to;
    };
    seek.oninput = () => {
      term = gpxCastTerm(); idx = 0;
      advance(seek.value / 100);
      paint();
    };
    btn.onclick = () => {
      if (!playing && clock >= total) { term = gpxCastTerm(); idx = 0; clock = 0; }
      playing = !playing; prev = performance.now();
      btn.textContent = playing ? 'Pause' : 'Lecture';
    };
    const tick = (now) => {
      if (!document.getElementById('prec-screen')) return;
      if (playing) {
        const sp = +document.getElementById('prec-speed').value || 1;
        advance(Math.min(total, clock + ((now - prev) / 1000) * sp));
        paint();
        if (clock >= total) { playing = false; btn.textContent = 'Rejouer'; }
      }
      prev = now;
      requestAnimationFrame(tick);
    };
    paint();
    requestAnimationFrame(tick);
  };

  const load = async () => {
    const box = document.getElementById('prec-list');
    if (!box) return;
    try {
      const d = await api('GET', '/portal/recordings' + q) || {};
      const list = d.recordings || [];
      if (!list.length) { box.textContent = 'Aucun enregistrement.'; return; }
      box.innerHTML = '<table class="table" style="width:100%;font-size:12px"><thead><tr>' +
        '<th>Date</th><th>Utilisateur</th><th>Destination</th><th>Façade</th><th>Durée</th><th>Taille</th><th></th></tr></thead><tbody>' +
        list.map(m => '<tr>' +
          '<td>' + esc(new Date(m.started).toLocaleString()) + '</td>' +
          '<td>' + esc(m.actor) + '</td>' +
          '<td><code>' + esc(m.target_id) + '</code></td>' +
          '<td>' + esc(m.facade) + '</td>' +
          '<td>' + esc(dur(m.duration_sec)) + '</td>' +
          '<td>' + esc(size(m.bytes)) + '</td>' +
          '<td style="white-space:nowrap"><button class="btn btn-secondary btn-sm" data-play="' + esc(m.id) + '">Rejouer</button> ' +
          '<button class="btn btn-secondary btn-sm" data-del="' + esc(m.id) + '">Supprimer</button></td></tr>').join('') +
        '</tbody></table>';
      box.querySelectorAll('[data-play]').forEach(b => { b.onclick = () => play(list.find(x => x.id === b.dataset.play)); });
      box.querySelectorAll('[data-del]').forEach(b => {
        b.onclick = async () => {
          if (!confirm('Supprimer définitivement cet enregistrement ?')) return;
          try {
            await api('DELETE', '/portal/recordings/' + encodeURIComponent(b.dataset.del) + q);
            toast('Enregistrement supprimé.', 'success');
            load();
          } catch (e) { toast(e.message || e, 'error'); }
        };
      });
    } catch (e) {
      box.textContent = e.message || String(e);
    }
  };
  document.getElementById('prec-refresh').onclick = load;
  await load();
};

// Observation en direct : suit la sortie d'une connexion en cours (jamais la saisie).
async function gpxWatchSession(edgeName, s) {
  const ctl = new AbortController();
  modal(esc(s.actor) + ' → ' + esc(s.target_id) + ' <span class="muted" style="font-size:11px">en direct</span>',
    `<pre id="pwatch-screen" style="background:#0b0d12;color:#d8dce8;font:12px/1.35 var(--font-mono, monospace);padding:12px;border-radius:6px;height:380px;overflow:auto;margin:0;white-space:pre"></pre>
     <p class="muted" id="pwatch-state" style="font-size:11px;margin:8px 0 0">Connexion…</p>
     <p class="muted" style="font-size:11px;margin:4px 0 0">Vous voyez ce que l'utilisateur voit, pas ce qu'il tape. Cette observation est journalisée.</p>`,
    '', true);
  const screen = document.getElementById('pwatch-screen');
  const state_ = document.getElementById('pwatch-state');
  const term = gpxCastTerm();
  const dec = new TextDecoder();
  const stop = setInterval(() => { if (!document.getElementById('pwatch-screen')) { ctl.abort(); clearInterval(stop); } }, 500);
  try {
    const res = await fetch('/api/v1/portal/sessions/' + encodeURIComponent(s.id) + '/watch?edge=' + encodeURIComponent(edgeName), {
      headers: { 'Authorization': 'Bearer ' + state.token },
      signal: ctl.signal,
    });
    if (!res.ok) { state_.textContent = 'Session introuvable ou déjà terminée.'; clearInterval(stop); return; }
    state_.textContent = 'Observation en cours.';
    const reader = res.body.getReader();
    let buf = '';
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += new TextDecoder().decode(value, { stream: true });
      let i;
      while ((i = buf.indexOf('\n\n')) >= 0) {
        const block = buf.slice(0, i);
        buf = buf.slice(i + 2);
        if (block.startsWith('event: end')) { state_.textContent = 'La session est terminée.'; continue; }
        if (!block.startsWith('data: ')) continue;
        const bin = atob(block.slice(6).trim());
        const bytes = Uint8Array.from(bin, ch => ch.charCodeAt(0));
        term.feed(dec.decode(bytes, { stream: true }));
        const stick = screen.scrollTop + screen.clientHeight >= screen.scrollHeight - 20;
        screen.textContent = term.text();
        if (stick) screen.scrollTop = screen.scrollHeight;
      }
    }
    if (state_.textContent === 'Observation en cours.') state_.textContent = 'La session est terminée.';
  } catch (e) {
    if (e.name !== 'AbortError') state_.textContent = e.message || String(e);
  } finally {
    clearInterval(stop);
  }
}
