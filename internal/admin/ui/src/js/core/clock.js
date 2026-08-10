// ── Horloge topbar (fuseau serveur via /health) ────────────────────────────

let _clockTimer = null;
let _tzFetched = false;

async function ensureServerTimezone() {
  if (_tzFetched && state.timezone) return state.timezone;
  try {
    const h = await api('GET', '/health');
    if (h?.timezone) {
      state.timezone = h.timezone;
      localStorage.setItem('gpx_tz', h.timezone);
    }
  } catch { /* ignore — fallback navigateur */ }
  _tzFetched = true;
  return state.timezone;
}

function tickTopbarClock() {
  const timeEl = document.getElementById('topbar-clock-time');
  const tzEl = document.getElementById('topbar-clock-tz');
  if (!timeEl) return;
  const opts = { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false };
  if (state.timezone) opts.timeZone = state.timezone;
  try {
    timeEl.textContent = new Date().toLocaleTimeString(typeof gpxBCP47 === 'function' ? gpxBCP47() : 'en-US', opts);
  } catch {
    timeEl.textContent = new Date().toLocaleTimeString(typeof gpxBCP47 === 'function' ? gpxBCP47() : 'en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  }
  if (tzEl) {
    const label = state.timezone || Intl.DateTimeFormat().resolvedOptions().timeZone || '';
    tzEl.textContent = label;
    const clock = document.getElementById('topbar-clock');
    if (clock) clock.title = (typeof t === 'function' ? t('common.server_time') : 'Server time') + ' — ' + (label || 'local');
  }
}

async function startTopbarClock() {
  await ensureServerTimezone();
  tickTopbarClock();
  if (_clockTimer) clearInterval(_clockTimer);
  _clockTimer = setInterval(tickTopbarClock, 1000);
}
