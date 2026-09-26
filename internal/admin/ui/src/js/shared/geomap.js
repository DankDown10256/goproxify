// ── Carte du monde Leaflet partagée (Prism, Sécurité) ────────────────────────
// Fond = contours de pays embarqués (vendor/world/countries.geojson) : aucune tuile
// ni requête vers un tiers. Trois couches : pays (choroplèthe), villes (bulles) et
// pulsations live. Leaflet est chargé à la demande, à la première carte affichée.

const GEO_PALETTES = {
  requests:   [89, 128, 166],
  error_rate: [220, 53, 69],
  banned_ips: [217, 119, 6],
  errors:     [220, 53, 69],
};
const GEO_LABELS = { requests: 'Requêtes', error_rate: 'Taux d\'erreur (%)', banned_ips: 'IPs bannies', errors: 'Erreurs' };
const GEO_LIVE_COLORS = { banned: '#ef4444', error: '#f59e0b', visit: '#3b82f6' };

const gmNum = n => n == null ? '0' : n >= 1e6 ? (n / 1e6).toFixed(1) + 'M' : n >= 1e3 ? (n / 1e3).toFixed(1) + 'k' : String(n);

let _gpxGeoLoading = null;

function gpxGeoLoad() {
  if (_gpxGeoLoading) return _gpxGeoLoading;
  _gpxGeoLoading = (async () => {
    if (!window.L) {
      const css = document.createElement('link');
      css.rel = 'stylesheet';
      css.href = '/lib/leaflet/leaflet.css';
      document.head.appendChild(css);
      await new Promise((ok, ko) => {
        const s = document.createElement('script');
        s.src = '/lib/leaflet/leaflet.js';
        s.onload = ok;
        s.onerror = () => ko(new Error('leaflet'));
        document.head.appendChild(s);
      });
    }
    const countries = await (await fetch('/lib/world/countries.geojson')).json();
    return { L: window.L, countries };
  })().catch(e => { _gpxGeoLoading = null; throw e; });
  return _gpxGeoLoading;
}

function _geoValue(entry, mode) {
  if (mode === 'error_rate') return entry.error_rate || 0;
  if (mode === 'banned_ips') return entry.banned_ips || 0;
  if (mode === 'errors') return entry.errors || 0;
  return entry.requests || 0;
}

// Centre de la plus grande île/polygone d'un pays (le centre de la boîte englobante
// tomberait en plein océan pour les États-Unis ou la Russie, à cheval sur l'antiméridien).
function mainlandCenter(L, geom) {
  let best = null, bestArea = -1;
  for (const poly of geom.coordinates) {
    let x0 = 180, x1 = -180, y0 = 90, y1 = -90;
    for (const [x, y] of poly[0]) { x0 = Math.min(x0, x); x1 = Math.max(x1, x); y0 = Math.min(y0, y); y1 = Math.max(y1, y); }
    const area = (x1 - x0) * (y1 - y0);
    if (area > bestArea) { bestArea = area; best = L.latLng((y0 + y1) / 2, (x0 + x1) / 2); }
  }
  return best;
}

/**
 * Monte une carte dans `el`.
 * @param {HTMLElement} el
 * @param {{onCountry?:(cc:string)=>void, onPoint?:(pt:object)=>void}} opts
 * @returns {Promise<{update:Function, pulse:Function, resize:Function, destroy:Function}>}
 */
async function gpxGeoMap(el, opts = {}) {
  const { L, countries } = await gpxGeoLoad();
  el.innerHTML = '';
  const map = L.map(el, {
    minZoom: 1, maxZoom: 8, zoomSnap: 0.5, worldCopyJump: false,
    maxBounds: [[-85, -190], [85, 190]], maxBoundsViscosity: 0.8, attributionControl: false,
  });
  L.control.attribution({ prefix: false }).addAttribution('Natural Earth · Leaflet').addTo(map);
  map.fitBounds([[-58, -170], [80, 170]]);

  let state = { countries: [], points: [], mode: 'requests', style: 'zones', selected: '' };
  let byCC = {};
  let max = 0;
  const colorOf = () => GEO_PALETTES[state.mode] || GEO_PALETTES.requests;

  const centroids = {};
  const countryLayer = L.geoJSON(countries, {
    style: () => ({ fillColor: 'var(--bg2)', fillOpacity: 1, color: 'var(--border)', weight: 0.6 }),
    onEachFeature: (f, layer) => {
      const cc = f.properties.iso;
      centroids[cc] = mainlandCenter(L, f.geometry);
      layer.on({
        click: () => { if (byCC[cc] && opts.onCountry) opts.onCountry(cc); },
        mouseover: () => { if (byCC[cc]) layer.setStyle({ color: 'var(--accent)', weight: 1.4 }); },
        mouseout: () => restyle(),
      });
      layer.bindTooltip(() => {
        const e = byCC[cc];
        if (!e) return esc(f.properties.name);
        return `<b>${esc(e.country_name || f.properties.name)}</b> <span style="opacity:.6">${esc(cc)}</span><br>` +
          `${gmNum(e.requests)} req · <b>${(e.pct || 0).toFixed(1)}%</b><br>` +
          `<span style="opacity:.7">Tx err. ${(e.error_rate || 0).toFixed(1)}% · Bans ${e.banned_ips || 0}</span>`;
      }, { sticky: true, className: 'gm-tip' });
    },
  }).addTo(map);

  const pointLayer = L.layerGroup().addTo(map);
  const liveLayer = L.layerGroup().addTo(map);

  const legend = L.control({ position: 'bottomleft' });
  legend.onAdd = () => {
    const d = L.DomUtil.create('div', 'prism-legend gm-legend');
    d.innerHTML = '<div class="lg-title"></div><div class="lg-grad"></div><div class="lg-scale"><span>0</span><span class="lg-max"></span></div>';
    return d;
  };
  legend.addTo(map);

  const hint = L.control({ position: 'topright' });
  hint.onAdd = () => {
    const d = L.DomUtil.create('div', 'gm-hint');
    d.textContent = 'Localisation des villes en cours…';
    d.style.display = 'none';
    return d;
  };
  hint.addTo(map);

  function restyle() {
    const [r, g, b] = colorOf();
    countryLayer.eachLayer(layer => {
      const cc = layer.feature.properties.iso, e = byCC[cc];
      let fill = 'var(--bg2)';
      if (e && state.style === 'zones' && max > 0) {
        const v = _geoValue(e, state.mode);
        fill = `rgba(${r},${g},${b},${v > 0 ? (0.12 + Math.pow(v / max, 0.55) * 0.83).toFixed(2) : '0.06'})`;
      }
      const sel = cc === state.selected;
      layer.setStyle({
        fillColor: fill, fillOpacity: 1,
        color: sel ? 'var(--text)' : e ? 'var(--bg)' : 'var(--border)',
        weight: sel ? 1.8 : e ? 0.6 : 0.4,
      });
      if (sel) layer.bringToFront();
    });
    const lg = legend.getContainer();
    if (lg) {
      lg.querySelector('.lg-title').textContent = GEO_LABELS[state.mode];
      lg.querySelector('.lg-grad').style.background = `linear-gradient(90deg,rgba(${r},${g},${b},.1),rgba(${r},${g},${b},1))`;
      lg.querySelector('.lg-max').textContent = state.mode === 'error_rate' ? max.toFixed(1) + '%' : gmNum(Math.round(max));
      lg.style.display = max > 0 ? '' : 'none';
    }
  }

  function drawPoints() {
    pointLayer.clearLayers();
    if (state.style !== 'cities') return;
    const [r, g, b] = colorOf();
    const val = p => _geoValue(p, state.mode);
    const pts = state.points.filter(p => val(p) > 0);
    const pmax = Math.max(...pts.map(val), 0);
    for (const p of pts) {
      const m = L.circleMarker([p.lat, p.lon], {
        radius: 4 + Math.sqrt(val(p) / pmax) * 16,
        color: `rgb(${r},${g},${b})`, weight: 1, fillColor: `rgb(${r},${g},${b})`, fillOpacity: 0.4,
      }).addTo(pointLayer);
      const place = [p.city, p.region].filter(Boolean).join(', ');
      m.bindTooltip(`<b>${esc(place || p.country_name)}</b> <span style="opacity:.6">${esc(p.country_code)}</span><br>` +
        `${gmNum(p.requests)} req · ${gmNum(p.ips)} IP<br>` +
        `<span style="opacity:.7">Tx err. ${(p.error_rate || 0).toFixed(1)}% · Bans ${p.banned_ips || 0}</span>`,
        { className: 'gm-tip' });
      m.on('click', () => { if (opts.onPoint) opts.onPoint(p); });
    }
  }

  const ro = typeof ResizeObserver === 'function' ? new ResizeObserver(() => map.invalidateSize()) : null;
  if (ro) ro.observe(el);

  return {
    /** @param {{countries?:object[], points?:object[], mode?:string, style?:'zones'|'cities', selected?:string}} next */
    update(next) {
      state = { ...state, ...next };
      byCC = {};
      max = 0;
      for (const e of state.countries) {
        byCC[e.country_code] = e;
        max = Math.max(max, _geoValue(e, state.mode));
      }
      restyle();
      drawPoints();
      hint.getContainer().style.display = state.style === 'cities' && !state.points.length ? '' : 'none';
    },
    /** Pulsation à la position (ville) de chaque événement, à défaut au centre du pays. */
    pulse(events) {
      const seen = new Set();
      for (const ev of events) {
        const hasPos = ev.lat || ev.lon;
        const key = hasPos ? ev.lat.toFixed(1) + ',' + ev.lon.toFixed(1) : ev.country_code;
        if (seen.has(key)) continue;
        seen.add(key);
        const at = hasPos ? [ev.lat, ev.lon] : centroids[ev.country_code];
        if (!at) continue;
        const color = GEO_LIVE_COLORS[ev.kind] || GEO_LIVE_COLORS.visit;
        const m = L.marker(at, {
          interactive: false, keyboard: false,
          icon: L.divIcon({ className: 'gm-pulse-wrap', html: `<span class="gm-pulse" style="--c:${color}"></span>`, iconSize: [0, 0] }),
        }).addTo(liveLayer);
        setTimeout(() => liveLayer.removeLayer(m), 6000);
      }
    },
    clearLive() { liveLayer.clearLayers(); },
    resize() { map.invalidateSize(); },
    destroy() { if (ro) ro.disconnect(); map.remove(); },
  };
}
