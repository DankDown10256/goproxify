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
const geoLabel = m => ({ requests: t('prism.requests'), error_rate: t('pz.err_rate_pct'), banned_ips: t('pz.banned_ips'), errors: t('prism.errors') }[m]);
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

let _gpxRegionsLoading = null;

// Contours des régions (Natural Earth admin-1, ~2 Mo) : chargés seulement quand le style « Régions » est choisi.
function gpxGeoRegions() {
  if (!_gpxRegionsLoading) {
    _gpxRegionsLoading = fetch('/lib/world/regions.geojson').then(r => r.json()).catch(e => { _gpxRegionsLoading = null; throw e; });
  }
  return _gpxRegionsLoading;
}

// Point (lon, lat) dans un anneau, par comptage des croisements.
function _ringHas(ring, x, y) {
  let c = false;
  for (let i = 0, j = ring.length - 1; i < ring.length; j = i++) {
    const a = ring[i], b = ring[j];
    if ((a[1] > y) !== (b[1] > y) && x < (b[0] - a[0]) * (y - a[1]) / (b[1] - a[1]) + a[0]) c = !c;
  }
  return c;
}

// Index des régions par pays, avec boîte englobante de chaque polygone.
function _regionIndex(fc) {
  const by = new Map();
  for (const f of fc.features) {
    const polys = f.geometry.coordinates.map(rings => {
      let x0 = 180, y0 = 90, x1 = -180, y1 = -90;
      for (const [x, y] of rings[0]) { x0 = Math.min(x0, x); x1 = Math.max(x1, x); y0 = Math.min(y0, y); y1 = Math.max(y1, y); }
      return { bbox: [x0, y0, x1, y1], rings };
    });
    if (!by.has(f.properties.iso)) by.set(f.properties.iso, []);
    by.get(f.properties.iso).push({ f, polys });
  }
  return by;
}

function _regionContaining(list, lon, lat) {
  for (const r of list) {
    for (const p of r.polys) {
      const b = p.bbox;
      if (lon < b[0] || lon > b[2] || lat < b[1] || lat > b[3]) continue;
      if (_ringHas(p.rings[0], lon, lat) && !p.rings.slice(1).some(h => _ringHas(h, lon, lat))) return r.f;
    }
  }
  return null;
}

// La région d'une position. Les contours simplifiés peuvent laisser une ville côtière en mer :
// à défaut, on retient la région du même pays dont un sommet est à moins de 1°.
function _findRegion(idx, iso, lon, lat) {
  const own = idx.get(iso) || [];
  const all = [].concat(...idx.values());
  const hit = _regionContaining(own, lon, lat) || _regionContaining(all, lon, lat);
  if (hit) return hit;
  let best = null, bd = 1;
  for (const r of own.length ? own : all) for (const p of r.polys) for (const [x, y] of p.rings[0]) {
    const d = (x - lon) ** 2 + (y - lat) ** 2;
    if (d < bd) { bd = d; best = r.f; }
  }
  return best;
}

// Agrège les villes par région (les villes sans position sont ignorées).
function _regionStats(idx, points) {
  const stats = new Map();
  for (const p of points) {
    if (!p.lat && !p.lon) continue;
    const f = _findRegion(idx, p.country_code, p.lon, p.lat);
    if (!f) continue;
    const k = f.properties.code || f.properties.iso + ':' + f.properties.name;
    let s = stats.get(k);
    if (!s) { s = { code: k, name: f.properties.name, iso: f.properties.iso, requests: 0, errors: 0, banned_ips: 0, ips: 0 }; stats.set(k, s); }
    s.requests += p.requests; s.errors += p.errors; s.banned_ips += p.banned_ips; s.ips += p.ips;
  }
  for (const s of stats.values()) s.error_rate = s.requests ? s.errors / s.requests * 100 : 0;
  return stats;
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
  let regionIdx = null;
  let regionData = null;
  let regionLayer = null;
  let regionStats = new Map();
  let regionsPending = false;
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
          `${t('pz.tip_country', { n: gmNum(e.requests), pct: (e.pct || 0).toFixed(1) })}<br>` +
          `<span style="opacity:.7">${t('pz.tip_err', { rate: (e.error_rate || 0).toFixed(1), bans: e.banned_ips || 0 })}</span>`;
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
    d.textContent = t('pz.cities_locating');
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
      lg.querySelector('.lg-title').textContent = geoLabel(state.mode);
      lg.querySelector('.lg-grad').style.background = `linear-gradient(90deg,rgba(${r},${g},${b},.1),rgba(${r},${g},${b},1))`;
      lg.querySelector('.lg-max').textContent = state.mode === 'error_rate' ? max.toFixed(1) + '%' : gmNum(Math.round(max));
      lg.style.display = max > 0 ? '' : 'none';
    }
  }

  function drawRegions() {
    if (regionLayer) { map.removeLayer(regionLayer); regionLayer = null; }
    if (state.style !== 'regions' || !regionData) return;
    const [r, g, b] = colorOf();
    const isos = new Set([...regionStats.values()].map(s => s.iso));
    regionLayer = L.geoJSON({ type: 'FeatureCollection', features: regionData.features.filter(f => isos.has(f.properties.iso)) }, {
      style: f => {
        const s = regionStats.get(f.properties.code || f.properties.iso + ':' + f.properties.name);
        const v = s ? _geoValue(s, state.mode) : 0;
        return {
          fillColor: `rgb(${r},${g},${b})`, fillOpacity: v > 0 && max > 0 ? 0.12 + Math.pow(v / max, 0.55) * 0.83 : 0,
          color: 'var(--text3)', weight: 0.5, opacity: 0.6,
        };
      },
      onEachFeature: (f, layer) => {
        layer.bindTooltip(() => {
          const s = regionStats.get(f.properties.code || f.properties.iso + ':' + f.properties.name);
          if (!s) return esc(f.properties.name);
          return `<b>${esc(s.name)}</b> <span style="opacity:.6">${esc(s.iso)}</span><br>` +
            `${t('pz.tip_city', { n: gmNum(s.requests), ips: gmNum(s.ips) })}<br>` +
            `<span style="opacity:.7">${t('pz.tip_err', { rate: (s.error_rate || 0).toFixed(1), bans: s.banned_ips || 0 })}</span>`;
        }, { sticky: true, className: 'gm-tip' });
      },
    }).addTo(map);
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
        `${t('pz.tip_city', { n: gmNum(p.requests), ips: gmNum(p.ips) })}<br>` +
        `<span style="opacity:.7">${t('pz.tip_err', { rate: (p.error_rate || 0).toFixed(1), bans: p.banned_ips || 0 })}</span>`,
        { className: 'gm-tip' });
      m.on('click', () => { if (opts.onPoint) opts.onPoint(p); });
    }
  }

  const ro = typeof ResizeObserver === 'function' ? new ResizeObserver(() => map.invalidateSize()) : null;
  if (ro) ro.observe(el);

  const ctl = {
    /* next : {countries, points, mode, style: zones|cities|regions, selected} */
    update(next) {
      state = { ...state, ...next };
      byCC = {};
      max = 0;
      for (const e of state.countries) {
        byCC[e.country_code] = e;
        max = Math.max(max, _geoValue(e, state.mode));
      }
      let hintText = '';
      if (state.style === 'regions') {
        if (!regionData) {
          hintText = t('pz.regions_loading');
          if (!regionsPending) {
            regionsPending = true;
            gpxGeoRegions().then(fc => { regionData = fc; regionIdx = _regionIndex(fc); regionsPending = false; ctl.update({}); })
              .catch(() => { regionsPending = false; });
          }
        } else {
          regionStats = _regionStats(regionIdx, state.points);
          max = Math.max(0, ...[...regionStats.values()].map(s => _geoValue(s, state.mode)));
          if (!regionStats.size) hintText = t('pz.cities_locating');
        }
      } else if (state.style === 'cities' && !state.points.length) {
        hintText = t('pz.cities_locating');
      }
      restyle();
      drawPoints();
      drawRegions();
      const hc = hint.getContainer();
      hc.textContent = hintText;
      hc.style.display = hintText ? '' : 'none';
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
  return ctl;
}
