// ── Histogramme empilé partagé (Logs d'accès, Logs système, Journal d'audit) ─────
// Une barre par tranche de temps : normal (accent), avertissements (jaune), erreurs (rouge).
// Chaque barre porte data-<attr>="<tranche>" et data-unit pour zoomer sur sa période.

/**
 * @param {{bucket:string,total:number,warn?:number,error?:number}[]} pts
 * @param {string} unit  minute | hour | day
 * @param {{attr:string,title:string,hint:string}} opt
 */
function gpxHistHTML(pts, unit, opt) {
  if (!Array.isArray(pts) || !pts.length) return '';
  const W = 900, H = 70, pad = 2, bw = W / pts.length;
  const mx = Math.max(1, ...pts.map(x => x.total));
  const bars = pts.map((x, i) => {
    const warn = x.warn || 0, err = x.error || 0, ok = Math.max(0, x.total - warn - err);
    const hOk = ok / mx * (H - 4), hWarn = warn / mx * (H - 4), hErr = err / mx * (H - 4);
    const xx = (i * bw + pad / 2).toFixed(1), w = Math.max(1, bw - pad).toFixed(1);
    return `<g ${opt.attr}="${esc(x.bucket)}" data-unit="${esc(unit)}" style="cursor:pointer"><title>${esc(x.bucket)} — ${x.total}${warn ? ' · ' + warn + ' warn' : ''}${err ? ' · ' + err + ' err' : ''}</title>
      <rect x="${xx}" y="0" width="${w}" height="${H}" fill="transparent"/>
      <rect x="${xx}" y="${(H - hOk).toFixed(1)}" width="${w}" height="${hOk.toFixed(1)}" fill="var(--accent)" opacity=".55"/>
      <rect x="${xx}" y="${(H - hOk - hWarn).toFixed(1)}" width="${w}" height="${hWarn.toFixed(1)}" fill="var(--yellow)"/>
      <rect x="${xx}" y="${(H - hOk - hWarn - hErr).toFixed(1)}" width="${w}" height="${hErr.toFixed(1)}" fill="var(--red)"/></g>`;
  }).join('');
  return `<div class="logs-hist-h"><span>${esc(opt.title)}</span><span>${esc(opt.hint)}</span></div>
    <svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="${esc(opt.title)}">${bars}</svg>`;
}

// Position (iso) → clé de tranche, dans le même format que les buckets renvoyés par le serveur
// (heure locale du navigateur, en supposant qu'elle coïncide avec celle du serveur).
function gpxBucketKey(iso, unit) {
  const d = new Date(iso);
  if (isNaN(d)) return null;
  const p = n => String(n).padStart(2, '0');
  if (unit === 'day') return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
  if (unit === 'minute') return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:00`;
}

// Étendue [from, to] d'une tranche → ISO (pour les filtres date_from / date_to ou from / to).
function gpxBucketISO(bucket, unit) {
  if (typeof obsBucketRange !== 'function') return null;
  const r = obsBucketRange(bucket, unit);
  return r.from ? { from: new Date(r.from).toISOString(), to: new Date(r.to).toISOString() } : null;
}
