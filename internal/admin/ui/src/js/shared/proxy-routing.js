// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Options de routage avancé d'un proxy (onglet Avancé de la modale) : split, maintenance, URLs signées,
// GraphQL, hedge, gRPC-Web, débit, masquage JSON, fichiers statiques, schéma de requête.
// _proutRender(cfg) rend les cartes, _proutCollect(prev) lit les champs et renvoie { clé: valeur | undefined }.

(function () {
  const e = v => (typeof esc === 'function' ? esc(v) : String(v ?? ''));
  const card = (key, title, desc, on, body) => `
    <details class="prout-card" data-prout="${key}" ${on ? 'open' : ''} style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:12px 16px;">
      <summary style="cursor:pointer;display:flex;align-items:center;gap:8px;list-style:none;">
        <span style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);flex:1;">${title}</span>
        <span class="tag ${on ? 'tag-accent' : 'tag-neutral'}" id="prout-${key}-tag">${on ? 'Actif' : 'Inactif'}</span>
      </summary>
      <div style="font-size:11px;color:var(--text3);margin:8px 0 10px;">${desc}</div>
      ${body}
    </details>`;
  const toggle = (id, label, checked) => `
    <label style="display:flex;align-items:center;gap:8px;cursor:pointer;margin-bottom:10px;">
      <label class="toggle"><input type="checkbox" id="${id}" ${checked ? 'checked' : ''} onchange="_proutTag(this)"><span class="toggle-slider"></span></label>
      <span style="font-size:13px;font-weight:500;">${label}</span>
    </label>`;
  const field = (id, label, value, attrs = '', grow = true) => `
    <div class="field" style="${grow ? 'flex:1;min-width:140px;' : ''}margin:0;"><label class="field-label" style="font-size:11px">${label}</label><input id="${id}" class="input" value="${e(value ?? '')}" ${attrs}></div>`;
  const area = (id, label, value, attrs = '', rows = 3) => `
    <div class="field" style="margin:8px 0 0;"><label class="field-label" style="font-size:11px">${label}</label><textarea id="${id}" class="input" rows="${rows}" style="font-size:12px;font-family:monospace;" ${attrs}>${e(value ?? '')}</textarea></div>`;
  const row = inner => `<div style="display:flex;gap:10px;flex-wrap:wrap;">${inner}</div>`;
  const lines = s => (s || '').split('\n').map(x => x.trim()).filter(Boolean);
  const csv = s => (s || '').split(',').map(x => x.trim()).filter(Boolean);
  const num = id => parseInt(document.getElementById(id)?.value, 10) || 0;
  const val = id => document.getElementById(id)?.value.trim() || '';
  const checked = id => !!document.getElementById(id)?.checked;

  window._proutTag = function (input) {
    const key = input.closest('[data-prout]')?.dataset.prout;
    const tag = document.getElementById(`prout-${key}-tag`);
    if (!tag) return;
    const first = input.closest('[data-prout]').querySelector('input[type=checkbox]');
    tag.textContent = first.checked ? 'Actif' : 'Inactif';
    tag.className = 'tag ' + (first.checked ? 'tag-accent' : 'tag-neutral');
  };


  // Rapport de l'apprentissage de surface (ADR 0016). Une passerelle de groupe HA rend le profil fusionné de ses pairs :
  // on garde le rapport qui en réunit le plus.
  const fmtBytes = n => n >= 1048576 ? (n / 1048576).toFixed(1) + ' Mo' : n >= 1024 ? (n / 1024).toFixed(1) + ' Ko' : n + ' o';
  const fmtDate = d => d && !String(d).startsWith('0001') ? new Date(d).toLocaleString() : '—';
  const counts = (list, max = 6) => (list || []).slice(0, max).map(c => `${e(c.name)} <span style="color:var(--text3)">${c.count}</span>`).join(', ') || '—';

  window._proutSurfaceReport = async function () {
    const box = document.getElementById('prout-sf-report');
    if (!box) return;
    const host = window._openProxyCfg?.host;
    if (!host) { box.innerHTML = '<div style="font-size:12px;color:var(--text3)">Enregistrez d\'abord le proxy.</div>'; return; }
    box.innerHTML = '<div style="font-size:12px;color:var(--text3)">Lecture des passerelles…</div>';
    let res;
    try { res = await api('GET', `/security/surface/report?route=${encodeURIComponent(host)}`); }
    catch (err) { box.innerHTML = `<div style="font-size:12px;color:var(--danger)">${e(err.message || err)}</div>`; return; }
    const reports = (res?.gateways || []).filter(g => g.report).map(g => ({ node: g.node_name, r: g.report }));
    reports.sort((a, b) => (b.r.members - a.r.members) || (b.r.learned - a.r.learned));
    const partial = res?.unreachable?.length ? `<div style="font-size:11px;color:var(--warn);margin-bottom:6px">Passerelle(s) injoignable(s) : ${e(res.unreachable.map(u => u.node_name).join(', '))}</div>` : '';
    if (!reports.length) {
      box.innerHTML = partial + '<div style="font-size:12px;color:var(--text3)">Aucun profil pour l\'instant. Activez l\'apprentissage et enregistrez le proxy : le profil se construit à mesure que le trafic arrive.</div>';
      return;
    }
    const { node, r } = reports[0];
    const cv = r.convergence || {};
    const badge = cv.converged ? '<span class="tag tag-accent">Profil fiable</span>' : '<span class="tag tag-neutral">En cours d\'apprentissage</span>';
    const reasons = (cv.reasons || []).map(x => `<li>${e(x)}</li>`).join('');
    const rows = (r.templates || []).map(t => `<tr>
        <td style="font-family:monospace">${e(t.path)}${t.low_support ? ' <span class="tag tag-neutral" title="Peu de clients ou de jours distincts : à confirmer">à confirmer</span>' : ''}</td>
        <td>${t.requests}</td><td>${counts(t.methods, 4)}</td><td>${counts(t.statuses, 4)}</td>
        <td>${counts(t.request_media, 2)}</td><td>${t.body_p99 ? fmtBytes(t.body_p99) : '—'}</td>
        <td>${t.clients}</td><td>${t.days}</td>
        <td>${(t.params || []).map(p => e(p.name) + (p.enum ? ' (liste)' : '')).join(', ') || '—'}</td></tr>`).join('');
    box.innerHTML = partial + `
      <div style="font-size:12px;display:flex;flex-direction:column;gap:8px;">
        <div>${badge} <span style="color:var(--text3)">passerelle ${e(node)}${r.members > 1 ? ` · ${r.members} membres du groupe fusionnés` : ''} · depuis ${fmtDate(r.since)}</span></div>
        ${reasons ? `<ul style="margin:0 0 0 18px;color:var(--text3)">${reasons}</ul>` : ''}
        <div>${r.requests} requêtes vues · ${r.learned} apprises · ${r.excluded} d'IP suspectes ignorées · ${(r.failed || []).reduce((n, f) => n + f.count, 0)} en échec · ≈ ${r.clients} clients distincts</div>
        <div><b>Méthodes</b> ${counts(r.methods)} · <b>Pays</b> ${counts(r.countries)} · <b>AS</b> ${counts(r.asns, 4)}</div>
        <div><b>Types de requête</b> ${counts(r.request_media, 5)} · <b>Types de réponse</b> ${counts(r.response_media, 5)}${r.body_max ? ` · <b>Corps</b> max ${fmtBytes(r.body_max)}, p99 ≤ ${fmtBytes(r.body_p99)}` : ''}</div>
        ${typeHtml(r)}
        <div><b>En-têtes vus</b> ${counts(r.headers, 12)}</div>
        <div style="overflow:auto;max-height:340px;"><table class="table" style="width:100%;font-size:11px;">
          <thead><tr><th>Chemin</th><th>Req.</th><th>Méthodes</th><th>Statuts</th><th>Type requête</th><th>Corps p99</th><th>Clients</th><th>Jours</th><th>Paramètres</th></tr></thead>
          <tbody>${rows || '<tr><td colspan="9" style="color:var(--text3)">Aucun chemin appris.</td></tr>'}</tbody></table></div>
        ${violationsHtml(r)}
        ${wafHtml(r)}
        ${suggestionsHtml(r)}
        ${enforceHtml(r)}
        ${r.template_count > (r.templates || []).length ? `<div style="color:var(--text3)">${r.template_count} chemins au total, les ${(r.templates || []).length} plus demandés sont listés.</div>` : ''}
      </div>`;
  };

  // Propositions de réglages tirées du profil (ADR 0016, étape 2). Rien n'est appliqué : chaque proposition donne la commande
  // qui la pose, à copier.
  let sfCmds = [];
  window._proutSurfaceCopy = function (i) {
    if (sfCmds[i] && navigator.clipboard) navigator.clipboard.writeText(sfCmds[i]).catch(() => {});
  };

  window._proutSurfaceProposals = async function () {
    const box = document.getElementById('prout-sf-proposals');
    if (!box) return;
    const host = window._openProxyCfg?.host;
    if (!host) { box.innerHTML = '<div style="font-size:12px;color:var(--text3)">Enregistrez d\'abord le proxy.</div>'; return; }
    box.innerHTML = '<div style="font-size:12px;color:var(--text3)">Calcul des propositions…</div>';
    let res;
    try { res = await api('GET', `/security/surface/proposals?route=${encodeURIComponent(host)}`); }
    catch (err) { box.innerHTML = `<div style="font-size:12px;color:var(--danger)">${e(err.message || err)}</div>`; return; }
    const all = (res?.gateways || []).filter(g => g.proposals).map(g => ({ node: g.node_name, p: g.proposals }));
    all.sort((a, b) => (b.p.members - a.p.members) || (b.p.learned - a.p.learned));
    if (!all.length) {
      box.innerHTML = '<div style="font-size:12px;color:var(--text3)">Aucun profil pour l\'instant : rien à proposer.</div>';
      return;
    }
    const { node, p } = all[0];
    sfCmds = [];
    const cv = p.convergence || {};
    const warn = cv.converged ? '' : `<div style="font-size:11px;color:var(--warn)"><b>Profil pas encore fiable</b> : ${e((cv.reasons || []).join(' ; '))}. Ces propositions sont un aperçu : attendez avant de les appliquer.</div>`;
    const items = (p.items || []).map(it => {
      sfCmds.push(it.command);
      const refuse = it.measured
        ? `<div>${it.would_refuse === 0 ? 'N\'aurait refusé aucune' : 'Aurait refusé <b>' + it.would_refuse + '</b>'} des ${it.of} requêtes apprises.</div>`
        : '<div style="color:var(--text3)">Impact non mesurable sur le profil.</div>';
      return `<div style="border:1px solid var(--border);border-radius:8px;padding:10px 12px;display:flex;flex-direction:column;gap:6px;">
        <div style="font-weight:600">${e(it.summary)} <span class="tag tag-neutral">${e(it.setting)}</span></div>
        <div style="color:var(--text3)">Actuellement : ${e(it.current)}</div>
        <ul style="margin:0 0 0 18px">${(it.evidence || []).map(x => `<li>${e(x)}</li>`).join('')}</ul>
        ${refuse}
        ${(it.cautions || []).length ? `<ul style="margin:0 0 0 18px;color:var(--warn)">${it.cautions.map(x => `<li>${e(x)}</li>`).join('')}</ul>` : ''}
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap"><code style="font-size:11px;word-break:break-all;flex:1">${e(it.command)}</code>
          <button type="button" class="btn btn-secondary btn-sm" onclick="_proutSurfaceCopy(${sfCmds.length - 1})">Copier</button></div>
      </div>`;
    }).join('');
    const skipped = (p.skipped || []).map(x => `<li><b>${e(x.setting)}</b> : ${e(x.reason)}</li>`).join('');
    box.innerHTML = `<div style="font-size:12px;display:flex;flex-direction:column;gap:8px;">
      <div style="color:var(--text3)">Propositions de la passerelle ${e(node)}${p.members > 1 ? ` (${p.members} membres fusionnés)` : ''} sur ${p.learned} requêtes apprises. Rien n'est appliqué.</div>
      ${warn}
      ${(p.notes || []).map(x => `<div style="color:var(--text3)">${e(x)}</div>`).join('')}
      ${items || '<div style="color:var(--text3)">Le profil ne permet de proposer aucun réglage pour l\'instant.</div>'}
      ${skipped ? `<details><summary style="cursor:pointer;color:var(--text3)">Réglages non proposés (${(p.skipped || []).length})</summary><ul style="margin:6px 0 0 18px;color:var(--text3)">${skipped}</ul></details>` : ''}
    </div>`;
  };

  // Type du proxy (ADR 0016) : une API a une surface fermée, un site un contenu ouvert où une liste de chemins n'a pas de sens.
  const typeHtml = r => {
    const label = { api: 'API', site: 'site' };
    const declared = r.type ? `Type déclaré : <b>${e(label[r.type] || r.type)}</b>.` : 'Type non précisé (traité comme une API).';
    const hint = r.type_hint && r.type_hint !== r.type
      ? `<span style="color:var(--warn)"> Le trafic ressemble à celui d'${r.type_hint === 'site' ? 'un <b>site</b>' : 'une <b>API</b>'} (${e(r.type_hint_why || '')}) : choisissez ce type ci-dessus${r.type_hint === 'site' ? ' pour que la convergence ne dépende plus des chemins et que la politique de chemins ne soit pas proposée' : ''}.</span>` : '';
    return `<div style="color:var(--text3)">${declared}${hint}</div>`;
  };

  // Violations de la politique (contrôle openapi du proxy) vues pendant l'apprentissage.
  const REASONS = { unknown_path: 'chemin inconnu', unknown_method: 'méthode inconnue', invalid_param: 'paramètre invalide', invalid_body: 'corps invalide', unsupported_media: 'type de contenu', too_large: 'corps trop gros' };
  const violationsHtml = r => {
    if (!(r.violations || []).length) return '';
    const rows = r.violations.map(v => `<tr>
        <td>${e(REASONS[v.reason] || v.reason)}</td><td>${e(v.method)}</td><td style="font-family:monospace">${e(v.path)}</td>
        <td>${v.count}</td><td>${v.legit}</td><td>${v.clients}</td>
        <td>${v.likely_legit ? '<span class="tag tag-accent" title="Réussit le plus souvent depuis plusieurs clients propres : probablement un chemin légitime qui manque à la politique">à ajouter ?</span>' : ''}</td></tr>`).join('');
    const total = (r.violation_totals || []).map(c => `${e(REASONS[c.name] || c.name)} <span style="color:var(--text3)">${c.count}</span>`).join(', ');
    return `<div><b>Hors de la politique openapi</b> (${total})
      <div style="overflow:auto;max-height:260px;margin-top:4px;"><table class="table" style="width:100%;font-size:11px;">
        <thead><tr><th>Raison</th><th>Méthode</th><th>Chemin</th><th>Req.</th><th>Réussies</th><th>Clients</th><th></th></tr></thead><tbody>${rows}</tbody></table></div></div>`;
  };

  // Politique positive : une spécification OpenAPI générée à partir du profil, pour le contrôle openapi du proxy, en detect
  // (ADR 0016, étape 3). Rien n'est appliqué sans enregistrer le proxy.
  let sfOpenAPI = null;
  window._proutSurfaceOpenAPI = async function () {
    const box = document.getElementById('prout-sf-openapi');
    if (!box) return;
    const host = window._openProxyCfg?.host;
    if (!host) { box.innerHTML = '<div style="font-size:12px;color:var(--text3)">Enregistrez d\'abord le proxy.</div>'; return; }
    box.innerHTML = '<div style="font-size:12px;color:var(--text3)">Génération de la politique…</div>';
    const low = document.getElementById('prout-sf-low')?.checked ? '&include_low_support=1' : '';
    let res;
    try { res = await api('GET', `/security/surface/openapi?route=${encodeURIComponent(host)}${low}`); }
    catch (err) { box.innerHTML = `<div style="font-size:12px;color:var(--danger)">${e(err.message || err)}</div>`; return; }
    const all = (res?.gateways || []).filter(g => g.openapi).map(g => ({ node: g.node_name, o: g.openapi }));
    all.sort((a, b) => (b.o.members - a.o.members) || (b.o.learned - a.o.learned));
    sfOpenAPI = null;
    if (!all.length) {
      box.innerHTML = '<div style="font-size:12px;color:var(--text3)">Aucun profil pour l\'instant : rien à générer.</div>';
      return;
    }
    const { node, o } = all[0];
    if (o.error || !o.config) {
      box.innerHTML = `<div style="font-size:12px;color:var(--text3)">Aucune politique générée : ${e(o.error || 'profil vide')}.</div>`;
      return;
    }
    sfOpenAPI = o;
    const excluded = (o.excluded || []).map(x => `<li><span style="font-family:monospace">${e(x.path)}</span> : ${e(x.reason)}</li>`).join('');
    box.innerHTML = `<div style="font-size:12px;display:flex;flex-direction:column;gap:8px;border:1px solid var(--border);border-radius:8px;padding:10px 12px;">
      <div style="font-weight:600">Politique générée : ${o.paths} chemin(s), ${o.operations} opération(s), ${o.parameters} paramètre(s)
        ${o.ready ? '<span class="tag tag-accent">profil fiable</span>' : '<span class="tag tag-neutral">profil pas encore fiable</span>'}</div>
      <div style="color:var(--text3)">Passerelle ${e(node)}${o.members > 1 ? ` (${o.members} membres fusionnés)` : ''}, ${o.learned} requêtes apprises. Mode <b>detect</b> : aucune requête n'est refusée, celles qui sortent de la politique sont comptées et listées dans le rapport.</div>
      <ul style="margin:0 0 0 18px;color:var(--warn)">${(o.cautions || []).map(x => `<li>${e(x)}</li>`).join('')}</ul>
      ${excluded ? `<details><summary style="cursor:pointer;color:var(--text3)">Chemins hors de la politique (${(o.excluded || []).length})</summary><ul style="margin:6px 0 0 18px;color:var(--text3)">${excluded}</ul></details>` : ''}
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button type="button" class="btn btn-secondary btn-sm" onclick="_proutSurfaceApplyOpenAPI()">Pré-remplir la validation OpenAPI</button>
        <button type="button" class="btn btn-secondary btn-sm" onclick="_proutSurfaceCopyOpenAPI()">Copier la configuration</button>
      </div>
      <div id="prout-sf-openapi-msg" style="color:var(--text3)"></div>
    </div>`;
  };

  window._proutSurfaceCopyOpenAPI = function () {
    if (sfOpenAPI && navigator.clipboard) navigator.clipboard.writeText(JSON.stringify(sfOpenAPI.config, null, 2)).catch(() => {});
  };

  // Remplit la carte « Validation OpenAPI » de la modale ; la politique ne s'applique qu'à l'enregistrement du proxy.
  window._proutSurfaceApplyOpenAPI = function () {
    const msg = document.getElementById('prout-sf-openapi-msg');
    if (!sfOpenAPI) return;
    if (sfOpenAPI.replaces && !confirm('Ce proxy a déjà une validation OpenAPI active : elle sera remplacée par la politique apprise. Continuer ?')) return;
    const on = document.getElementById('prout-oa-on'), spec = document.getElementById('prout-oa-spec');
    if (!on || !spec) { if (msg) msg.textContent = 'La carte « Validation OpenAPI » est introuvable dans cette modale.'; return; }
    on.checked = true;
    window._proutTag(on);
    const mode = document.getElementById('prout-oa-mode'), unknown = document.getElementById('prout-oa-unknown');
    if (mode) mode.value = 'detect';
    if (unknown) unknown.value = 'block';
    spec.value = JSON.stringify(sfOpenAPI.config.spec, null, 2);
    if (window._openProxyCfg?.openapi) delete window._openProxyCfg.openapi.block_reasons;
    if (msg) msg.textContent = 'La carte « Validation OpenAPI » est remplie (mode detect). Enregistrez le proxy pour appliquer la politique.';
  };

  // Règles du WAF déclenchées, surtout par des clients ordinaires : candidates à l'exclusion (voir les propositions).
  const wafHtml = r => {
    if (!(r.waf || []).length) return '';
    const rows = r.waf.map(w => `<tr>
        <td>${w.id}</td><td>${e(w.category)}</td><td>${e(w.message)}</td><td>${w.hits}</td>
        <td>${w.clean}</td><td>${w.served}</td><td>${w.blocked}</td><td>${w.clients}</td><td>${w.days}</td>
        <td>${(w.paths || []).slice(0, 2).map(p => `<span style="font-family:monospace">${e(p.name)}</span>`).join(', ') || '—'}</td></tr>`).join('');
    return `<div><b>Règles du WAF déclenchées</b>
      <div style="color:var(--text3)">« Propres » : requêtes d'IP sans autre signal que le WAF. Une règle qui revient de plusieurs clients propres sur plusieurs jours est proposée à l'exclusion (propositions).</div>
      <div style="overflow:auto;max-height:240px;margin-top:4px;"><table class="table" style="width:100%;font-size:11px;">
        <thead><tr><th>Règle</th><th>Type</th><th>Message</th><th>Déclench.</th><th>Propres</th><th>Servies</th><th>Refusées</th><th>Clients</th><th>Jours</th><th>Chemins</th></tr></thead><tbody>${rows}</tbody></table></div></div>`;
  };

  // Suggestions d'ajout à la politique (ADR 0016, étape 5) : des chemins ou méthodes hors politique qui reviennent de plusieurs clients
  // propres sur plusieurs jours. La politique ne s'élargit jamais seule : on coche, on ajoute.
  let sfSuggestions = [];
  const suggestionsHtml = r => {
    sfSuggestions = r.suggestions || [];
    if (!sfSuggestions.length) return '';
    const rows = sfSuggestions.map((x, i) => `<label style="display:flex;gap:8px;align-items:flex-start;cursor:pointer;border-top:1px solid var(--border);padding-top:6px;">
        <input type="checkbox" class="prout-sf-sugg" value="${i}" ${x.confidence === 'high' ? 'checked' : ''} style="margin-top:3px">
        <span style="display:flex;flex-direction:column;gap:2px;">
          <span><b style="font-family:monospace">${e(x.method)} ${e(x.path)}</b>
            <span class="tag ${x.confidence === 'high' ? 'tag-accent' : 'tag-neutral'}">${x.confidence === 'high' ? 'confiance haute' : 'à examiner'}</span>
            ${x.reason === 'unknown_method' ? '<span class="tag tag-neutral">méthode</span>' : ''}</span>
          <span style="color:var(--text3)">${(x.why || []).map(e).join(' ; ')}</span>
          ${(x.cautions || []).map(c => `<span style="color:var(--warn)">${e(c)}</span>`).join('')}
        </span></label>`).join('');
    return `<div style="border:1px solid var(--border);border-radius:8px;padding:10px 12px;display:flex;flex-direction:column;gap:6px;">
      <b>Ajouts suggérés à la politique (${sfSuggestions.length})</b>
      <div style="color:var(--text3)">Ces chemins reviennent de plusieurs clients ordinaires sur plusieurs jours. Rien n'est ajouté sans votre accord, et un ajout ne retire jamais rien.</div>
      ${rows}
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button type="button" class="btn btn-secondary btn-sm" onclick="_proutSurfaceAccept(true)">Simuler</button>
        <button type="button" class="btn btn-secondary btn-sm" onclick="_proutSurfaceAccept(false)">Ajouter à la politique</button>
      </div>
      <div id="prout-sf-accept-msg"></div></div>`;
  };

  window._proutSurfaceAccept = async function (dry) {
    const box = document.getElementById('prout-sf-accept-msg');
    const keys = [...document.querySelectorAll('.prout-sf-sugg:checked')].map(c => sfSuggestions[parseInt(c.value, 10)]?.key).filter(Boolean);
    const host = window._openProxyCfg?.host;
    if (!box) return;
    if (!keys.length) { box.innerHTML = '<div style="color:var(--danger)">Cochez au moins une suggestion.</div>'; return; }
    let res;
    try { res = await api('POST', `/security/surface/accept?route=${encodeURIComponent(host)}`, { keys, dry_run: !!dry }); }
    catch (err) {
      let body = null;
      try { body = JSON.parse(err.message); } catch { /* corps non JSON */ }
      box.innerHTML = `<div style="color:var(--danger)">${e(body ? (body.blockers || []).concat(body.warnings || []).join(' ; ') || 'Refusé.' : String(err.message || err))}</div>`;
      return;
    }
    const added = (res.added || []).map(a => `<li><span style="font-family:monospace">${e(a.method)} ${e(a.path)}</span></li>`).join('');
    const skipped = (res.skipped || []).map(x => `<li>${e(x.key)} : ${e(x.reason)}</li>`).join('');
    box.innerHTML = `<div style="font-size:12px;display:flex;flex-direction:column;gap:4px;">
      <b>${res.applied ? 'Ajouté à la politique.' : 'Simulation : rien n\'est écrit.'}</b>
      ${added ? `<ul style="margin:0 0 0 18px">${added}</ul>` : ''}
      ${skipped ? `<ul style="margin:0 0 0 18px;color:var(--text3)">${skipped}</ul>` : ''}
      ${(res.warnings || []).map(w => `<div style="color:var(--warn)">${e(w)}</div>`).join('')}</div>`;
    if (res.applied && res.spec) {
      // La modale garde la spécification qu'elle affiche : sans cela, l'enregistrer retirerait ce qui vient d'être ajouté.
      const spec = document.getElementById('prout-oa-spec');
      const text = JSON.stringify(res.spec, null, 2);
      if (spec) spec.value = text;
      if (window._openProxyCfg?.openapi) window._openProxyCfg.openapi.spec = res.spec;
    }
  };

  // Passage en block de la politique, type de violation par type de violation (ADR 0016, étape 4). Les garde-fous sont côté
  // Admin : la réponse dit lesquels refusent (blockers) et ce que le refus couperait (impact).
  const enforceHtml = r => {
    const totals = Object.fromEntries((r.violation_totals || []).map(c => [c.name, c.count]));
    const blockedNow = new Set(window._openProxyCfg?.openapi?.block_reasons || []);
    const legit = {};
    for (const v of r.violations || []) legit[v.reason] = (legit[v.reason] || 0) + v.legit;
    const rows = Object.keys(REASONS).map(k => `<label style="display:flex;align-items:center;gap:6px;cursor:pointer;">
        <input type="checkbox" class="prout-sf-reason" value="${k}" ${blockedNow.has(k) ? 'checked' : ''}>
        <span>${e(REASONS[k])}</span>
        <span style="color:var(--text3)">${totals[k] || 0} vue(s)${legit[k] ? `, dont ${legit[k]} réussie(s) depuis des IP propres` : ''}</span></label>`).join('');
    return `<div style="border:1px solid var(--border);border-radius:8px;padding:10px 12px;display:flex;flex-direction:column;gap:6px;">
      <b>Refuser les violations de la politique</b>
      <div style="color:var(--text3)">Le contrôle openapi du proxy refuse alors ces types de violation et laisse passer, en les comptant, les autres. Cochez ce que vous voulez refuser.</div>
      ${rows}
      <label style="display:flex;align-items:center;gap:6px;cursor:pointer;color:var(--text3)"><input type="checkbox" id="prout-sf-force"> passer outre les garde-fous (consigné à l'audit)</label>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button type="button" class="btn btn-secondary btn-sm" onclick="_proutSurfaceEnforce(true)">Simuler</button>
        <button type="button" class="btn btn-secondary btn-sm" onclick="_proutSurfaceEnforce(false)">Refuser ces violations</button>
        <button type="button" class="btn btn-secondary btn-sm" onclick="_proutSurfaceRelax()">Repasser en detect</button>
      </div>
      <div id="prout-sf-enforce-msg"></div></div>`;
  };

  const showEnforce = res => {
    const box = document.getElementById('prout-sf-enforce-msg');
    if (!box) return;
    const list = (title, items, color) => (items || []).length ? `<div style="color:${color}"><b>${title}</b><ul style="margin:2px 0 0 18px">${items.map(x => `<li>${e(x)}</li>`).join('')}</ul></div>` : '';
    const impact = (res.impact || []).map(i => `${e(REASONS[i.reason] || i.reason)} : ${i.total} vue(s), ${i.legit} réussie(s) depuis des IP propres`).join(' · ');
    const head = res.applied ? '<b>Appliqué.</b> Enregistrez le proxy si vous modifiez d\'autres réglages de la modale.' : res.dry_run ? '<b>Simulation</b> : rien n\'est écrit.' : '<b>Refusé</b> : rien n\'a été modifié.';
    box.innerHTML = `<div style="font-size:12px;display:flex;flex-direction:column;gap:4px;">${head}
      ${(res.block_reasons || []).length ? `<div>Refusés : ${(res.block_reasons || []).map(k => e(REASONS[k] || k)).join(', ')}${res.forced ? ' (forcé)' : ''}</div>` : ''}
      ${list('Garde-fous', res.blockers, 'var(--danger)')}${list('À savoir', res.warnings, 'var(--warn)')}
      ${impact ? `<div style="color:var(--text3)">${impact}</div>` : ''}</div>`;
  };

  // Garde la modale d'accord avec ce que l'Admin vient d'écrire : sinon l'enregistrer remettrait l'ancien état.
  const syncOpenAPIFields = res => {
    const cfg = window._openProxyCfg;
    if (cfg?.openapi) {
      cfg.openapi.mode = 'detect';
      if (res.block_reasons?.length) cfg.openapi.block_reasons = res.block_reasons; else delete cfg.openapi.block_reasons;
      if (res.unknown_paths) cfg.openapi.unknown_paths = res.unknown_paths;
    }
    const mode = document.getElementById('prout-oa-mode'), unknown = document.getElementById('prout-oa-unknown');
    if (mode) mode.value = 'detect';
    if (unknown && res.unknown_paths) unknown.value = res.unknown_paths;
  };

  const callEnforce = async (path, body) => {
    const host = window._openProxyCfg?.host;
    if (!host) { showEnforce({ blockers: ['Enregistrez d\'abord le proxy.'] }); return null; }
    try { return await api('POST', `/security/surface/${path}?route=${encodeURIComponent(host)}`, body); }
    catch (err) {
      let res = null;
      try { res = JSON.parse(err.message); } catch { /* corps non JSON */ }
      showEnforce(res && typeof res === 'object' ? res : { blockers: [String(err.message || err)] });
      return null;
    }
  };

  window._proutSurfaceEnforce = async function (dry) {
    const reasons = [...document.querySelectorAll('.prout-sf-reason:checked')].map(c => c.value);
    if (!reasons.length) { showEnforce({ blockers: ['Cochez au moins un type de violation (ou « Repasser en detect »).'] }); return; }
    const res = await callEnforce('enforce', { reasons, force: !!document.getElementById('prout-sf-force')?.checked, dry_run: !!dry });
    if (!res) return;
    if (res.applied) syncOpenAPIFields(res);
    showEnforce(res);
  };

  window._proutSurfaceRelax = async function () {
    if (!confirm('Repasser le contrôle openapi en detect ? Plus aucune violation ne sera refusée.')) return;
    const res = await callEnforce('relax');
    if (!res) return;
    syncOpenAPIFields({ block_reasons: [], unknown_paths: res.unknown_paths });
    document.querySelectorAll('.prout-sf-reason').forEach(c => { c.checked = false; });
    showEnforce(res);
  };

  window._proutSurfaceReset = async function () {
    const host = window._openProxyCfg?.host;
    if (!host || !confirm('Effacer le profil appris de ce proxy ? L\'apprentissage repart de zéro.')) return;
    try { await api('POST', `/security/surface/reset?route=${encodeURIComponent(host)}`); } catch (err) { alert(err.message || err); return; }
    window._proutSurfaceReport();
  };

  window._proutGtSrc = function () {
    const set = document.getElementById('prout-gt-src')?.value === 'set';
    const p = document.getElementById('prout-gt-proto'), s = document.getElementById('prout-gt-set');
    if (p) p.style.display = set ? 'none' : 'block';
    if (s) s.style.display = set ? 'block' : 'none';
  };

  window._proutAddVariant = function (v = {}) {
    const list = document.getElementById('prout-split-list');
    if (!list) return;
    const div = document.createElement('div');
    div.className = 'prout-variant';
    div.style.cssText = 'display:flex;gap:6px;margin-bottom:6px;align-items:center;';
    div.innerHTML = `
      <input class="input prout-v-name" style="width:110px" placeholder="nom (v2)" value="${e(v.name || '')}">
      <input class="input prout-v-backend" style="flex:1" placeholder="http://10.0.0.6:3000" value="${e(v.backend || '')}">
      <input class="input prout-v-weight" style="width:70px" type="number" min="1" placeholder="Poids" value="${e(v.weight || '')}">
      <button type="button" class="btn-icon" title="Supprimer" onclick="this.closest('.prout-variant').remove()">×</button>`;
    list.appendChild(div);
  };

  window._proutRender = function (cfg) {
    cfg = cfg || {};
    const sp = cfg.split, mt = cfg.maintenance, su = cfg.signed_url, gq = cfg.graphql, hg = cfg.hedge;
    const bw = cfg.bandwidth, rj = cfg.redact_json, hi = cfg.html_inject, st = cfg.static, rs = cfg.request_schema, oa = cfg.openapi, gt = cfg.grpc_transcode, sf = cfg.surface;
    const gtFiles = Object.keys(gt?.proto || {});
    const variants = sp?.variants?.length ? sp.variants : [{}, {}];
    setTimeout(() => { variants.forEach(v => window._proutAddVariant(v)); }, 0);
    return `
      <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);">Routage avancé</div>
      ${card('split', 'Split pondéré (A/B)', 'Répartit le trafic entre plusieurs backends nommés au prorata de leur poids. Un cookie d\'affectation garde la variante d\'un visiteur ; l\'override force le choix par header ou cookie.', !!sp?.variants?.length,
        toggle('prout-split-on', 'Activer le split', !!sp?.variants?.length) +
        `<div id="prout-split-list"></div><button type="button" class="btn btn-secondary btn-sm" onclick="_proutAddVariant()">+ Variante</button>` +
        `<div style="margin-top:10px;">${row(field('prout-split-cookie', 'Cookie d\'affectation (sticky)', sp?.sticky_cookie, 'placeholder="gpx_ab"') + field('prout-split-override', 'Override (header ou cookie)', sp?.override, 'placeholder="X-Variant"'))}</div>`)}
      ${card('maintenance', 'Mode maintenance', 'Coupe la route avec une page 503 sans la supprimer. Les CIDR et l\'en-tête de contournement laissent passer les équipes qui testent.', !!mt?.enabled,
        toggle('prout-mt-on', 'Route en maintenance', mt?.enabled) +
        row(field('prout-mt-msg', 'Message', mt?.message, 'placeholder="Retour dans quelques minutes"') + field('prout-mt-retry', 'Retry-After (s)', mt?.retry_after_sec || '', 'type="number" min="0" placeholder="120"', false)) +
        `<div style="margin-top:10px;">${row(field('prout-mt-cidrs', 'CIDR autorisés (virgules)', (mt?.bypass_cidrs || []).join(', '), 'placeholder="10.0.0.0/8"') + field('prout-mt-header', 'En-tête de contournement', mt?.bypass_header, 'placeholder="X-Bypass: secret"'))}</div>` +
        area('prout-mt-html', 'Page HTML (optionnelle)', mt?.html))}
      ${card('signed_url', 'URLs signées', 'N\'accepte que les URLs portant une signature HMAC-SHA256 valide et non expirée (chemin + expiration).', !!su?.enabled,
        toggle('prout-su-on', 'Exiger une signature', su?.enabled) +
        row(field('prout-su-secret', 'Secret', su?.secret, 'type="password" autocomplete="new-password"') + field('prout-su-sig', 'Paramètre signature', su?.param_sig, 'placeholder="sig"') + field('prout-su-exp', 'Paramètre expiration', su?.param_expires, 'placeholder="expires"')) +
        `<div style="margin-top:10px;">${field('prout-su-paths', 'Préfixes protégés (virgules, vide = toute la route)', (su?.paths || []).join(', '), 'placeholder="/download/, /private/"')}</div>`)}
      ${card('graphql', 'Garde-fous GraphQL', 'Borne la profondeur et le nombre d\'alias des requêtes GraphQL, et peut bloquer l\'introspection.', !!gq?.enabled,
        toggle('prout-gq-on', 'Activer', gq?.enabled) +
        row(field('prout-gq-depth', 'Profondeur max (0 = illimitée)', gq?.max_depth || '', 'type="number" min="0"') + field('prout-gq-alias', 'Alias max (0 = illimité)', gq?.max_aliases || '', 'type="number" min="0"')) +
        `<label style="display:flex;align-items:center;gap:6px;font-size:12px;margin-top:10px;cursor:pointer;"><input type="checkbox" id="prout-gq-intro" ${gq?.block_introspection ? 'checked' : ''}> Bloquer l'introspection</label>`)}
      ${card('hedge', 'Requêtes « hedged »', 'Un GET/HEAD sans corps dont le backend tarde à répondre est doublé vers un autre backend ; la première réponse est gardée.', !!hg,
        toggle('prout-hg-on', 'Activer', !!hg) +
        row(field('prout-hg-delay', 'Délai avant doublon (ms)', hg?.delay_ms || '', 'type="number" min="1" placeholder="200"') + field('prout-hg-extra', 'Tentatives supplémentaires', hg?.max_extra || '', 'type="number" min="1" placeholder="1"')))}
      ${card('grpc_web', 'gRPC-Web', 'Traduit gRPC-Web (navigateurs) en gRPC vers le backend, qui doit parler HTTP/2.', !!cfg.grpc_web,
        toggle('prout-gw-on', 'Activer la traduction gRPC-Web', !!cfg.grpc_web))}
      ${card('bandwidth', 'Plafond de débit', 'Limite le débit de chaque réponse, par connexion.', !!bw?.bytes_per_sec,
        toggle('prout-bw-on', 'Activer', !!bw?.bytes_per_sec) +
        field('prout-bw-bps', 'Octets par seconde', bw?.bytes_per_sec || '', 'type="number" min="1" placeholder="1048576"', false))}
      ${card('redact_json', 'Masquage de champs JSON', 'Masque des champs des réponses JSON avant envoi au client : un nom de clé (à toute profondeur) ou un chemin a.b.c par ligne.', !!rj?.fields?.length,
        toggle('prout-rj-on', 'Activer', !!rj?.fields?.length) +
        area('prout-rj-fields', 'Champs (un par ligne)', (rj?.fields || []).join('\n'), 'placeholder="password\nuser.ssn"') +
        `<div style="margin-top:10px;max-width:200px;">${field('prout-rj-mask', 'Valeur de remplacement', rj?.mask, 'placeholder="***"', false)}</div>`)}
      ${card('html_inject', 'Injection dans les pages HTML', 'Insère un fragment (script, balise) dans les pages HTML du backend, avant </head> ou avant </body>. Avec le nonce CSP, {{nonce}} est remplacé par une valeur propre à chaque réponse et ajouté à script-src du Content-Security-Policy du backend. Seules les réponses non compressées ou gzip sont modifiées.', !!hi?.content,
        toggle('prout-hi-on', 'Activer', !!hi?.content) +
        `<div class="field" style="max-width:260px;margin:0 0 10px;"><label class="field-label" style="font-size:11px">Position</label><select id="prout-hi-pos" class="input"><option value="body_end" ${hi?.position !== 'head_end' ? 'selected' : ''}>Avant &lt;/body&gt;</option><option value="head_end" ${hi?.position === 'head_end' ? 'selected' : ''}>Avant &lt;/head&gt;</option></select></div>` +
        area('prout-hi-content', 'Fragment HTML (16 Kio max)', hi?.content || '', 'spellcheck="false" placeholder="&lt;script nonce=&quot;{{nonce}}&quot; src=&quot;/analytics.js&quot;&gt;&lt;/script&gt;"', 5) +
        `<label style="display:flex;align-items:center;gap:6px;font-size:12px;margin-top:10px;cursor:pointer;"><input type="checkbox" id="prout-hi-nonce" ${hi?.csp_nonce ? 'checked' : ''}> Nonce CSP ({{nonce}})</label>`)}
      ${card('static', 'Fichiers statiques', 'Sert un dossier de la passerelle sans backend. Le repli SPA renvoie l\'index pour les chemins de page introuvables.', !!st?.enabled,
        toggle('prout-st-on', 'Servir un dossier', st?.enabled) +
        row(field('prout-st-root', 'Dossier (sur la passerelle)', st?.root, 'placeholder="/var/www/app"') + field('prout-st-index', 'Index', st?.index, 'placeholder="index.html"') + field('prout-st-cache', 'Cache max-age (s)', st?.cache_max_age || '', 'type="number" min="0"', false)) +
        `<label style="display:flex;align-items:center;gap:6px;font-size:12px;margin-top:10px;cursor:pointer;"><input type="checkbox" id="prout-st-spa" ${st?.spa_fallback ? 'checked' : ''}> Repli SPA vers l'index</label>`)}
      ${card('request_schema', 'Validation JSON Schema des requêtes', 'Valide le corps JSON des requêtes. Chaque règle : { "methods": [..], "path_prefix": "/api", "schema": {…} } — la première qui correspond s\'applique.', !!rs?.enabled,
        toggle('prout-rs-on', 'Activer', rs?.enabled) +
        row(`<div class="field" style="flex:1;min-width:140px;margin:0;"><label class="field-label" style="font-size:11px">Mode</label><select id="prout-rs-mode" class="input"><option value="block" ${rs?.mode !== 'detect' ? 'selected' : ''}>Bloquer (422)</option><option value="detect" ${rs?.mode === 'detect' ? 'selected' : ''}>Détecter (métrique seule)</option></select></div>` +
          field('prout-rs-max', 'Corps max lu (octets)', rs?.max_body || '', 'type="number" min="0" placeholder="1048576"')) +
        area('prout-rs-rules', 'Règles (JSON)', rs?.rules ? JSON.stringify(rs.rules, null, 2) : '[]', 'spellcheck="false"', 8))}
      ${card('openapi', 'Validation OpenAPI', 'Valide chemins, méthodes, paramètres (chemin, requête, en-tête, cookie) et corps JSON contre une spécification OpenAPI 3.0 ou 3.1 (YAML ou JSON, références « #/… » uniquement). Commencer en mode « détecter » pour roder la spécification avant de refuser.', !!oa?.enabled,
        toggle('prout-oa-on', 'Activer', oa?.enabled) +
        row(`<div class="field" style="flex:1;min-width:140px;margin:0;"><label class="field-label" style="font-size:11px">Mode</label><select id="prout-oa-mode" class="input"><option value="block" ${oa?.mode !== 'detect' ? 'selected' : ''}>Bloquer (400 / 422)</option><option value="detect" ${oa?.mode === 'detect' ? 'selected' : ''}>Détecter (métrique seule)</option></select></div>` +
          `<div class="field" style="flex:1;min-width:140px;margin:0;"><label class="field-label" style="font-size:11px">Chemins absents de la spécification</label><select id="prout-oa-unknown" class="input"><option value="allow" ${oa?.unknown_paths !== 'block' ? 'selected' : ''}>Laisser passer</option><option value="block" ${oa?.unknown_paths === 'block' ? 'selected' : ''}>Refuser (404 / 405)</option></select></div>`) +
        `<div style="margin-top:10px;">${row(field('prout-oa-prefix', 'Préfixe retiré avant la recherche', oa?.strip_prefix, 'placeholder="/api/v1"') + field('prout-oa-max', 'Corps max lu (octets)', oa?.max_body || '', 'type="number" min="0" placeholder="1048576"', false))}</div>` +
        `<div style="display:flex;gap:14px;flex-wrap:wrap;margin-top:10px;font-size:12px;"><span style="color:var(--text3);">Ne pas contrôler :</span>${[['path', 'chemin'], ['query', 'requête'], ['header', 'en-têtes'], ['cookie', 'cookies'], ['body', 'corps']].map(([k, l]) => `<label style="display:flex;align-items:center;gap:5px;cursor:pointer;"><input type="checkbox" class="prout-oa-skip" value="${k}" ${(oa?.skip || []).includes(k) ? 'checked' : ''}> ${l}</label>`).join('')}</div>` +
        area('prout-oa-spec', 'Spécification (YAML ou JSON)', typeof oa?.spec === 'string' ? oa.spec : (oa?.spec ? JSON.stringify(oa.spec, null, 2) : ''), 'spellcheck="false" placeholder="openapi: 3.0.3&#10;paths:&#10;  /users/{id}: …"', 14))}
      ${card('surface', 'Apprentissage de la surface', 'La passerelle observe le trafic légitime de ce proxy (méthodes, chemins, types de contenu, tailles, paramètres, clients) pour établir ce qui est réellement utilisé. Aucun blocage : le profil sert à comprendre, puis à proposer des réglages. Les requêtes d\'IP suspectes, ou qui échouent, n\'y entrent pas. Un profil n\'est fiable qu\'après 7 jours, 1 000 requêtes et 48 h sans nouveau chemin.', sf?.mode === 'learn',
        toggle('prout-sf-on', 'Apprendre la surface (aucun effet sur le trafic)', sf?.mode === 'learn') +
        `<div class="field" style="max-width:420px;margin:0 0 10px;"><label class="field-label" style="font-size:11px">Type de proxy</label><select id="prout-sf-type" class="input"><option value="" ${!sf?.type ? 'selected' : ''}>Non précisé (traité comme une API)</option><option value="api" ${sf?.type === 'api' ? 'selected' : ''}>API : surface fermée, une liste de chemins a un sens</option><option value="site" ${sf?.type === 'site' ? 'selected' : ''}>Site : contenu ouvert, des milliers de chemins</option></select></div>` +
        `<div style="display:flex;gap:8px;flex-wrap:wrap;"><button type="button" class="btn btn-secondary btn-sm" onclick="_proutSurfaceReport()">Voir le rapport</button><button type="button" class="btn btn-secondary btn-sm" onclick="_proutSurfaceProposals()">Voir les propositions</button><button type="button" class="btn btn-secondary btn-sm" onclick="_proutSurfaceOpenAPI()">Générer la politique (OpenAPI)</button><label style="display:flex;align-items:center;gap:6px;font-size:11px;color:var(--text3);cursor:pointer;"><input type="checkbox" id="prout-sf-low"> inclure les chemins à confirmer</label><button type="button" class="btn btn-secondary btn-sm" onclick="_proutSurfaceReset()">Repartir de zéro</button></div><div id="prout-sf-report" style="margin-top:10px;"></div><div id="prout-sf-proposals" style="margin-top:10px;"></div><div id="prout-sf-openapi" style="margin-top:10px;"></div>`)}
      ${card('grpc_transcode', 'Transcodage REST ↔ gRPC', 'Expose un backend gRPC unaire en REST/JSON : chaque méthode est publiée selon ses annotations google.api.http (get, post, body, response_body…). Le backend doit parler gRPC en HTTP/2 (h2c accepté en http://). Flux serveur : NDJSON ; flux client : corps en suite de valeurs JSON.', !!gt?.enabled,
        toggle('prout-gt-on', 'Activer', gt?.enabled) +
        (gtFiles.length > 1
          ? `<div style="font-size:12px;color:var(--text3);margin-bottom:8px;">${gtFiles.length} fichiers .proto enregistrés (${esc(gtFiles.join(', '))}) : à modifier par la CLI ou l'éditeur YAML — ils sont conservés tels quels.</div>`
          : row(`<div class="field" style="flex:1;min-width:160px;margin:0;"><label class="field-label" style="font-size:11px">Source des descripteurs</label><select id="prout-gt-src" class="input" onchange="_proutGtSrc()"><option value="proto" ${!gt?.descriptor_set ? 'selected' : ''}>Fichier .proto</option><option value="set" ${gt?.descriptor_set ? 'selected' : ''}>FileDescriptorSet (base64)</option></select></div>`)) +
        (gtFiles.length > 1 ? '' :
          `<div id="prout-gt-proto" style="display:${gt?.descriptor_set ? 'none' : 'block'}">${area('prout-gt-protosrc', 'Contenu du .proto (imports google/api/*, google/protobuf/* fournis)', gtFiles.length ? gt.proto[gtFiles[0]] : '', 'spellcheck="false" placeholder="syntax = &quot;proto3&quot;;&#10;import &quot;google/api/annotations.proto&quot;;&#10;service Users { rpc Get(Req) returns (Res) { option (google.api.http) = { get: &quot;/v1/users/{id}&quot; }; } }"', 12)}</div>` +
          `<div id="prout-gt-set" style="display:${gt?.descriptor_set ? 'block' : 'none'}">${area('prout-gt-setsrc', 'FileDescriptorSet en base64 (protoc --include_imports --descriptor_set_out=…)', gt?.descriptor_set || '', 'spellcheck="false"', 6)}</div>`) +
        `<div style="margin-top:10px;">${field('prout-gt-services', 'Services publiés (noms complets, virgules ; vide = tous)', (gt?.services || []).join(', '), 'placeholder="demo.v1.Users"')}</div>` +
        `<div style="display:flex;gap:16px;flex-wrap:wrap;margin-top:10px;font-size:12px;">${[['prout-gt-auto', 'Publier aussi les méthodes sans annotation en POST /paquet.Service/Méthode', gt?.auto_mapping], ['prout-gt-defaults', 'Écrire les champs à valeur par défaut', gt?.emit_defaults], ['prout-gt-names', 'Garder les noms de champs du .proto', gt?.proto_field_names]].map(([id, l, c]) => `<label style="display:flex;align-items:center;gap:5px;cursor:pointer;"><input type="checkbox" id="${id}" ${c ? 'checked' : ''}> ${l}</label>`).join('')}</div>`)}`;
  };

  // Lit les cartes et renvoie les options à poser. Une option sans interrupteur actif est retirée,
  // sauf celles qui portent un `enabled` et existaient déjà (on garde leurs réglages désactivés).
  window._proutCollect = function (prev) {
    prev = prev || {};
    if (!document.getElementById('prout-split-on')) {
      const keep = {};
      for (const k of ['split', 'maintenance', 'signed_url', 'graphql', 'hedge', 'grpc_web', 'bandwidth', 'redact_json', 'html_inject', 'static', 'request_schema', 'openapi', 'grpc_transcode', 'surface'])
        if (prev[k] !== undefined) keep[k] = prev[k];
      return keep;
    }
    const out = {};
    if (checked('prout-split-on')) {
      const variants = [...document.querySelectorAll('.prout-variant')].map(r => ({
        name: r.querySelector('.prout-v-name').value.trim(),
        backend: r.querySelector('.prout-v-backend').value.trim(),
        weight: parseInt(r.querySelector('.prout-v-weight').value, 10) || 1,
      })).filter(v => v.name || v.backend);
      if (variants.length < 2) throw new Error('Split : au moins deux variantes sont nécessaires');
      if (variants.some(v => !v.name || !/^https?:\/\/.+/.test(v.backend))) throw new Error('Split : chaque variante exige un nom et une URL http(s)');
      out.split = { variants, ...(val('prout-split-cookie') ? { sticky_cookie: val('prout-split-cookie') } : {}), ...(val('prout-split-override') ? { override: val('prout-split-override') } : {}) };
    }
    if (checked('prout-mt-on') || prev.maintenance) {
      out.maintenance = {
        enabled: checked('prout-mt-on'),
        ...(val('prout-mt-msg') ? { message: val('prout-mt-msg') } : {}),
        ...(document.getElementById('prout-mt-html')?.value.trim() ? { html: document.getElementById('prout-mt-html').value } : {}),
        ...(num('prout-mt-retry') > 0 ? { retry_after_sec: num('prout-mt-retry') } : {}),
        ...(csv(val('prout-mt-cidrs')).length ? { bypass_cidrs: csv(val('prout-mt-cidrs')) } : {}),
        ...(val('prout-mt-header') ? { bypass_header: val('prout-mt-header') } : {}),
      };
    }
    if (checked('prout-su-on') || prev.signed_url) {
      if (checked('prout-su-on') && !val('prout-su-secret')) throw new Error('URLs signées : le secret est obligatoire');
      out.signed_url = {
        enabled: checked('prout-su-on'),
        secret: val('prout-su-secret'),
        ...(val('prout-su-sig') ? { param_sig: val('prout-su-sig') } : {}),
        ...(val('prout-su-exp') ? { param_expires: val('prout-su-exp') } : {}),
        ...(csv(val('prout-su-paths')).length ? { paths: csv(val('prout-su-paths')) } : {}),
      };
    }
    if (checked('prout-gq-on') || prev.graphql) {
      out.graphql = {
        enabled: checked('prout-gq-on'),
        ...(num('prout-gq-depth') > 0 ? { max_depth: num('prout-gq-depth') } : {}),
        ...(num('prout-gq-alias') > 0 ? { max_aliases: num('prout-gq-alias') } : {}),
        ...(checked('prout-gq-intro') ? { block_introspection: true } : {}),
      };
    }
    if (checked('prout-hg-on')) {
      if (num('prout-hg-delay') <= 0) throw new Error('Hedge : le délai (ms) est obligatoire');
      out.hedge = { delay_ms: num('prout-hg-delay'), ...(num('prout-hg-extra') > 0 ? { max_extra: num('prout-hg-extra') } : {}) };
    }
    if (checked('prout-gw-on')) out.grpc_web = true;
    if (checked('prout-bw-on')) {
      if (num('prout-bw-bps') <= 0) throw new Error('Plafond de débit : indiquer des octets par seconde');
      out.bandwidth = { bytes_per_sec: num('prout-bw-bps') };
    }
    if (checked('prout-rj-on')) {
      const fields = lines(document.getElementById('prout-rj-fields')?.value);
      if (!fields.length) throw new Error('Masquage JSON : indiquer au moins un champ');
      out.redact_json = { fields, ...(val('prout-rj-mask') ? { mask: val('prout-rj-mask') } : {}) };
    }
    if (checked('prout-hi-on')) {
      const content = document.getElementById('prout-hi-content')?.value || '';
      if (!content.trim()) throw new Error('Injection HTML : le fragment est obligatoire');
      if (content.length > 16384) throw new Error('Injection HTML : 16 Kio au maximum');
      out.html_inject = { content, position: val('prout-hi-pos') === 'head_end' ? 'head_end' : 'body_end', ...(checked('prout-hi-nonce') ? { csp_nonce: true } : {}) };
    }
    if (checked('prout-st-on') || prev.static) {
      if (checked('prout-st-on') && !val('prout-st-root')) throw new Error('Fichiers statiques : le dossier est obligatoire');
      out.static = {
        enabled: checked('prout-st-on'),
        root: val('prout-st-root'),
        ...(val('prout-st-index') ? { index: val('prout-st-index') } : {}),
        ...(checked('prout-st-spa') ? { spa_fallback: true } : {}),
        ...(num('prout-st-cache') > 0 ? { cache_max_age: num('prout-st-cache') } : {}),
      };
    }
    if (checked('prout-rs-on') || prev.request_schema) {
      let rules;
      try { rules = JSON.parse(document.getElementById('prout-rs-rules')?.value || '[]'); } catch (err) { throw new Error('Schéma de requête : règles JSON invalides (' + err.message + ')'); }
      if (!Array.isArray(rules)) throw new Error('Schéma de requête : les règles doivent former un tableau');
      out.request_schema = {
        enabled: checked('prout-rs-on'),
        mode: val('prout-rs-mode') === 'detect' ? 'detect' : 'block',
        ...(num('prout-rs-max') > 0 ? { max_body: num('prout-rs-max') } : {}),
        rules,
      };
    }
    if (checked('prout-oa-on') || prev.openapi) {
      const spec = document.getElementById('prout-oa-spec')?.value || '';
      if (checked('prout-oa-on') && !spec.trim()) throw new Error('OpenAPI : la spécification est obligatoire');
      const skip = [...document.querySelectorAll('.prout-oa-skip:checked')].map(c => c.value);
      out.openapi = {
        enabled: checked('prout-oa-on'),
        spec,
        mode: val('prout-oa-mode') === 'detect' ? 'detect' : 'block',
        ...(val('prout-oa-unknown') === 'block' ? { unknown_paths: 'block' } : {}),
        ...(val('prout-oa-prefix') ? { strip_prefix: val('prout-oa-prefix') } : {}),
        ...(num('prout-oa-max') > 0 ? { max_body: num('prout-oa-max') } : {}),
        ...(skip.length ? { skip } : {}),
        ...(prev.openapi?.block_reasons?.length ? { block_reasons: prev.openapi.block_reasons } : {}),
      };
    }
    if (checked('prout-sf-on') || prev.surface) out.surface = { mode: checked('prout-sf-on') ? 'learn' : 'off', ...(val('prout-sf-type') ? { type: val('prout-sf-type') } : {}) };
    if (checked('prout-gt-on') || prev.grpc_transcode) {
      const prevGt = prev.grpc_transcode || {};
      const multi = Object.keys(prevGt.proto || {}).length > 1;
      const useSet = !multi && val('prout-gt-src') === 'set';
      const protoText = document.getElementById('prout-gt-protosrc')?.value || '';
      const setText = val('prout-gt-setsrc');
      const gt = { enabled: checked('prout-gt-on') };
      if (multi) gt.proto = prevGt.proto;
      else if (useSet) gt.descriptor_set = setText;
      else if (protoText.trim()) gt.proto = { [Object.keys(prevGt.proto || {})[0] || 'service.proto']: protoText };
      if (checked('prout-gt-on') && !gt.proto && !gt.descriptor_set) throw new Error('Transcodage gRPC : renseigner un fichier .proto ou un FileDescriptorSet');
      if (csv(val('prout-gt-services')).length) gt.services = csv(val('prout-gt-services'));
      if (checked('prout-gt-auto')) gt.auto_mapping = true;
      if (checked('prout-gt-defaults')) gt.emit_defaults = true;
      if (checked('prout-gt-names')) gt.proto_field_names = true;
      for (const k of ['max_request_body', 'max_response_body']) if (prevGt[k]) gt[k] = prevGt[k];
      out.grpc_transcode = gt;
    }
    return out;
  };
})();
