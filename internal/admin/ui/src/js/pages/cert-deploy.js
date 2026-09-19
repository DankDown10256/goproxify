// ── Certificate Deploy Hub ─────────────────────────────────────────────────

pages['cert-deploy'] = async function() {
  const content = document.getElementById('page-content');
  content.innerHTML = `<p style="opacity:0.5;font-size:13px;">${t('common.loading')}</p>`;

  const certs = await api('GET', '/certs').catch(() => []);
  const list = Array.isArray(certs) ? certs : [];

  content.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;flex-wrap:wrap;gap:12px;">
      <div>
        <h1 style="margin:0 0 4px;font-size:28px;font-family:var(--font-heading);font-weight:600;">${t('cert_deploy.title')}</h1>
        <p style="margin:0;opacity:0.65;font-size:14px;">${t('cert_deploy.subtitle')}</p>
      </div>
    </div>
    ${!list.length ? `
      <div style="text-align:center;padding:48px 16px;opacity:0.5;font-size:14px;">
        <svg width="40" height="40" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24" style="margin-bottom:12px;opacity:0.4"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        <p>${t('cert_deploy.no_certs')}</p>
      </div>` :
      `<div id="cert-deploy-list" style="display:flex;flex-direction:column;gap:16px;">
        ${list.map(c => certDeployCard(c)).join('')}
      </div>`
    }
    <div id="cert-deploy-panel"></div>`;
};

function certDeployCard(c) {
  const exp = c.expires_at ? new Date(c.expires_at) : null;
  const daysLeft = exp ? Math.ceil((exp - Date.now()) / 86400000) : null;
  const expColor = daysLeft !== null ? (daysLeft < 7 ? 'var(--red)' : daysLeft < 30 ? 'var(--yellow,#f59e0b)' : 'var(--green)') : 'var(--text2)';
  return `<div class="card" style="padding:16px 18px;">
    <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;margin-bottom:14px;">
      <div>
        <span style="font-weight:600;font-size:15px;">${esc(c.domain)}</span>
        <span style="margin-left:10px;font-size:11px;opacity:0.55;">${esc(c.issuer||'')}</span>
      </div>
      <div style="display:flex;align-items:center;gap:10px;">
        ${daysLeft !== null ? `<span style="font-size:11px;color:${expColor};">Exp. ${fmtDate ? fmtDate(c.expires_at) : c.expires_at} (J${daysLeft >= 0 ? '-' : '+'}${Math.abs(daysLeft)})</span>` : ''}
        <button class="btn btn-secondary" style="font-size:12px;" onclick="openCertDeployPanel('${esc(c.id)}','${esc(c.domain)}')">
          Gérer les déploiements
        </button>
      </div>
    </div>
    <div id="cert-targets-${esc(c.id)}" style="display:none;"></div>
  </div>`;
}

window.openCertDeployPanel = async function(certID, domain) {
  const panel = document.getElementById('cert-deploy-panel');
  panel.innerHTML = '';

  const overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed;inset:0;z-index:9990;background:rgba(0,0,0,0.45);display:flex;align-items:flex-start;justify-content:flex-end;';
  overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };

  const drawer = document.createElement('div');
  drawer.style.cssText = 'background:var(--bg1);border-left:1px solid var(--border);width:min(560px,100vw);height:100vh;overflow-y:auto;padding:24px;display:flex;flex-direction:column;gap:0;';
  drawer.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;">
      <div>
        <h2 style="margin:0 0 2px;font-size:18px;font-weight:600;">${esc(domain)}</h2>
        <p style="margin:0;font-size:12px;opacity:0.55;">Déploiements & tokens de pull</p>
      </div>
      <button class="btn btn-ghost btn-icon" onclick="this.closest('.cert-deploy-overlay').remove()"><svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6 6 18M6 6l12 12"/></svg></button>
    </div>

    <div style="display:flex;gap:0;border-bottom:1px solid var(--border);margin-bottom:20px;" id="cdtabs">
      <button class="btn btn-ghost" style="border-radius:0;border-bottom:2px solid var(--accent);font-size:13px;padding:8px 14px;" onclick="cdTab('targets','${esc(certID)}','${esc(domain)}')" id="cdtab-targets">Deploy Targets</button>
      <button class="btn btn-ghost" style="border-radius:0;border-bottom:2px solid transparent;font-size:13px;padding:8px 14px;" onclick="cdTab('tokens','${esc(certID)}','${esc(domain)}')" id="cdtab-tokens">Pull Tokens</button>
    </div>
    <div id="cd-tab-content" style="flex:1;"></div>`;

  drawer.classList.add('cert-deploy-overlay');
  overlay.appendChild(drawer);
  panel.appendChild(overlay);

  await cdLoadTargets(certID, domain);
};

window.cdTab = async function(tab, certID, domain) {
  document.getElementById('cdtab-targets').style.borderBottom = tab === 'targets' ? '2px solid var(--accent)' : '2px solid transparent';
  document.getElementById('cdtab-tokens').style.borderBottom = tab === 'tokens' ? '2px solid var(--accent)' : '2px solid transparent';
  if (tab === 'targets') await cdLoadTargets(certID, domain);
  else await cdLoadTokens(certID, domain);
};

async function cdLoadTargets(certID, domain) {
  const el = document.getElementById('cd-tab-content');
  if (!el) return;
  el.innerHTML = `<p style="opacity:0.5;font-size:13px;">${t('common.loading')}</p>`;

  const targets = await api('GET', `/certs/${certID}/deploy-targets`).catch(() => []);

  el.innerHTML = `
    <div style="margin-bottom:16px;display:flex;justify-content:flex-end;">
      <button class="btn btn-primary" style="font-size:12px;" onclick="openAddTargetModal('${esc(certID)}','${esc(domain)}')">+ Nouveau target</button>
    </div>
    ${!(targets||[]).length ? `<p style="opacity:0.5;font-size:13px;text-align:center;padding:32px 0;">Aucun deploy target configuré.</p>` :
    `<div style="display:flex;flex-direction:column;gap:10px;">
      ${targets.map(tgt => targetRow(tgt, certID, domain)).join('')}
    </div>`}`;
}

function targetRow(tgt, certID, domain) {
  const statusColor = tgt.last_status === 'ok' ? 'var(--green)' : tgt.last_status === 'error' ? 'var(--red)' : 'var(--text2)';
  const typeIcon = tgt.type === 'webhook'
    ? `<svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>`
    : `<svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>`;

  const cfg = tgt.config || {};
  const cfgHint = tgt.type === 'webhook' ? esc(cfg.url || '') : '';

  return `<div class="card" style="padding:12px 14px;">
    <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;">
      <div style="display:flex;align-items:center;gap:8px;min-width:0;">
        <span style="opacity:0.55;">${typeIcon}</span>
        <div style="min-width:0;">
          <div style="font-weight:500;font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${esc(tgt.name)}</div>
          ${cfgHint ? `<div style="font-size:11px;opacity:0.5;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${cfgHint}</div>` : ''}
        </div>
      </div>
      <div style="display:flex;align-items:center;gap:8px;flex-shrink:0;">
        <span style="font-size:11px;color:${statusColor};">${esc(tgt.last_status)}</span>
        ${tgt.last_deploy ? `<span style="font-size:11px;opacity:0.4;">${fmtDate ? fmtDate(tgt.last_deploy) : tgt.last_deploy}</span>` : ''}
        <button class="btn btn-ghost btn-icon" title="Déclencher" onclick="triggerTarget('${esc(tgt.id)}','${esc(certID)}','${esc(domain)}')">
          <svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polygon points="5 3 19 12 5 21 5 3"/></svg>
        </button>
        <button class="btn btn-ghost btn-icon" title="Historique" onclick="openTargetHistory('${esc(tgt.id)}','${esc(tgt.name)}','${esc(certID)}')">
          <svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 102.13-9.36L1 10"/></svg>
        </button>
        <button class="btn btn-ghost btn-icon" title="Supprimer" onclick="deleteTarget('${esc(tgt.id)}','${esc(certID)}','${esc(domain)}')">
          <svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M3 6h18"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/></svg>
        </button>
      </div>
    </div>
  </div>`;
}

async function cdLoadTokens(certID, domain) {
  const el = document.getElementById('cd-tab-content');
  if (!el) return;
  el.innerHTML = `<p style="opacity:0.5;font-size:13px;">${t('common.loading')}</p>`;

  const tokens = await api('GET', `/certs/${certID}/pull-tokens`).catch(() => []);
  const baseURL = window.location.origin;

  el.innerHTML = `
    <div style="background:color-mix(in srgb,var(--accent) 8%,transparent);border:1px solid color-mix(in srgb,var(--accent) 25%,transparent);border-radius:8px;padding:12px 14px;margin-bottom:16px;font-size:12px;line-height:1.55;">
      Un pull token permet à n'importe quelle machine de télécharger le certificat via <code>curl "${baseURL}/api/v1/cert-bundle?token=TOKEN&format=pem"</code>. Le token est affiché une seule fois à la création.
    </div>
    <div style="margin-bottom:16px;display:flex;justify-content:flex-end;">
      <button class="btn btn-primary" style="font-size:12px;" onclick="openAddTokenModal('${esc(certID)}','${esc(domain)}')">+ Nouveau token</button>
    </div>
    ${!(tokens||[]).length ? `<p style="opacity:0.5;font-size:13px;text-align:center;padding:32px 0;">Aucun pull token configuré.</p>` :
    `<div class="table-wrap"><table>
      <thead><tr>
        <th style="font-size:11px;">Nom</th>
        <th style="font-size:11px;">Format</th>
        <th style="font-size:11px;">Usages</th>
        <th style="font-size:11px;">Expiration</th>
        <th style="font-size:11px;"></th>
      </tr></thead>
      <tbody>${(tokens||[]).map(tk => `<tr>
        <td style="font-size:13px;">${esc(tk.name)}</td>
        <td><code style="font-size:11px;">${esc(tk.format)}</code></td>
        <td style="font-size:12px;">${tk.uses}/${tk.max_uses <= 0 ? '∞' : tk.max_uses}</td>
        <td style="font-size:12px;${!tk.expires_at?'opacity:0.4':''}">${tk.expires_at ? (fmtDate ? fmtDate(tk.expires_at) : tk.expires_at) : '—'}</td>
        <td style="text-align:right;">
          <button class="btn btn-ghost btn-icon" title="Révoquer" onclick="revokeToken('${esc(tk.id)}','${esc(certID)}','${esc(domain)}')">
            <svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M3 6h18"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/></svg>
          </button>
        </td>
      </tr>`).join('')}</tbody>
    </table></div>`}`;
}

// ── Actions ─────────────────────────────────────────────────────────────────

window.openAddTargetModal = function(certID, domain) {
  modal(
    'Nouveau deploy target',
    `<div style="display:flex;flex-direction:column;gap:14px;">
      <div class="field"><label>Nom</label><input class="input" id="tgt-name" placeholder="Ex: nginx-prod" autofocus></div>
      <div class="field"><label>Type</label>
        <select class="input" id="tgt-type" onchange="onTgtTypeChange()">
          <option value="webhook">Webhook (HTTP POST signé)</option>
        </select>
      </div>
      <div id="tgt-cfg-webhook" style="display:flex;flex-direction:column;gap:10px;">
        <div class="field"><label>URL du webhook</label><input class="input" id="tgt-url" placeholder="https://votre-serveur.com/cert-hook" type="url"></div>
        <div class="field"><label>Secret HMAC <span style="opacity:0.5;font-size:11px;">(optionnel)</span></label><input class="input" id="tgt-secret" placeholder="Clé secrète partagée" type="password" autocomplete="new-password"></div>
      </div>
      <div class="field"><label>Déclenchement</label>
        <select class="input" id="tgt-trigger">
          <option value="on_renewal">Automatique — à chaque renouvellement</option>
          <option value="manual">Manuel uniquement</option>
        </select>
      </div>
    </div>`,
    `<button class="btn btn-secondary" onclick="closeModal()">${t('common.cancel')}</button>
     <button class="btn btn-primary" onclick="submitAddTarget('${esc(certID)}','${esc(domain)}')">Créer</button>`,
    false
  );
};

window.onTgtTypeChange = function() {};

window.submitAddTarget = async function(certID, domain) {
  const name = document.getElementById('tgt-name')?.value.trim();
  const type = document.getElementById('tgt-type')?.value;
  const triggerOn = document.getElementById('tgt-trigger')?.value;
  let config = {};
  if (type === 'webhook') {
    config = {
      url: document.getElementById('tgt-url')?.value.trim(),
      secret: document.getElementById('tgt-secret')?.value.trim(),
    };
    if (!config.url) { alert('URL requise'); return; }
    if (!config.secret) delete config.secret;
  }
  if (!name) { alert('Nom requis'); return; }
  try {
    await api('POST', `/certs/${certID}/deploy-targets`, { name, type, config, trigger_on: triggerOn });
    closeModal();
    await cdLoadTargets(certID, domain);
  } catch(e) {
    alert(e.message || 'Erreur');
  }
};

window.triggerTarget = async function(targetID, certID, domain) {
  try {
    await api('POST', `/certs/${certID}/deploy-targets/${targetID}/trigger`);
    setTimeout(() => cdLoadTargets(certID, domain), 1500);
  } catch(e) {
    alert(e.message || 'Erreur');
  }
};

window.deleteTarget = async function(targetID, certID, domain) {
  if (!confirm('Supprimer ce deploy target ?')) return;
  await api('DELETE', `/certs/${certID}/deploy-targets/${targetID}`).catch(() => {});
  await cdLoadTargets(certID, domain);
};

window.openTargetHistory = async function(targetID, targetName, certID) {
  modal(
    `Historique — ${esc(targetName)}`,
    `<p style="opacity:0.5;font-size:13px;">${t('common.loading')}</p>`,
    `<button class="btn btn-secondary" onclick="closeModal()">${t('common.close')}</button>`,
    false
  );
  const body = document.querySelector('#modal-overlay .dialog-body');
  if (!body) return;

  const hist = await api('GET', `/certs/${certID}/deploy-targets/${targetID}/history`).catch(() => []);
  if (!(hist||[]).length) {
    body.innerHTML = '<p style="opacity:0.5;font-size:13px;margin:0;">Aucun historique.</p>';
    return;
  }
  body.innerHTML = `<div class="table-wrap"><table>
    <thead><tr><th style="font-size:11px;">Date</th><th style="font-size:11px;">Statut</th><th style="font-size:11px;">Message</th></tr></thead>
    <tbody>${hist.map(h => `<tr>
      <td style="font-size:12px;white-space:nowrap">${fmtDate ? fmtDate(h.deployed_at) : h.deployed_at}</td>
      <td><span style="color:${h.status==='ok'?'var(--green)':'var(--red)'};font-size:12px;">${esc(h.status)}</span></td>
      <td style="font-size:12px;opacity:0.65;">${esc(h.message)}</td>
    </tr>`).join('')}</tbody>
  </table></div>`;
};

window.openAddTokenModal = function(certID, domain) {
  modal(
    'Nouveau pull token',
    `<div style="display:flex;flex-direction:column;gap:14px;">
      <div class="field"><label>Nom</label><input class="input" id="ptk-name" placeholder="Ex: deploy-ci" autofocus></div>
      <div class="field"><label>Format</label>
        <select class="input" id="ptk-format">
          <option value="pem">PEM (certificat seul)</option>
          <option value="key">PEM (clé privée seule)</option>
          <option value="fullchain">Full chain (cert + clé)</option>
          <option value="json">JSON (cert + clé)</option>
        </select>
      </div>
      <div style="display:flex;gap:12px;">
        <div class="field" style="flex:1"><label>Usages max</label><input class="input" id="ptk-uses" type="number" min="0" value="1" placeholder="0 = illimité"></div>
        <div class="field" style="flex:1"><label>TTL (heures)</label><input class="input" id="ptk-ttl" type="number" min="0" value="24" placeholder="0 = pas d'expiration"></div>
      </div>
      <p style="font-size:12px;opacity:0.5;margin:0;">Le token sera affiché <strong>une seule fois</strong> à la création.</p>
    </div>`,
    `<button class="btn btn-secondary" onclick="closeModal()">${t('common.cancel')}</button>
     <button class="btn btn-primary" onclick="submitAddToken('${esc(certID)}','${esc(domain)}')">Créer</button>`,
    false
  );
};

window.submitAddToken = async function(certID, domain) {
  const name = document.getElementById('ptk-name')?.value.trim() || '';
  const format = document.getElementById('ptk-format')?.value || 'pem';
  const maxUses = parseInt(document.getElementById('ptk-uses')?.value || '1', 10);
  const ttlHours = parseInt(document.getElementById('ptk-ttl')?.value || '24', 10);
  try {
    const res = await api('POST', `/certs/${certID}/pull-tokens`, { name, format, max_uses: maxUses, ttl_hours: ttlHours });
    closeModal();
    const baseURL = window.location.origin;
    const curlCmd = `curl -s "${baseURL}/api/v1/cert-bundle?token=${res.token}&format=${res.format}" -o cert.${format === 'key' ? 'key' : format === 'json' ? 'json' : 'pem'}`;
    modal(
      'Token créé — conservez-le maintenant',
      `<p style="font-size:13px;margin:0 0 12px;">Ce token <strong>ne sera plus affiché</strong>. Copiez-le maintenant :</p>
       <div style="display:flex;gap:6px;align-items:center;">
         <code id="pull-token-val" style="flex:1;font-size:11px;background:var(--bg2);padding:8px 10px;border-radius:6px;word-break:break-all;cursor:text;">${esc(res.token)}</code>
         <button class="btn btn-ghost btn-icon" title="Copier" onclick="navigator.clipboard.writeText('${esc(res.token)}').then(()=>this.innerHTML='✓')"><svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></button>
       </div>
       <p style="font-size:12px;margin:14px 0 4px;opacity:0.65;">Commande d'exemple :</p>
       <code style="font-size:11px;background:var(--bg2);padding:8px 10px;border-radius:6px;display:block;word-break:break-all;">${esc(curlCmd)}</code>`,
      `<button class="btn btn-primary" onclick="closeModal()">J'ai copié le token</button>`,
      false
    );
    cdLoadTokens(certID, domain);
  } catch(e) {
    alert(e.message || 'Erreur');
  }
};

window.revokeToken = async function(tokenID, certID, domain) {
  if (!confirm('Révoquer ce token ? Les machines qui l\'utilisent ne pourront plus récupérer le certificat.')) return;
  await api('DELETE', `/certs/${certID}/pull-tokens/${tokenID}`).catch(() => {});
  await cdLoadTokens(certID, domain);
};
