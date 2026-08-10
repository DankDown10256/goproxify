// ── PAGE: Onboarding wizard ─────────────────────────────────────────────
// Extrait de pages-all.js — phase 3. Appelé aussi via checkNeedOnboarding (auth).

// ── ONBOARDING WIZARD ─────────────────────────────────────────────────────

const onb = { step: 0, mode: null, infra: null, token: null, pollTimer: null, backupData: null, backupSummary: null, configProxies: null, dnsProvider: 'none', pendingNodes: [], acceptedNodes: [] };

const DNS_PROVIDERS = [
  { id: 'none',       nameKey: 'onboarding.dns.none', hintKey: 'onboarding.dns.none_hint', fields: [] },
  { id: 'cloudflare', name: 'Cloudflare',        hintKey: 'onboarding.dns.cloudflare_hint',
    fields: [{ id:'api_token',                label:'API Token',          type:'password' }] },
  { id: 'ovh',        name: 'OVH',               hintKey: 'onboarding.dns.ovh_hint',
    fields: [
      { id:'endpoint',               label:'Endpoint',           type:'text',     placeholder:'ovh-eu' },
      { id:'app_key',                label:'Application Key',    type:'password' },
      { id:'app_secret',             label:'Application Secret', type:'password' },
      { id:'consumer_key',           label:'Consumer Key',       type:'password' },
    ] },
  { id: 'gandi',      name: 'Gandi',             hintKey: 'onboarding.dns.gandi_hint',
    fields: [{ id:'api_key',                    label:'API Key',            type:'password' }] },
  { id: 'route53',    name: 'AWS Route53',        hintKey: 'onboarding.dns.route53_hint',
    fields: [
      { id:'AWS_ACCESS_KEY_ID',      label:'Access Key ID',      type:'text' },
      { id:'AWS_SECRET_ACCESS_KEY',  label:'Secret Access Key',  type:'password' },
      { id:'AWS_REGION',             label:'Region',             type:'text',     placeholder:'eu-west-1' },
    ] },
  { id: 'hetzner',    name: 'Hetzner',            hintKey: 'onboarding.dns.hetzner_hint',
    fields: [{ id:'HETZNER_API_KEY',             label:'API Key',            type:'password' }] },
];

const INFRA_SVG = {
  standalone: `<svg width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.8" viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>`,
  'cluster-ha': `<svg width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.8" viewBox="0 0 24 24"><path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"/></svg>`,
  'multi-region': `<svg width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.8" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>`,
  kubernetes: `<svg width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.8" viewBox="0 0 24 24"><polygon points="12 2 19 6.5 19 17.5 12 22 5 17.5 5 6.5"/><line x1="12" y1="2" x2="12" y2="22"/><line x1="5" y1="6.5" x2="19" y2="17.5"/><line x1="19" y1="6.5" x2="5" y2="17.5"/></svg>`,
};

const INFRA_TYPES = [
  {
    id: 'standalone',
    nameKey: 'onboarding.infra.standalone.name',
    descKey: 'onboarding.infra.standalone.desc',
    tagKeys: ['onboarding.infra.standalone.tag1', 'onboarding.infra.standalone.tag2', 'onboarding.infra.standalone.tag3'],
    minCores: 1,
    cmdExtra: '',
  },
  {
    id: 'cluster-ha',
    nameKey: 'onboarding.infra.cluster_ha.name',
    descKey: 'onboarding.infra.cluster_ha.desc',
    tagKeys: ['onboarding.infra.cluster_ha.tag1', 'onboarding.infra.cluster_ha.tag2', 'onboarding.infra.cluster_ha.tag3'],
    minCores: 3,
    cmdExtra: ' \\\n  --cluster-enabled \\\n  --cluster-group=cluster-1 \\\n  --node-id=core-1 \\\n  --raft-port=8002 \\\n  --peers=core-2:8002,core-3:8002',
  },
  {
    id: 'multi-region',
    nameKey: 'onboarding.infra.multi_region.name',
    descKey: 'onboarding.infra.multi_region.desc',
    tagKeys: ['onboarding.infra.multi_region.tag1', 'onboarding.infra.multi_region.tag2', 'onboarding.infra.multi_region.tag3'],
    minCores: 3,
    cmdExtra: ' \\\n  --cluster-enabled \\\n  --cluster-group=eu-cluster \\\n  --node-id=core-eu-1 \\\n  --raft-port=8002 \\\n  --region=eu-west \\\n  --peers=core-eu-2:8002,core-us-1:8002',
  },
  {
    id: 'kubernetes',
    nameKey: 'onboarding.infra.kubernetes.name',
    descKey: 'onboarding.infra.kubernetes.desc',
    tagKeys: ['onboarding.infra.kubernetes.tag1', 'onboarding.infra.kubernetes.tag2', 'onboarding.infra.kubernetes.tag3'],
    minCores: 1,
    cmdExtra: null,
  },
];

async function checkNeedOnboarding() {
  try {
    const nodes = await api('GET', '/nodes');
    const list = nodes || [];
    // Un Core "connu" = a déjà envoyé un heartbeat (entrée dans la table nodes).
    // Les statuts 'pending' et 'declared' ne comptent pas : le nœud n'a pas encore prouvé
    // sa connexion. On ne retrigge pas le wizard si un Core reconnu est temporairement offline.
    const hasCoreRegistered = list.some(
      n => n.role === 'core' && n.status !== 'pending' && n.status !== 'declared'
    );
    return !hasCoreRegistered;
  } catch { return false; }
}

pages.onboarding = async function() {
  document.getElementById('topbar-actions').innerHTML =
    `<button class="btn btn-secondary btn-sm" onclick="stopCorePolling();navigate('dashboard')">${t('onboarding.skip_wizard')}</button>`;
  try {
    const nodes = await api('GET', '/nodes');
    onb.pendingNodes = (nodes || []).filter(n => n.status === 'pending');
  } catch { onb.pendingNodes = []; }
  renderWizardStep();
};

function renderWizardStep() {
  const content = document.getElementById('content');
  content.innerHTML = `<div class="wizard-wrap">${wizardStepsHtml()}<div id="wizard-body"></div></div>`;
  const body = document.getElementById('wizard-body');
  if (onb.step === 0) { body.innerHTML = wizardStep0Html(); return; }
  if (onb.mode === 'deploy') {
    if (onb.step === 1) body.innerHTML = wizardStep1Html();      // choix infra
    else if (onb.step === 2) body.innerHTML = wizardStep2Html(); // config files
    else body.innerHTML = wizardStep3Html();                     // attente + accept
  } else if (onb.mode === 'import-backup') {
    if (onb.step === 1) body.innerHTML = wizardImport1Html();
    else if (onb.step === 2) body.innerHTML = wizardImport2Html();
    else body.innerHTML = wizardImportDoneHtml();
  } else if (onb.mode === 'migrate-config') {
    if (onb.step === 1) body.innerHTML = wizardMigrateCoreHtml();   // vérif Core
    else if (onb.step === 2) body.innerHTML = wizardMigrate1Html(); // format + contenu
    else if (onb.step === 3) body.innerHTML = wizardMigrate2Html(); // sélection proxies
    else body.innerHTML = wizardMigrateDoneHtml();
  } else if (onb.mode === 'detect') {
    body.innerHTML = wizardPendingHtml();
  }
}

function wizardStepsHtml() {
  if (onb.step === 0 || onb.mode === null || onb.mode === 'detect') return '';
  const labels = {
    'deploy':         [t('onboarding.step.infrastructure'), t('onboarding.step.deployment'), t('onboarding.step.connection')],
    'import-backup':  [t('onboarding.step.backup'), t('onboarding.step.selection'), t('onboarding.step.done')],
    'migrate-config': [t('onboarding.step.core'), t('onboarding.step.import'), t('onboarding.step.selection'), t('onboarding.step.done')],
  };
  const steps = labels[onb.mode] || [];
  // step 1 = index 0 dans le breadcrumb
  const activeIdx = onb.step - 1;
  return `<div class="wizard-steps">
    ${steps.map((s, i) => {
      const done = i < activeIdx;
      const active = i === activeIdx;
      return (i > 0 ? `<div class="wizard-step-line${done ? ' done' : ''}"></div>` : '') +
        `<div class="wizard-step-item">
          <div class="wizard-step-bubble${done ? ' done' : active ? ' active' : ''}">${done ? '✓' : i+1}</div>
          <span class="wizard-step-label${active ? ' active' : ''}">${s}</span>
        </div>`;
    }).join('')}
  </div>`;
}

// ── Wizard étape -1 : architecture Goproxify ─────────────────────────────────
function wizardArchHtml() {
  return `
    <div class="wizard-card">
      <div class="wizard-title">${t('onboarding.welcome_title')}</div>
      <div class="wizard-sub">${t('onboarding.welcome_sub_arch')}</div>

      <!-- Schéma architecture -->
      <div style="margin:24px 0;padding:20px;background:var(--bg3);border-radius:10px;border:1px solid var(--border);">
        <div style="display:flex;align-items:center;justify-content:center;gap:0;flex-wrap:wrap;">

          <!-- Admin -->
          <div style="text-align:center;min-width:120px;">
            <div style="background:var(--accent);color:#fff;border-radius:8px;padding:10px 16px;font-weight:700;font-size:13px;display:inline-flex;flex-direction:column;align-items:center;gap:6px;">
              <svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>
              Admin
            </div>
            <div style="font-size:11px;color:var(--text2);margin-top:6px;">${t('onboarding.you_are_here')}</div>
          </div>

          <!-- Flèche Admin↔Core -->
          <div style="display:flex;flex-direction:column;align-items:center;padding:0 8px;gap:4px;">
            <div style="font-size:9px;color:var(--text3);">${t('onboarding.label_config')}</div>
            <svg width="28" height="16" viewBox="0 0 28 16" fill="none"><path d="M2 5h24M20 1l6 4-6 4" stroke="var(--accent)" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/><path d="M26 11H2M8 7l-6 4 6 4" stroke="var(--accent)" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" opacity=".5"/></svg>
          </div>

          <!-- Core(s) -->
          <div style="text-align:center;min-width:120px;">
            <div style="background:var(--bg2);border:2px solid var(--accent);border-radius:8px;padding:10px 16px;font-weight:700;font-size:13px;display:inline-flex;flex-direction:column;align-items:center;gap:6px;">
              <svg width="20" height="20" fill="none" stroke="var(--accent)" stroke-width="2" viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
              Core
            </div>
            <div style="font-size:11px;color:var(--text2);margin-top:6px;">${t('onboarding.instances_1_to_n')}</div>
          </div>

          <!-- Flèche Core←Agent -->
          <div style="display:flex;flex-direction:column;align-items:center;padding:0 8px;gap:4px;">
            <div style="font-size:9px;color:var(--text3);">${t('onboarding.label_routes')}</div>
            <svg width="28" height="12" viewBox="0 0 28 12" fill="none"><path d="M26 6H2M8 2L2 6l6 4" stroke="var(--green)" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" stroke-dasharray="4 2"/></svg>
          </div>

          <!-- Agent -->
          <div style="text-align:center;min-width:120px;">
            <div style="background:var(--bg2);border:1.5px dashed var(--border);border-radius:8px;padding:10px 16px;font-weight:700;font-size:13px;display:inline-flex;flex-direction:column;align-items:center;gap:6px;opacity:.85;">
              <svg width="20" height="20" fill="none" stroke="var(--green)" stroke-width="2" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
              Agent
            </div>
            <div style="font-size:11px;color:var(--text2);margin-top:6px;">${t('onboarding.optional')}</div>
          </div>

        </div>
      </div>

      <!-- Rôles -->
      <div style="display:flex;flex-direction:column;gap:12px;">

        <div style="display:flex;gap:14px;padding:14px;background:var(--bg2);border-radius:8px;border:1px solid var(--border);">
          <div style="width:36px;height:36px;border-radius:8px;background:rgba(124,58,237,.12);display:flex;align-items:center;justify-content:center;flex-shrink:0;">
            <svg width="18" height="18" fill="none" stroke="var(--accent)" stroke-width="2" viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>
          </div>
          <div>
            <div style="font-weight:700;font-size:13px;margin-bottom:4px;">${t('onboarding.role_admin_title')}</div>
            <div style="font-size:12px;color:var(--text2);line-height:1.6;">
              ${t('onboarding.role_admin_desc')}
            </div>
          </div>
        </div>

        <div style="display:flex;gap:14px;padding:14px;background:var(--bg2);border-radius:8px;border:1px solid color-mix(in srgb,var(--accent) 25%,transparent);">
          <div style="width:36px;height:36px;border-radius:8px;background:rgba(124,58,237,.15);display:flex;align-items:center;justify-content:center;flex-shrink:0;">
            <svg width="18" height="18" fill="none" stroke="var(--accent)" stroke-width="2" viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
          </div>
          <div>
            <div style="font-weight:700;font-size:13px;margin-bottom:4px;">${t('onboarding.role_core_title')}</div>
            <div style="font-size:12px;color:var(--text2);line-height:1.6;">
              ${t('onboarding.role_core_desc')}
            </div>
          </div>
        </div>

        <div style="display:flex;gap:14px;padding:14px;background:var(--bg2);border-radius:8px;border:1px solid var(--border);opacity:.9;">
          <div style="width:36px;height:36px;border-radius:8px;background:rgba(34,197,94,.1);display:flex;align-items:center;justify-content:center;flex-shrink:0;">
            <svg width="18" height="18" fill="none" stroke="var(--green)" stroke-width="2" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
          </div>
          <div>
            <div style="font-weight:700;font-size:13px;margin-bottom:4px;">${t('onboarding.role_agent_title')}</div>
            <div style="font-size:12px;color:var(--text2);line-height:1.6;">
              ${t('onboarding.role_agent_desc')}
            </div>
          </div>
        </div>

      </div>

      <!-- Flux résumé -->
      <div style="margin-top:16px;padding:12px 16px;background:var(--bg3);border-radius:8px;border-left:3px solid var(--accent);font-size:12px;color:var(--text2);line-height:1.7;">
        <strong style="color:var(--text);">${t('onboarding.in_practice')}</strong>
        ${t('onboarding.practice_full')}
      </div>

    </div>
    <div class="wizard-nav">
      <span class="wizard-skip" onclick="onb.step=0;renderWizardStep()">${t('onboarding.back_to_choice')}</span>
      ${onb.mode === 'discover' ? '' : `<button class="btn btn-primary" onclick="onb.step=2;renderWizardStep()">${t('onboarding.continue')}</button>`}
    </div>`;
}

// ── Wizard étape 0 : choix du mode ───────────────────────────────────────────
function wizardStep0Html() {
  const pending = onb.pendingNodes.length;
  const detectBadge = pending > 0
    ? `<div style="position:absolute;top:-8px;right:-8px;background:#f97316;color:#fff;border-radius:99px;min-width:20px;height:20px;font-size:10px;font-weight:700;display:flex;align-items:center;justify-content:center;padding:0 5px;z-index:1">${pending}</div>`
    : '';

  const tile = (mode, iconHtml, title, desc, badge = '', accent = false) => `
    <div onclick="selectOnbMode('${mode}')" style="position:relative;flex:1;min-width:0;background:var(--bg2);border:1.5px solid ${accent ? 'var(--accent)' : 'var(--border)'};border-radius:12px;padding:24px 16px 20px;cursor:pointer;transition:all .18s;display:flex;flex-direction:column;align-items:center;gap:14px;text-align:center;"
      onmouseover="this.style.borderColor='var(--accent)';this.style.transform='translateY(-3px)';this.style.boxShadow='0 8px 24px rgba(0,0,0,.15)'"
      onmouseout="this.style.borderColor='${accent ? 'var(--accent)' : 'var(--border)'}';this.style.transform='';this.style.boxShadow=''">
      ${badge}
      <div style="width:52px;height:52px;border-radius:14px;background:${accent ? 'var(--accent)' : 'var(--bg3)'};display:flex;align-items:center;justify-content:center;flex-shrink:0;">
        ${iconHtml}
      </div>
      <div>
        <div style="font-weight:700;font-size:13px;margin-bottom:6px;color:var(--text)">${title}</div>
        <div style="font-size:12px;color:var(--text2);line-height:1.5">${desc}</div>
      </div>
    </div>`;

  return `
    <div class="wizard-card">
      <div class="wizard-title">${t('onboarding.welcome_title')}</div>
      <div class="wizard-sub">${t('onboarding.welcome_sub_choice')}</div>

      <!-- Schéma architecture intégré -->
      <div style="margin:18px 0 22px;padding:16px;background:var(--bg3);border-radius:10px;border:1px solid var(--border);">
        <div style="display:flex;align-items:center;justify-content:center;gap:0;flex-wrap:wrap;">
          <div style="text-align:center;min-width:90px;">
            <div style="background:var(--accent);color:#fff;border-radius:8px;padding:7px 12px;font-weight:700;font-size:12px;display:inline-flex;flex-direction:column;align-items:center;gap:4px;">
              <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>
              Admin
            </div>
            <div style="font-size:10px;color:var(--text2);margin-top:4px;">${t('onboarding.you_are_here')}</div>
          </div>
          <div style="display:flex;flex-direction:column;align-items:center;padding:0 6px;gap:2px;">
            <div style="font-size:9px;color:var(--text3);">${t('onboarding.label_config')}</div>
            <svg width="22" height="14" viewBox="0 0 28 16" fill="none"><path d="M2 5h24M20 1l6 4-6 4" stroke="var(--accent)" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/><path d="M26 11H2M8 7l-6 4 6 4" stroke="var(--accent)" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" opacity=".5"/></svg>
          </div>
          <div style="text-align:center;min-width:90px;">
            <div style="background:var(--bg2);border:2px solid var(--accent);border-radius:8px;padding:7px 12px;font-weight:700;font-size:12px;display:inline-flex;flex-direction:column;align-items:center;gap:4px;">
              <svg width="16" height="16" fill="none" stroke="var(--accent)" stroke-width="2" viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
              Core
            </div>
            <div style="font-size:10px;color:var(--text2);margin-top:4px;">${t('onboarding.instances_1_to_n')}</div>
          </div>
          <div style="display:flex;flex-direction:column;align-items:center;padding:0 6px;gap:2px;">
            <div style="font-size:9px;color:var(--text3);">${t('onboarding.label_routes')}</div>
            <svg width="22" height="10" viewBox="0 0 28 12" fill="none"><path d="M26 6H2M8 2L2 6l6 4" stroke="var(--green)" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" stroke-dasharray="4 2"/></svg>
          </div>
          <div style="text-align:center;min-width:90px;">
            <div style="background:var(--bg2);border:1.5px dashed var(--border);border-radius:8px;padding:7px 12px;font-weight:700;font-size:12px;display:inline-flex;flex-direction:column;align-items:center;gap:4px;opacity:.85;">
              <svg width="16" height="16" fill="none" stroke="var(--green)" stroke-width="2" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
              Agent
            </div>
            <div style="font-size:10px;color:var(--text2);margin-top:4px;">${t('onboarding.optional')}</div>
          </div>
        </div>
        <div style="margin-top:10px;padding:8px 12px;background:var(--bg2);border-radius:6px;border-left:3px solid var(--accent);font-size:11px;color:var(--text2);line-height:1.6;">
          <strong style="color:var(--text);">${t('onboarding.in_practice')}</strong>
          ${t('onboarding.practice_short')}
        </div>
      </div>

      <!-- 3 tuiles portrait -->
      <div class="wizard-mode-tiles">
        ${tile('deploy',
          `<svg width="24" height="24" fill="none" stroke="#fff" stroke-width="1.8" viewBox="0 0 24 24"><path d="M12 19V5M5 12l7-7 7 7"/><path d="M3 19h18" stroke-linecap="round"/></svg>`,
          t('onboarding.tile_deploy_title'),
          t('onboarding.tile_deploy_desc'),
          '', true)}
        ${tile('import-backup',
          `<svg width="24" height="24" fill="none" stroke="var(--accent)" stroke-width="1.8" viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>`,
          t('onboarding.tile_restore_title'),
          t('onboarding.tile_restore_desc'))}
        ${tile('detect',
          `<svg width="24" height="24" fill="none" stroke="var(--accent)" stroke-width="1.8" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/><path d="M11 8v6M8 11h6" stroke-linecap="round"/></svg>`,
          t('onboarding.tile_detect_title'),
          t('onboarding.tile_detect_desc'),
          detectBadge)}
      </div>
    </div>
    <div class="wizard-nav">
      <span class="wizard-skip" onclick="stopCorePolling();navigate('dashboard')">${t('onboarding.skip_wizard')}</span>
    </div>`;
}

window.selectOnbMode = function(mode) {
  onb.mode = mode;
  onb.step = 1;
  renderWizardStep();
  if (mode === 'detect') startCorePolling();
};

window.confirmOnbMode = function() {
  if (!onb.mode) return;
  onb.step = 1;
  renderWizardStep();
};

// ── Wizard import-backup ───────────────────────────────────────────────────────
function wizardImport1Html() {
  return `
    <div class="wizard-card">
      <div class="wizard-title">${t('onboarding.import.title')}</div>
      <div class="wizard-sub">${t('import.restore.hint')}</div>
      <div class="field">
        <label class="field-label">${t('onboarding.backup_file')}</label>
        <input type="file" id="onb-backup-file" class="input" accept=".gpx-admin-backup,.json">
      </div>
      <div id="onb-backup-status" style="color:var(--text2);font-size:12px;margin-top:8px"></div>
    </div>
    <div class="wizard-nav">
      <span class="wizard-skip" onclick="onb.step=0;onb.mode=null;renderWizardStep()">${t('onboarding.back_to_choice')}</span>
      <button class="btn btn-primary" id="wizard-btn-import1" onclick="previewBackup()" disabled>${t('trafic.analyze')}</button>
    </div>`;
}

document.addEventListener('change', function(e) {
  if (e.target && e.target.id === 'onb-backup-file') {
    const f = e.target.files[0];
    const st = document.getElementById('onb-backup-status');
    if (st && f) st.textContent = t('onboarding.file_selected', { name: f.name, size: (f.size/1024).toFixed(1) });
    const btn = document.getElementById('wizard-btn-import1');
    if (btn) btn.disabled = !f;
    onb.backupData = null;
  }
});

window.previewBackup = async function() {
  const input = document.getElementById('onb-backup-file');
  if (!input?.files[0]) return;
  const btn = document.getElementById('wizard-btn-import1');
  if (btn) { btn.disabled = true; btn.textContent = t('import.analyzing'); }
  try {
    const text = await input.files[0].text();
    onb.backupData = text;
    const res = await fetch('/api/v1/import/backup/preview', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + state.token, 'Content-Type': 'application/octet-stream' },
      body: text,
    });
    if (!res.ok) throw new Error(await res.text());
    onb.backupSummary = await res.json();
    onb.step = 2;
    renderWizardStep();
  } catch(e) { toast(t('import.error_backup', { msg: e.message }), 'error'); if (btn) { btn.disabled = false; btn.textContent = t('trafic.analyze'); } }
};

function wizardImport2Html() {
  const s = onb.backupSummary || {};
  const proxies = s.proxies || [];
  return `
    <div class="wizard-card">
      <div class="wizard-title">${t('import.content.kicker')}</div>
      <div class="wizard-sub">${t('onboarding.backup_created_sub', { date: s.created_at ? fmtDate(s.created_at) : '—' })}</div>
      <div class="gp-split-2" style="margin-bottom:20px">
        <label class="infra-card" style="cursor:pointer;padding:12px 14px">
          <input type="checkbox" id="imp-users" ${s.user_count?'':'disabled'}> &nbsp;${t('import.entity.users')} <span style="color:var(--text3)">(${s.user_count||0})</span>
          <div class="infra-card-desc" style="margin-top:4px">${t('onboarding.users_pw_warn')}</div>
        </label>
        <label class="infra-card" style="cursor:pointer;padding:12px 14px">
          <input type="checkbox" id="imp-tokens" ${s.token_count?'':'disabled'}> &nbsp;${t('import.entity.tokens')} <span style="color:var(--text3)">(${s.token_count||0})</span>
        </label>
        <label class="infra-card" style="cursor:pointer;padding:12px 14px">
          <input type="checkbox" id="imp-snippets" ${s.snippet_count?'':'disabled'}> &nbsp;${t('import.entity.snippets')} <span style="color:var(--text3)">(${s.snippet_count||0})</span>
        </label>
        <label class="infra-card" style="cursor:pointer;padding:12px 14px">
          <input type="checkbox" id="imp-channels" ${s.channel_count?'':'disabled'}> &nbsp;${t('import.entity.channels')} <span style="color:var(--text3)">(${s.channel_count||0})</span>
        </label>
        <label class="infra-card" style="cursor:pointer;padding:12px 14px">
          <input type="checkbox" id="imp-rules" ${s.rule_count?'':'disabled'}> &nbsp;${t('import.entity.rules')} <span style="color:var(--text3)">(${s.rule_count||0})</span>
        </label>
      </div>
      ${proxies.length ? `
      <div class="field-label" style="margin-bottom:8px">${t('import.proxies_to_import', { n: proxies.length })}</div>
      <div style="background:var(--bg3);border-radius:var(--radius);padding:4px 8px;max-height:200px;overflow-y:auto">
        <label style="display:flex;align-items:center;gap:8px;padding:6px 4px;border-bottom:1px solid var(--border);font-size:12px;cursor:pointer">
          <input type="checkbox" id="imp-all-proxies" onchange="toggleAllProxies(this.checked)"> <b>${t('trafic.select_all')}</b>
        </label>
        ${proxies.map(p => `<label style="display:flex;align-items:center;gap:8px;padding:6px 4px;border-bottom:1px solid var(--border);font-size:12px;cursor:pointer">
          <input type="checkbox" class="imp-proxy-cb" data-id="${esc(p.id)}" checked>
          <span style="flex:1">${esc(p.name)}</span>
          <span class="mono" style="color:var(--text3);font-size:11px">${esc(p.host||'—')}</span>
          <span class="tag tag-neutral" style="font-size:10px">${esc(p.type||'http')}</span>
          ${p.enabled ? '' : `<span class="tag tag-red" style="font-size:10px">${t('trafic.inactive')}</span>`}
        </label>`).join('')}
      </div>` : `<p style="color:var(--text2);font-size:13px">${t('import.no_proxies_in_backup')}</p>`}
      <div class="field" style="margin-top:16px;margin-bottom:0">
        <label class="field-label">${t('import.conflict')}</label>
        <select id="imp-conflict" class="input" style="max-width:220px">
          <option value="skip">${t('trafic.skip_keep')}</option>
          <option value="overwrite">${t('trafic.overwrite')}</option>
        </select>
      </div>
    </div>
    <div class="wizard-nav">
      <span class="wizard-skip" onclick="onb.step=1;renderWizardStep()">${t('onboarding.back')}</span>
      <button class="btn btn-primary" onclick="applyBackupImport()">${t('import.apply_selection')}</button>
    </div>`;
}

window.toggleAllProxies = function(checked) {
  document.querySelectorAll('.imp-proxy-cb').forEach(cb => cb.checked = checked);
};

window.applyBackupImport = async function() {
  const selectedProxies = [...document.querySelectorAll('.imp-proxy-cb:checked')].map(cb => cb.dataset.id);
  const selection = {
    proxy_ids: selectedProxies,
    import_users:    document.getElementById('imp-users')?.checked || false,
    import_tokens:   document.getElementById('imp-tokens')?.checked || false,
    import_snippets: document.getElementById('imp-snippets')?.checked || false,
    import_alert_channels: document.getElementById('imp-channels')?.checked || false,
    import_alert_rules:    document.getElementById('imp-rules')?.checked || false,
    on_conflict: document.getElementById('imp-conflict')?.value || 'skip',
  };
  try {
    const res = await api('POST', '/import/backup/apply', { data: JSON.parse(onb.backupData), selection });
    onb.importResult = res;
    onb.step = 3;
    renderWizardStep();
  } catch(e) { toast(t('import.error_import', { msg: e.message }), 'error'); }
};

function wizardImportDoneHtml() {
  const r = onb.importResult || {};
  return `
    <div class="wizard-card" style="text-align:center;padding:36px 32px">
      <div style="width:64px;height:64px;border-radius:16px;background:rgba(34,197,94,.12);border:1px solid rgba(34,197,94,.25);display:flex;align-items:center;justify-content:center;margin:0 auto 20px">
        <svg width="28" height="28" fill="none" stroke="var(--green)" stroke-width="2.5" viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></svg>
      </div>
      <div class="wizard-title">${t('import.result.kicker')}</div>
      <div class="gp-kpi-grid" style="margin:24px auto;max-width:400px">
        ${[[t('trafic.proxies'),r.proxies||0],[t('import.entity.users'),r.users||0],[t('import.entity.tokens'),r.tokens||0],
           [t('import.entity.snippets'),r.snippets||0],[t('import.result.channels'),r.channels||0],[t('import.result.rules'),r.rules||0]].map(([l,v])=>`
          <div style="background:var(--bg3);border-radius:var(--radius);padding:12px 8px;text-align:center">
            <div style="font-size:20px;font-weight:700;color:var(--accent)">${v}</div>
            <div style="font-size:11px;color:var(--text2)">${l}</div>
          </div>`).join('')}
      </div>
      ${r.skipped ? `<p style="color:var(--text3);font-size:12px;margin-bottom:16px">${t('import.result.skipped', { n: r.skipped })}</p>` : ''}
      <button class="btn btn-primary" onclick="navigate('dashboard')">${t('onboarding.go_dashboard')}</button>
    </div>`;
}

// ── Wizard migrate-config ──────────────────────────────────────────────────────
let onbMigrateFormat = null;

// ── Wizard migrate step 2 : vérification Core ────────────────────────────────
function wizardMigrateCoreHtml() {
  const cores = (window._cachedNodes || []).filter(n => n.role === 'core' && n.status === 'online');
  const hasCores = cores.length > 0;
  return `
    <div class="wizard-card">
      <div class="wizard-title">${t('onboarding.core_required.title')}</div>
      <div class="wizard-sub">${t('onboarding.core_required.sub')}</div>
      ${hasCores ? `
        <div style="padding:14px;background:color-mix(in srgb,var(--green) 10%,transparent);border:1px solid color-mix(in srgb,var(--green) 30%,transparent);border-radius:8px;margin-bottom:16px;">
          <div style="font-weight:700;font-size:13px;color:var(--green);margin-bottom:6px;display:flex;align-items:center;gap:6px;"><svg width="14" height="14" fill="none" stroke="var(--green)" stroke-width="2.5" viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></svg> ${t('onboarding.core_connected', { n: cores.length })}</div>
          <div style="font-size:12px;color:var(--text2);">${cores.map(c => esc(c.node_name||c.id)).join(', ')}</div>
        </div>
        <p style="font-size:13px;color:var(--text2);">${t('onboarding.core_connected_continue', { target: cores.length > 1 ? t('onboarding.core_target_plural') : t('onboarding.core_target_singular') })}</p>
      ` : `
        <div style="padding:14px;background:color-mix(in srgb,var(--yellow) 10%,transparent);border:1px solid color-mix(in srgb,var(--yellow) 30%,transparent);border-radius:8px;margin-bottom:16px;">
          <div style="font-weight:700;font-size:13px;color:var(--yellow);margin-bottom:6px;">${t('onboarding.core_none.title')}</div>
          <div style="font-size:12px;color:var(--text2);">${t('onboarding.core_none.sub')}</div>
        </div>
        <p style="font-size:13px;color:var(--text2);">${t('onboarding.core_none.hint')}</p>
      `}
    </div>
    <div class="wizard-nav">
      <span class="wizard-skip" onclick="onb.step=0;renderWizardStep()">${t('onboarding.back')}</span>
      <button class="btn btn-primary" onclick="onb.step=2;renderWizardStep()">
        ${hasCores ? t('onboarding.import_config') : t('onboarding.continue_anyway')}
      </button>
    </div>`;
}

function wizardMigrate1Html() {
  return `
    <div class="wizard-card">
      <div class="wizard-title">${t('import.migrate.title')}</div>
      <div class="wizard-sub">${t('import.migrate.hint')}</div>
      <div class="infra-grid" style="grid-template-columns:repeat(auto-fill,minmax(min(120px,100%),1fr));margin-bottom:20px">
        ${configFormatPickerHtml(onbMigrateFormat, id => `selectMigrateFormat('${id}')`)}
      </div>
      <div class="field">
        <label class="field-label">${t('import.file_upload')}</label>
        <input type="file" id="onb-migrate-file" class="input" accept=".conf,.yaml,.yml,.toml,.json,.txt">
      </div>
      <div class="field">
        <label class="field-label">${t('import.paste_label')}</label>
        <textarea id="onb-migrate-content" class="input" rows="8" placeholder="${t('import.paste_ph')}" style="font-family:monospace;font-size:12px"></textarea>
      </div>
    </div>
    <div class="wizard-nav">
      <span class="wizard-skip" onclick="onb.step=1;renderWizardStep()">${t('onboarding.back')}</span>
      <button class="btn btn-primary" id="wizard-btn-migrate1" onclick="parseMigrateConfig()" ${onbMigrateFormat?'':'disabled'}>${t('trafic.analyze')}</button>
    </div>`;
}

window.selectMigrateFormat = function(id) {
  onbMigrateFormat = id;
  document.querySelectorAll('.infra-card[data-format]').forEach(c => {
    c.classList.toggle('selected', c.getAttribute('data-format') === id);
  });
  const btn = document.getElementById('wizard-btn-migrate1');
  if (btn) btn.disabled = false;
};

document.addEventListener('change', function(e) {
  if (e.target && e.target.id === 'onb-migrate-file') {
    const f = e.target.files[0];
    if (!f) return;
    const reader = new FileReader();
    reader.onload = ev => {
      const ta = document.getElementById('onb-migrate-content');
      if (ta) ta.value = ev.target.result;
    };
    reader.readAsText(f);
    // Auto-detect format from extension
    const ext = f.name.split('.').pop().toLowerCase();
    const map = { yaml: 'traefik-yaml', yml: 'traefik-yaml', toml: 'traefik-toml', conf: 'nginx' };
    if (map[ext] && !onbMigrateFormat) {
      onbMigrateFormat = map[ext];
      // re-render to show selection (next tick)
      setTimeout(renderWizardStep, 50);
    }
  }
});

window.parseMigrateConfig = async function() {
  const content = document.getElementById('onb-migrate-content')?.value?.trim();
  if (!content) { toast(t('trafic.no_config'), 'error'); return; }
  if (!onbMigrateFormat) { toast(t('onboarding.select_format'), 'error'); return; }
  const btn = document.getElementById('wizard-btn-migrate1');
  if (btn) { btn.disabled = true; btn.textContent = t('import.analyzing'); }
  try {
    const res = await api('POST', '/import/config/parse', { format: onbMigrateFormat, content });
    onb.configProxies = (res?.proxies || []).map(p => ({ ...p, _selected: true }));
    onb.step = 3;
    renderWizardStep();
  } catch(e) {
    toast(t('import.error_parse', { msg: e.message }), 'error');
    if (btn) { btn.disabled = false; btn.textContent = t('trafic.analyze'); }
  }
};

function wizardMigrate2Html() {
  const proxies = onb.configProxies || [];
  if (!proxies.length) {
    return `<div class="wizard-card" style="text-align:center;padding:36px">
      <div style="width:56px;height:56px;border-radius:14px;background:rgba(251,146,60,.1);border:1px solid rgba(251,146,60,.25);display:flex;align-items:center;justify-content:center;margin:0 auto 16px">
        <svg width="24" height="24" fill="none" stroke="#fb923c" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
      </div>
      <div class="wizard-title">${t('trafic.no_proxy_detected')}</div>
      <p style="color:var(--text2);font-size:13px;margin:12px 0">${t('trafic.check_format')}</p>
      <button class="btn btn-secondary" onclick="onb.step=2;renderWizardStep()">${t('onboarding.back')}</button>
    </div>`;
  }
  return `
    <div class="wizard-card">
      <div class="wizard-title">${t('import.detected.title', { n: proxies.length })}</div>
      <div class="wizard-sub">${t('onboarding.migrate_select_sub')}</div>
      <label style="display:flex;align-items:center;gap:8px;padding:8px 4px;border-bottom:1px solid var(--border);font-size:12px;cursor:pointer;margin-bottom:4px">
        <input type="checkbox" id="mig-all" onchange="toggleAllMigrate(this.checked)" checked> <b>${t('trafic.select_all')}</b>
        <span style="color:var(--text3);margin-left:auto">${t('import.entries', { n: proxies.length })}</span>
      </label>
      <div style="background:var(--bg3);border-radius:var(--radius);max-height:280px;overflow-y:auto">
        ${proxies.map((p,i) => `
          <label style="display:flex;align-items:flex-start;gap:10px;padding:8px 10px;border-bottom:1px solid var(--border);cursor:pointer;font-size:12px">
            <input type="checkbox" class="mig-proxy-cb" data-idx="${i}" ${p._selected?'checked':''} onchange="onb.configProxies[${i}]._selected=this.checked">
            <div style="flex:1">
              <div style="font-weight:600">${esc(p.host)}</div>
              <div style="color:var(--text3);margin-top:2px">${(p.backends||[]).map(b=>`<span class="chip" style="font-size:10px">${esc(b)}</span>`).join(' ')}</div>
            </div>
            ${p.tls ? '<span class="tag tag-green" style="font-size:10px">TLS</span>' : ''}
            <span class="tag tag-neutral" style="font-size:10px">${esc(p.source)}</span>
          </label>`).join('')}
      </div>
      <div class="field" style="margin-top:16px;margin-bottom:0">
        <label class="field-label">${t('import.conflict')}</label>
        <select id="mig-conflict" class="input" style="max-width:220px">
          <option value="skip">${t('trafic.skip_keep')}</option>
          <option value="overwrite">${t('trafic.overwrite')}</option>
        </select>
      </div>
    </div>
    <div class="wizard-nav">
      <span class="wizard-skip" onclick="onb.step=2;renderWizardStep()">${t('onboarding.back')}</span>
      <button class="btn btn-primary" onclick="applyMigrateConfig()">${t('trafic.import_go')}</button>
    </div>`;
}

window.toggleAllMigrate = function(checked) {
  document.querySelectorAll('.mig-proxy-cb').forEach((cb,i) => {
    cb.checked = checked;
    if (onb.configProxies[i]) onb.configProxies[i]._selected = checked;
  });
};

window.applyMigrateConfig = async function() {
  const selected = (onb.configProxies || []).filter(p => p._selected);
  if (!selected.length) { toast(t('trafic.no_proxy_sel'), 'error'); return; }
  const onConflict = document.getElementById('mig-conflict')?.value || 'skip';
  try {
    const res = await api('POST', '/import/config/apply', { proxies: selected, on_conflict: onConflict });
    onb.migrateResult = res;
    onb.step = 4;
    renderWizardStep();
  } catch(e) { toast(t('import.error_import', { msg: e.message }), 'error'); }
};

function wizardMigrateDoneHtml() {
  const r = onb.migrateResult || {};
  return `
    <div class="wizard-card" style="text-align:center;padding:36px 32px">
      <div style="width:64px;height:64px;border-radius:16px;background:rgba(34,197,94,.12);border:1px solid rgba(34,197,94,.25);display:flex;align-items:center;justify-content:center;margin:0 auto 20px">
        <svg width="28" height="28" fill="none" stroke="var(--green)" stroke-width="2.5" viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></svg>
      </div>
      <div class="wizard-title">${t('import.migrate.kicker_done')}</div>
      <div style="display:flex;justify-content:center;gap:24px;margin:24px auto">
        <div style="text-align:center"><div style="font-size:28px;font-weight:700;color:var(--green)">${r.imported||0}</div><div style="color:var(--text2);font-size:12px">${t('import.migrate.imported')}</div></div>
        <div style="text-align:center"><div style="font-size:28px;font-weight:700;color:var(--text3)">${r.skipped||0}</div><div style="color:var(--text2);font-size:12px">${t('import.migrate.skipped')}</div></div>
        ${r.errors ? `<div style="text-align:center"><div style="font-size:28px;font-weight:700;color:var(--red)">${r.errors}</div><div style="color:var(--text2);font-size:12px">${t('trafic.errors')}</div></div>` : ''}
      </div>
      <p style="color:var(--text2);font-size:13px;margin-bottom:20px">${t('onboarding.migrate_done_hint')}</p>
      <div style="display:flex;gap:10px;justify-content:center">
        <button class="btn btn-secondary" onclick="onb.step=0;onb.mode=null;onb.configProxies=null;renderWizardStep()">${t('onboarding.other_action')}</button>
        <button class="btn btn-primary" onclick="navigate('admin-trafic')">${t('trafic.see_proxies')}</button>
      </div>
    </div>`;
}

function wizardStep1Html() {
  return `
    <div class="wizard-card">
      <div class="wizard-title">${t('onboarding.deploy.no_core.title')}</div>
      <div class="wizard-sub">${t('onboarding.deploy.no_core.sub')}</div>
      <div class="infra-grid">
        ${INFRA_TYPES.map(inf => `
          <div class="infra-card${onb.infra === inf.id ? ' selected' : ''}" onclick="selectInfra('${inf.id}')">
            <div class="infra-card-icon" style="color:var(--accent)">${INFRA_SVG[inf.id]||''}</div>
            <div class="infra-card-name">${t(inf.nameKey)}</div>
            <div class="infra-card-desc">${t(inf.descKey)}</div>
            <div class="infra-card-tags">${inf.tagKeys.map(tg => `<span class="infra-tag">${t(tg)}</span>`).join('')}</div>
          </div>`).join('')}
      </div>
    </div>
    <div class="wizard-nav">
      <span class="wizard-skip" onclick="onb.step=0;renderWizardStep()">${t('onboarding.back')}</span>
      <button class="btn btn-primary" id="wizard-btn-next1" onclick="wizardNext1()" ${onb.infra ? '' : 'disabled'}>
        ${t('onboarding.continue')}
      </button>
    </div>`;
}

window.selectInfra = function(id) {
  onb.infra = id;
  document.querySelectorAll('.infra-card').forEach(c => {
    c.classList.toggle('selected', c.getAttribute('onclick') === `selectInfra('${id}')`);
  });
  const btn = document.getElementById('wizard-btn-next1');
  if (btn) btn.disabled = false;
};

window.wizardNext1 = function() {
  if (!onb.infra) return;
  onb.step = 2;
  renderWizardStep();
};

// ── Wizard step 2 : génération des fichiers de configuration ───────────

function _onbCompose() {
  const infra = INFRA_TYPES.find(t => t.id === onb.infra) || INFRA_TYPES[0];
  const isCluster = infra.minCores > 1;
  const clusterGroup = infra.id === 'multi-region' ? 'eu-cluster' : 'cluster-1';

  const clusterEnv = !isCluster ? '' : `
      - GPX_CLUSTER_ENABLED=true
      - GPX_CLUSTER_GROUP=${clusterGroup}
      - GPX_CLUSTER_NODE_ID=core-1
      - GPX_CLUSTER_RAFT_PORT=8002
      - GPX_CLUSTER_PEERS=core-2:8002,core-3:8002`;

  const clusterPort = isCluster ? '\n      - "8002:8002"' : '';

  const agentService = !onb.withAgent ? '' : `

  # ── Agent ── Découverte automatique des conteneurs Docker ─────────────
  # Entre en PENDING à la connexion — acceptez-le depuis l'interface Admin.
  goproxify-agent:
    image: \${GOPROXIFY_REGISTRY}/agent:\${GOPROXIFY_TAG}
    container_name: goproxify-agent
    restart: unless-stopped
    command: ["agent"]
    environment:
      - GPX_PAIRING_SECRET=\${GPX_PAIRING_SECRET}
      - GPX_CONTROL_PLANE_CORE_ENDPOINT=http://goproxify-core:8000
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - goproxify_agent_data:/etc/goproxify
    networks:
      - goproxify_infra
    depends_on:
      goproxify-core:
        condition: service_started`;

  const acmeAdminEnv = (() => {
    const p = DNS_PROVIDERS.find(p => p.id === onb.dnsProvider);
    if (!p || onb.dnsProvider === 'none') return '';
    const providerVars = p.fields.map(f => `\n      - ${f.id}=\\\${${f.id}}`).join('');
    return `
      # ── ACME / DNS-01 (Admin uniquement) ────────────────────────────────
      - GPX_ACME_ENABLED=true
      - GPX_ACME_EMAIL=\\\${ACME_EMAIL}
      - GPX_ACME_DNS_TYPE=${onb.dnsProvider}${providerVars}`;
  })();

  return `# docker-compose.yml
# Lancement : docker compose up -d
# Prérequis : compléter le fichier .env dans le même dossier

networks:
  goproxify_infra:
    driver: bridge

volumes:
  goproxify_admin_data:
  goproxify_core_data:${onb.withAgent ? '\n  goproxify_agent_data:' : ''}

services:

  # ── Admin ── Control Plane (interface web, config, tokens) ────────────
  goproxify-admin:
    image: \${GOPROXIFY_REGISTRY}/admin:\${GOPROXIFY_TAG}
    container_name: goproxify-admin
    restart: unless-stopped
    command: ["admin"]
    environment:
      - GPX_SECURITY_JWT_SECRET=\${GPX_JWT_SECRET}
      - GPX_PAIRING_SECRET=\${GPX_PAIRING_SECRET}
      - GPX_FIRST_ADMIN_EMAIL=\${GPX_FIRST_ADMIN_EMAIL:-admin@example.com}
      - GPX_FIRST_ADMIN_PASSWORD=\${GPX_FIRST_ADMIN_PASSWORD}
      - GPX_IDENTITY_CORE_NODE_NAME=\${CORE_NODE_NAME:-goproxify-core}${acmeAdminEnv}
    ports:
      - "\${ADMIN_PORT:-9443}:9443"
    volumes:
      - goproxify_admin_data:/etc/goproxify
    networks:
      - goproxify_infra
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost:9443/api/v1/health"]
      interval: 15s
      timeout: 5s
      retries: 5
      start_period: 10s

  # ── Core ── Data Plane (reverse proxy HTTP/HTTPS/TCP/UDP) ─────────────
  # Entre en PENDING à la connexion — acceptez-le depuis l'interface Admin.
  goproxify-core:
    image: \${GOPROXIFY_REGISTRY}/core:\${GOPROXIFY_TAG}
    container_name: goproxify-core
    restart: unless-stopped
    command: ["core"]
    environment:
      - GPX_PAIRING_SECRET=\${GPX_PAIRING_SECRET}${clusterEnv}
    ports:
      - "80:80"
      - "443:443"
      - "443:443/udp"
      - "8000:8000"${clusterPort}
    volumes:
      - goproxify_core_data:/etc/goproxify
    networks:
      - goproxify_infra
    depends_on:
      goproxify-admin:
        condition: service_healthy
${agentService}`;
}

function _onbEnv() {
  const infra = INFRA_TYPES.find(t => t.id === onb.infra) || INFRA_TYPES[0];
  const isCluster = infra.minCores > 1;

  return `# .env
# 4 variables suffisent pour démarrer. Ne commitez pas ce fichier.
# Générez les secrets avec : openssl rand -hex 32

# ── SÉCURITÉ (REQUIS) ─────────────────────────────────────────────────
GPX_JWT_SECRET=
GPX_PAIRING_SECRET=

# ── COMPTE ADMINISTRATEUR INITIAL ─────────────────────────────────────
GPX_FIRST_ADMIN_EMAIL=admin@example.com
GPX_FIRST_ADMIN_PASSWORD=

# ── CONNEXION ADMIN → CORE ────────────────────────────────────────────
# Hostname/IP du Core joignable par l'Admin (port 8000)
CORE_NODE_NAME=goproxify-core

# ── IMAGE ─────────────────────────────────────────────────────────────
GOPROXIFY_REGISTRY=ghcr.io/vincamok/goproxify
GOPROXIFY_TAG=preview
${!isCluster ? '' : `
# ── CLUSTER ───────────────────────────────────────────────────────────
# Répliquez ce fichier sur chaque nœud Core en ajustant GPX_CLUSTER_NODE_ID.
# GPX_CLUSTER_NODE_ID=core-2
# GPX_CLUSTER_PEERS=core-1:8002,core-3:8002
`}${(() => {
    const p = DNS_PROVIDERS.find(p => p.id === onb.dnsProvider);
    if (!p || onb.dnsProvider === 'none') return '';
    return `
# ── TLS / ACME DNS-01 (Admin uniquement) ──────────────────────────────
GPX_ACME_ENABLED=true
GPX_ACME_EMAIL=admin@example.com
GPX_ACME_DNS_TYPE=${onb.dnsProvider}
${p.fields.map(f => `${f.id}=${f.placeholder||''}`).join('\n')}
`;
  })()}`;
}

function _onbCli() {
  return `# CLI — démarrage sans Docker
# Installation : go install github.com/vincamok/goproxify/cmd/goproxify@latest

# ── Admin (Control Plane) ──────────────────────────────────────────────
goproxify admin \\
  --jwt-secret=<GPX_JWT_SECRET> \\
  --pairing-secret=<GPX_PAIRING_SECRET> \\
  --first-admin-email=admin@example.com \\
  --first-admin-password=<mot_de_passe>

# ── Core (Data Plane) ─────────────────────────────────────────────────
# L'Admin se connecte au Core (pas l'inverse). Exposez le port 8000.
goproxify core \\
  --pairing-secret=<GPX_PAIRING_SECRET>${(INFRA_TYPES.find(t=>t.id===onb.infra)||{}).cmdExtra||''}`;
}

function _onbK8s() {
  const infra = INFRA_TYPES.find(t => t.id === onb.infra) || INFRA_TYPES[0];
  const isCluster = infra.minCores > 1;
  const clusterGroup = infra.id === 'multi-region' ? 'eu-cluster' : 'cluster-1';

  return `# Kubernetes — ConfigMap + Secret par service
# Adaptez les noms de namespace, image et valeurs selon votre cluster.

# ── Secret (valeurs sensibles) ─────────────────────────────────────────
apiVersion: v1
kind: Secret
metadata:
  name: goproxify-secrets
  namespace: goproxify
type: Opaque
stringData:
  GPX_JWT_SECRET: "<openssl rand -hex 32>"
  GPX_PAIRING_SECRET: "<openssl rand -hex 32>"
  GPX_FIRST_ADMIN_PASSWORD: "<mot_de_passe>"

---
# ── ConfigMap Admin ────────────────────────────────────────────────────
apiVersion: v1
kind: ConfigMap
metadata:
  name: goproxify-admin-config
  namespace: goproxify
data:
  GPX_FIRST_ADMIN_EMAIL: "admin@example.com"
  GPX_ENGINE_LOG_LEVEL: "info"
  GPX_IDENTITY_CORE_NODE_NAME: "goproxify-core"
  ADMIN_PORT: "9443"

---
# ── ConfigMap Core ─────────────────────────────────────────────────────
apiVersion: v1
kind: ConfigMap
metadata:
  name: goproxify-core-config
  namespace: goproxify
data:
  GPX_NETWORK_HTTP_PORT: "80"
  GPX_NETWORK_HTTPS_PORT: "443"
  GPX_NETWORK_INTERNAL_API_PORT: "8000"${!isCluster ? '' : `
  GPX_CLUSTER_ENABLED: "true"
  GPX_CLUSTER_GROUP: "${clusterGroup}"
  GPX_CLUSTER_NODE_ID: "core-1"
  GPX_CLUSTER_RAFT_PORT: "8002"
  GPX_CLUSTER_PEERS: "core-2:8002,core-3:8002"`}
${!onb.withAgent ? '' : `
---
# ── ConfigMap Agent ────────────────────────────────────────────────────
apiVersion: v1
kind: ConfigMap
metadata:
  name: goproxify-agent-config
  namespace: goproxify
data:
  GPX_CONTROL_PLANE_CORE_ENDPOINT: "http://goproxify-core:8000"
  GPX_DOCKER_RUNTIME: "docker"`}`;
}

function _onbFileBlock(id, filename, content) {
  return `<div style="margin-bottom:16px">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px">
      <span style="font-size:11px;font-weight:700;color:var(--text2);letter-spacing:.04em;font-family:monospace">${esc(filename)}</span>
      <button onclick="copyOnbFile('${id}')" style="padding:3px 10px;font-size:11px;background:var(--bg2);border:1px solid var(--border);border-radius:6px;cursor:pointer;color:var(--text2)">${t('dockerlbl.copy')}</button>
    </div>
    <pre id="onb-file-${id}" style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:14px;font-size:11px;line-height:1.6;margin:0;white-space:pre;overflow-x:auto;max-height:360px;overflow-y:auto">${esc(content)}</pre>
  </div>`;
}

function wizardStep2Html() {
  const stackToggle = (key, label, hint) => {
    const on = onb[key];
    return `<div onclick="onb.${key}=!onb.${key};renderWizardStep()" style="display:flex;align-items:flex-start;gap:12px;padding:10px 12px;border-radius:8px;border:1.5px solid ${on?'var(--accent)':'var(--border)'};cursor:pointer;transition:all .15s;background:${on?'color-mix(in srgb,var(--accent) 6%,transparent)':'var(--bg3)'}">
      <div style="margin-top:2px;width:16px;height:16px;border-radius:4px;border:2px solid ${on?'var(--accent)':'var(--border)'};background:${on?'var(--accent)':'transparent'};display:flex;align-items:center;justify-content:center;flex-shrink:0">
        ${on?'<svg width="10" height="10" viewBox="0 0 10 10" fill="none"><polyline points="1.5,5 4,7.5 8.5,2.5" stroke="#fff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>':''}
      </div>
      <div><div style="font-size:13px;font-weight:600;color:var(--text)">${label}</div><div style="font-size:11px;color:var(--text2);margin-top:2px">${hint}</div></div>
    </div>`;
  };

  const tabs = [
    { id: 'compose', label: t('onboarding.tab.compose') },
    { id: 'cli',     label: t('onboarding.tab.cli') },
    { id: 'k8s',     label: t('onboarding.tab.k8s') },
  ];

  return `
    <div class="wizard-card">
      <div class="wizard-title" style="margin-bottom:4px">${t('onboarding.compose_stack.title')}</div>
      <div class="wizard-sub">${t('onboarding.compose_stack.sub')}</div>
      <div style="display:flex;flex-direction:column;gap:8px;margin-top:12px">
        <div style="padding:10px 12px;border-radius:8px;border:1.5px solid var(--accent);background:color-mix(in srgb,var(--accent) 6%,transparent);display:flex;align-items:center;gap:10px">
          <svg width="15" height="15" fill="none" stroke="var(--accent)" stroke-width="1.8" viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg>
          <div><div style="font-size:13px;font-weight:600">${t('onboarding.stack.admin.title')}</div><div style="font-size:11px;color:var(--text2);margin-top:1px">${t('onboarding.stack.admin.desc')}</div></div>
        </div>
        <div style="padding:10px 12px;border-radius:8px;border:1.5px solid var(--accent);background:color-mix(in srgb,var(--accent) 6%,transparent);display:flex;align-items:center;gap:10px">
          <svg width="15" height="15" fill="none" stroke="var(--accent)" stroke-width="1.8" viewBox="0 0 24 24"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
          <div><div style="font-size:13px;font-weight:600">${t('onboarding.stack.core.title')}</div><div style="font-size:11px;color:var(--text2);margin-top:1px">${t('onboarding.stack.core.desc')}</div></div>
        </div>
        ${stackToggle('withAgent', t('onboarding.stack.agent.title'), t('onboarding.stack.agent.desc'))}
      </div>
      <div style="margin-top:16px;padding-top:16px;border-top:1px solid var(--border)">
        <div style="font-size:12px;font-weight:700;color:var(--text2);letter-spacing:.04em;margin-bottom:8px">${t('onboarding.tls.title')}</div>
        <div style="font-size:12px;color:var(--text3);margin-bottom:10px">${t('onboarding.tls.sub')}</div>
        <div style="display:flex;flex-wrap:wrap;gap:6px">
          ${DNS_PROVIDERS.map(p => `
            <button onclick="onb.dnsProvider='${p.id}';renderWizardStep()"
              style="padding:5px 12px;font-size:11px;font-weight:600;border-radius:6px;border:1.5px solid ${onb.dnsProvider===p.id?'var(--accent)':'var(--border)'};background:${onb.dnsProvider===p.id?'color-mix(in srgb,var(--accent) 8%,transparent)':'var(--bg3)'};color:${onb.dnsProvider===p.id?'var(--accent)':'var(--text2)'};cursor:pointer;transition:all .15s" title="${t(p.hintKey)}">
              ${p.nameKey ? t(p.nameKey) : p.name}
            </button>`).join('')}
        </div>
        ${onb.dnsProvider && onb.dnsProvider !== 'none' ? `
          <div style="margin-top:10px;padding:8px 12px;background:var(--bg3);border-radius:6px;border:1px solid var(--border);font-size:11px;color:var(--text2)">
            ${t('onboarding.tls.vars_added', { vars: DNS_PROVIDERS.find(p=>p.id===onb.dnsProvider)?.fields?.map(f=>f.id).join(', ') })}
          </div>` : ''}
      </div>
    </div>

    <div class="wizard-card">
      <div class="wizard-title" style="margin-bottom:4px">${t('onboarding.config.title')}</div>

      <div style="display:flex;gap:0;border-bottom:1px solid var(--border);margin:14px 0 20px" id="onb-deploy-tabs">
        ${tabs.map((t,i) => `<button id="onb-tab-${t.id}" data-onb-tab="${t.id}" ${i===0?'data-active':''} onclick="onbSwitchTab('${t.id}')"
          style="padding:7px 16px;font-size:12px;font-weight:600;border:none;background:none;cursor:pointer;border-bottom:2px solid ${i===0?'var(--accent)':'transparent'};color:${i===0?'var(--accent)':'var(--text2)'};transition:all .15s">${t.label}</button>`).join('')}
      </div>

      <div id="onb-panel-compose">
        <div style="font-size:12px;color:var(--text2);margin-bottom:14px;padding:8px 12px;background:var(--bg3);border-radius:6px;line-height:1.5">
          ${t('onboarding.compose_hint')}
        </div>
        ${_onbFileBlock('docker-compose','docker-compose.yml',_onbCompose())}
        ${_onbFileBlock('dotenv','.env',_onbEnv())}
      </div>

      <div id="onb-panel-cli" style="display:none">
        <div style="font-size:12px;color:var(--text2);margin-bottom:14px;padding:8px 12px;background:var(--bg3);border-radius:6px;line-height:1.5">
          ${t('onboarding.cli_hint')}
        </div>
        ${_onbFileBlock('cli','commandes',_onbCli())}
      </div>

      <div id="onb-panel-k8s" style="display:none">
        <div style="font-size:12px;color:var(--text2);margin-bottom:14px;padding:8px 12px;background:var(--bg3);border-radius:6px;line-height:1.5">
          ${t('onboarding.k8s_hint')}
        </div>
        ${_onbFileBlock('k8s','manifests.yaml',_onbK8s())}
      </div>
    </div>

    <div class="wizard-nav">
      <button class="btn btn-secondary" onclick="onb.step=1;renderWizardStep()">${t('onboarding.back')}</button>
      <button class="btn btn-primary" onclick="wizardNext2()">${t('onboarding.wait_connection')}</button>
    </div>`;
}

window.onbSwitchTab = function(id) {
  ['compose','cli','k8s'].forEach(t => {
    const btn   = document.getElementById('onb-tab-'+t);
    const panel = document.getElementById('onb-panel-'+t);
    const active = t === id;
    if (btn) {
      btn.style.borderBottomColor = active ? 'var(--accent)' : 'transparent';
      btn.style.color = active ? 'var(--accent)' : 'var(--text2)';
      if (active) btn.setAttribute('data-active',''); else btn.removeAttribute('data-active');
    }
    if (panel) panel.style.display = active ? 'block' : 'none';
  });
};

window.copyOnbFile = function(id) {
  const pre = document.getElementById('onb-file-'+id);
  if (pre) copyText(pre.textContent, t('dockerlbl.copied'));
};

window.copyOnbPanel = function(id) {
  const pre = document.querySelector('#onb-panel-'+id+' pre');
  if (pre) copyText(pre.textContent, t('dockerlbl.copied'));
};

window.copyOnbToken = function() {
  copyText(onb.token || '', t('onboarding.token_copied'));
};
window.copyOnbCmd = function() {
  const raw = document.getElementById('wizard-cmd')?.childNodes;
  let txt = '';
  if (raw) raw.forEach(n => { if (n.nodeType === 3) txt += n.textContent; });
  copyText(txt.trim(), t('onboarding.cmd_copied'));
};

window.wizardNext2 = function() {
  onb.step = 3;
  renderWizardStep();
  startCorePolling();
};

function wizardStep3Html() {
  return `
    <div class="wizard-card">
      <div class="wizard-title" style="margin-bottom:6px">${t('onboarding.deploying.title')}</div>
      <p style="color:var(--text2);font-size:13px;margin-bottom:20px">${t('onboarding.deploying.sub')}</p>

      <div id="wizard-pending-area" style="margin-bottom:16px">${wizardPendingInnerHtml()}</div>

      <div id="wizard-wait-area">
        <div class="wizard-waiting" style="padding:20px 0">
          <div class="wizard-spinner"></div>
          <p style="color:var(--text2);font-size:13px;margin-top:8px">${t('onboarding.waiting_core')}</p>
        </div>
      </div>
    </div>
    <div class="wizard-nav">
      <button class="btn btn-secondary" onclick="stopCorePolling();onb.step=2;renderWizardStep()">${t('onboarding.back')}</button>
      <button class="btn btn-secondary" onclick="stopCorePolling();navigate('dashboard')">${t('onboarding.skip')}</button>
    </div>`;
}

function startCorePolling() {
  stopCorePolling();
  onb.pollTimer = setInterval(async () => {
    try {
      const nodes = await api('GET', '/nodes');
      const list = nodes || [];

      // Refresh pending nodes area (deploy step 3 and detect mode)
      onb.pendingNodes = list.filter(n => n.status === 'pending');
      const pendingArea = document.getElementById('wizard-pending-area');
      if (pendingArea) pendingArea.innerHTML = wizardPendingInnerHtml();

      // Check for a connected Core (deploy mode only)
      const cores = list.filter(n => n.role === 'core' && n.status === 'online');
      if (cores.length > 0) {
        stopCorePolling();
        const area = document.getElementById('wizard-wait-area');
        if (area) area.innerHTML = `
          <div class="wizard-connected" style="text-align:center;padding:16px 0">
            <div style="width:56px;height:56px;border-radius:14px;background:rgba(34,197,94,.12);border:1px solid rgba(34,197,94,.3);display:flex;align-items:center;justify-content:center;margin:0 auto 14px"><svg width="24" height="24" fill="none" stroke="var(--green)" stroke-width="2.5" viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></svg></div>
            <div style="font-size:18px;font-weight:700;color:var(--green);margin-bottom:4px">
              ${t('onboarding.cores_connected', { n: cores.length })}
            </div>
            <p style="color:var(--text2);font-size:13px">${cores.map(c => esc(c.node_name)).join(', ')}</p>
            <button class="btn btn-primary" style="margin-top:14px" onclick="navigate('dashboard')">${t('onboarding.go_dashboard')}</button>
          </div>`;
        toast(t('onboarding.core_connected_toast'), 'success');
      }
    } catch {}
  }, 5000);
}

function stopCorePolling() {
  if (onb.pollTimer) { clearInterval(onb.pollTimer); onb.pollTimer = null; }
}

// ── Wizard : nœuds en attente ────────────────────────────────────────────────

function wizardPendingInnerHtml() {
  const nodes = onb.pendingNodes;
  if (!nodes.length) {
    return `<div style="padding:14px;text-align:center;color:var(--text3);font-size:12px;background:var(--bg3);border-radius:8px;border:1px solid var(--border);">
      ${t('onboarding.pending.empty')}
    </div>`;
  }
  return `
    <div>
      <div style="font-size:11px;font-weight:700;color:var(--text2);letter-spacing:.05em;margin-bottom:8px;">${t('onboarding.pending.section')}</div>
      <div style="display:flex;flex-direction:column;gap:6px;">
        ${nodes.map(n => `
          <div style="display:flex;align-items:center;gap:10px;padding:10px 14px;background:var(--bg3);border-radius:8px;border:1px solid color-mix(in srgb,var(--yellow,#f59e0b) 30%,transparent);">
            <div style="width:8px;height:8px;border-radius:50%;background:var(--yellow,#f59e0b);flex-shrink:0;"></div>
            <div style="flex:1;min-width:0;">
              <div style="font-weight:600;font-size:13px;">${esc(n.node_name)}</div>
              <div style="font-size:11px;color:var(--text2);">${esc(n.role)} · ${esc(n.endpoint || '—')}</div>
            </div>
            <button onclick="acceptNode('${esc(n.id)}')" class="btn btn-primary" style="padding:4px 12px;font-size:11px;">${t('onboarding.accept')}</button>
            <button onclick="rejectNode('${esc(n.id)}')" style="padding:4px 12px;font-size:11px;background:transparent;border:1px solid var(--border);border-radius:6px;cursor:pointer;color:var(--red,#ef4444);">${t('onboarding.reject')}</button>
          </div>`).join('')}
      </div>
    </div>`;
}

function wizardPendingHtml() {
  return `
    <div class="wizard-card">
      <div class="wizard-title">${t('onboarding.pending.title')}</div>
      <div class="wizard-sub">${t('onboarding.pending.sub')}</div>
      <div id="wizard-pending-area" style="margin-top:12px;">${wizardPendingInnerHtml()}</div>
    </div>
    <div class="wizard-nav">
      <span class="wizard-skip" onclick="stopCorePolling();onb.step=0;onb.mode=null;renderWizardStep()">${t('onboarding.back_to_choice')}</span>
      <button class="btn btn-secondary" onclick="stopCorePolling();navigate('dashboard')">${t('onboarding.dashboard')}</button>
    </div>`;
}

window.acceptNode = async function(id) {
  try {
    await api('POST', `/nodes/${encodeURIComponent(id)}/accept`);
    if (typeof onb !== 'undefined' && Array.isArray(onb.pendingNodes)) {
      onb.pendingNodes = onb.pendingNodes.filter(n => n.id !== id && n.node_name !== id);
    }
    const area = document.getElementById('wizard-pending-area');
    if (area && typeof wizardPendingInnerHtml === 'function') area.innerHTML = wizardPendingInnerHtml();
    toast(t('onboarding.node_accepted'), 'success');
    if (state.page === 'infrastructure') navigate('infrastructure');
  } catch(e) {
    const msg = String(e.message || '');
    if (msg.includes('404') || /introuvable/i.test(msg)) {
      toast(t('onboarding.node_gone'), 'info');
      if (state.page === 'infrastructure') navigate('infrastructure');
      else if (typeof onb !== 'undefined') navigate('onboarding');
    } else {
      toast(t('common.error_msg', { msg }), 'error');
    }
  }
};

window.rejectNode = async function(id) {
  try {
    await api('POST', `/nodes/${encodeURIComponent(id)}/reject`);
    if (typeof onb !== 'undefined' && Array.isArray(onb.pendingNodes)) {
      onb.pendingNodes = onb.pendingNodes.filter(n => n.id !== id && n.node_name !== id);
    }
    const area = document.getElementById('wizard-pending-area');
    if (area && typeof wizardPendingInnerHtml === 'function') area.innerHTML = wizardPendingInnerHtml();
    toast(t('onboarding.node_rejected'), 'success');
    if (state.page === 'infrastructure') navigate('infrastructure');
  } catch(e) {
    const msg = String(e.message || '');
    if (msg.includes('404') || /introuvable/i.test(msg)) {
      toast(t('onboarding.node_gone'), 'info');
      if (state.page === 'infrastructure') navigate('infrastructure');
    } else {
      toast(t('common.error_msg', { msg }), 'error');
    }
  }
};

