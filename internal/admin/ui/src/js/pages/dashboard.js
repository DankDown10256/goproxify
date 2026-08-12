// ── PAGE: Dashboard
// Extrait de pages-all.js — phase 4.

pages.dashboard = async function() {
  const content = document.getElementById('content');
  content.innerHTML = '<p style="color:var(--text2)">' + t('common.loading') + '</p>';
  try {
    const [health, proxies, nodes, domains, auditData] = await Promise.all([
      api('GET', '/health').catch(() => null),
      api('GET', '/proxies').catch(() => []),
      api('GET', '/nodes').catch(() => []),
      api('GET', '/domains').catch(() => []),
      api('GET', '/audit?limit=8').catch(() => null),
    ]);

    const allNodes    = nodes || [];
    const coreNodes   = allNodes.filter(n => n.role === 'core');
    const agentNodes  = allNodes.filter(n => n.role === 'agent');
    const coresOnline = coreNodes.filter(n => n.status === 'online').length;
    const allProxies  = proxies || [];
    const enabledCnt  = allProxies.filter(p => p.enabled !== false).length;
    const allDomains  = domains || [];
    const now         = Date.now();

    const certsExpiring = allDomains.filter(d => {
      if (!d.cert_expires_at) return false;
      const days = Math.round((new Date(d.cert_expires_at) - now) / 86400000);
      return days < 30;
    });
    const certsExpired = certsExpiring.filter(d => new Date(d.cert_expires_at) < now);
    const certsSoon    = certsExpiring.filter(d => new Date(d.cert_expires_at) >= now);

    const nodesOffline = allNodes.filter(n => n.status !== 'online');

    const hasCritical = certsExpired.length > 0 || nodesOffline.filter(n => n.role === 'core').length > 0;
    const hasWarning  = !hasCritical && (certsSoon.length > 0 || nodesOffline.length > 0 || health?.status !== 'ok');
    const statusColor = hasCritical ? 'var(--red)' : hasWarning ? 'var(--yellow)' : 'var(--green)';
    const statusLabel = hasCritical ? t('dash.status.critical') : hasWarning ? t('dash.status.warning') : t('dash.status.ok');
    const statusDot   = '●';

    const onlineCores = coreNodes.filter(n => n.status === 'online');
    const avgCpu = onlineCores.length
      ? Math.round(onlineCores.reduce((s, n) => s + (n.cpu_pct || 0), 0) / onlineCores.length)
      : null;
    const avgMem = onlineCores.length
      ? Math.round(onlineCores.reduce((s, n) => s + (n.mem_pct || 0), 0) / onlineCores.length)
      : null;

    const auditEntries = auditData?.entries || [];

    const fmtTime = iso => {
      if (!iso) return '—';
      const d = new Date(iso);
      const now2 = new Date();
      const diff = Math.round((now2 - d) / 1000);
      if (diff < 60) return t('dash.ago_s', { n: diff });
      if (diff < 3600) return t('dash.ago_m', { n: Math.round(diff/60) });
      if (diff < 86400) return t('dash.ago_h', { n: Math.round(diff/3600) });
      return d.toLocaleDateString(typeof gpxBCP47==='function'?gpxBCP47():'en-US');
    };

    const miniBar = (pct, color) => {
      if (pct == null) return '<span style="opacity:.4;font-size:11px">—</span>';
      const p = Math.max(0, Math.min(100, pct));
      const c = p > 85 ? 'var(--red)' : p > 65 ? 'var(--yellow)' : color || 'var(--accent)';
      return `<div style="display:flex;align-items:center;gap:6px">
        <div style="flex:1;height:4px;border-radius:2px;background:var(--border);overflow:hidden">
          <div style="width:${p}%;height:100%;background:${c};border-radius:2px;transition:width .4s"></div>
        </div>
        <span style="font-size:10px;opacity:.65;min-width:26px;text-align:right">${p}%</span>
      </div>`;
    };

    const attentionItems = [
      ...nodesOffline.map(n => ({
        icon: `<svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`,
        color: n.role === 'core' ? 'var(--red)' : 'var(--yellow)',
        text: t('dash.node_offline', { role: n.role === 'core' ? 'Core' : 'Agent', name: esc(n.display_name || n.node_name) }),
        action: `navigate('infrastructure')`,
        actionLabel: t('dash.see'),
      })),
      ...certsExpired.map(d => ({
        icon: `<svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M12 2l5 3v4c0 3-2.5 5.5-5 6.5C9.5 14.5 7 12 7 9V5l5-3z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
        color: 'var(--red)',
        text: t('dash.cert_expired', { domain: esc(d.domain) }),
        action: `navigate('certs')`,
        actionLabel: t('dash.renew'),
      })),
      ...certsSoon.map(d => {
        const days = Math.round((new Date(d.cert_expires_at) - now) / 86400000);
        return {
          icon: `<svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M12 2l5 3v4c0 3-2.5 5.5-5 6.5C9.5 14.5 7 12 7 9V5l5-3z"/></svg>`,
          color: days < 7 ? 'var(--red)' : 'var(--yellow)',
          text: t('dash.cert_soon', { domain: esc(d.domain), days }),
          action: `navigate('certs')`,
          actionLabel: t('dash.see'),
        };
      }),
    ];

    const expiredLabel = certsExpired.length
      ? `<span style="font-size:13px;color:var(--red);margin-left:6px">⚠ ${certsExpired.length} ${t('dash.expired')}</span>`
      : certsSoon.length
        ? `<span style="font-size:13px;color:var(--yellow);margin-left:6px">⚠ ${certsSoon.length} ${t('dash.soon')}</span>`
        : '';

    content.innerHTML = `
      <div class="gp-stat-grid" style="margin-bottom:20px">
        <div class="card blueprint" style="padding:20px 22px;cursor:default">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          <div class="card-kicker">${t('dash.status_global')}</div>
          <div style="font-size:22px;font-weight:700;font-family:var(--font-heading);color:${statusColor};margin:6px 0 2px;line-height:1">${statusDot} ${statusLabel}</div>
          <div class="card-meta">${t('dash.nodes_meta', { version: esc(health?.version||'—'), n: allNodes.length })}</div>
        </div>
        <div class="card blueprint" style="padding:20px 22px;cursor:default">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          <div class="card-kicker">${t('nav.cores')}</div>
          <div style="font-size:22px;font-weight:700;font-family:var(--font-heading);margin:6px 0 8px;line-height:1">
            ${coresOnline}<span style="font-size:15px;font-weight:400;opacity:.45"> / ${coreNodes.length}</span>
            ${nodesOffline.some(n=>n.role==='core') ? `<span style="font-size:12px;color:var(--red);margin-left:6px">● ${t('dash.cores_offline')}</span>` : ''}
          </div>
          <div style="display:flex;flex-direction:column;gap:4px">
            <div style="display:flex;align-items:center;gap:8px;font-size:11px;opacity:.65"><span style="width:28px">CPU</span>${miniBar(avgCpu)}</div>
            <div style="display:flex;align-items:center;gap:8px;font-size:11px;opacity:.65"><span style="width:28px">RAM</span>${miniBar(avgMem)}</div>
          </div>
        </div>
        <div class="card blueprint" style="padding:20px 22px;cursor:pointer" onclick="navigate('admin-trafic')">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          <div class="card-kicker">${t('dash.proxies_active')}</div>
          <div style="font-size:22px;font-weight:700;font-family:var(--font-heading);margin:6px 0 2px;line-height:1">
            ${enabledCnt}<span style="font-size:15px;font-weight:400;opacity:.45"> / ${allProxies.length}</span>
          </div>
          <div class="card-meta">${t('dash.proxies_meta')}</div>
        </div>
        <div class="card blueprint" style="padding:20px 22px;cursor:pointer" onclick="navigate('certs')">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          <div class="card-kicker">${t('dash.domains')}</div>
          <div style="font-size:22px;font-weight:700;font-family:var(--font-heading);margin:6px 0 2px;line-height:1">
            ${allDomains.length}
            ${expiredLabel}
          </div>
          <div class="card-meta">${t('dash.certs_meta')}</div>
        </div>
      </div>

      ${attentionItems.length ? `
      <div class="card blueprint" style="margin-bottom:20px;border-color:${hasCritical?'color-mix(in srgb,var(--red) 35%,var(--border))':'color-mix(in srgb,var(--yellow) 35%,var(--border))'}">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <div class="card-header">
          <span class="card-title" style="color:${hasCritical?'var(--red)':'var(--yellow)'}">
            <svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" style="vertical-align:middle;margin-right:4px"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            ${t('dash.attention')}
          </span>
          <span style="font-size:11px;opacity:.55">${t('dash.items', { n: attentionItems.length })}</span>
        </div>
        <div style="padding:0 20px 16px;display:flex;flex-direction:column;gap:8px">
          ${attentionItems.map(item => `
            <div style="display:flex;align-items:center;gap:10px;padding:10px 14px;background:var(--bg2);border-radius:8px;border:1px solid var(--border)">
              <span style="color:${item.color};flex-shrink:0">${item.icon}</span>
              <span style="flex:1;font-size:13px">${item.text}</span>
              <button class="btn btn-ghost btn-sm" onclick="${item.action}" style="flex-shrink:0;font-size:11px">${item.actionLabel} →</button>
            </div>`).join('')}
        </div>
      </div>` : ''}

      <div class="gp-dash-split">
        <div class="card blueprint" style="overflow:hidden">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          <div class="card-header">
            <span class="card-title">${t('nav.cores')}</span>
            <button class="btn btn-ghost btn-sm" onclick="navigate('infrastructure')" style="font-size:11px">${t('dash.see_all')}</button>
          </div>
          ${coreNodes.length ? `
          <div style="padding:0 0 8px">
            ${coreNodes.map((n, i) => {
              const online = n.status === 'online';
              const cpu = n.cpu_pct != null ? Math.round(n.cpu_pct) : null;
              const mem = n.mem_pct != null ? Math.round(n.mem_pct) : null;
              const cpuColor = cpu > 85 ? 'var(--red)' : cpu > 65 ? 'var(--yellow)' : 'var(--accent)';
              const memColor = mem > 85 ? 'var(--red)' : mem > 65 ? 'var(--yellow)' : 'var(--accent)';
              return `<div style="display:flex;align-items:center;gap:12px;padding:10px 20px;cursor:pointer;transition:background .15s"
                           onmouseover="this.style.background='var(--bg2)'" onmouseout="this.style.background=''"
                           onclick="selectCore(window._coreNodes[${i}])">
                <div style="width:8px;height:8px;border-radius:50%;background:${online?'var(--green)':'var(--red)'};flex-shrink:0"></div>
                <div style="flex:1;min-width:0">
                  <div style="font-size:13px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(n.display_name||n.node_name)}</div>
                  <div style="font-size:11px;opacity:.5">${esc(n.endpoint||'—')}</div>
                </div>
                ${online && cpu != null ? `
                <div style="display:flex;flex-direction:column;gap:3px;min-width:80px">
                  <div style="display:flex;align-items:center;gap:4px;font-size:10px;opacity:.6">
                    <span style="width:26px">CPU</span>
                    <div style="flex:1;height:3px;border-radius:2px;background:var(--border)"><div style="width:${cpu}%;height:100%;background:${cpuColor};border-radius:2px"></div></div>
                    <span style="min-width:22px;text-align:right">${cpu}%</span>
                  </div>
                  <div style="display:flex;align-items:center;gap:4px;font-size:10px;opacity:.6">
                    <span style="width:26px">RAM</span>
                    <div style="flex:1;height:3px;border-radius:2px;background:var(--border)"><div style="width:${mem||0}%;height:100%;background:${memColor};border-radius:2px"></div></div>
                    <span style="min-width:22px;text-align:right">${mem??'—'}%</span>
                  </div>
                </div>` : `<span style="font-size:11px;color:var(--red);opacity:.8">${online?'':' '+t('common.offline')}</span>`}
              </div>`;
            }).join('')}
          </div>` : `
          <div style="padding:32px 20px;text-align:center;color:var(--text2);font-size:13px">
            ${t('dash.no_cores')}
            <button class="btn btn-primary btn-sm" style="display:block;margin:12px auto 0" onclick="navigate('tokens')">${t('dash.create_token')}</button>
          </div>`}
        </div>

        <div class="card blueprint" style="overflow:hidden">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          <div class="card-header">
            <span class="card-title">${t('dash.recent')}</span>
            <button class="btn btn-ghost btn-sm" onclick="navigate('audit')" style="font-size:11px">${t('dash.full_journal')}</button>
          </div>
          ${auditEntries.length ? `
          <div style="padding:0 0 8px">
            ${auditEntries.map(e => {
              const sevColor = e.severity === 'error' ? 'var(--red)' : e.severity === 'warning' ? 'var(--yellow)' : 'var(--accent)';
              return `<div style="display:flex;align-items:flex-start;gap:10px;padding:9px 20px;border-bottom:1px solid var(--border)">
                <div style="width:6px;height:6px;border-radius:50%;background:${sevColor};margin-top:5px;flex-shrink:0"></div>
                <div style="flex:1;min-width:0">
                  <div style="font-size:12px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(e.action||'—')}</div>
                  <div style="font-size:11px;opacity:.5">${esc(e.actor||t('dash.system'))} · ${fmtTime(e.created_at)}</div>
                </div>
                <span class="tag tag-neutral" style="font-size:10px;flex-shrink:0">${esc(e.resource_type||e.component||'admin')}</span>
              </div>`;
            }).join('')}
          </div>` : `
          <div style="padding:32px 20px;text-align:center;color:var(--text2);font-size:13px">${t('dash.no_activity')}</div>`}
        </div>

      </div>`;

    window._coreNodes = coreNodes;
    window.openCore = function(i, page) { selectCore(window._coreNodes[i], page); };
    if (typeof refreshNavCores === 'function') refreshNavCores();
  } catch(e) { content.innerHTML = `
                <div class="empty">
                    <p style="color:var(--red)">${esc(e.message)}</p>
                    <button class="btn btn-primary" onclick="pages.dashboard()">
                        ${t('common.retry')}
                    </button>
                </div>
                `;
             }
};
