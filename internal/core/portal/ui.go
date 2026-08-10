// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

// UI portail — terminal xterm.js (CDN) + auth locale / provider.
const portalIndexHTML = `<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>GoProxify Access</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
<link href="https://fonts.googleapis.com/css2?family=Figtree:wght@400;500;600;700&family=Syne:wght@700;800&display=swap" rel="stylesheet"/>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/css/xterm.min.css"/>
<style>
:root {
  --ink: #14212b;
  --ink-soft: #3a4a56;
  --mist: #eef3f6;
  --paper: #f7fafb;
  --line: #d3dde4;
  --signal: #0f6e56;
  --signal-deep: #0a4f3d;
  --warn: #b42318;
  --mono: "ui-monospace", "SFMono-Regular", Menlo, Consolas, monospace;
  --display: "Syne", sans-serif;
  --sans: "Figtree", sans-serif;
  --radius: 10px;
  --shadow-soft: 0 18px 50px rgba(20, 33, 43, 0.08);
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  margin: 0; min-height: 100vh;
  font-family: var(--sans);
  color: var(--ink);
  background-color: var(--mist);
  background-image:
    radial-gradient(ellipse 900px 480px at 8% -5%, rgba(15, 110, 86, 0.14), transparent 60%),
    radial-gradient(ellipse 700px 420px at 100% 0%, rgba(36, 72, 99, 0.10), transparent 55%),
    linear-gradient(180deg, #f4f8fa 0%, var(--mist) 40%, #e7eef2 100%),
    repeating-linear-gradient(0deg, transparent, transparent 23px, rgba(20,33,43,0.035) 24px),
    repeating-linear-gradient(90deg, transparent, transparent 23px, rgba(20,33,43,0.035) 24px);
  background-attachment: fixed;
}
body::before {
  content: "";
  position: fixed; inset: 0; pointer-events: none; z-index: 0;
  background: radial-gradient(circle at 70% 80%, rgba(15,110,86,0.05), transparent 40%);
  animation: drift 18s ease-in-out infinite alternate;
}
@keyframes drift {
  from { transform: translate3d(0,0,0); opacity: .7; }
  to { transform: translate3d(-2%, 1.5%, 0); opacity: 1; }
}
@keyframes rise {
  from { opacity: 0; transform: translateY(14px); }
  to { opacity: 1; transform: translateY(0); }
}
@keyframes fadeIn {
  from { opacity: 0; }
  to { opacity: 1; }
}
.shell {
  position: relative; z-index: 1;
  width: min(980px, calc(100% - 2rem));
  margin: 0 auto;
  padding: 2.5rem 0 3.5rem;
}
.brand-block {
  animation: rise .55s ease both;
  margin-bottom: 1.75rem;
}
.brand-block .mark {
  display: inline-flex; align-items: center; gap: .55rem;
  margin-bottom: .65rem;
}
.brand-block .mark-dot {
  width: 10px; height: 10px; border-radius: 2px;
  background: var(--signal);
  box-shadow: 0 0 0 4px rgba(15,110,86,.15);
  animation: pulseDot 2.4s ease-in-out infinite;
}
@keyframes pulseDot {
  0%, 100% { box-shadow: 0 0 0 4px rgba(15,110,86,.12); }
  50% { box-shadow: 0 0 0 7px rgba(15,110,86,.06); }
}
.brand-block h1 {
  margin: 0;
  font-family: var(--display);
  font-weight: 800;
  font-size: clamp(2.1rem, 5vw, 3rem);
  letter-spacing: -0.04em;
  line-height: 1.05;
  color: var(--ink);
}
.brand-block .tagline {
  margin: .55rem 0 0;
  max-width: 34rem;
  color: var(--ink-soft);
  font-size: 1.05rem;
  line-height: 1.45;
}
.panel {
  background: color-mix(in srgb, var(--paper) 92%, white);
  border: 1px solid var(--line);
  border-radius: calc(var(--radius) + 4px);
  box-shadow: var(--shadow-soft);
  padding: 1.35rem 1.4rem 1.5rem;
  animation: rise .6s .08s ease both;
}
.panel + .panel { margin-top: 1rem; }
.panel h2, .panel h3 {
  margin: 0 0 .85rem;
  font-family: var(--display);
  font-weight: 700;
  letter-spacing: -0.02em;
}
.panel h2 { font-size: 1.15rem; }
.panel h3 {
  font-size: .95rem;
  color: var(--ink-soft);
  margin-top: 1.35rem;
  padding-top: 1.1rem;
  border-top: 1px solid var(--line);
}
.panel h3:first-child { margin-top: 0; padding-top: 0; border-top: none; }
label {
  display: block;
  font-size: .78rem;
  font-weight: 600;
  letter-spacing: .02em;
  text-transform: uppercase;
  color: var(--ink-soft);
  margin-bottom: .35rem;
}
input, select, textarea {
  font: inherit;
  width: 100%;
  border-radius: var(--radius);
  border: 1px solid var(--line);
  background: #fff;
  color: var(--ink);
  padding: .65rem .75rem;
  transition: border-color .15s ease, box-shadow .15s ease;
}
input:focus, select:focus, textarea:focus {
  outline: none;
  border-color: color-mix(in srgb, var(--signal) 55%, var(--line));
  box-shadow: 0 0 0 3px rgba(15, 110, 86, 0.15);
}
textarea { resize: vertical; min-height: 5rem; font-family: var(--mono); font-size: .85rem; }
button {
  font: inherit;
  font-weight: 600;
  border-radius: var(--radius);
  border: 1px solid transparent;
  cursor: pointer;
  padding: .62rem 1.05rem;
  transition: transform .15s ease, background .15s ease, border-color .15s ease, color .15s ease;
}
button:hover { transform: translateY(-1px); }
button:active { transform: translateY(0); }
button:disabled { opacity: .5; cursor: not-allowed; transform: none; }
.btn-primary {
  background: var(--signal);
  color: #f4fffa;
}
.btn-primary:hover { background: var(--signal-deep); }
.btn-ghost {
  background: transparent;
  color: var(--ink);
  border-color: var(--line);
}
.btn-ghost:hover {
  border-color: color-mix(in srgb, var(--signal) 40%, var(--line));
  color: var(--signal-deep);
}
.actions {
  display: flex; flex-wrap: wrap; gap: .55rem;
  margin-top: 1rem;
}
.row {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: .75rem;
  align-items: end;
}
.row.tight { margin-top: .75rem; }
.hidden { display: none !important; }
.hint {
  margin: 0 0 1rem;
  color: var(--ink-soft);
  font-size: .92rem;
  line-height: 1.4;
}
.err {
  color: var(--warn);
  font-size: .9rem;
  margin-top: .75rem;
  min-height: 1.2em;
}
.session-bar {
  display: flex; justify-content: space-between; align-items: center;
  gap: 1rem; flex-wrap: wrap;
  margin-bottom: .25rem;
}
.session-bar strong {
  font-family: var(--display);
  font-size: 1.05rem;
}
.targets { list-style: none; padding: 0; margin: 0; }
.targets li {
  display: flex; justify-content: space-between; gap: 1rem; align-items: center;
  padding: .9rem 0;
  border-bottom: 1px solid var(--line);
  animation: fadeIn .35s ease both;
}
.targets li:last-child { border-bottom: none; }
.targets .meta {
  margin-top: .2rem;
  color: var(--ink-soft);
  font-size: .82rem;
  font-family: var(--mono);
}
.targets .row { display: flex; gap: .45rem; flex: 0; grid-template-columns: none; }
.tabs {
  display: flex; flex-wrap: wrap; gap: .4rem;
  margin: 1rem 0 1.1rem;
  padding-bottom: .75rem;
  border-bottom: 1px solid var(--line);
}
.tabs button.tab {
  background: transparent;
  border: 1px solid transparent;
  color: var(--ink-soft);
  padding: .45rem .85rem;
  font-size: .9rem;
}
.tabs button.tab:hover { color: var(--ink); border-color: var(--line); }
.tabs button.tab.active {
  color: var(--signal-deep);
  background: color-mix(in srgb, var(--signal) 10%, white);
  border-color: color-mix(in srgb, var(--signal) 35%, var(--line));
}
.tab-panel.hidden { display: none !important; }
.catalog-toolbar {
  display: flex; flex-wrap: wrap; gap: .65rem;
  align-items: center; margin-bottom: 1rem;
}
.catalog-toolbar .search-wrap { flex: 1; min-width: 180px; }
.catalog-toolbar input { margin: 0; }
.tile-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: .85rem;
  list-style: none; padding: 0; margin: 0;
}
.tile {
  display: flex; flex-direction: column; gap: .65rem;
  background: #fff;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  padding: .95rem 1rem;
  animation: rise .4s ease both;
  transition: border-color .15s ease, box-shadow .15s ease;
}
.tile:hover {
  border-color: color-mix(in srgb, var(--signal) 40%, var(--line));
  box-shadow: 0 8px 24px rgba(20, 33, 43, 0.06);
}
.tile.fav {
  border-color: color-mix(in srgb, var(--signal) 45%, var(--line));
  background: color-mix(in srgb, var(--signal) 5%, white);
}
.tile-head {
  display: flex; justify-content: space-between; align-items: flex-start; gap: .5rem;
}
.tile-head strong {
  font-family: var(--display);
  font-size: 1rem;
  letter-spacing: -.02em;
  line-height: 1.2;
}
.tile .meta {
  color: var(--ink-soft);
  font-size: .78rem;
  font-family: var(--mono);
  line-height: 1.35;
  word-break: break-all;
}
.tile-actions { display: flex; flex-wrap: wrap; gap: .4rem; margin-top: auto; }
.tile-actions button { flex: 1; min-width: 4.5rem; padding: .45rem .6rem; font-size: .85rem; }
button.star {
  flex: 0; padding: .35rem .55rem; font-size: 1rem; line-height: 1;
  border-color: var(--line); background: transparent; color: var(--ink-soft);
}
button.star.on { color: var(--signal-deep); border-color: color-mix(in srgb, var(--signal) 40%, var(--line)); }
.twofa-grid { margin-top: .85rem; }
.twofa-tile .twofa-title {
  display: flex; align-items: flex-start; gap: .7rem; min-width: 0;
}
.twofa-glyph {
  flex: 0 0 auto;
  width: 2.25rem; height: 2.25rem;
  display: grid; place-items: center;
  border-radius: 8px;
  background: color-mix(in srgb, var(--signal) 12%, white);
  color: var(--signal-deep);
  border: 1px solid color-mix(in srgb, var(--signal) 22%, var(--line));
}
.twofa-tile.on .twofa-glyph {
  background: color-mix(in srgb, var(--signal) 18%, white);
  border-color: color-mix(in srgb, var(--signal) 40%, var(--line));
}
.twofa-badge {
  flex: 0 0 auto;
  font-size: .72rem;
  font-weight: 600;
  letter-spacing: .02em;
  text-transform: uppercase;
  padding: .22rem .55rem;
  border-radius: 999px;
  border: 1px solid var(--line);
  color: var(--ink-soft);
  background: var(--paper);
}
.twofa-tile.on .twofa-badge {
  color: var(--signal-deep);
  border-color: color-mix(in srgb, var(--signal) 40%, var(--line));
  background: color-mix(in srgb, var(--signal) 10%, white);
}
.twofa-tile.on {
  border-color: color-mix(in srgb, var(--signal) 40%, var(--line));
  background: color-mix(in srgb, var(--signal) 4%, white);
}
.icon-actions { display: flex; gap: .35rem; margin-top: auto; justify-content: flex-end; }
.icon-actions button { flex: 0 0 auto; min-width: 0; }
.btn-icon {
  display: inline-grid; place-items: center;
  width: 2.15rem; height: 2.15rem;
  padding: 0;
  border-radius: 8px;
  border: 1px solid var(--line);
  background: #fff;
  color: var(--ink-soft);
  cursor: pointer;
  transition: border-color .15s ease, color .15s ease, background .15s ease;
}
.btn-icon:hover {
  color: var(--ink);
  border-color: color-mix(in srgb, var(--signal) 35%, var(--line));
  background: color-mix(in srgb, var(--signal) 6%, white);
}
.btn-icon.danger:hover {
  color: var(--warn);
  border-color: color-mix(in srgb, var(--warn) 35%, var(--line));
  background: color-mix(in srgb, var(--warn) 6%, white);
}
.btn-icon:disabled {
  opacity: .38; cursor: not-allowed;
}
.btn-icon svg { display: block; }
.totp-setup {
  margin-top: .75rem;
  padding-top: .75rem;
  border-top: 1px solid var(--line);
}
.empty-hint {
  color: var(--ink-soft); border: none; padding: .5rem 0; font-size: .92rem;
}
pre.chain {
  margin: 0;
  background: var(--ink);
  color: #d7e4ea;
  border-radius: var(--radius);
  padding: 1rem 1.05rem;
  overflow-x: auto;
  font-family: var(--mono);
  font-size: .82rem;
  line-height: 1.45;
  white-space: pre-wrap;
  word-break: break-all;
}
#term {
  height: min(420px, 55vh);
  background: #101820;
  border: 1px solid #24313c;
  border-radius: var(--radius);
  padding: .4rem;
  overflow: hidden;
}
.auth-hero .panel { max-width: 520px; }
@media (max-width: 640px) {
  .shell { width: calc(100% - 1.25rem); padding-top: 1.5rem; }
  .brand-block h1 { font-size: 2rem; }
  .targets li { flex-direction: column; align-items: stretch; }
  .targets .row { width: 100%; }
  .targets .row button { flex: 1; }
}
@media (prefers-reduced-motion: reduce) {
  *, *::before { animation: none !important; transition: none !important; }
}
</style>
</head>
<body>
<div class="shell">
  <header class="brand-block">
    <div class="mark"><span class="mark-dot" aria-hidden="true"></span></div>
    <h1>GoProxify Access</h1>
    <p class="tagline">Sessions SSH et shell à jeton UUID — VM, bare-metal et conteneurs Docker.</p>
  </header>

  <section id="auth" class="auth-hero">
    <div class="panel">
      <h2>Connexion</h2>
      <p id="authHint" class="hint"></p>
      <div class="row">
        <div><label for="user">Utilisateur</label><input id="user" autocomplete="username"/></div>
        <div><label for="pass">Mot de passe</label><input id="pass" type="password" autocomplete="current-password"/></div>
      </div>
      <div class="actions">
        <button type="button" class="btn-primary" id="btnLogin">Connexion</button>
        <button type="button" class="btn-ghost hidden" id="btnSSO">Connexion SSO</button>
      </div>
      <div id="authErr" class="err"></div>
    </div>
  </section>

  <section id="invite" class="auth-hero hidden">
    <div class="panel">
      <h2>Activer votre compte</h2>
      <p class="hint">Choisissez un mot de passe (8 caractères minimum).</p>
      <div class="row">
        <div><label for="invitePass">Mot de passe</label><input id="invitePass" type="password" autocomplete="new-password"/></div>
        <div><label for="invitePass2">Confirmation</label><input id="invitePass2" type="password" autocomplete="new-password"/></div>
      </div>
      <div class="actions">
        <button type="button" class="btn-primary" id="btnInvite">Enregistrer</button>
      </div>
      <div id="inviteErr" class="err"></div>
    </div>
  </section>

  <section id="twofa" class="auth-hero hidden">
    <div class="panel">
      <h2>Vérification 2FA</h2>
      <p class="hint" id="twofaHint">Entrez le code de votre application ou OTP email.</p>
      <div class="row">
        <div><label for="twofaMethod">Méthode</label>
          <select id="twofaMethod"><option value="totp">TOTP</option><option value="email">Email</option></select>
        </div>
        <div><label for="twofaCode">Code</label><input id="twofaCode" inputmode="numeric" autocomplete="one-time-code"/></div>
      </div>
      <div class="actions">
        <button type="button" class="btn-primary" id="btnTwoFA">Valider</button>
        <button type="button" class="btn-ghost hidden" id="btnTwoFAEmail">Envoyer OTP email</button>
      </div>
      <div id="twofaErr" class="err"></div>
    </div>
  </section>

  <section id="app" class="hidden">
    <div class="panel">
      <div class="session-bar">
        <strong id="who"></strong>
        <button type="button" class="btn-ghost" id="btnLogout">Déconnexion</button>
      </div>

      <nav class="tabs" role="tablist" aria-label="Sections Access">
        <button type="button" class="tab active" data-tab="catalog" role="tab">Catalogue</button>
        <button type="button" class="tab" data-tab="vault" role="tab">Coffre</button>
        <button type="button" class="tab" data-tab="sessions" role="tab">Sessions</button>
        <button type="button" class="tab" data-tab="account" role="tab">Compte</button>
      </nav>

      <div id="tab-catalog" class="tab-panel">
        <div class="catalog-toolbar">
          <div class="search-wrap">
            <label for="catalogSearch">Recherche</label>
            <input id="catalogSearch" type="search" placeholder="Nom, host, agent…" autocomplete="off"/>
          </div>
        </div>
        <ul class="tile-grid" id="list"></ul>
        <div id="personalBlock" class="hidden" style="margin-top:1.25rem">
          <h3 style="margin-top:0;padding-top:0;border:none">Cible personnelle</h3>
          <div class="row">
            <div><label for="tKind">Type</label>
              <select id="tKind">
                <option value="ssh">SSH (VM / bare-metal)</option>
              </select>
            </div>
            <div><label for="tName">Nom</label><input id="tName"/></div>
          </div>
          <div id="sshFields">
            <div class="row tight">
              <div><label for="tHost">Host</label><input id="tHost" placeholder="10.0.0.5"/></div>
              <div><label for="tPort">Port</label><input id="tPort" type="number" value="22"/></div>
            </div>
            <div class="row tight">
              <div><label for="tUser">User SSH</label><input id="tUser"/></div>
              <div><label for="tPass">Mot de passe cible</label><input id="tPass" type="password" autocomplete="new-password"/></div>
            </div>
            <div class="tight" style="margin-top:.75rem"><label for="tKey">Clé privée (optionnel)</label><textarea id="tKey" rows="3"></textarea></div>
          </div>
          <div class="actions">
            <button type="button" class="btn-primary" id="btnAdd">Enregistrer la cible</button>
          </div>
          <div id="targetErr" class="err"></div>
        </div>
      </div>

      <div id="tab-vault" class="tab-panel hidden">
        <p class="hint">Login SSH + mot de passe ou clé — chiffrés côté serveur. Jamais le mail Access.</p>
        <div class="row tight">
          <div><label for="vTarget">Cible</label><select id="vTarget"></select></div>
          <div><label for="vUser">Login SSH</label><input id="vUser" autocomplete="username" placeholder="root, ubuntu…"/></div>
        </div>
        <div class="row tight" style="margin-top:.75rem">
          <div><label for="vPass">Mot de passe</label><input id="vPass" type="password" autocomplete="new-password"/></div>
        </div>
        <div class="tight" style="margin-top:.75rem"><label for="vKey">Clé privée (optionnel)</label><textarea id="vKey" rows="2" placeholder="Si pas de mot de passe"></textarea></div>
        <div class="actions">
          <button type="button" class="btn-primary" id="btnVaultSave">Enregistrer dans le coffre</button>
          <button type="button" class="btn-ghost" id="btnVaultDel">Retirer</button>
        </div>
        <div id="vaultErr" class="err"></div>
        <ul class="targets" id="vaultList" style="margin-top:.75rem"></ul>
      </div>

      <div id="tab-sessions" class="tab-panel hidden">
        <h3 style="margin-top:0;padding-top:0;border:none">Chaîne de connexion</h3>
        <pre class="chain" id="chain">Générez une session depuis une cible du catalogue.</pre>
        <h3>Mes sessions</h3>
        <p class="hint" style="margin-top:-.35rem">UUID actifs — révocables avant connexion.</p>
        <ul class="targets" id="sessionList"></ul>
        <div id="sessionErr" class="err"></div>
        <h3>Historique</h3>
        <p class="hint" style="margin-top:-.35rem">Audit personnel (sans contenu terminal).</p>
        <ul class="targets" id="auditList"></ul>
        <h3>Terminal web</h3>
        <div id="term"></div>
      </div>

      <div id="tab-account" class="tab-panel hidden">
        <h3 style="margin-top:0;padding-top:0;border:none">Sécurité 2FA</h3>
        <p class="hint" style="margin-top:-.35rem" id="twofaStatusHint">Choisissez une ou plusieurs méthodes OTP.</p>
        <div class="tile-grid twofa-grid">
          <article class="tile twofa-tile" id="tileTotp">
            <div class="tile-head">
              <div class="twofa-title">
                <span class="twofa-glyph" aria-hidden="true">
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="5" y="2" width="14" height="20" rx="2"/><path d="M12 18h.01"/></svg>
                </span>
                <div>
                  <strong>TOTP</strong>
                  <div class="meta">Application Authenticator</div>
                </div>
              </div>
              <span class="twofa-badge" id="totpBadge">Inactif</span>
            </div>
            <div class="icon-actions">
              <button type="button" class="btn-icon" id="btnTotpSetup" title="Configurer / QR code" aria-label="Configurer TOTP">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><path d="M14 14h3v3h-3zM20 14v6M14 20h6"/></svg>
              </button>
              <button type="button" class="btn-icon danger hidden" id="btnTotpOff" title="Désactiver TOTP" aria-label="Désactiver TOTP">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>
              </button>
            </div>
            <div id="totpSetupBox" class="totp-setup hidden">
              <p class="hint" style="margin-top:0">Scannez ce QR code, puis saisissez le code généré.</p>
              <div style="display:flex;justify-content:center;margin:.65rem 0">
                <img id="totpQR" alt="QR code TOTP" width="176" height="176" style="display:none;background:#fff;padding:8px;border-radius:8px"/>
              </div>
              <p class="hint" style="margin:0 0 .5rem"><a id="totpOpenApp" href="#" target="_blank" rel="noopener">Ouvrir dans l'application Authenticator</a></p>
              <p class="hint">Clé manuelle : <code id="totpSecret"></code></p>
              <div class="row tight">
                <div><label for="totpEnableCode">Code TOTP</label><input id="totpEnableCode" inputmode="numeric" maxlength="6" autocomplete="one-time-code"/></div>
              </div>
              <div class="icon-actions" style="justify-content:flex-start;margin-top:.65rem">
                <button type="button" class="btn-icon" id="btnTotpEnable" title="Activer TOTP" aria-label="Activer TOTP" style="width:auto;padding:0 .85rem;gap:.4rem;display:inline-flex;align-items:center">
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6L9 17l-5-5"/></svg>
                  Activer
                </button>
              </div>
            </div>
          </article>

          <article class="tile twofa-tile" id="tileEmail">
            <div class="tile-head">
              <div class="twofa-title">
                <span class="twofa-glyph" aria-hidden="true">
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
                </span>
                <div>
                  <strong>OTP email</strong>
                  <div class="meta">Code à usage unique par e-mail</div>
                </div>
              </div>
              <span class="twofa-badge" id="emailBadge">Inactif</span>
            </div>
            <div class="icon-actions">
              <button type="button" class="btn-icon" id="btnEmailOn" title="Activer OTP email" aria-label="Activer OTP email">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14"/><path d="M5 12h14"/></svg>
              </button>
              <button type="button" class="btn-icon danger hidden" id="btnEmailOff" title="Désactiver OTP email" aria-label="Désactiver OTP email">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>
              </button>
            </div>
          </article>
        </div>
        <div id="twofaManageErr" class="err"></div>
      </div>
    </div>
  </section>
</div>
<script src="https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/lib/xterm.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/@xterm/addon-fit@0.10.0/lib/addon-fit.min.js"></script>
<script>
const TOK_KEY = 'gpx_portal_tok';
const USER_KEY = 'gpx_portal_user';
const state = {
  token: sessionStorage.getItem(TOK_KEY) || '',
  user: sessionStorage.getItem(USER_KEY) || '',
  allowPersonal: false,
  challengeId: '',
  targets: [],
  favorites: [],
  catalogQuery: '',
  term: null, fit: null, ws: null
};
const $ = (id) => document.getElementById(id);
function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function setTab(name) {
  document.querySelectorAll('.tabs .tab').forEach(b => b.classList.toggle('active', b.dataset.tab === name));
  ['catalog','vault','sessions','account'].forEach(id => {
    const el = $('tab-' + id);
    if (el) el.classList.toggle('hidden', id !== name);
  });
  if (name === 'sessions' && state.term && state.fit) {
    try { state.fit.fit(); } catch (_) {}
  }
}
document.querySelectorAll('.tabs .tab').forEach(btn => {
  btn.addEventListener('click', () => setTab(btn.dataset.tab));
});
function isFav(id) { return (state.favorites || []).includes(id); }
function matchQuery(t, q) {
  q = (q || '').trim().toLowerCase();
  if (!q) return true;
  const hay = [t.name, t.kind, t.source, t.host, t.agent_name, t.container].join(' ').toLowerCase();
  return hay.includes(q);
}
function sortedTargets() {
  const fav = state.favorites || [];
  const all = (state.targets || []).filter(t => matchQuery(t, state.catalogQuery));
  const favItems = [];
  const rest = [];
  const placed = {};
  fav.forEach(id => {
    const t = all.find(x => x.id === id);
    if (t) { favItems.push(t); placed[id] = true; }
  });
  all.forEach(t => { if (!placed[t.id]) rest.push(t); });
  return favItems.concat(rest);
}

function showApp() {
  $('auth').classList.add('hidden');
  $('invite').classList.add('hidden');
  $('twofa').classList.add('hidden');
  $('app').classList.remove('hidden');
  $('who').textContent = state.user;
  refreshAll();
}
function showAuth() {
  $('app').classList.add('hidden');
  $('invite').classList.add('hidden');
  $('twofa').classList.add('hidden');
  $('auth').classList.remove('hidden');
}
function showInvite() {
  $('app').classList.add('hidden');
  $('auth').classList.add('hidden');
  $('twofa').classList.add('hidden');
  $('invite').classList.remove('hidden');
}
function showTwoFA(methods) {
  $('app').classList.add('hidden');
  $('auth').classList.add('hidden');
  $('invite').classList.add('hidden');
  $('twofa').classList.remove('hidden');
  const sel = $('twofaMethod');
  sel.innerHTML = '';
  (methods || ['totp']).forEach(m => {
    const o = document.createElement('option');
    o.value = m; o.textContent = m === 'email' ? 'OTP email' : 'TOTP';
    sel.append(o);
  });
  $('btnTwoFAEmail').classList.toggle('hidden', !(methods || []).includes('email'));
  $('twofaCode').value = '';
  $('twofaErr').textContent = '';
}
function clearSession() {
  state.token = ''; state.user = '';
  sessionStorage.removeItem(TOK_KEY);
  sessionStorage.removeItem(USER_KEY);
  try {
    localStorage.removeItem(TOK_KEY);
    localStorage.removeItem(USER_KEY);
    localStorage.removeItem('gpx_portal_pass');
  } catch (_) {}
}
function persistSession() {
  sessionStorage.setItem(TOK_KEY, state.token);
  sessionStorage.setItem(USER_KEY, state.user);
}
async function api(path, opts = {}) {
  const headers = Object.assign({ 'Content-Type': 'application/json' }, opts.headers || {});
  if (state.token) headers.Authorization = 'Bearer ' + state.token;
  const res = await fetch(path, Object.assign({}, opts, { headers }));
  if (res.status === 401 && path !== '/api/login') {
    clearSession();
    showAuth();
    throw new Error('Session expirée — reconnectez-vous');
  }
  if (!res.ok) throw new Error(await res.text());
  if (res.status === 204) return null;
  return res.json();
}
async function loadAuthInfo() {
  try {
    const info = await fetch('/api/auth-info').then(r => r.json());
    state.allowPersonal = !!info.allow_personal_targets;
    const hint = $('authHint');
    const btnSSO = $('btnSSO');
    if (info.provider) {
      const p = info.provider;
      let msg = 'Fournisseur « ' + (p.name || p.id) + ' » (' + p.type + ').';
      if (p.oidc) {
        msg += ' Préférez Connexion SSO, ou un compte local.';
        btnSSO.classList.remove('hidden');
        btnSSO.onclick = () => { location.href = p.oidc_start || '/api/oidc/start'; };
      } else if (p.form_login) {
        msg += ' Identifiants IdP (basic/LDAP), ou compte local.';
      } else {
        msg += ' Formulaire non supporté pour ce type — comptes locaux OK.';
      }
      hint.textContent = msg;
    } else {
      hint.textContent = 'Comptes locaux du portail.';
    }
    if (info.provider_error) hint.textContent += ' (' + info.provider_error + ')';
  } catch (_) {}
}
$('btnLogin').onclick = async () => {
  $('authErr').textContent = '';
  try {
    const d = await api('/api/login', { method: 'POST', body: JSON.stringify({ username: $('user').value, password: $('pass').value }) });
    $('pass').value = '';
    if (d.need_2fa) {
      state.challengeId = d.challenge_id;
      state.user = d.username || '';
      showTwoFA(d.methods || []);
      return;
    }
    state.token = d.token; state.user = d.username;
    persistSession();
    showApp();
  } catch (e) { $('authErr').textContent = e.message; }
};
$('btnTwoFA').onclick = async () => {
  $('twofaErr').textContent = '';
  try {
    const d = await api('/api/2fa/verify', { method: 'POST', body: JSON.stringify({
      challenge_id: state.challengeId,
      method: $('twofaMethod').value,
      code: $('twofaCode').value.trim()
    })});
    state.token = d.token; state.user = d.username;
    state.challengeId = '';
    $('twofaCode').value = '';
    persistSession();
    showApp();
  } catch (e) { $('twofaErr').textContent = e.message; }
};
$('btnTwoFAEmail').onclick = async () => {
  $('twofaErr').textContent = '';
  try {
    await api('/api/2fa/email/send', { method: 'POST', body: JSON.stringify({ challenge_id: state.challengeId }) });
    $('twofaHint').textContent = 'Code envoyé par email — saisissez-le ci-dessous.';
  } catch (e) { $('twofaErr').textContent = e.message; }
};
$('btnInvite').onclick = async () => {
  $('inviteErr').textContent = '';
  try {
    const p1 = $('invitePass').value;
    const p2 = $('invitePass2').value;
    if (p1.length < 8) throw new Error('Mot de passe trop court (≥8)');
    if (p1 !== p2) throw new Error('Les mots de passe ne correspondent pas');
    const params = new URLSearchParams(location.search);
    const token = params.get('invite') || '';
    if (!token) throw new Error('Jeton d\'invitation manquant');
    const d = await api('/api/complete-invite', { method: 'POST', body: JSON.stringify({ token, password: p1 }) });
    state.token = d.token; state.user = d.username;
    $('invitePass').value = $('invitePass2').value = '';
    persistSession();
    history.replaceState({}, '', location.pathname);
    showApp();
  } catch (e) { $('inviteErr').textContent = e.message; }
};
$('btnLogout').onclick = async () => {
  try { await api('/api/logout', { method: 'POST' }); } catch (_) {}
  clearSession();
  showAuth();
};
$('tKind').onchange = () => {};
$('btnAdd').onclick = async () => {
  $('targetErr').textContent = '';
  try {
    const kind = $('tKind').value || 'ssh';
    const body = { name: $('tName').value.trim(), kind };
    if (!body.name) throw new Error('Nom requis');
    if (kind === 'docker') {
      throw new Error('Docker personnel interdit — utilisez le catalogue');
    }
    body.host = $('tHost').value.trim();
    body.port = +$('tPort').value || 22;
    body.username = $('tUser').value.trim();
    body.password = $('tPass').value;
    body.private_key = $('tKey').value;
    if (!body.host) throw new Error('Host requis');
    await api('/api/targets', { method: 'POST', body: JSON.stringify(body) });
    $('tName').value = $('tHost').value = $('tUser').value = $('tPass').value = $('tKey').value = '';
    await refreshAll();
  } catch (e) {
    $('targetErr').textContent = e.message || String(e);
  }
};
$('btnVaultSave').onclick = async () => {
  $('vaultErr').textContent = '';
  try {
    const id = $('vTarget').value;
    if (!id) throw new Error('Choisissez une cible');
    const username = ($('vUser').value || '').trim();
    const password = $('vPass').value;
    const private_key = $('vKey').value;
    if (!username) throw new Error('Login SSH requis (pas votre email Access)');
    if (!password && !private_key) throw new Error('Mot de passe ou clé privée requis');
    await api('/api/vault/' + encodeURIComponent(id), {
      method: 'PUT', body: JSON.stringify({ username, password, private_key })
    });
    $('vPass').value = '';
    $('vKey').value = '';
    await refreshVault();
  } catch (e) { $('vaultErr').textContent = e.message || String(e); }
};
$('btnVaultDel').onclick = async () => {
  $('vaultErr').textContent = '';
  try {
    const id = $('vTarget').value;
    if (!id) throw new Error('Choisissez une cible');
    await api('/api/vault/' + encodeURIComponent(id), { method: 'DELETE' });
    await refreshVault();
  } catch (e) { $('vaultErr').textContent = e.message || String(e); }
};
async function refreshAll() {
  try {
    const me = await api('/api/me');
    state.allowPersonal = !!me.allow_personal_targets;
    state.favorites = me.favorites || [];
    sync2FATiles(me);
  } catch (_) {}
  $('personalBlock').classList.toggle('hidden', !state.allowPersonal);
  await refreshTargets();
  await refreshVault();
  await refreshSessions();
  await refreshAudit();
}
function sync2FATiles(me) {
  const totpOn = !!me.totp_enabled;
  const emailOn = !!me.email_otp_enabled;
  $('tileTotp').classList.toggle('on', totpOn);
  $('tileEmail').classList.toggle('on', emailOn);
  $('totpBadge').textContent = totpOn ? 'Actif' : 'Inactif';
  $('emailBadge').textContent = emailOn ? 'Actif' : 'Inactif';
  $('btnTotpSetup').classList.toggle('hidden', totpOn);
  $('btnTotpOff').classList.toggle('hidden', !totpOn);
  $('btnEmailOn').classList.toggle('hidden', emailOn);
  $('btnEmailOff').classList.toggle('hidden', !emailOn);
  if (totpOn) {
    $('totpSetupBox').classList.add('hidden');
    $('totpEnableCode').value = '';
  }
  const bits = [];
  if (totpOn) bits.push('TOTP');
  if (emailOn) bits.push('OTP email');
  let hint = 'Choisissez une ou plusieurs méthodes OTP.';
  if (me.require_2fa && !bits.length) {
    hint = '2FA obligatoire — activez TOTP ou OTP email.';
  } else if (bits.length) {
    hint = (me.require_2fa ? '2FA obligatoire · ' : '') + 'Actif : ' + bits.join(', ') + '.';
  }
  $('twofaStatusHint').textContent = hint;
}
async function refreshSessions() {
  try {
    const d = await api('/api/sessions');
    const ul = $('sessionList'); ul.innerHTML = '';
    (d.sessions || []).forEach(s => {
      const li = document.createElement('li');
      li.innerHTML = '<div><strong>' + esc(s.facade || '') + '</strong><div class="meta">' +
        esc(s.target_id || '') + ' · exp ' + esc(s.expires_at || '') + '</div></div>';
      const b = document.createElement('button');
      b.className = 'btn-ghost'; b.textContent = 'Révoquer';
      b.onclick = () => revokeSession(s.id);
      li.append(b);
      ul.append(li);
    });
    if (!(d.sessions || []).length) {
      ul.innerHTML = '<li style="color:var(--ink-soft);border:none;padding:.35rem 0">Aucune session active.</li>';
    }
  } catch (e) {
    if ($('sessionErr')) $('sessionErr').textContent = e.message;
  }
}
async function revokeSession(id) {
  $('sessionErr').textContent = '';
  try {
    await api('/api/sessions/' + encodeURIComponent(id), { method: 'DELETE' });
    await refreshSessions();
    await refreshAudit();
  } catch (e) { $('sessionErr').textContent = e.message || String(e); }
}
async function refreshAudit() {
  try {
    const d = await api('/api/audit');
    const ul = $('auditList'); ul.innerHTML = '';
    (d.events || []).slice(0, 30).forEach(e => {
      const li = document.createElement('li');
      const ts = e.ts ? (typeof e.ts === 'string' ? e.ts : e.ts) : '';
      li.innerHTML = '<div><strong>' + esc(e.detail || (e.success ? 'ok' : 'échec')) + '</strong><div class="meta">' +
        esc(ts) + ' · ' + esc(e.target_id || '') + ' · ' + esc(e.facade || '') + ' · ' + (e.success ? 'ok' : 'ko') + '</div></div>';
      ul.append(li);
    });
    if (!(d.events || []).length) {
      ul.innerHTML = '<li style="color:var(--ink-soft);border:none;padding:.35rem 0">Aucun événement.</li>';
    }
  } catch (_) {}
}
$('btnTotpSetup').onclick = async () => {
  $('twofaManageErr').textContent = '';
  try {
    const d = await api('/api/2fa/totp/setup', { method: 'POST', body: '{}' });
    $('totpSecret').textContent = d.secret || '';
    const img = $('totpQR');
    if (d.qr_code) {
      img.src = d.qr_code;
      img.style.display = 'block';
    } else {
      img.removeAttribute('src');
      img.style.display = 'none';
    }
    const open = $('totpOpenApp');
    if (d.otpauth_uri) {
      open.href = d.otpauth_uri;
      open.style.display = '';
    } else {
      open.removeAttribute('href');
      open.style.display = 'none';
    }
    $('totpSetupBox').classList.remove('hidden');
  } catch (e) { $('twofaManageErr').textContent = e.message; }
};
$('btnTotpEnable').onclick = async () => {
  $('twofaManageErr').textContent = '';
  try {
    await api('/api/2fa/totp/verify', { method: 'POST', body: JSON.stringify({ code: $('totpEnableCode').value.trim() }) });
    $('totpSetupBox').classList.add('hidden');
    $('totpEnableCode').value = '';
    await refreshAll();
  } catch (e) { $('twofaManageErr').textContent = e.message; }
};
$('btnTotpOff').onclick = async () => {
  try { await api('/api/2fa/totp', { method: 'DELETE' }); await refreshAll(); }
  catch (e) { $('twofaManageErr').textContent = e.message; }
};
$('btnEmailOn').onclick = async () => {
  try { await api('/api/2fa/email/enable', { method: 'POST', body: '{}' }); await refreshAll(); }
  catch (e) { $('twofaManageErr').textContent = e.message; }
};
$('btnEmailOff').onclick = async () => {
  try { await api('/api/2fa/email', { method: 'DELETE' }); await refreshAll(); }
  catch (e) { $('twofaManageErr').textContent = e.message; }
};
async function refreshTargets() {
  try {
    const d = await api('/api/targets');
    state.targets = d.targets || [];
    renderCatalog();
    const sel = $('vTarget');
    const prev = sel.value;
    sel.innerHTML = '';
    state.targets.forEach(t => {
      const opt = document.createElement('option');
      opt.value = t.id;
      opt.textContent = t.name + ' (' + t.source + ')';
      sel.append(opt);
    });
    if (prev) sel.value = prev;
  } catch (e) {
    if ($('vaultErr')) $('vaultErr').textContent = e.message;
  }
}
function renderCatalog() {
  const ul = $('list'); ul.innerHTML = '';
  const items = sortedTargets();
  items.forEach((t, i) => {
    const li = document.createElement('li');
    li.className = 'tile' + (isFav(t.id) ? ' fav' : '');
    li.style.animationDelay = (i * 35) + 'ms';
    const meta = t.kind === 'docker'
      ? (t.agent_name || '') + ' / ' + (t.container || '')
      : (t.host || '') + ':' + (t.port || '');
    const head = document.createElement('div');
    head.className = 'tile-head';
    head.innerHTML = '<div><strong>' + esc(t.name) + '</strong><div class="meta">' +
      esc(t.source) + ' · ' + esc(t.kind) + ' · ' + esc(meta) + '</div></div>';
    const star = document.createElement('button');
    star.type = 'button';
    star.className = 'star' + (isFav(t.id) ? ' on' : '');
    star.title = 'Favori';
    star.textContent = isFav(t.id) ? '★' : '☆';
    star.onclick = () => toggleFavorite(t.id);
    head.append(star);
    li.append(head);
    const actions = document.createElement('div');
    actions.className = 'tile-actions';
    const bSSH = document.createElement('button'); bSSH.className = 'btn-primary'; bSSH.textContent = 'SSH';
    bSSH.onclick = () => createSession(t, 'ssh').catch(err => { $('vaultErr').textContent = err.message; setTab('vault'); });
    const bWeb = document.createElement('button'); bWeb.className = 'btn-ghost'; bWeb.textContent = 'Web';
    bWeb.onclick = () => createSession(t, 'web').catch(err => { $('vaultErr').textContent = err.message; setTab('vault'); });
    actions.append(bSSH, bWeb);
    li.append(actions);
    ul.append(li);
  });
  if (!items.length) {
    ul.innerHTML = '<li class="empty-hint" style="grid-column:1/-1">' +
      ((state.targets || []).length ? 'Aucun résultat pour cette recherche.' : 'Aucune cible visible.') + '</li>';
  }
}
async function toggleFavorite(id) {
  try {
    const d = await api('/api/favorites/' + encodeURIComponent(id), { method: 'POST', body: '{}' });
    state.favorites = d.favorites || [];
    renderCatalog();
  } catch (e) {
    if ($('targetErr')) $('targetErr').textContent = e.message;
  }
}
$('catalogSearch').addEventListener('input', () => {
  state.catalogQuery = $('catalogSearch').value || '';
  renderCatalog();
});
async function refreshVault() {
  try {
    const d = await api('/api/vault');
    const ul = $('vaultList'); ul.innerHTML = '';
    const byId = {};
    state.targets.forEach(t => { byId[t.id] = t; });
    (d.entries || []).forEach(e => {
      const t = byId[e.target_id];
      const name = t ? t.name : e.target_id;
      const li = document.createElement('li');
      const flags = [];
      if (e.username) flags.push('login ' + e.username);
      if (e.has_password) flags.push('password');
      if (e.has_private_key) flags.push('clé');
      li.innerHTML = '<div><strong>' + esc(name) + '</strong><div class="meta">' + esc(flags.join(' · ') || 'vide') + '</div></div>';
      ul.append(li);
    });
    if (!(d.entries || []).length) {
      ul.innerHTML = '<li style="color:var(--ink-soft);border:none;padding:.35rem 0">Coffre vide.</li>';
    }
  } catch (e) {
    if ($('vaultErr')) $('vaultErr').textContent = e.message;
  }
}
async function createSession(t, facade) {
  const d = await api('/api/sessions', { method: 'POST', body: JSON.stringify({ target_id: t.id, source: t.source, facade }) });
  $('chain').textContent = 'SSH:\n' + d.ssh + '\n\nWeb:\n' + d.web_url + '\n\nUUID (TTL ' + d.ttl_sec + 's, ' + (d.mode || '') + '):\n' + d.uuid;
  setTab('sessions');
  await refreshSessions();
  await refreshAudit();
  if (facade === 'web') openTerm(d.uuid);
}
function ensureTerm() {
  if (state.term) return;
  state.term = new Terminal({
    cursorBlink: true,
    fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
    fontSize: 13,
    theme: { background: '#101820', foreground: '#d7e4ea', cursor: '#0f6e56' },
  });
  state.fit = new FitAddon.FitAddon();
  state.term.loadAddon(state.fit);
  state.term.open($('term'));
  state.fit.fit();
  window.addEventListener('resize', () => { try { state.fit.fit(); } catch (_) {} });
}
function openTerm(uuid) {
  ensureTerm();
  if (state.ws) { try { state.ws.close(); } catch (_) {} }
  state.term.reset();
  state.term.focus();
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(proto + '//' + location.host + '/api/ws/' + uuid);
  state.ws = ws;
  ws.binaryType = 'arraybuffer';
  ws.onopen = () => { try { state.fit.fit(); } catch (_) {} };
  ws.onmessage = (ev) => {
    if (typeof ev.data === 'string') state.term.write(ev.data);
    else state.term.write(new Uint8Array(ev.data));
  };
  ws.onclose = () => { state.term.writeln('\r\n[session fermée]'); };
  ws.onerror = () => { state.term.writeln('\r\n[erreur WS]'); };
  state.term.onData((data) => {
    if (ws.readyState === 1) ws.send(data);
  });
}
(async () => {
  const inviteTok = new URLSearchParams(location.search).get('invite');
  if (inviteTok) {
    showInvite();
    return;
  }
  const sso2fa = location.hash.match(/sso_2fa=([^&]+)/);
  if (sso2fa) {
    const params = new URLSearchParams(location.hash.replace(/^#/, ''));
    state.challengeId = decodeURIComponent(sso2fa[1]);
    state.user = params.get('user') || '';
    const methods = (params.get('methods') || 'totp').split(',').filter(Boolean);
    history.replaceState(null, '', location.pathname + location.search);
    showTwoFA(methods);
    return;
  }
  const ssoMatch = location.hash.match(/(?:^|[&#])sso=([^&]+)/);
  if (ssoMatch) {
    try {
      const tok = decodeURIComponent(ssoMatch[1]);
      state.token = tok;
      persistSession();
      history.replaceState(null, '', location.pathname + location.search);
      const me = await api('/api/me');
      state.user = me.username || '';
      persistSession();
      showApp();
      await loadAuthInfo();
      return;
    } catch (e) {
      clearSession();
      $('authErr').textContent = e.message || 'SSO échoué';
    }
  }
  await loadAuthInfo();
  if (state.token) {
    try {
      const me = await api('/api/me');
      state.user = me.username || state.user;
      persistSession();
      showApp();
    } catch (_) {
      clearSession();
      showAuth();
    }
  }
  const m = location.hash.match(/term=([0-9a-f-]{36})/i);
  if (m) openTerm(m[1]);
})();
</script>
</body>
</html>
`
