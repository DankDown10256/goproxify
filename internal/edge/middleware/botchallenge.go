// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/edge/metrics"
	"github.com/vincamok/goproxify/internal/edge/router"
)

const (
	botCookie             = "_gpx_bot"
	botChallengePath      = "/.gpx/challenge"
	defaultChallengeBits  = 16
	maxChallengeBits      = 24
	challengeLifetime     = 5 * time.Minute
	defaultChallengeTTL   = 24 * time.Hour
	minChallengeTTL       = time.Minute
	maxChallengeBodyBytes = 8 << 10
)

// URLs de vérification des fournisseurs de captcha (variables pour les tests).
var captchaVerifyURL = map[string]string{
	"turnstile": "https://challenges.cloudflare.com/turnstile/v0/siteverify",
	"hcaptcha":  "https://hcaptcha.com/siteverify",
}

var captchaHTTPClient = &http.Client{Timeout: 5 * time.Second}

// botChallenge porte les réglages résolus d'un challenge navigateur.
type botChallenge struct {
	secret      string
	provider    string // pow | turnstile | hcaptcha
	bits        int
	passTTL     time.Duration
	siteKey     string
	providerKey string
	exempt      []string
	// cookie et verifyPath distinguent le défi de la passerelle (GatewayChallenge) de celui d'une route : deux défis aux
	// secrets différents ne doivent ni se disputer un cookie ni se partager une URL de vérification.
	cookie     string
	verifyPath string
}

func newBotChallenge(cfg *router.BotConfig, secret string) *botChallenge {
	c := &botChallenge{
		secret:      secret,
		provider:    strings.ToLower(strings.TrimSpace(cfg.ChallengeProvider)),
		bits:        cfg.ChallengeDifficulty,
		passTTL:     defaultChallengeTTL,
		siteKey:     cfg.ChallengeSiteKey,
		providerKey: cfg.ChallengeProviderSecret,
		exempt:      cfg.ChallengeExemptPaths,
		cookie:      botCookie,
		verifyPath:  botChallengePath,
	}
	if c.provider == "" {
		c.provider = "pow"
	}
	if c.bits <= 0 {
		c.bits = defaultChallengeBits
	}
	if c.bits > maxChallengeBits {
		c.bits = maxChallengeBits
	}
	if d, err := time.ParseDuration(strings.TrimSpace(cfg.ChallengeTTL)); err == nil && d >= minChallengeTTL {
		c.passTTL = d
	}
	return c
}

func (c *botChallenge) isExempt(path string) bool {
	for _, p := range c.exempt {
		if p != "" && strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// bind lie une preuve à l'IP et au User-Agent du client : un cookie copié ailleurs ne sert à rien.
func bind(r *http.Request) string {
	sum := sha256.Sum256([]byte(clientIP(r) + "|" + r.Header.Get("User-Agent")))
	return hex.EncodeToString(sum[:8])
}

func (c *botChallenge) mac(parts ...string) string {
	m := hmac.New(sha256.New, []byte(c.secret))
	_, _ = m.Write([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(m.Sum(nil))
}

// passToken : "<expiration>.<mac>" — émis après résolution du challenge, stocké en cookie.
func (c *botChallenge) passToken(r *http.Request) string {
	exp := strconv.FormatInt(time.Now().Add(c.passTTL).Unix(), 10)
	return exp + "." + c.mac("pass", exp, bind(r))
}

func (c *botChallenge) hasProof(r *http.Request) bool {
	ck, err := r.Cookie(c.cookie)
	if err != nil {
		return false
	}
	exp, mac, ok := strings.Cut(ck.Value, ".")
	if !ok {
		return false
	}
	ts, err := strconv.ParseInt(exp, 10, 64)
	if err != nil || ts < time.Now().Unix() {
		return false
	}
	return hmac.Equal([]byte(mac), []byte(c.mac("pass", exp, bind(r))))
}

// newChallenge émet un défi sans état : "<expiration>.<aléa>.<bits>.<mac>".
func (c *botChallenge) newChallenge(r *http.Request) string {
	nonce := make([]byte, 8)
	_, _ = rand.Read(nonce)
	body := fmt.Sprintf("%d.%s.%d", time.Now().Add(challengeLifetime).Unix(), hex.EncodeToString(nonce), c.bits)
	return body + "." + c.mac("ch", body, bind(r))
}

// verifyChallenge contrôle la signature, l'expiration et la preuve de travail.
func (c *botChallenge) verifyChallenge(r *http.Request, token, nonce string) bool {
	i := strings.LastIndexByte(token, '.')
	if i < 0 || len(nonce) == 0 || len(nonce) > 20 {
		return false
	}
	body, mac := token[:i], token[i+1:]
	if !hmac.Equal([]byte(mac), []byte(c.mac("ch", body, bind(r)))) {
		return false
	}
	f := strings.Split(body, ".")
	if len(f) != 3 {
		return false
	}
	exp, err1 := strconv.ParseInt(f[0], 10, 64)
	bits, err2 := strconv.Atoi(f[2])
	if err1 != nil || err2 != nil || exp < time.Now().Unix() {
		return false
	}
	sum := sha256.Sum256([]byte(token + ":" + nonce))
	return leadingZeroBits(sum[:]) >= bits
}

func leadingZeroBits(b []byte) int {
	n := 0
	for _, v := range b {
		if v == 0 {
			n += 8
			continue
		}
		for mask := byte(0x80); mask != 0 && v&mask == 0; mask >>= 1 {
			n++
		}
		break
	}
	return n
}

// verifyCaptcha valide un jeton Turnstile ou hCaptcha auprès du fournisseur.
func (c *botChallenge) verifyCaptcha(r *http.Request, token string) bool {
	endpoint := captchaVerifyURL[c.provider]
	if endpoint == "" || token == "" || len(token) > 4096 {
		return false
	}
	resp, err := captchaHTTPClient.PostForm(endpoint, url.Values{
		"secret":   {c.providerKey},
		"response": {token},
		"remoteip": {clientIP(r)},
	})
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	var out struct {
		Success bool `json:"success"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out) != nil {
		return false
	}
	return out.Success
}

// handleVerify reçoit la solution (POST JSON {c, n} ou {t}) et pose le cookie de preuve.
func (c *botChallenge) handleVerify(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Challenge string `json:"c"`
		Nonce     string `json:"n"`
		Token     string `json:"t"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, maxChallengeBodyBytes)).Decode(&body) != nil {
		http.Error(w, "400 Bad Request", http.StatusBadRequest)
		return
	}
	var ok bool
	if c.provider == "pow" {
		ok = c.verifyChallenge(r, body.Challenge, body.Nonce)
	} else {
		ok = c.verifyCaptcha(r, body.Token)
	}
	if !ok {
		metrics.Pipeline.BlockedTotal.WithLabelValues(metrics.HostOf(r), "bot", "challenge_failed").Inc()
		http.Error(w, "403 Forbidden", http.StatusForbidden)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     c.cookie,
		Value:    c.passToken(r),
		Path:     "/",
		MaxAge:   int(c.passTTL.Seconds()),
		HttpOnly: true,
		Secure:   CookieSecure(r),
		SameSite: http.SameSiteLaxMode,
	})
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// serve répond à la place du backend : page de défi pour un navigateur (GET/HEAD), 403 sinon
// (une page ne peut pas rejouer un POST).
func (c *botChallenge) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "403 Forbidden: browser challenge required", http.StatusForbidden)
		return
	}
	redirect, _ := json.Marshal(SafeLocalRedirect(r.URL.RequestURI()))
	verify, _ := json.Marshal(c.verifyPath)

	var widget, script string
	switch c.provider {
	case "turnstile":
		widget = `<div class="cf-turnstile" data-sitekey="` + html.EscapeString(c.siteKey) + `" data-callback="gpxDone"></div>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>`
		script = captchaScript
	case "hcaptcha":
		widget = `<div class="h-captcha" data-sitekey="` + html.EscapeString(c.siteKey) + `" data-callback="gpxDone"></div>
<script src="https://js.hcaptcha.com/1/api.js" async defer></script>`
		script = captchaScript
	default:
		token, _ := json.Marshal(c.newChallenge(r))
		widget = `<p id="gpx-msg">Checking your browser, please wait…</p>`
		script = `var gpxToken=` + string(token) + `;` + powScript
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Checking your browser...</title>
<style>body{font:16px system-ui,sans-serif;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0;background:#f6f7f9;color:#222}main{text-align:center;padding:2rem}</style></head>
<body><main><h1>Checking your browser...</h1>%s<noscript><p>JavaScript is required to continue.</p></noscript></main>
<script>
var gpxRedirect=%s,gpxVerify=%s;
function gpxSubmit(body){return fetch(gpxVerify,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)}).then(function(r){if(r.ok){location.replace(gpxRedirect)}else{location.reload()}})}
%s
</script></body></html>`, widget, redirect, verify, script)
}

const captchaScript = `function gpxDone(t){gpxSubmit({t:t})}`

// powScript cherche un nonce tel que SHA-256(défi + ":" + nonce) ait au moins `bits` bits de tête à zéro.
// SHA-256 est réimplémenté (crypto.subtle n'existe qu'en contexte sécurisé : HTTPS ou localhost).
const powScript = `
var gpxK=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
function gpxSha256(m){
  var l=m.length,n=((l+9+63)>>6)<<6,b=new Uint8Array(n),i,j,w=new Uint32Array(64);
  b.set(m);b[l]=0x80;
  var bl=l*8;b[n-4]=bl>>>24;b[n-3]=bl>>>16;b[n-2]=bl>>>8;b[n-1]=bl;
  var h=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
  for(i=0;i<n;i+=64){
    for(j=0;j<16;j++)w[j]=(b[i+4*j]<<24)|(b[i+4*j+1]<<16)|(b[i+4*j+2]<<8)|b[i+4*j+3];
    for(j=16;j<64;j++){var a=w[j-15],c=w[j-2];w[j]=(((a>>>7|a<<25)^(a>>>18|a<<14)^(a>>>3))+w[j-7]+((c>>>17|c<<15)^(c>>>19|c<<13)^(c>>>10))+w[j-16])|0}
    var A=h[0],B=h[1],C=h[2],D=h[3],E=h[4],F=h[5],G=h[6],H=h[7];
    for(j=0;j<64;j++){
      var t1=(H+((E>>>6|E<<26)^(E>>>11|E<<21)^(E>>>25|E<<7))+((E&F)^(~E&G))+gpxK[j]+w[j])|0;
      var t2=(((A>>>2|A<<30)^(A>>>13|A<<19)^(A>>>22|A<<10))+((A&B)^(A&C)^(B&C)))|0;
      H=G;G=F;F=E;E=(D+t1)|0;D=C;C=B;B=A;A=(t1+t2)|0;
    }
    h[0]=(h[0]+A)|0;h[1]=(h[1]+B)|0;h[2]=(h[2]+C)|0;h[3]=(h[3]+D)|0;h[4]=(h[4]+E)|0;h[5]=(h[5]+F)|0;h[6]=(h[6]+G)|0;h[7]=(h[7]+H)|0;
  }
  return h;
}
function gpxZeroBits(h){var n=0;for(var i=0;i<8;i++){if(h[i]===0){n+=32;continue}n+=Math.clz32(h[i]);break}return n}
(function(){
  var bits=parseInt(gpxToken.split(".")[2],10),enc=new TextEncoder(),prefix=gpxToken+":",nonce=0;
  function step(){
    var end=nonce+20000;
    for(;nonce<end;nonce++){
      if(gpxZeroBits(gpxSha256(enc.encode(prefix+nonce)))>=bits){gpxSubmit({c:gpxToken,n:String(nonce)});return}
    }
    setTimeout(step,0);
  }
  step();
})();`
