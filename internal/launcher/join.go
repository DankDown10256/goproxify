// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package launcher

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/deploy"
)

// maxSpecSize borne la description reçue : c'est du JSON de configuration, pas des données.
const maxSpecSize = 4 << 20

var fingerprintRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// NormalizeFingerprint met une empreinte SHA-256 en hexadécimal minuscule sans séparateur (`AB:CD…` est accepté).
// Vide reste vide ; une valeur qui n'est pas une empreinte est refusée.
func NormalizeFingerprint(s string) (string, error) {
	s = strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(s)))
	if s != "" && !fingerprintRe.MatchString(s) {
		return "", errors.New("empreinte invalide : 64 caractères hexadécimaux (SHA-256) attendus")
	}
	return s, nil
}

// FetchSpec récupère la description d'un hôte auprès de l'Admin (GET specURL, du ticket de la section 4 de l'ADR 0019).
//
// Seul HTTPS est accepté : la réponse porte des clés. Avec une empreinte, le certificat de l'Admin doit être exactement
// celui-là (c'est ainsi qu'on parle à un Admin au certificat auto-signé sans l'accepter les yeux fermés) ; la poignée de
// main échoue sinon, avant que le jeton ne parte. Sans empreinte, la chaîne de confiance du système s'applique (Admin
// derrière un reverse proxy au certificat public). Aucune redirection n'est suivie, aucun proxy d'environnement n'est
// utilisé.
func FetchSpec(ctx context.Context, specURL, fingerprint string) (*deploy.HostSpec, error) {
	u, err := url.Parse(specURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("l'adresse de l'Admin doit être en https")
	}
	fp, err := NormalizeFingerprint(fingerprint)
	if err != nil {
		return nil, err
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if fp != "" {
		// La chaîne n'est pas vérifiée (auto-signée) : c'est l'empreinte qui authentifie l'Admin.
		tlsCfg.InsecureSkipVerify = true
		tlsCfg.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("l'Admin n'a présenté aucun certificat")
			}
			sum := sha256.Sum256(raw[0])
			if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(fp)) != 1 {
				return errors.New("le certificat de l'Admin n'a pas l'empreinte attendue")
			}
			return nil
		}
	}
	client := &http.Client{
		Timeout:       30 * time.Second,
		Transport:     &http.Transport{TLSClientConfig: tlsCfg},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, specURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Admin injoignable : %w", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, errors.New("ticket inconnu ou expiré : recréez-en un dans l'Admin")
	case resp.StatusCode != http.StatusOK:
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("l'Admin a répondu %d : %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxSpecSize+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxSpecSize {
		return nil, errors.New("description reçue trop volumineuse")
	}
	var spec deploy.HostSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return nil, fmt.Errorf("description illisible : %w", err)
	}
	if err := spec.Validate(nil); err != nil {
		return nil, fmt.Errorf("description refusée : %w", err)
	}
	return &spec, nil
}

// JoinReport est ce qu'un hôte qui rejoint a installé.
type JoinReport struct {
	Host       string
	Containers []string
}

// Join récupère la description de l'hôte puis l'applique par le moteur (retour arrière si une étape échoue). Il ne
// consomme pas le ticket : il l'est quand les nœuds arrivent chez l'Admin, donc un échec se relance avec le même.
func Join(ctx context.Context, api deploy.API, specURL, fingerprint string, progress func(deploy.Event)) (*JoinReport, error) {
	spec, err := FetchSpec(ctx, specURL, fingerprint)
	if err != nil {
		return nil, err
	}
	id, err := randomHex(6)
	if err != nil {
		return nil, err
	}
	res, err := deploy.New(api, deploy.Options{DeployID: id, Progress: progress}).Apply(ctx, spec)
	if err != nil {
		return nil, err
	}
	rep := &JoinReport{Host: spec.Name}
	for _, c := range res.Containers {
		rep.Containers = append(rep.Containers, c.Name)
	}
	return rep, nil
}
