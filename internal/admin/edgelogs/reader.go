// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgelogs

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"github.com/vincamok/goproxify/internal/edge/logapi"
	"github.com/vincamok/goproxify/internal/edge/logserve"
	"github.com/vincamok/goproxify/internal/edge/logstore"
)

// Sources de lecture des logs (réglage logs.read_source).
const (
	SourceAuto    = "auto"    // la copie de l'Admin quand elle est à jour, sinon la passerelle
	SourceGateway = "gateway" // toujours la passerelle
	SourceAdmin   = "admin"   // toujours la copie de l'Admin
)

// ValidSource dit si v est une valeur de logs.read_source.
func ValidSource(v string) bool { return v == SourceAuto || v == SourceGateway || v == SourceAdmin }

// Existing rend le store d'une passerelle seulement s'il existe déjà sur le volume : lire ne crée rien.
func (v *Vault) Existing(nodeID string) (*logstore.Store, bool) {
	v.mu.Lock()
	if e, ok := v.stores[nodeID]; ok {
		v.mu.Unlock()
		return e.store, true
	}
	v.mu.Unlock()
	if st, err := os.Stat(filepath.Join(v.dir, dirName(nodeID))); err != nil || !st.IsDir() {
		return nil, false
	}
	s, err := v.Store(nodeID, "")
	return s, err == nil
}

// Service rend le service de lecture du store d'une passerelle : le même code que la passerelle applique à sa base.
func (v *Vault) Service(nodeID, name string) *logserve.Service {
	s, ok := v.Existing(nodeID)
	if !ok {
		return nil
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	e := v.stores[nodeID]
	if e == nil {
		return nil
	}
	if e.svc == nil {
		e.svc = &logserve.Service{Store: s, Node: name, Log: v.log, Gate: logserve.NewGate(), SourceIDs: true}
	}
	if name != "" {
		e.svc.Node = name
	}
	return e.svc
}

// Reader lit les logs des passerelles dans le volume de logs de l'Admin (edgeproxy.LocalLogs).
type Reader struct {
	Vault *Vault
	// Source rend le réglage logs.read_source.
	Source func() string
	// Announced rend les derniers identifiants que la passerelle a annoncés (accès, système) ; ok est faux si elle n'a rien
	// annoncé récemment.
	Announced func(nodeName string) (access, system int64, ok bool)
}

// usable décide si la copie de la passerelle peut répondre.
func (r *Reader) usable(nodeID, nodeName string) bool {
	source := SourceAuto
	if r.Source != nil {
		source = r.Source()
	}
	if source == SourceGateway {
		return false
	}
	st, ok := r.Vault.Existing(nodeID)
	if !ok {
		return false
	}
	if source == SourceAdmin {
		return true
	}
	access, _ := st.ShipCursor(logstore.KindAccess)
	system, _ := st.ShipCursor(logstore.KindSystem)
	if access == 0 && system == 0 {
		return false // rien reçu : la copie n'est pas activée, ou pas commencée
	}
	if r.Announced == nil {
		return true
	}
	lastAccess, lastSystem, known := r.Announced(nodeName)
	if !known {
		return true // passerelle muette (éteinte, déconnectée) : la copie est tout ce qu'on a
	}
	// La copie est à jour quand elle a rattrapé ce que la passerelle annonçait : tant qu'elle remplit son retard (copie tout
	// juste activée), la passerelle répond.
	return access >= lastAccess && system >= lastSystem
}

// Serve répond à une lecture de logs d'une passerelle depuis son store.
func (r *Reader) Serve(ctx context.Context, nodeID, nodeName, method, pathAndQuery string, body []byte) (int, []byte, bool) {
	if r.Vault == nil {
		return 0, nil, false
	}
	u, err := url.Parse(pathAndQuery)
	if err != nil {
		return 0, nil, false
	}
	if !readable(method, u.Path) || !r.usable(nodeID, nodeName) {
		return 0, nil, false
	}
	svc := r.Vault.Service(nodeID, nodeName)
	if svc == nil {
		return 0, nil, false
	}
	req, err := http.NewRequestWithContext(ctx, method, pathAndQuery, bytes.NewReader(body))
	if err != nil {
		return 0, nil, false
	}
	req.Header.Set("Content-Type", "application/json")
	rec := &recorder{header: http.Header{}, status: http.StatusOK}
	switch u.Path {
	case logapi.PathSearch:
		svc.Search(rec, req)
	case logapi.PathHistogram:
		svc.Histogram(rec, req)
	case logapi.PathFacets:
		svc.Facets(rec, req)
	case logapi.PathTop:
		svc.Top(rec, req)
	case logapi.PathUniqueIPs:
		svc.UniqueIPs(rec, req)
	case logapi.PathReveal:
		svc.Reveal(rec, req)
		if rec.status == http.StatusNotFound {
			return 0, nil, false // la ligne n'est pas (encore) dans la copie : la passerelle la connaît peut-être
		}
	}
	return rec.status, rec.buf.Bytes(), true
}

// readable : les chemins que la copie sait servir. Les écritures (effacement) et les autres lectures (simulation Ephor, surface)
// restent chez la passerelle.
func readable(method, path string) bool {
	switch path {
	case logapi.PathSearch, logapi.PathHistogram, logapi.PathFacets, logapi.PathUniqueIPs:
		return method == http.MethodGet
	case logapi.PathTop, logapi.PathReveal:
		return method == http.MethodPost
	}
	return false
}

// recorder capture la réponse d'un handler appelé sans réseau.
type recorder struct {
	header http.Header
	status int
	buf    bytes.Buffer
}

func (r *recorder) Header() http.Header         { return r.header }
func (r *recorder) Write(b []byte) (int, error) { return r.buf.Write(b) }
func (r *recorder) WriteHeader(code int)        { r.status = code }
