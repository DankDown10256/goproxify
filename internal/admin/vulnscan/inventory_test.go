// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package vulnscan

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"database/sql"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/appinv"
	"github.com/vincamok/goproxify/internal/edge/logapi"
)

func TestImageQueriesAndLabels(t *testing.T) {
	entries := []logapi.InventoryEntry{
		{Backend: "http://a", Finding: appinv.Finding{Product: "wordpress", CPE: "wordpress:wordpress", Version: "6.4.2", Evidence: "wordpress:6.4.2"}},
		{Backend: "http://a", Finding: appinv.Finding{Product: "wordpress", CPE: "wordpress:wordpress", Version: "6.4.2", Evidence: "wordpress:6.4.2-apache"}},
		{Backend: "http://a", Finding: appinv.Finding{Product: "grafana", CPE: "grafana:grafana", Evidence: "grafana/grafana:latest"}},
		{Backend: "http://a", Finding: appinv.Finding{Product: "vaultwarden", Version: "1.30.1", Evidence: "vaultwarden/server:1.30.1"}},
		{Backend: "http://a", Finding: appinv.Finding{Product: "postgresql", CPE: "postgresql:postgresql", Version: "16.1", Partial: true, Evidence: "postgres:16.1"}},
		{Backend: "http://a", Finding: appinv.Finding{Source: appinv.SourceImage, Evidence: "team/app:2"}},
	}
	q := inventoryQueries(entries)
	if len(q) != 2 || q[0].label != "wordpress 6.4.2" || q[1].product != "postgresql" {
		t.Fatalf("seuls les produits à CPE et à version se cherchent, une fois chacun : %+v", q)
	}
	if !strings.Contains(q[0].url, "cpe%3A2.3%3Aa%3Awordpress%3Awordpress%3A6.4.2") {
		t.Errorf("requête NVD par CPE : %s", q[0].url)
	}
	want := []string{"grafana (version inconnue)", "postgresql 16.1 (version partielle)", "team/app:2 (image non reconnue)", "vaultwarden 1.30.1 (non couvert)", "wordpress 6.4.2"}
	if got := appLabels(entries); !slices.Equal(got, want) {
		t.Errorf("libellés : %q", got)
	}
}

// fakeWorld : une fausse passerelle (inventaire) et un faux NVD, derrière un transport qui redirige tout appel externe du scanner.
type fakeWorld struct {
	inventory []logapi.InventoryEntry
	nvd       map[string][]string // fragment de requête → identifiants de CVE
	nvdCalls  int
}

type rewrite struct{ to *httptest.Server }

func (r rewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	u := *req.URL
	u.Scheme, u.Host = "http", strings.TrimPrefix(r.to.URL, "http://")
	r2 := req.Clone(req.Context())
	r2.URL = &u
	return http.DefaultTransport.RoundTrip(r2)
}

func newScanWorld(t *testing.T) (*Scanner, *fakeWorld, *sql.DB) {
	t.Helper()
	db, err := admindb.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	w := &fakeWorld{nvd: map[string][]string{}}
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == logapi.PathInventory:
			_ = json.NewEncoder(rw).Encode(logapi.InventoryResponse{Entries: w.inventory})
		case r.URL.Path == "/rest/json/cves/2.0":
			w.nvdCalls++
			var vulns []map[string]any
			for frag, ids := range w.nvd {
				if !strings.Contains(r.URL.RawQuery, frag) {
					continue
				}
				for _, id := range ids {
					vulns = append(vulns, map[string]any{"cve": map[string]any{
						"id": id, "descriptions": []map[string]any{{"lang": "en", "value": "d " + id}},
						"metrics": map[string]any{"cvssMetricV31": []map[string]any{{"cvssData": map[string]any{"baseScore": 9.8}}}},
					}})
				}
			}
			_ = json.NewEncoder(rw).Encode(map[string]any{"vulnerabilities": vulns})
		case strings.HasPrefix(r.URL.Path, "/internal/"):
			_ = json.NewEncoder(rw).Encode(map[string]any{"production": []any{}})
		default:
			http.NotFound(rw, r)
		}
	}))
	t.Cleanup(srv.Close)
	_, _ = db.Exec(`INSERT INTO tokens (id, node_name, role, token, node_endpoint, revoked)
		VALUES ('tok-inv','edge-inv','edge','gpx_edge_invtesttoken',?,0)`, srv.URL)
	old := nvdRateLimit
	nvdRateLimit = time.NewTicker(time.Millisecond)
	t.Cleanup(func() { nvdRateLimit = old })
	s := New(db, slog.Default(), "")
	s.client = &http.Client{Transport: rewrite{srv}}
	return s, w, db
}

// cveRows : « identifiant@backend » → [proxy|produit, version, source, statut].
func cveRows(t *testing.T, db *sql.DB) map[string][4]string {
	t.Helper()
	rows, err := db.Query(`SELECT cve_id, backend_url, host, product, version, source, status FROM security_cves`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string][4]string{}
	for rows.Next() {
		var id, backend, host, product, version, source, status string
		if err := rows.Scan(&id, &backend, &host, &product, &version, &source, &status); err != nil {
			t.Fatal(err)
		}
		out[id+"@"+backend] = [4]string{host + "|" + product, version, source, status}
	}
	return out
}

func TestScanUsesTheImageInventoryInsteadOfProbing(t *testing.T) {
	s, w, db := newScanWorld(t)
	wp := func(version, backend, container string) logapi.InventoryEntry {
		return logapi.InventoryEntry{Route: "docker-host:blog.test", Host: "blog.test", Backend: backend, Container: container,
			Finding: appinv.Finding{Product: "wordpress", CPE: "wordpress:wordpress", Version: version, Source: "image", Evidence: "wordpress:" + version}}
	}
	// Réseau Docker privé : la sonde de l'Admin ne les atteindrait pas, l'inventaire suffit.
	w.inventory = []logapi.InventoryEntry{wp("6.4.2", "http://10.9.0.1:80", "c1"), wp("6.4.2", "http://10.9.0.2:80", "c2")}
	w.nvd["wordpress%3A6.4.2"] = []string{"CVE-2024-0001", "CVE-2024-0002"}
	w.nvd["wordpress%3A6.5.0"] = []string{"CVE-2024-0002"}

	s.run(context.Background())
	st := s.GetState()
	if st.InventoryN != 2 || st.UnreachableN != 0 || st.FoundCVEs != 4 {
		t.Fatalf("état : inventaire %d, injoignables %d, CVE %d", st.InventoryN, st.UnreachableN, st.FoundCVEs)
	}
	if w.nvdCalls != 1 {
		t.Errorf("deux conteneurs de la même image : une seule question à NVD, %d faites", w.nvdCalls)
	}
	rows := cveRows(t, db)
	got := rows["CVE-2024-0001@http://10.9.0.1:80"]
	if got != [4]string{"blog.test|wordpress", "6.4.2", "image", "open"} {
		t.Errorf("une CVE est rattachée à un proxy, un produit, une version et une source : %v", got)
	}
	for _, r := range st.Results {
		if r.Status != "inventory" || r.Host != "blog.test" || len(r.Apps) != 1 || r.Apps[0] != "wordpress 6.4.2" {
			t.Errorf("résultat : %+v", r)
		}
	}

	// Le conteneur est mis à jour : la CVE qui ne concerne plus la version est corrigée, l'autre reste ouverte à la nouvelle version.
	w.inventory = []logapi.InventoryEntry{wp("6.5.0", "http://10.9.0.1:80", "c1"), wp("6.4.2", "http://10.9.0.2:80", "c2")}
	s.run(context.Background())
	rows = cveRows(t, db)
	if g := rows["CVE-2024-0001@http://10.9.0.1:80"]; g[3] != "fixed" {
		t.Errorf("CVE-2024-0001 ne concerne plus 6.5.0 : %v", g)
	}
	if g := rows["CVE-2024-0002@http://10.9.0.1:80"]; g[3] != "open" || g[1] != "6.5.0" {
		t.Errorf("CVE-2024-0002 concerne encore 6.5.0 : %v", g)
	}
	if g := rows["CVE-2024-0001@http://10.9.0.2:80"]; g[3] != "open" || g[1] != "6.4.2" {
		t.Errorf("l'autre conteneur est resté en 6.4.2 : %v", g)
	}
}

func TestScanFallsBackToProbingWhenTheImageGivesNoVersion(t *testing.T) {
	s, w, _ := newScanWorld(t)
	w.inventory = []logapi.InventoryEntry{{Host: "g.test", Backend: "http://10.9.0.3:3000",
		Finding: appinv.Finding{Product: "grafana", CPE: "grafana:grafana", Source: "image", Evidence: "grafana/grafana:latest"}}}
	s.run(context.Background())
	st := s.GetState()
	if st.InventoryN != 0 || len(st.Results) != 1 || st.Results[0].Status != "unreachable" {
		t.Fatalf("sans version, on sonde (ici interdit : IP privée) : %+v", st.Results)
	}
	if got := st.Results[0].Apps; len(got) != 1 || got[0] != "grafana (version inconnue)" {
		t.Errorf("l'application reste affichée : %v", got)
	}
}

func TestScanUsesWhatTheGatewaySawInTheBackendResponses(t *testing.T) {
	s, w, db := newScanWorld(t)
	// Un serveur hors Docker, sur un réseau privé que l'Admin n'atteint pas : seule la passerelle l'a vu répondre.
	w.inventory = []logapi.InventoryEntry{{Route: "p9", Host: "erp.test", Backend: "http://192.168.1.20:8080",
		Finding: appinv.Finding{Product: "nginx", CPE: "nginx:nginx", Version: "1.18.0", Source: appinv.SourceHeaders, Evidence: "Server: nginx/1.18.0"}}}
	w.nvd["nginx%3A1.18.0"] = []string{"CVE-2021-23017"}
	s.run(context.Background())
	st := s.GetState()
	if st.InventoryN != 1 || st.UnreachableN != 0 || st.FoundCVEs != 1 {
		t.Fatalf("état : inventaire %d, injoignables %d, CVE %d", st.InventoryN, st.UnreachableN, st.FoundCVEs)
	}
	got := cveRows(t, db)["CVE-2021-23017@http://192.168.1.20:8080"]
	if got != [4]string{"erp.test|nginx", "1.18.0", "headers", "open"} {
		t.Errorf("la source est celle de l'empreinte : %v", got)
	}
}
