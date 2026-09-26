// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxystore

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestYAMLRoundTrip vérifie que la conversion JSON→YAML→JSON préserve
// fidèlement les valeurs à risque : URLs avec //, backslashes, PEM,
// regex, filtres LDAP, bcrypt, valeurs YAML ambiguës (true/false/null/yes/no).
func TestYAMLRoundTrip(t *testing.T) {
	tricky := map[string]any{
		// URLs avec double slash
		"url":            "http://backend:8080",
		"url_https":      "https://id.example.com/auth//callback",
		"ldap_url":       "ldap://dc.corp.local:389",
		"forward_url":    "http://authelia//api/verify",
		// Backslashes dans des regex
		"regex_simple":   `\d+`,
		"regex_path":     `^\/api\/v\d+\/.*`,
		"regex_named":    `(?P<version>\d+\.\d+)`,
		"sub_filter_to":  `$1//new-path`,
		// Filtre LDAP
		"ldap_filter":    "(sAMAccountName=%s)",
		"ldap_group":     "(&(objectClass=group)(member=%s))",
		// bcrypt (contient $)
		"bcrypt":         "$2b$10$abcdefghijklmnopqrstuvuABCDEFGHIJKLMNOPQRSTUVWXYZabc",
		// Valeurs ambiguës YAML (doivent rester des strings)
		"ambig_true":     "true",
		"ambig_false":    "false",
		"ambig_null":     "null",
		"ambig_yes":      "yes",
		"ambig_no":       "no",
		"ambig_on":       "on",
		"ambig_off":      "off",
		"ambig_tilde":    "~",
		"ambig_number":   "1.0",
		"ambig_octal":    "0755",
		// PEM avec newlines réels
		"cert_pem": "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END CERTIFICATE-----\n",
		"key_pem":  "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n",
		// Caractères spéciaux divers
		"colon_in_val":   "host:port:extra",
		"hash_in_val":    "value#with#hashes",
		"bracket_val":    "[not-an-array]",
		"brace_val":      "{not-a-map}",
		"percent_val":    "100%",
		"backslash_n":    `literal \n not newline`,
		"double_quote":   `say "hello"`,
		"single_quote":   "it's fine",
	}

	configJSON, err := json.Marshal(tricky)
	if err != nil {
		t.Fatal("marshal initial:", err)
	}

	dir := t.TempDir()
	st := New(dir)
	now := time.Now().UTC().Truncate(time.Second)
	env := &Envelope{
		SchemaVersion: SchemaVersionV1,
		ID:            "round-trip-1",
		Host:          "app.example.fr",
		Enabled:       true,
		UpdatedAt:     now,
		Config:        json.RawMessage(configJSON),
	}
	if err := st.WriteProd(env); err != nil {
		t.Fatal("WriteProd:", err)
	}

	got, err := st.ReadProdByID("round-trip-1")
	if err != nil {
		t.Fatal("ReadProdByID:", err)
	}

	var gotMap map[string]any
	if err := json.Unmarshal(got.Config, &gotMap); err != nil {
		t.Fatal("unmarshal result:", err)
	}

	for k, want := range tricky {
		gotVal, ok := gotMap[k]
		if !ok {
			t.Errorf("clé %q absente après round-trip", k)
			continue
		}
		// Toutes les valeurs sont des strings ; json.Unmarshal les restitue en string.
		if gotStr, ok := gotVal.(string); !ok {
			t.Errorf("clé %q : type attendu string, obtenu %T (%v)", k, gotVal, gotVal)
		} else if gotStr != want.(string) {
			t.Errorf("clé %q :\n  want %q\n  got  %q", k, want, gotStr)
		}
	}
}

func sampleConfig(id, host string) json.RawMessage {
	raw, _ := json.Marshal(map[string]any{
		"id":   id,
		"host": host,
		"type": "http",
		"backends": []map[string]any{
			{"url": "http://127.0.0.1:8080", "weight": 1},
		},
		"lb": "round_robin",
	})
	return raw
}

func TestSanitizeHost(t *testing.T) {
	cases := map[string]string{
		"App.Example.FR":     "app.example.fr",
		"app/../evil.fr":     "app_.._evil.fr",
		"  spaced host.com ": "spaced_host.com",
		"":                   "",
	}
	for in, want := range cases {
		if got := SanitizeHost(in); got != want {
			t.Errorf("SanitizeHost(%q)=%q want %q", in, got, want)
		}
	}
}

func TestProdFilename(t *testing.T) {
	if got := ProdFilename("app.example.fr", "uuid"); got != "app.example.fr.yaml" {
		t.Fatalf("got %q", got)
	}
	if got := ProdFilename("", "abc-123"); got != "proxy_abc-123.yaml" {
		t.Fatalf("empty host got %q", got)
	}
	if got := ProdFilenameTyped("Minecraft", "id-tcp", "tcp"); got != "minecraft_tcp.yaml" {
		t.Fatalf("tcp got %q", got)
	}
	if got := ProdFilenameTyped("Minecraft", "id-udp", "udp"); got != "minecraft_udp.yaml" {
		t.Fatalf("udp got %q", got)
	}
	if ProdFilenameTyped("Minecraft", "id-tcp", "tcp") == ProdFilenameTyped("Minecraft", "id-udp", "udp") {
		t.Fatal("TCP and UDP with same host must not share a filename")
	}
}

func TestRevisionFilename(t *testing.T) {
	got := RevisionFilename("a1b2c3d4", "r7f3")
	if got != "a1b2c3d4--r7f3.yaml" {
		t.Fatalf("got %q", got)
	}
}

func TestWriteListReadProd(t *testing.T) {
	dir := t.TempDir()
	st := New(dir)
	now := time.Now().UTC().Truncate(time.Second)
	env := &Envelope{
		SchemaVersion: SchemaVersionV1,
		ID:            "id-1",
		Host:          "app.example.fr",
		Enabled:      true,
		Status:        StatusPending, // WriteProd force production
		UpdatedAt:     now,
		Config:        sampleConfig("id-1", "app.example.fr"),
	}
	if err := st.WriteProd(env); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(st.ProdDir(), "app.example.fr.yaml")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("fichier absent: %v", err)
	}

	list, err := st.ListProd()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("list len=%d", len(list))
	}
	if list[0].Status != StatusProduction {
		t.Fatalf("status=%s", list[0].Status)
	}
	if list[0].Revision != "" {
		t.Fatalf("revision should be empty in prod")
	}

	got, err := st.ReadProdByID("id-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Host != "app.example.fr" {
		t.Fatalf("host=%s", got.Host)
	}
}

func TestWriteReadRevision(t *testing.T) {
	dir := t.TempDir()
	st := New(dir)
	now := time.Now().UTC()
	env := &Envelope{
		SchemaVersion: SchemaVersionV1,
		ID:            "id-1",
		Revision:      "r1",
		Host:          "app.example.fr",
		Enabled:      true,
		Status:        StatusPending,
		CreatedAt:     &now,
		UpdatedAt:     now,
		CreatedBy:     "admin@example.fr",
		Config:        sampleConfig("id-1", "app.example.fr"),
	}
	if err := st.WriteRevision(env); err != nil {
		t.Fatal(err)
	}

	got, err := st.ReadRevision("id-1", "r1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusPending {
		t.Fatalf("status=%s", got.Status)
	}

	revs, err := st.ListRevisions("id-1")
	if err != nil || len(revs) != 1 {
		t.Fatalf("revs=%d err=%v", len(revs), err)
	}

	if err := st.DeleteRevision("id-1", "r1"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ReadRevision("id-1", "r1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestAtomicWritePreservesOnFailedRename(t *testing.T) {
	// Write twice: second write replaces via rename; first content must not be half-written.
	dir := t.TempDir()
	st := New(dir)
	now := time.Now().UTC()
	cfg1 := sampleConfig("id-1", "app.example.fr")
	env := &Envelope{
		SchemaVersion: SchemaVersionV1,
		ID:            "id-1",
		Host:          "app.example.fr",
		Enabled:       true,
		UpdatedAt:     now,
		Config:        cfg1,
	}
	if err := st.WriteProd(env); err != nil {
		t.Fatal(err)
	}

	cfg2, _ := json.Marshal(map[string]any{
		"id": "id-1", "host": "app.example.fr", "type": "http",
		"backends": []map[string]any{{"url": "http://10.0.0.2:9", "weight": 1}},
		"lb":       "round_robin",
		"marker":   "second",
	})
	env.Config = cfg2
	if err := st.WriteProd(env); err != nil {
		t.Fatal(err)
	}

	got, err := st.ReadProdByHostID("app.example.fr", "id-1")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(got.Config, &m); err != nil {
		t.Fatal(err)
	}
	if m["marker"] != "second" {
		t.Fatalf("config not updated: %v", m)
	}
}

func TestEnvelopeValidate(t *testing.T) {
	env := &Envelope{SchemaVersion: 1, ID: "x", Status: StatusPending, Config: sampleConfig("x", "")}
	if err := env.Validate(); err == nil {
		t.Fatal("expected revision required")
	}
	env.Revision = "r1"
	if err := env.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestRemoveProdIfHostChanged(t *testing.T) {
	dir := t.TempDir()
	st := New(dir)
	now := time.Now().UTC()
	env := &Envelope{
		SchemaVersion: SchemaVersionV1,
		ID:            "id-1",
		Host:          "old.example.fr",
		Enabled:       true,
		UpdatedAt:     now,
		Config:        sampleConfig("id-1", "old.example.fr"),
	}
	if err := st.WriteProd(env); err != nil {
		t.Fatal(err)
	}
	env.Host = "new.example.fr"
	env.Config = sampleConfig("id-1", "new.example.fr")
	if err := st.WriteProd(env); err != nil {
		t.Fatal(err)
	}
	if err := st.RemoveProdIfHostChanged("old.example.fr", "new.example.fr", "id-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(st.ProdPath("old.example.fr", "id-1")); !os.IsNotExist(err) {
		t.Fatal("old file should be gone")
	}
	if _, err := st.ReadProdByHostID("new.example.fr", "id-1"); err != nil {
		t.Fatal(err)
	}
}

func TestMigrateJSONToYAML(t *testing.T) {
	dir := t.TempDir()
	st := New(dir)
	if err := st.EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	env := &Envelope{
		SchemaVersion: SchemaVersionV1,
		ID:            "mig-1",
		Host:          "mig.example.fr",
		Enabled:       true,
		Status:        StatusProduction,
		UpdatedAt:     now,
		Config:        sampleConfig("mig-1", "mig.example.fr"),
	}
	jsonPath := filepath.Join(st.ProdDir(), "mig.example.fr.json")
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(jsonPath, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}

	results := st.MigrateJSONToYAML()
	if len(results) != 1 {
		t.Fatalf("results=%d want 1", len(results))
	}
	if results[0].Err != nil {
		t.Fatalf("migrate: %v", results[0].Err)
	}
	if _, err := os.Stat(jsonPath); !os.IsNotExist(err) {
		t.Fatal("json should be removed")
	}
	yamlPath := filepath.Join(st.ProdDir(), "mig.example.fr.yaml")
	got, err := st.ReadProdFile(yamlPath)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "mig-1" || got.Host != "mig.example.fr" {
		t.Fatalf("got id=%q host=%q", got.ID, got.Host)
	}
}

func TestListProdSkipsCorruptFile(t *testing.T) {
	dir := t.TempDir()
	st := New(dir)
	if err := st.EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	// Write one valid proxy.
	now := time.Now().UTC()
	valid := &Envelope{
		SchemaVersion: SchemaVersionV1,
		ID:            "ok-1",
		Host:          "ok.example.fr",
		Enabled:       true,
		UpdatedAt:     now,
		Config:        sampleConfig("ok-1", "ok.example.fr"),
	}
	if err := st.WriteProd(valid); err != nil {
		t.Fatal(err)
	}
	// Plant a corrupt YAML file alongside the valid one.
	corrupt := filepath.Join(st.ProdDir(), "broken.yaml")
	if err := os.WriteFile(corrupt, []byte(":\n  - !!invalid"), 0o644); err != nil {
		t.Fatal(err)
	}
	// ListProd must still return the valid proxy despite the corrupt neighbour.
	list, err := st.ListProd()
	if err != nil {
		t.Fatalf("ListProd should not fail on corrupt file, got: %v", err)
	}
	if len(list) != 1 || list[0].ID != "ok-1" {
		t.Fatalf("expected 1 valid proxy, got %d", len(list))
	}
}

func TestTCPStreamRoundTrip(t *testing.T) {
	dir := t.TempDir()
	st := New(dir)
	now := time.Now().UTC().Truncate(time.Millisecond)
	cfg, _ := json.Marshal(map[string]any{
		"type":        "tcp",
		"host":        "redis_cache",
		"listen_port": 6379,
		"id":          "tcp-stream-1",
		"updated_at":  now.Format(time.RFC3339Nano),
		"backends":    []map[string]any{{"url": "10.0.0.1:6379"}},
	})
	env := &Envelope{
		SchemaVersion: SchemaVersionV1,
		ID:            "tcp-stream-1",
		Host:          "redis_cache",
		Enabled:       true,
		UpdatedAt:     now,
		Config:        json.RawMessage(cfg),
	}
	if err := st.WriteProd(env); err != nil {
		t.Fatal("WriteProd:", err)
	}
	wantName := "redis_cache_tcp.yaml"
	if _, err := os.Stat(filepath.Join(dir, ProdDirName, wantName)); err != nil {
		t.Fatalf("expected file %s: %v", wantName, err)
	}
	got, err := st.ReadProdByID("tcp-stream-1")
	if err != nil {
		t.Fatal("ReadProdByID:", err)
	}
	var cfgOut map[string]any
	if err := json.Unmarshal(got.Config, &cfgOut); err != nil {
		t.Fatal("unmarshal:", err)
	}
	if cfgOut["type"] != "tcp" {
		t.Errorf("type: want tcp, got %v", cfgOut["type"])
	}
	// listen_port survives YAML round-trip as a number.
	port, _ := cfgOut["listen_port"].(float64)
	if int(port) != 6379 {
		t.Errorf("listen_port: want 6379, got %v", cfgOut["listen_port"])
	}
	backends, _ := cfgOut["backends"].([]any)
	if len(backends) != 1 {
		t.Fatalf("backends len=%d", len(backends))
	}
	b, _ := backends[0].(map[string]any)
	if b["url"] != "10.0.0.1:6379" {
		t.Errorf("backends[0].url: want 10.0.0.1:6379, got %v", b["url"])
	}
}

func TestTCPAndUDPSameHostBothPersist(t *testing.T) {
	dir := t.TempDir()
	st := New(dir)
	now := time.Now().UTC()
	write := func(id, typ string, port int) {
		t.Helper()
		cfg, _ := json.Marshal(map[string]any{
			"type": typ, "host": "Minecraft", "listen_port": port,
			"id": id, "backends": []map[string]any{{"url": "10.0.0.1:25565"}},
		})
		env := &Envelope{
			SchemaVersion: SchemaVersionV1,
			ID:            id,
			Host:          "Minecraft",
			Enabled:       true,
			UpdatedAt:     now,
			Config:        json.RawMessage(cfg),
		}
		if err := st.WriteProd(env); err != nil {
			t.Fatalf("WriteProd %s: %v", id, err)
		}
	}
	write("id-tcp", "tcp", 25565)
	write("id-udp", "udp", 25565)
	list, err := st.ListProd()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("ListProd len=%d want 2 (TCP+UDP must not share one host.yaml)", len(list))
	}
	ids := map[string]bool{}
	for _, e := range list {
		ids[e.ID] = true
	}
	if !ids["id-tcp"] || !ids["id-udp"] {
		t.Fatalf("missing streams: %v", ids)
	}
	if _, err := os.Stat(filepath.Join(st.ProdDir(), "minecraft_tcp.yaml")); err != nil {
		t.Fatalf("minecraft_tcp.yaml: %v", err)
	}
	if _, err := os.Stat(filepath.Join(st.ProdDir(), "minecraft_udp.yaml")); err != nil {
		t.Fatalf("minecraft_udp.yaml: %v", err)
	}
}
