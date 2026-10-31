package api

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestBackupStatusCarriesTheLauncherImage(t *testing.T) {
	h, srv, tok := newKeyHandler(t)
	h.LauncherImage = "reg.exemple/goproxify/launcher:1.2"

	rec := call(srv, tok["ad"], http.MethodGet, "/api/v1/backups/status", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("état : %d %s", rec.Code, rec.Body)
	}
	var st map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st["launcher_image"] != "reg.exemple/goproxify/launcher:1.2" {
		t.Errorf("l'image du launcher sert à la commande de reconstruction : %v", st["launcher_image"])
	}
	if _, ok := st["key_set"]; !ok {
		t.Errorf("l'état habituel est conservé : %v", st)
	}

	h.LauncherImage = ""
	rec = call(srv, tok["ad"], http.MethodGet, "/api/v1/backups/status", "")
	st = map[string]any{}
	_ = json.Unmarshal(rec.Body.Bytes(), &st)
	if _, ok := st["launcher_image"]; ok {
		t.Error("sans image configurée, le champ est absent")
	}
}
