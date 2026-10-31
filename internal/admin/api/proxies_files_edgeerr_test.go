package api

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/edgeproxy"
)

// Un 401 de la passerelle ne doit jamais devenir un 401 de l'Admin : l'interface y verrait une session expirée.
func TestWriteEdgeErrNeverRelaysAuthFailures(t *testing.T) {
	h := &ProxiesHandler{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		rec := httptest.NewRecorder()
		h.writeEdgeErr(rec, httptest.NewRequest(http.MethodGet, "/api/v1/proxies", nil), &edgeproxy.HTTPError{Status: status, Body: "401 Unauthorized\n"})
		if rec.Code != http.StatusBadGateway {
			t.Errorf("passerelle %d : l'Admin a répondu %d, 502 attendu", status, rec.Code)
		}
	}
}
