package waf

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

type hijackRecorder struct{ *httptest.ResponseRecorder }

var errHijacked = errors.New("hijacked")

func (hijackRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) { return nil, nil, errHijacked }

// Sans Unwrap, ReverseProxy ne peut pas détourner la connexion et l'upgrade WebSocket finit en 502.
func TestStatusCaptureAllowsHijack(t *testing.T) {
	w := &statusCapture{ResponseWriter: hijackRecorder{httptest.NewRecorder()}}
	if _, _, err := http.NewResponseController(w).Hijack(); !errors.Is(err, errHijacked) {
		t.Fatalf("Hijack non relayé: %v", err)
	}
}
