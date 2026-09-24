package middleware

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

func TestTransformWriterAllowsHijack(t *testing.T) {
	w := &transformWriter{ResponseWriter: hijackRecorder{httptest.NewRecorder()}}
	if _, _, err := http.NewResponseController(w).Hijack(); !errors.Is(err, errHijacked) {
		t.Fatalf("Hijack non relayé: %v", err)
	}
}
