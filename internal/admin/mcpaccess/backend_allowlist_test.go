package mcpaccess

import "testing"

func TestCheckBackend(t *testing.T) {
	allow := []string{"10.0.0.0/8", "192.168.1.5", "*.internal", "api.corp.example"}
	ok := []string{
		"http://10.2.3.4:8080", "192.168.1.5:80", "http://app:3000", "https://svc.internal",
		"http://api.corp.example/x", "http://API.corp.example.:80",
	}
	bad := []string{
		"http://203.0.113.9", "https://evil.example.com", "http://192.168.1.6",
		"http://internal.evil.com", "http://10.0.0.1.evil.com", "",
	}
	for _, b := range ok {
		if err := checkBackend(allow, b); err != nil {
			t.Errorf("%q devrait passer: %v", b, err)
		}
	}
	for _, b := range bad {
		if err := checkBackend(allow, b); err == nil {
			t.Errorf("%q devrait être refusé", b)
		}
	}
	if err := checkBackend(nil, "http://evil.example.com"); err != nil {
		t.Errorf("liste vide = pas de restriction: %v", err)
	}
}
