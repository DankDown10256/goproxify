// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
)

const oldID = "5d3a1c9f8b2e7a4c6b1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b"

// composeInspect : un conteneur tel que Compose le crée, avec tout ce qu'une recréation ne doit pas perdre.
const composeInspect = `{
  "Id": "` + oldID + `",
  "Name": "/goproxify-admin",
  "Config": {
    "Hostname": "5d3a1c9f8b2e",
    "Image": "registry/admin:1.0",
    "Env": ["GPX_SERVER_API_PORT=9443", "TZ=Europe/Paris"],
    "Cmd": ["admin"],
    "Labels": {"goproxify.managed": "true"},
    "ExposedPorts": {"9443/tcp": {}},
    "Healthcheck": {"Test": ["CMD", "true"]}
  },
  "HostConfig": {
    "NetworkMode": "goproxify-net",
    "RestartPolicy": {"Name": "unless-stopped"},
    "PortBindings": {"9443/tcp": [{"HostIp": "", "HostPort": "9443"}]},
    "Binds": ["gpx-data:/data", "/etc/localtime:/etc/localtime:ro"]
  },
  "Mounts": [
    {"Type": "volume", "Name": "gpx-data", "Destination": "/data", "RW": true},
    {"Type": "bind", "Source": "/etc/localtime", "Destination": "/etc/localtime", "RW": false},
    {"Type": "volume", "Name": "anon-1234", "Destination": "/var/cache", "RW": true},
    {"Type": "volume", "Name": "anon-5678", "Destination": "/var/ro", "RW": false}
  ],
  "NetworkSettings": {
    "Networks": {
      "goproxify-net": {"Aliases": ["admin", "5d3a1c9f8b2e"], "NetworkID": "n1", "IPAddress": "172.20.0.2", "MacAddress": "02:42:ac:14:00:02"},
      "monitoring": {"Aliases": ["goproxify-admin"], "IPAMConfig": {"IPv4Address": "172.30.0.9"}, "IPAddress": "172.30.0.9"}
    }
  }
}`

func parseInspect(t *testing.T, s string) map[string]any {
	t.Helper()
	var raw map[string]any
	if err := json.Unmarshal([]byte(s), &raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSpecFromInspectKeepsFullConfig(t *testing.T) {
	spec := specFromInspect(parseInspect(t, composeInspect), "registry/admin:2.0")
	body := spec.body

	if body["Image"] != "registry/admin:2.0" {
		t.Fatalf("image = %v", body["Image"])
	}
	for _, k := range []string{"Env", "Cmd", "Labels", "ExposedPorts", "Healthcheck"} {
		if body[k] == nil {
			t.Errorf("%s perdu", k)
		}
	}
	if _, ok := body["Hostname"]; ok {
		t.Error("le nom d'hôte par défaut (identifiant de l'ancien conteneur) ne doit pas être repris")
	}

	hc := asMap(body["HostConfig"])
	if hc["NetworkMode"] != "goproxify-net" || asMap(hc["RestartPolicy"])["Name"] != "unless-stopped" {
		t.Errorf("HostConfig = %v", hc)
	}
	if hc["PortBindings"] == nil {
		t.Error("PortBindings perdu")
	}
	wantBinds := []string{"gpx-data:/data", "/etc/localtime:/etc/localtime:ro", "anon-1234:/var/cache", "anon-5678:/var/ro:ro"}
	if got := toStrings(hc["Binds"]); !reflect.DeepEqual(got, wantBinds) {
		t.Errorf("Binds = %v, attendu %v", got, wantBinds)
	}
}

func TestSpecFromInspectNetworks(t *testing.T) {
	spec := specFromInspect(parseInspect(t, composeInspect), "img")

	eps := asMap(asMap(spec.body["NetworkingConfig"])["EndpointsConfig"])
	primary := asMap(eps["goproxify-net"])
	if got := toStrings(primary["Aliases"]); !reflect.DeepEqual(got, []string{"admin"}) {
		t.Errorf("alias du réseau principal = %v, l'identifiant court de l'ancien conteneur doit disparaître", got)
	}
	if _, ok := primary["IPAddress"]; ok {
		t.Error("l'adresse attribuée ne doit pas être reprise")
	}

	extra, ok := spec.extraNets["monitoring"]
	if !ok || len(spec.extraNets) != 1 {
		t.Fatalf("réseaux supplémentaires = %v", spec.extraNets)
	}
	if extra["IPAMConfig"] == nil {
		t.Error("IP fixe du second réseau perdue")
	}
	if got := toStrings(extra["Aliases"]); !reflect.DeepEqual(got, []string{"goproxify-admin"}) {
		t.Errorf("alias du second réseau = %v", got)
	}
}

func TestSpecFromInspectHostNetworkHasNoEndpoints(t *testing.T) {
	raw := parseInspect(t, `{"Id":"`+oldID+`","Name":"/x","Config":{"Image":"a"},
	  "HostConfig":{"NetworkMode":"host"},
	  "NetworkSettings":{"Networks":{"host":{"NetworkID":"h"}}}}`)
	spec := specFromInspect(raw, "b")
	if spec.body["NetworkingConfig"] != nil || len(spec.extraNets) != 0 {
		t.Errorf("le mode host n'a pas de réseau à brancher : %v %v", spec.body["NetworkingConfig"], spec.extraNets)
	}
}

// fakeEngine joue le démon Docker pour un seul conteneur et note chaque appel.
type fakeEngine struct {
	mu        sync.Mutex
	calls     []string
	created   map[string]any
	connected map[string]any
	failOn    string // "create" | "start-new"
}

func (f *fakeEngine) client(inspect string) *Client {
	return &Client{http: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		path := r.URL.Path
		if q := r.URL.Query().Get("name"); q != "" {
			path += "?name=" + q
		}
		f.calls = append(f.calls, r.Method+" "+path)
		reply := func(code int, body string) (*http.Response, error) {
			return &http.Response{StatusCode: code, Header: http.Header{"Content-Type": {"application/json"}},
				Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
		}
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/json"):
			return reply(200, inspect)
		case strings.HasSuffix(r.URL.Path, "/containers/create"):
			if f.failOn == "create" {
				return reply(500, `{"message":"boom"}`)
			}
			_ = json.NewDecoder(r.Body).Decode(&f.created)
			return reply(201, `{"Id":"new0123456789abcdef"}`)
		case strings.Contains(r.URL.Path, "/connect"):
			_ = json.NewDecoder(r.Body).Decode(&f.connected)
			return reply(200, `{}`)
		case strings.HasSuffix(r.URL.Path, "/new0123456789abcdef/start") && f.failOn == "start-new":
			return reply(500, `{"message":"port already allocated"}`)
		default:
			return reply(204, ``)
		}
	})}}
}

func newTestManager(c *Client) *LifecycleManager {
	return NewLifecycleManager(c, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestRecreateContainerKeepsConfigAndSwapsAfterStart(t *testing.T) {
	eng := &fakeEngine{}
	m := newTestManager(eng.client(composeInspect))

	if err := m.RecreateContainer(context.Background(), oldID, "registry/admin:2.0", false); err != nil {
		t.Fatal(err)
	}

	if eng.created["Image"] != "registry/admin:2.0" || asMap(eng.created["HostConfig"])["PortBindings"] == nil {
		t.Errorf("corps de création incomplet : %v", eng.created)
	}
	if asMap(eng.connected)["Container"] != "new0123456789abcdef" {
		t.Errorf("second réseau non branché : %v", eng.connected)
	}

	// L'ancien conteneur n'est supprimé qu'une fois le nouveau démarré.
	idx := map[string]int{}
	for i, c := range eng.calls {
		idx[c] = i
	}
	start, del := idx["POST /containers/new0123456789abcdef/start"], idx["DELETE /containers/"+oldID]
	if start == 0 || del == 0 || del < start {
		t.Errorf("ordre des appels = %v", eng.calls)
	}
	if !strings.HasPrefix(eng.calls[2], "POST /containers/"+oldID+"/rename?name=goproxify-admin-gpx-old-") {
		t.Errorf("l'ancien conteneur doit être renommé avant la création : %v", eng.calls)
	}
}

func TestRecreateContainerRestoresOldOnFailure(t *testing.T) {
	for _, failOn := range []string{"create", "start-new"} {
		t.Run(failOn, func(t *testing.T) {
			eng := &fakeEngine{failOn: failOn}
			m := newTestManager(eng.client(composeInspect))

			if err := m.RecreateContainer(context.Background(), oldID, "registry/admin:2.0", false); err == nil {
				t.Fatal("l'échec doit être remonté")
			}

			joined := strings.Join(eng.calls, "\n")
			if strings.Contains(joined, "DELETE /containers/"+oldID) {
				t.Errorf("l'ancien conteneur ne doit pas être supprimé : %v", eng.calls)
			}
			if !strings.Contains(joined, "POST /containers/"+oldID+"/rename?name=goproxify-admin\n") {
				t.Errorf("l'ancien conteneur doit retrouver son nom : %v", eng.calls)
			}
			if last := eng.calls[len(eng.calls)-1]; last != "POST /containers/"+oldID+"/start" {
				t.Errorf("l'ancien conteneur doit être redémarré en dernier : %v", eng.calls)
			}
		})
	}
}
