// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package launcher

import (
	"encoding/json"
	"fmt"

	"github.com/vincamok/goproxify/internal/deploy"
)

// Valeurs du démarrage rapide (scripts/quickstart.sh), que le launcher reprend pour que les deux installations se
// ressemblent.
const (
	DefaultRegistry = "ghcr.io/vincamok/goproxify"
	DefaultTag      = "preview"
	netName         = "goproxify_net"
	adminPort       = 9443
	dockerSock      = "/var/run/docker.sock"
	stateDir        = "/etc/goproxify"
)

// Env regroupe ce qui, hors de la topologie, entre dans la description d'un hôte.
type Env struct {
	Secrets    *Secrets
	Registry   string
	Tag        string
	TZ         string
	AdminEmail string
	AdminCert  *AdminCert
	// RootPrevious (GPX_PAIRING_SECRET_PREVIOUS) et ArchitectureJSON ne servent qu'à une installation à partir d'une
	// sauvegarde : le secret racine précédent est repris, et architecture.json est déposé tel quel plutôt que reconstruit
	// depuis la topologie (qui ne porte ni domaines, ni délégations, ni réglages des passerelles).
	RootPrevious     string
	ArchitectureJSON []byte
}

func (e Env) registry() string {
	if e.Registry == "" {
		return DefaultRegistry
	}
	return e.Registry
}

func (e Env) tag() string {
	if e.Tag == "" {
		return DefaultTag
	}
	return e.Tag
}

// Image est l'image d'un composant (admin, edge, agent, launcher) au registre et à l'étiquette de l'installation.
func (e Env) Image(role string) string { return e.image(role) }

func (e Env) image(role string) string {
	return fmt.Sprintf("%s/%s:%s", e.registry(), role, e.tag())
}

// HostSpec décrit ce qu'il faut déployer sur un hôte de la topologie : l'Admin, la passerelle et l'Agent qui lui sont
// confiés, dans cet ordre.
func (t *Topology) HostSpec(hostName string, env Env) (*deploy.HostSpec, error) {
	h, ok := t.host(hostName)
	if !ok {
		return nil, fmt.Errorf("hôte %q absent de la topologie", hostName)
	}
	if env.Secrets == nil {
		return nil, fmt.Errorf("secrets manquants")
	}
	spec := &deploy.HostSpec{
		Version:  deploy.SpecVersion,
		Name:     h.Name,
		Networks: []deploy.Network{{Name: netName}},
	}
	tz := env.TZ
	if tz == "" {
		tz = "Europe/Paris"
	}

	if h.Has(RoleAdmin) {
		c, err := t.adminContainer(h, env, tz)
		if err != nil {
			return nil, err
		}
		spec.Volumes = append(spec.Volumes, "goproxify_admin_data")
		spec.Containers = append(spec.Containers, c)
	}
	if h.Has(RoleEdge) {
		spec.Volumes = append(spec.Volumes, "goproxify_edge_data")
		spec.Containers = append(spec.Containers, t.edgeContainer(h, env, tz))
	}
	if h.Has(RoleAgent) {
		spec.Volumes = append(spec.Volumes, "goproxify_agent_data")
		spec.Containers = append(spec.Containers, t.agentContainer(h, env, tz))
	}
	return spec, nil
}

func (t *Topology) adminContainer(h Host, env Env, tz string) (deploy.Container, error) {
	if env.AdminCert == nil {
		return deploy.Container{}, fmt.Errorf("certificat de l'Admin manquant")
	}
	arch := append([]byte(nil), env.ArchitectureJSON...)
	if len(arch) > 0 && arch[len(arch)-1] != '\n' {
		arch = append(arch, '\n')
	}
	if len(arch) == 0 {
		raw, err := json.MarshalIndent(t.Architecture(), "", "  ")
		if err != nil {
			return deploy.Container{}, err
		}
		arch = append(raw, '\n')
	}
	s := env.Secrets
	vars := map[string]string{
		"TZ":                             tz,
		"GPX_SECURITY_JWT_SECRET":        s.JWT,
		"GPX_PAIRING_SECRET":             s.Root,
		"GPX_BACKUP_KEY":                 s.Backup,
		"GPX_EDGE_CHANNEL_ROOT_FALLBACK": "false",
		"GPX_AGENT_PAIRING_ROOT":         "false",
		"GPX_FIRST_ADMIN_EMAIL":          env.AdminEmail,
		"GPX_FIRST_ADMIN_PASSWORD":       s.AdminPassword,
		"GPX_SERVER_API_PORT":            fmt.Sprint(adminPort),
		"GPX_ADMIN_TLS_CERT":             stateDir + "/tls/admin.crt",
		"GPX_ADMIN_TLS_KEY":              stateDir + "/tls/admin.key",
		"GPX_ADMIN_PUBLIC_URL":           fmt.Sprintf("https://%s:%d", h.Addr, adminPort),
		// Les hôtes qui rejoignent par ticket reçoivent les mêmes images que ceux-ci (internal/admin/api/hosts.go).
		"GPX_DEPLOY_REGISTRY": env.registry(),
		"GPX_DEPLOY_TAG":      env.tag(),
	}
	if env.RootPrevious != "" {
		vars["GPX_PAIRING_SECRET_PREVIOUS"] = env.RootPrevious
	}
	// L'Admin joint la passerelle de son hôte par le DNS du réseau Docker ; les autres sont dans architecture.json.
	if h.Has(RoleEdge) {
		vars["GPX_IDENTITY_EDGE_NODE_NAME"] = t.EdgeName(h)
	}
	return deploy.Container{
		Name:     "goproxify-admin",
		Image:    env.image("admin"),
		Env:      vars,
		Ports:    []deploy.Port{{HostPort: adminPort, ContainerPort: adminPort}},
		Mounts:   []deploy.Mount{{Type: "volume", Source: "goproxify_admin_data", Target: stateDir}},
		Networks: []deploy.Attach{{Name: netName}},
		// Le contrôle de santé de l'image parle en HTTP : l'Admin sert maintenant en HTTPS.
		Healthcheck: &deploy.Healthcheck{
			Test:      []string{"CMD", "wget", "-qO-", "--no-check-certificate", fmt.Sprintf("https://localhost:%d/api/v1/health", adminPort)},
			IntervalS: 5, TimeoutS: 5, Retries: 10, StartPeriodS: 10,
		},
		WaitHealthy: true,
		Files: []deploy.File{
			{Path: stateDir + "/tls/admin.crt", Mode: 0o644, Content: env.AdminCert.CertPEM},
			{Path: stateDir + "/tls/admin.key", Mode: 0o600, Content: env.AdminCert.KeyPEM},
			{Path: stateDir + "/state/architecture.json", Mode: 0o600, Content: string(arch)},
		},
	}, nil
}

func (t *Topology) edgeContainer(h Host, env Env, tz string) deploy.Container {
	name := t.EdgeName(h)
	s := env.Secrets
	// Les membres d'un groupe HA partagent la clé maître du portail ; sans groupe, elle est propre à la passerelle.
	scope := "group:" + t.GroupOf(h)
	ports := []deploy.Port{
		{HostPort: 80, ContainerPort: 80},
		{HostPort: 443, ContainerPort: 443},
		{HostPort: 443, ContainerPort: 443, Proto: "udp"},
	}
	// Le hub (8000) n'est publié que si un autre hôte doit le joindre.
	if h.Name != t.Local || len(t.Hosts) > 1 {
		ports = append(ports, deploy.Port{HostPort: edgeHubPort, ContainerPort: edgeHubPort})
	}
	return deploy.Container{
		Name:  "goproxify-edge",
		Image: env.image("edge"),
		Env: map[string]string{
			"TZ":                          tz,
			"GPX_EDGE_CHANNEL_KEY":        s.EdgeChannelKey(t.EdgeNodeID(h)),
			"GPX_AGENT_PAIRING_KEY":       s.AgentKey(),
			"GPX_PORTAL_MASTER_KEY":       s.PortalKey(scope),
			"GPX_IDENTITY_EDGE_NODE_NAME": name,
		},
		Ports:  ports,
		Mounts: []deploy.Mount{{Type: "volume", Source: "goproxify_edge_data", Target: stateDir}},
		// L'alias est le nom de nœud : c'est ainsi que l'Admin joint la passerelle de son hôte.
		Networks: []deploy.Attach{{Name: netName, Aliases: []string{name}}},
	}
}

func (t *Topology) agentContainer(h Host, env Env, tz string) deploy.Container {
	target := t.TargetEdge(h)
	endpoint := fmt.Sprintf("http://%s:%d", target.Addr, edgeHubPort)
	if target.Name == h.Name {
		endpoint = fmt.Sprintf("http://%s:%d", t.EdgeName(target), edgeHubPort)
	}
	return deploy.Container{
		Name:  "goproxify-agent",
		Image: env.image("agent"),
		Env: map[string]string{
			"TZ":                              tz,
			"GPX_AGENT_PAIRING_KEY":           env.Secrets.AgentKey(),
			"GPX_CONTROL_PLANE_EDGE_ENDPOINT": endpoint,
			"GPX_IDENTITY_AGENT_NODE_NAME":    t.AgentName(h),
		},
		Mounts: []deploy.Mount{
			{Type: "bind", Source: dockerSock, Target: dockerSock},
			{Type: "volume", Source: "goproxify_agent_data", Target: stateDir},
		},
		Networks: []deploy.Attach{{Name: netName}},
	}
}
