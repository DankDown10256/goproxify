// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package deploy applique la description structurée d'un hôte (réseaux, volumes, conteneurs) par l'API Docker, et
// défait ce qu'il a créé si une étape échoue (ADR 0019). C'est le moteur commun du launcher et, plus tard, de la
// recréation de conteneurs par l'Agent.
package deploy

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

// SpecVersion est la version du format. Un format plus récent est refusé plutôt que mal interprété.
const SpecVersion = 1

// HostSpec décrit ce qui doit tourner sur un hôte. L'ordre des conteneurs est l'ordre de démarrage.
type HostSpec struct {
	Version    int         `json:"version"`
	Name       string      `json:"name,omitempty"`
	Networks   []Network   `json:"networks,omitempty"`
	Volumes    []string    `json:"volumes,omitempty"`
	Containers []Container `json:"containers"`
}

// Network est un réseau bridge créé s'il n'existe pas.
type Network struct {
	Name     string `json:"name"`
	Internal bool   `json:"internal,omitempty"`
}

// Container décrit un conteneur. Rien ici ne permet le mode privilégié ni le réseau de l'hôte.
type Container struct {
	Name           string            `json:"name"`
	Image          string            `json:"image"`
	Env            map[string]string `json:"env,omitempty"`
	Cmd            []string          `json:"cmd,omitempty"`
	User           string            `json:"user,omitempty"`
	Labels         map[string]string `json:"labels,omitempty"`
	Ports          []Port            `json:"ports,omitempty"`
	Mounts         []Mount           `json:"mounts,omitempty"`
	Networks       []Attach          `json:"networks,omitempty"`
	Restart        string            `json:"restart,omitempty"`
	Healthcheck    *Healthcheck      `json:"healthcheck,omitempty"`
	WaitHealthy    bool              `json:"wait_healthy,omitempty"`
	CapAdd         []string          `json:"cap_add,omitempty"`
	CapDrop        []string          `json:"cap_drop,omitempty"`
	ReadOnlyRootfs bool              `json:"read_only_rootfs,omitempty"`
	Files          []File            `json:"files,omitempty"`
}

// File est un fichier déposé dans le conteneur après sa création et avant son démarrage : certificats, configuration
// initiale. Il peut se trouver dans un volume monté. Mode vaut 0644 par défaut.
type File struct {
	Path    string `json:"path"`
	Mode    int64  `json:"mode,omitempty"`
	Content string `json:"content"`
}

// maxFilesSize borne le contenu déposé : ce sont des petits fichiers de configuration, pas des données.
const maxFilesSize = 1 << 20

// Port publie un port du conteneur sur l'hôte.
type Port struct {
	HostIP        string `json:"host_ip,omitempty"`
	HostPort      int    `json:"host_port"`
	ContainerPort int    `json:"container_port"`
	Proto         string `json:"proto,omitempty"`
}

// Mount monte un volume déclaré dans la description (type "volume") ou un chemin de l'hôte (type "bind").
type Mount struct {
	Type     string `json:"type"`
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only,omitempty"`
}

// Attach branche un conteneur à un réseau déclaré ; le premier est le réseau principal.
type Attach struct {
	Name    string   `json:"name"`
	Aliases []string `json:"aliases,omitempty"`
}

// Healthcheck est exprimé en secondes.
type Healthcheck struct {
	Test         []string `json:"test"`
	IntervalS    int      `json:"interval_s,omitempty"`
	TimeoutS     int      `json:"timeout_s,omitempty"`
	Retries      int      `json:"retries,omitempty"`
	StartPeriodS int      `json:"start_period_s,omitempty"`
}

var (
	nameRe   = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)
	imageRe  = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._/:@-]*$`)
	envKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	capRe    = regexp.MustCompile(`^[A-Z_]+$`)
)

// DefaultAllowBind refuse les montages de l'hôte qui ne peuvent pas servir un composant GoProxify : la racine et les
// systèmes de fichiers du noyau. La description vient du réseau, le launcher détient le socket Docker.
func DefaultAllowBind(source string) error {
	if !path.IsAbs(source) || path.Clean(source) != source {
		return fmt.Errorf("chemin %q non absolu ou non normalisé", source)
	}
	for _, p := range []string{"/", "/proc", "/sys", "/dev", "/boot"} {
		if source == p || (p != "/" && strings.HasPrefix(source, p+"/")) {
			return fmt.Errorf("montage de %q refusé", source)
		}
	}
	return nil
}

// Validate vérifie la description avant qu'on touche au démon. allowBind juge les chemins de l'hôte montés
// (DefaultAllowBind si nil).
func (s *HostSpec) Validate(allowBind func(string) error) error {
	if allowBind == nil {
		allowBind = DefaultAllowBind
	}
	if s.Version != SpecVersion {
		return fmt.Errorf("version %d de la description non prise en charge (attendue : %d)", s.Version, SpecVersion)
	}
	if len(s.Containers) == 0 {
		return fmt.Errorf("aucun conteneur à déployer")
	}

	networks := map[string]bool{}
	for _, n := range s.Networks {
		if !nameRe.MatchString(n.Name) {
			return fmt.Errorf("réseau %q : nom invalide", n.Name)
		}
		if networks[n.Name] {
			return fmt.Errorf("réseau %q déclaré deux fois", n.Name)
		}
		networks[n.Name] = true
	}
	volumes := map[string]bool{}
	for _, v := range s.Volumes {
		if !nameRe.MatchString(v) {
			return fmt.Errorf("volume %q : nom invalide", v)
		}
		if volumes[v] {
			return fmt.Errorf("volume %q déclaré deux fois", v)
		}
		volumes[v] = true
	}

	seen := map[string]bool{}
	for i := range s.Containers {
		c := &s.Containers[i]
		if !nameRe.MatchString(c.Name) {
			return fmt.Errorf("conteneur %q : nom invalide", c.Name)
		}
		if seen[c.Name] {
			return fmt.Errorf("conteneur %q déclaré deux fois", c.Name)
		}
		seen[c.Name] = true
		if err := c.validate(networks, volumes, allowBind); err != nil {
			return fmt.Errorf("conteneur %q : %w", c.Name, err)
		}
	}
	return nil
}

func (c *Container) validate(networks, volumes map[string]bool, allowBind func(string) error) error {
	if !imageRe.MatchString(c.Image) {
		return fmt.Errorf("image %q invalide", c.Image)
	}
	for k := range c.Env {
		if !envKeyRe.MatchString(k) {
			return fmt.Errorf("variable %q invalide", k)
		}
	}
	switch c.Restart {
	case "", "no", "always", "unless-stopped", "on-failure":
	default:
		return fmt.Errorf("politique de redémarrage %q inconnue", c.Restart)
	}
	for _, p := range c.Ports {
		if p.ContainerPort < 1 || p.ContainerPort > 65535 || p.HostPort < 0 || p.HostPort > 65535 {
			return fmt.Errorf("port %d:%d invalide", p.HostPort, p.ContainerPort)
		}
		switch p.Proto {
		case "", "tcp", "udp", "sctp":
		default:
			return fmt.Errorf("protocole %q inconnu", p.Proto)
		}
	}
	for _, m := range c.Mounts {
		if !path.IsAbs(m.Target) {
			return fmt.Errorf("destination %q non absolue", m.Target)
		}
		switch m.Type {
		case "volume":
			if !volumes[m.Source] {
				return fmt.Errorf("volume %q non déclaré", m.Source)
			}
		case "bind":
			if err := allowBind(m.Source); err != nil {
				return err
			}
		default:
			return fmt.Errorf("type de montage %q inconnu", m.Type)
		}
	}
	for _, a := range c.Networks {
		if !networks[a.Name] {
			return fmt.Errorf("réseau %q non déclaré", a.Name)
		}
		for _, al := range a.Aliases {
			if !nameRe.MatchString(al) {
				return fmt.Errorf("alias %q invalide", al)
			}
		}
	}
	if h := c.Healthcheck; h != nil && len(h.Test) == 0 {
		return fmt.Errorf("contrôle de santé sans commande")
	}
	if c.WaitHealthy && c.Healthcheck == nil {
		return fmt.Errorf("wait_healthy exige un contrôle de santé")
	}
	total := 0
	for _, f := range c.Files {
		if !path.IsAbs(f.Path) || path.Clean(f.Path) != f.Path || f.Path == "/" {
			return fmt.Errorf("fichier %q : chemin non absolu ou non normalisé", f.Path)
		}
		if f.Mode < 0 || f.Mode > 0o777 {
			return fmt.Errorf("fichier %q : mode invalide", f.Path)
		}
		total += len(f.Content)
	}
	if total > maxFilesSize {
		return fmt.Errorf("fichiers déposés trop volumineux (%d octets, au plus %d)", total, maxFilesSize)
	}
	for _, cp := range append(append([]string{}, c.CapAdd...), c.CapDrop...) {
		if !capRe.MatchString(cp) {
			return fmt.Errorf("capacité %q invalide", cp)
		}
	}
	return nil
}
