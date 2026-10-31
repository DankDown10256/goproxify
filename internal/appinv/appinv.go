// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package appinv reconnaît l'application derrière un proxy (produit et version) à partir de ce que la passerelle en sait déjà, pour
// que le scanner de vulnérabilités cherche des CVE sur ce qui tourne réellement (ADR 0017). Une image de conteneur donne un produit et
// une version exacts ; elle ne donne rien quand l'étiquette n'est pas une version.
package appinv

import (
	"regexp"
	"strings"
)

// Source d'une information d'inventaire.
const (
	SourceImage = "image"
)

// Finding est une application reconnue : le produit, sa version quand elle est connue, et ce qui l'a fait reconnaître.
type Finding struct {
	// Product : nom court du produit (« nginx », « wordpress »). Vide quand l'image n'est pas dans la table.
	Product string `json:"product,omitempty"`
	// CPE : « vendor:product » dans la base NVD. Vide quand le produit est connu mais sans identifiant CPE sûr : il est alors listé
	// « non couvert » plutôt que cherché en texte libre.
	CPE string `json:"cpe,omitempty"`
	// Version : celle de l'étiquette de l'image, vide si l'étiquette n'est pas une version (latest, condensat, variante seule).
	Version string `json:"version,omitempty"`
	// Partial : la version n'a que deux composantes (« 1.25 ») ; NVD la compare à des plages précises, la correspondance est approchée.
	Partial  bool   `json:"partial,omitempty"`
	Source   string `json:"source"`
	Evidence string `json:"evidence"`
	// Note : ce qui est à savoir sur la fiabilité de l'entrée (désaccord entre l'image et les réponses du backend).
	Note string `json:"note,omitempty"`
}

// Image est une référence d'image décomposée.
type Image struct {
	Registry string
	Repo     string
	Tag      string
	Digest   string
}

// ParseImage décompose « [registre/]chemin[:étiquette][@condensat] ».
func ParseImage(ref string) Image {
	ref = strings.TrimSpace(ref)
	var img Image
	if i := strings.Index(ref, "@"); i >= 0 {
		img.Digest = ref[i+1:]
		ref = ref[:i]
	}
	// Une étiquette suit le dernier « : » situé après le dernier « / » (sinon c'est le port du registre).
	if i := strings.LastIndex(ref, ":"); i >= 0 && i > strings.LastIndex(ref, "/") {
		img.Tag = ref[i+1:]
		ref = ref[:i]
	}
	if i := strings.Index(ref, "/"); i >= 0 {
		first := ref[:i]
		if strings.ContainsAny(first, ".:") || first == "localhost" {
			img.Registry = first
			ref = ref[i+1:]
		}
	}
	img.Repo = strings.ToLower(ref)
	return img
}

type known struct{ product, cpe string }

// knownImages : nom d'image (dernier segment du chemin, ou les deux derniers pour les noms ambigus) vers le produit et son identifiant
// CPE dans NVD. Un identifiant n'y figure que s'il est sûr : un CPE faux donnerait de fausses CVE. Un produit sans CPE reste listé,
// « non couvert ».
var knownImages = map[string]known{
	"nginx":                   {"nginx", "nginx:nginx"},
	"httpd":                   {"apache http server", "apache:http_server"},
	"tomcat":                  {"apache tomcat", "apache:tomcat"},
	"caddy":                   {"caddy", "caddyserver:caddy"},
	"haproxy":                 {"haproxy", "haproxy:haproxy"},
	"traefik":                 {"traefik", "traefik:traefik"},
	"php":                     {"php", "php:php"},
	"wordpress":               {"wordpress", "wordpress:wordpress"},
	"drupal":                  {"drupal", "drupal:drupal"},
	"ghost":                   {"ghost", "ghost:ghost"},
	"nextcloud":               {"nextcloud", "nextcloud:nextcloud_server"},
	"gitea":                   {"gitea", "gitea:gitea"},
	"grafana":                 {"grafana", "grafana:grafana"},
	"prometheus":              {"prometheus", "prometheus:prometheus"},
	"jenkins":                 {"jenkins", "jenkins:jenkins"},
	"mattermost":              {"mattermost", "mattermost:mattermost_server"},
	"mattermost-team-edition": {"mattermost", "mattermost:mattermost_server"},
	"portainer":               {"portainer", "portainer:portainer"},
	"portainer-ce":            {"portainer", "portainer:portainer"},
	"jellyfin":                {"jellyfin", "jellyfin:jellyfin"},
	"n8n":                     {"n8n", "n8n:n8n"},
	"odoo":                    {"odoo", "odoo:odoo"},
	"zabbix-web-nginx-mysql":  {"zabbix", "zabbix:zabbix"},
	"zabbix-server-mysql":     {"zabbix", "zabbix:zabbix"},
	"keycloak":                {"keycloak", "redhat:keycloak"},
	"redis":                   {"redis", "redis:redis"},
	"postgres":                {"postgresql", "postgresql:postgresql"},
	"mysql":                   {"mysql", "oracle:mysql"},
	"mariadb":                 {"mariadb", "mariadb:mariadb"},
	"mongo":                   {"mongodb", "mongodb:mongodb"},
	"minio":                   {"minio", "minio:minio"},
	"rabbitmq":                {"rabbitmq", "vmware:rabbitmq"},
	"gitlab-ce":               {"gitlab", "gitlab:gitlab"},
	"gitlab-ee":               {"gitlab", "gitlab:gitlab"},
	"elasticsearch":           {"elasticsearch", "elastic:elasticsearch"},
	"kibana":                  {"kibana", "elastic:kibana"},
	"logstash":                {"logstash", "elastic:logstash"},
	"memcached":               {"memcached", "memcached:memcached"},
	"sonarqube":               {"sonarqube", "sonarsource:sonarqube"},
	"vault":                   {"vault", "hashicorp:vault"},
	"consul":                  {"consul", "hashicorp:consul"},
	"etcd":                    {"etcd", "etcd:etcd"},
	"influxdb":                {"influxdb", "influxdata:influxdb"},
	"telegraf":                {"telegraf", "influxdata:telegraf"},
	"airflow":                 {"airflow", "apache:airflow"},
	"kafka":                   {"kafka", "apache:kafka"},
	"solr":                    {"solr", "apache:solr"},
	"couchdb":                 {"couchdb", "apache:couchdb"},
	"cassandra":               {"cassandra", "apache:cassandra"},
	"node":                    {"node.js", "nodejs:node.js"},
	"python":                  {"python", "python:python"},
	"ruby":                    {"ruby", "ruby-lang:ruby"},
	"squid":                   {"squid", "squid-cache:squid"},
	"varnish":                 {"varnish", "varnish-cache:varnish"},
	"phpmyadmin":              {"phpmyadmin", "phpmyadmin:phpmyadmin"},
	"adminer":                 {"adminer", "adminer:adminer"},
	"roundcubemail":           {"roundcube", "roundcube:webmail"},
	"owncloud":                {"owncloud", "owncloud:owncloud"},
	"metabase":                {"metabase", "metabase:metabase"},
	"redmine":                 {"redmine", "redmine:redmine"},
	"matomo":                  {"matomo", "matomo:matomo"},
	"postfix":                 {"postfix", "postfix:postfix"},
	"dovecot":                 {"dovecot", "dovecot:dovecot"},
	"home-assistant":          {"home assistant", "home-assistant:home-assistant"},
	"node-red":                {"node-red", "nodered:node-red"},
	"authelia":                {"authelia", "authelia:authelia"},
	"argocd":                  {"argo cd", "argoproj:argo_cd"},
	"neo4j":                   {"neo4j", "neo4j:neo4j"},
	"clickhouse-server":       {"clickhouse", "clickhouse:clickhouse"},
	"eclipse-mosquitto":       {"mosquitto", "eclipse:mosquitto"},
	"strapi":                  {"strapi", "strapi:strapi"},
	"directus":                {"directus", "directus:directus"},
	"discourse":               {"discourse", "discourse:discourse"},
	"mediawiki":               {"mediawiki", "mediawiki:mediawiki"},
	"dokuwiki":                {"dokuwiki", "dokuwiki:dokuwiki"},
	"typo3":                   {"typo3", "typo3:typo3"},
	"grafana-oss":             {"grafana", "grafana:grafana"},
	"nexus3":                  {"nexus", ""},
	"uptime-kuma":             {"uptime kuma", ""},
	"harbor-core":             {"harbor", ""},
	"bookstack":               {"bookstack", ""},
	"seafile-mc":              {"seafile", ""},
	"pihole":                  {"pi-hole", ""},
	"sonarr":                  {"sonarr", ""},
	"radarr":                  {"radarr", ""},
	"vaultwarden/server":      {"vaultwarden", ""},
	"vaultwarden":             {"vaultwarden", ""},
	"immich-server":           {"immich", ""},
	"joomla":                  {"joomla", ""},
	"prestashop":              {"prestashop", "prestashop:prestashop"},
	"magento":                 {"magento", ""},
}

// versionTag : une étiquette qui commence par une version « 6.4.2 » ou « v10.2 », suivie ou non d'une variante (« -apache », « -alpine3.18 »).
var versionTag = regexp.MustCompile(`^v?(\d+(?:\.\d+){1,3})(?:[-_+.a-z].*)?$`)

// FromImage reconnaît le produit et la version d'une référence d'image. Rend faux quand la référence est vide.
func FromImage(ref string) (Finding, bool) {
	if strings.TrimSpace(ref) == "" {
		return Finding{}, false
	}
	img := ParseImage(ref)
	f := Finding{Source: SourceImage, Evidence: ref}
	segs := strings.Split(img.Repo, "/")
	last := segs[len(segs)-1]
	k, ok := knownImages[last]
	if !ok && len(segs) >= 2 {
		k, ok = knownImages[segs[len(segs)-2]+"/"+last]
	}
	if !ok {
		return f, true
	}
	f.Product, f.CPE = k.product, k.cpe
	if m := versionTag.FindStringSubmatch(strings.ToLower(img.Tag)); m != nil {
		f.Version = m[1]
		f.Partial = strings.Count(m[1], ".") == 1
	}
	return f, true
}
