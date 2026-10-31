// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package launcher

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/vincamok/goproxify/internal/admin/archstore"
	"github.com/vincamok/goproxify/internal/admin/backup"
	"github.com/vincamok/goproxify/internal/admin/importer"
)

// RestoreAdminEmail est le compte temporaire d'une installation à partir d'une sauvegarde : il sert à se connecter pour
// restaurer les données, puis se supprime. Il ne doit pas être celui d'un compte de la sauvegarde, dont la restauration
// échouerait sur l'unicité de l'adresse.
const RestoreAdminEmail = "restauration@goproxify.local"

// Restored est ce que le launcher tire d'une sauvegarde pour reconstruire le cadre d'un Admin : de quoi faire reconnaître l'Admin
// par les passerelles et les Agents déjà en place (secret racine), garder son empreinte (certificat) et retrouver
// la topologie déclarée. Les données (comptes, proxys, règles…) se restaurent ensuite dans l'Admin.
type Restored struct {
	Root         string
	RootPrevious string
	Cert         *AdminCert // nil si la sauvegarde n'en contient pas
	// ArchitectureJSON est architecture.json tel que sauvegardé : source de vérité, déposé tel quel dans l'Admin.
	ArchitectureJSON []byte
	Architecture     *archstore.Architecture
	BackupKey        string
}

// ReadBackup lit le fichier d'une sauvegarde d'Admin (snapshot, enveloppe chiffrée comprise) avec la clé de sauvegarde. Il
// échoue si la sauvegarde n'a pas le secret racine : sans lui, l'Admin reconstruit ne serait pas reconnu des hôtes en place.
func ReadBackup(data []byte, key string) (*Restored, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, errors.New("clé de sauvegarde manquante (GPX_BACKUP_KEY ou --backup-key)")
	}
	importer.SetFileKey(key)
	plain, err := backup.OpenSnapshot(data)
	if err != nil {
		return nil, fmt.Errorf("sauvegarde illisible : %w", err)
	}
	b, err := importer.ParseBackup(plain)
	if err != nil {
		return nil, fmt.Errorf("sauvegarde illisible : %w", err)
	}
	files, err := importer.SecretFiles(b)
	if err != nil {
		return nil, fmt.Errorf("partie secrets illisible (mauvaise clé, ou sauvegarde faite sans clé) : %w", err)
	}

	r := &Restored{BackupKey: key}
	raw, ok := files["config/admin-secrets.json"]
	if !ok {
		return nil, errors.New("cette sauvegarde ne contient pas le secret racine (faite avant Admin 0.224.0 ?) : sans lui, les hôtes en place ne reconnaîtraient pas l'Admin reconstruit")
	}
	var secrets map[string]string
	if err := json.Unmarshal(raw, &secrets); err != nil || secrets["GPX_PAIRING_SECRET"] == "" {
		return nil, errors.New("admin-secrets.json de la sauvegarde est illisible ou sans secret racine")
	}
	r.Root, r.RootPrevious = secrets["GPX_PAIRING_SECRET"], secrets["GPX_PAIRING_SECRET_PREVIOUS"]

	if crt, key := files["config/admin-tls.crt"], files["config/admin-tls.key"]; len(crt) > 0 && len(key) > 0 {
		fp, err := fingerprintOfPEM(crt)
		if err != nil {
			return nil, fmt.Errorf("certificat de la sauvegarde : %w", err)
		}
		r.Cert = &AdminCert{CertPEM: string(crt), KeyPEM: string(key), Fingerprint: fp}
	}
	if arch, ok := files["state/architecture.json"]; ok {
		var a archstore.Architecture
		if err := json.Unmarshal(arch, &a); err != nil {
			return nil, fmt.Errorf("architecture.json de la sauvegarde : %w", err)
		}
		r.ArchitectureJSON, r.Architecture = arch, &a
	}
	return r, nil
}

// fingerprintOfPEM est l'empreinte SHA-256 du premier certificat d'un PEM, comme celle que le launcher annonce.
func fingerprintOfPEM(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", errors.New("PEM de certificat attendu")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return "", err
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:]), nil
}

// TopologyFromBackup donne la topologie à reconstruire : celle d'architecture.json, où l'hôte de cette machine (name, ou
// celui qui porte addr) reçoit le rôle d'Admin, absent du fichier puisque l'Admin n'y est pas un nœud. addr, si donné,
// remplace l'adresse déclarée de cet hôte (la machine a pu changer d'adresse).
func (r *Restored) TopologyFromBackup(name, addr string) (*Topology, error) {
	if r.Architecture == nil {
		return nil, errors.New("la sauvegarde ne contient pas architecture.json : il n'y a pas d'infrastructure à reconstruire")
	}
	t := TopologyFromArchitecture(r.Architecture)
	if len(t.Hosts) == 0 {
		return nil, errors.New("architecture.json de la sauvegarde ne déclare aucun hôte")
	}
	local := -1
	for i, h := range t.Hosts {
		if (name != "" && h.Name == name) || (name == "" && addr != "" && h.Addr == addr) {
			local = i
			break
		}
	}
	if local < 0 {
		var names []string
		for _, h := range t.Hosts {
			names = append(names, fmt.Sprintf("%s (%s)", h.Name, h.Addr))
		}
		return nil, fmt.Errorf("quel hôte de la sauvegarde est cette machine ? indiquez --name parmi : %s", strings.Join(names, ", "))
	}
	h := &t.Hosts[local]
	if addr != "" {
		h.Addr = addr
	}
	if !h.Has(RoleAdmin) {
		h.Roles = append([]string{RoleAdmin}, h.Roles...)
	}
	t.Local = h.Name
	return t, nil
}
