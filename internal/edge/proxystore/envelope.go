// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxystore

import (
	"encoding/json"
	"fmt"
	"time"
)

// SchemaVersionV1 is the current on-disk envelope version.
const SchemaVersionV1 = 1

// Status is the pipeline lifecycle of a proxy document.
type Status string

const (
	StatusPending    Status = "pending"
	StatusValidated  Status = "validated"
	StatusProduction Status = "production"
	StatusRejected   Status = "rejected"
)

// DryRunResult records the last dry-run outcome for a revision.
type DryRunResult struct {
	OK        bool       `json:"ok"`
	CheckedAt *time.Time `json:"checked_at"`
	Errors    []string   `json:"errors"`
}

// Envelope is the on-disk JSON wrapper around a router.Route config.
type Envelope struct {
	SchemaVersion int             `json:"schema_version"`
	ID            string          `json:"id"`
	Revision      string          `json:"revision,omitempty"`
	Host          string          `json:"host"`
	Enabled       bool            `json:"enabled"`
	Status        Status          `json:"status"`
	CreatedAt     *time.Time     `json:"created_at,omitempty"`
	UpdatedAt     time.Time       `json:"updated_at"`
	CreatedBy     string          `json:"created_by,omitempty"`
	DryRun        *DryRunResult  `json:"dry_run,omitempty"`
	Config        json.RawMessage `json:"config"`
}

// Validate checks required envelope fields (not full route dry-run).
func (e *Envelope) Validate() error {
	if e == nil {
		return fmt.Errorf("proxystore: envelope nil")
	}
	if e.SchemaVersion < 1 {
		return fmt.Errorf("proxystore: schema_version invalide (%d)", e.SchemaVersion)
	}
	if e.ID == "" {
		return fmt.Errorf("proxystore: id requis")
	}
	if len(e.Config) == 0 {
		return fmt.Errorf("proxystore: config requise")
	}
	switch e.Status {
	case StatusPending, StatusValidated, StatusProduction, StatusRejected:
	case "":
		return fmt.Errorf("proxystore: status requis")
	default:
		return fmt.Errorf("proxystore: status inconnu %q", e.Status)
	}
	// Production files in proxies/ have empty revision; revision audit
	// copies in proxies-revisions/ keep StatusProduction with Revision set.
	if e.Status != StatusProduction && e.Revision == "" {
		return fmt.Errorf("proxystore: revision requise pour status %s", e.Status)
	}
	return nil
}
