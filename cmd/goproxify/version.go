// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

// Injectées au build via -ldflags (voir Makefile, versions lues depuis versions.json) :
//
//	-X 'main.VersionAdmin=0.2.0'
//	-X 'main.VersionCore=0.2.0'
//	-X 'main.VersionAgent=0.2.0'
//	-X 'main.VersionWebapp=0.2.0'
//	-X 'main.VersionLanding=0.1.0'
//	-X 'main.BuildTime=2026-07-16T00:00:00Z'
//	-X 'main.GitCommit=abc1234'
var (
	VersionAdmin   = "dev"
	VersionCore    = "dev"
	VersionAgent   = "dev"
	VersionWebapp  = "dev"
	VersionLanding = "dev"
	BuildTime      = "unknown"
	GitCommit      = "unknown"
)
