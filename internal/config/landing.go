// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package config

// LandingConfig est la configuration du serveur de la page de présentation.
// Chargée depuis internal/landing/config.json, surchargeable par GPX_*.
type LandingConfig struct {
	App struct {
		Environment string `mapstructure:"environment"`
		LogLevel    string `mapstructure:"log_level"`
	} `mapstructure:"app"`

	Server struct {
		ListenAddr string `mapstructure:"listen_addr"`
		Port       int    `mapstructure:"port"`
	} `mapstructure:"server"`

	Site struct {
		Domain    string `mapstructure:"domain"`
		Version   string `mapstructure:"version"`
		GoVersion string `mapstructure:"go_version"`
		GithubURL string `mapstructure:"github_url"`
		Tagline   string `mapstructure:"tagline"`
	} `mapstructure:"site"`
}
