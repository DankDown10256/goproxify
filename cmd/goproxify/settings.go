// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"
)

func runSettings() {
	sub := subcommand(os.Args, 2)
	switch sub {
	case "smtp":
		runSettingsSMTP()
	case "mfa":
		runSettingsMFA()
	case "help":
		fmt.Print(`Usage: goproxify settings <sous-commande> [options]

Sous-commandes :
  smtp  Configuration du serveur SMTP
  mfa   Configuration MFA serveur (SMS, WebAuthn)

goproxify settings smtp get  [-admin-url …] [-token …]
goproxify settings smtp set  -file <smtp.json> [-admin-url …] [-token …]
goproxify settings smtp test [-admin-url …] [-token …]

goproxify settings mfa sms     get [-admin-url …] [-token …]
goproxify settings mfa sms     set -file <sms.json> [-admin-url …] [-token …]
goproxify settings mfa webauthn get [-admin-url …] [-token …]
goproxify settings mfa webauthn set -file <webauthn.json> [-admin-url …] [-token …]
`)
	default:
		fmt.Fprintf(os.Stderr, "sous-commande settings inconnue : %q\n", sub)
		fmt.Fprintln(os.Stderr, "utilisez : goproxify settings help")
		os.Exit(1)
	}
}

func runSettingsSMTP() {
	sub := subcommand(os.Args, 3)
	switch sub {
	case "get", "":
		args := parseFlags(os.Args[4:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var result map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/settings/smtp", nil, &result); err != nil {
			fmt.Fprintf(os.Stderr, "settings smtp get : %v\n", err)
			os.Exit(1)
		}
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))

	case "set":
		args := parseFlags(os.Args[4:])
		file := flagValue(args, "-file", "")
		if file == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify settings smtp set -file <smtp.json>")
			os.Exit(1)
		}
		data, err := os.ReadFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "lecture fichier : %v\n", err)
			os.Exit(1)
		}
		var payload map[string]any
		if err := json.Unmarshal(data, &payload); err != nil {
			fmt.Fprintf(os.Stderr, "JSON invalide : %v\n", err)
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		if _, err := client.DoJSON("PUT", "/api/v1/settings/smtp", payload, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "settings smtp set : %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Configuration SMTP mise à jour.")

	case "test":
		args := parseFlags(os.Args[4:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var result map[string]any
		if _, err := client.DoJSON("POST", "/api/v1/settings/smtp/test", nil, &result, 200, 202); err != nil {
			fmt.Fprintf(os.Stderr, "settings smtp test : %v\n", err)
			os.Exit(1)
		}
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))

	default:
		fmt.Fprintf(os.Stderr, "sous-commande settings smtp inconnue : %q\n", sub)
		os.Exit(1)
	}
}

func runSettingsMFA() {
	sub := subcommand(os.Args, 3)
	switch sub {
	case "sms":
		runSettingsMFASub("sms")
	case "webauthn":
		runSettingsMFASub("webauthn")
	case "help", "":
		fmt.Print(`Usage: goproxify settings mfa <méthode> <action> [options]

Méthodes :
  sms      Fournisseur SMS (Twilio, OVH SMS…)
  webauthn Paramètres WebAuthn/FIDO2 (rp_id, rp_origin)

goproxify settings mfa sms     get [-admin-url …] [-token …]
goproxify settings mfa sms     set -file <sms.json>
goproxify settings mfa webauthn get [-admin-url …] [-token …]
goproxify settings mfa webauthn set -file <webauthn.json>

Exemple sms.json :
  { "provider": "twilio", "api_sid": "AC…", "api_secret": "…", "from": "+33600000000" }

Exemple webauthn.json :
  { "rp_id": "admin.example.fr", "rp_origin": "https://admin.example.fr", "display_name": "GoProxify" }

⚠ Un rp_origin incorrect bloque toutes les connexions WebAuthn.
  En cas de blocage, corrigez avec cette commande sans avoir besoin de l'UI.
`)
	default:
		fmt.Fprintf(os.Stderr, "méthode MFA inconnue : %q\n", sub)
		fmt.Fprintln(os.Stderr, "utilisez : goproxify settings mfa help")
		os.Exit(1)
	}
}

func runSettingsMFASub(method string) {
	sub := subcommand(os.Args, 4)
	endpoint := "/api/v1/settings/mfa/" + method
	switch sub {
	case "get", "":
		args := parseFlags(os.Args[5:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var result map[string]any
		if _, err := client.DoJSON("GET", endpoint, nil, &result); err != nil {
			fmt.Fprintf(os.Stderr, "settings mfa %s get : %v\n", method, err)
			os.Exit(1)
		}
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))

	case "set":
		args := parseFlags(os.Args[5:])
		file := flagValue(args, "-file", "")
		if file == "" {
			fmt.Fprintf(os.Stderr, "usage: goproxify settings mfa %s set -file <%s.json>\n", method, method)
			os.Exit(1)
		}
		data, err := os.ReadFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "lecture fichier : %v\n", err)
			os.Exit(1)
		}
		var payload map[string]any
		if err := json.Unmarshal(data, &payload); err != nil {
			fmt.Fprintf(os.Stderr, "JSON invalide : %v\n", err)
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		if _, err := client.DoJSON("PUT", endpoint, payload, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "settings mfa %s set : %v\n", method, err)
			os.Exit(1)
		}
		fmt.Printf("Configuration MFA %s mise à jour.\n", method)

	default:
		fmt.Fprintf(os.Stderr, "action inconnue pour settings mfa %s : %q\n", method, sub)
		os.Exit(1)
	}
}
