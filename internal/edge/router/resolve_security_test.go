// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"encoding/json"
	"testing"
)

func TestNormalizeBotConfig(t *testing.T) {
	cfg := &BotConfig{Mode: "challenge"}
	NormalizeBotConfig(cfg)
	if !cfg.Enabled || !cfg.JSChallenge {
		t.Fatalf("%#v", cfg)
	}
	cfg = &BotConfig{Mode: "off", Enabled: true}
	NormalizeBotConfig(cfg)
	if cfg.Enabled {
		t.Fatal("off should disable")
	}
}

func TestResolveSnippetsWAFAndBot(t *testing.T) {
	store := NewSnippetStore()
	wafCfg, _ := json.Marshal(WAFConfig{Enabled: true, Mode: "block", ExcludeIDs: []int{942100}})
	botCfg, _ := json.Marshal(BotConfig{Mode: "challenge"})
	store.Replace([]*Snippet{
		{ID: "w1", Name: "waf-default", Type: SnippetWAF, Config: wafCfg},
		{ID: "b1", Name: "bot-protect", Type: SnippetBot, Config: botCfg},
	})
	route := &Route{SnippetIDs: []string{"w1", "b1"}}
	got := ResolveSnippets(route, store)
	if got.WAF == nil || !got.WAF.Enabled || got.WAF.Mode != "block" {
		t.Fatalf("waf: %#v", got.WAF)
	}
	if got.Bot == nil || !got.Bot.Enabled || !got.Bot.JSChallenge {
		t.Fatalf("bot: %#v", got.Bot)
	}

	// Labels Docker référencent souvent le nom, pas l'UUID.
	byName := ResolveSnippets(&Route{SnippetIDs: []string{"waf-default"}}, store)
	if byName.WAF == nil || !byName.WAF.Enabled {
		t.Fatalf("resolve by name: %#v", byName.WAF)
	}
}
