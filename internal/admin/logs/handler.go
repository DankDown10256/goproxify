// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logs

import (
	"context"
	"log/slog"
	"strings"
	"time"
)

// StoreHandler écrit les records slog dans le Store comme logs système (status=0).
// À combiner avec un handler stderr via un fan-out.
type StoreHandler struct {
	Store     *Store
	Level     slog.Level
	Component string
	NodeName  string
	attrs     []slog.Attr
	groups    []string
}

func (h *StoreHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.Level
}

func (h *StoreHandler) Handle(_ context.Context, r slog.Record) error {
	if h.Store == nil {
		return nil
	}
	lvl := "info"
	switch {
	case r.Level >= slog.LevelError:
		lvl = "error"
	case r.Level >= slog.LevelWarn:
		lvl = "warn"
	case r.Level < slog.LevelInfo:
		lvl = "debug"
	}

	var domain string
	var parts []string
	appendAttr := func(a slog.Attr) {
		a.Value = a.Value.Resolve()
		if a.Equal(slog.Attr{}) {
			return
		}
		key := a.Key
		if len(h.groups) > 0 {
			key = strings.Join(h.groups, ".") + "." + key
		}
		val := a.Value.String()
		switch key {
		case "domain", "host":
			domain = val
		default:
			parts = append(parts, key+"="+val)
		}
	}
	for _, a := range h.attrs {
		appendAttr(a)
	}
	r.Attrs(func(a slog.Attr) bool {
		appendAttr(a)
		return true
	})

	msg := r.Message
	if len(parts) > 0 {
		msg = msg + " " + strings.Join(parts, " ")
	}

	comp := h.Component
	if comp == "" {
		comp = "admin"
	}
	ts := r.Time
	if ts.IsZero() {
		ts = time.Now()
	}
	h.Store.Write(Entry{
		Ts:        ts,
		Level:     lvl,
		Component: comp,
		NodeName:  h.NodeName,
		Domain:    domain,
		Message:   msg,
		// Status=0 → système
	})
	return nil
}

func (h *StoreHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	cp := *h
	cp.attrs = append(append([]slog.Attr{}, h.attrs...), attrs...)
	return &cp
}

func (h *StoreHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	cp := *h
	cp.groups = append(append([]string{}, h.groups...), name)
	return &cp
}

// FanoutHandler diffuse chaque record à plusieurs handlers.
type FanoutHandler struct {
	Handlers []slog.Handler
}

func (f *FanoutHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, h := range f.Handlers {
		if h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (f *FanoutHandler) Handle(ctx context.Context, r slog.Record) error {
	var first error
	for _, h := range f.Handlers {
		if !h.Enabled(ctx, r.Level) {
			continue
		}
		if err := h.Handle(ctx, r.Clone()); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (f *FanoutHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	hs := make([]slog.Handler, len(f.Handlers))
	for i, h := range f.Handlers {
		hs[i] = h.WithAttrs(attrs)
	}
	return &FanoutHandler{Handlers: hs}
}

func (f *FanoutHandler) WithGroup(name string) slog.Handler {
	hs := make([]slog.Handler, len(f.Handlers))
	for i, h := range f.Handlers {
		hs[i] = h.WithGroup(name)
	}
	return &FanoutHandler{Handlers: hs}
}
