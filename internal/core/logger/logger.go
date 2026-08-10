// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logger

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/lumberjack.v2"
)

// DynamicLogger est un logger rechargeable à chaud (niveau, format, destination).
// Utilisez Logger() pour obtenir le *slog.Logger courant, ou appelez directement
// Info/Warn/Error/Debug sur le DynamicLogger lui-même.
//
// Les entrées peuvent être expédiées vers l'Admin via SetForwarder (logs système,
// status=0 — distincts des access logs HTTP).
type DynamicLogger struct {
	ptr atomic.Pointer[slog.Logger]
	mu  sync.Mutex // sérialise Reload / SetForwarder / SetNodeName

	level  string
	format string
	path   string

	nodeName  string
	forwardFn func([]ShipEntry)

	shipCh   chan ShipEntry
	shipOnce sync.Once
}

// New crée un DynamicLogger avec les paramètres initiaux.
func New(level, format, path string) *DynamicLogger {
	dl := &DynamicLogger{
		level:  level,
		format: format,
		path:   path,
		shipCh: make(chan ShipEntry, 2048),
	}
	dl.ptr.Store(dl.build())
	return dl
}

// Logger retourne le *slog.Logger courant (lecture atomique).
func (dl *DynamicLogger) Logger() *slog.Logger { return dl.ptr.Load() }

// Reload recrée le handler avec de nouveaux paramètres sans interrompre les goroutines en cours.
// Une valeur vide conserve le comportement par défaut (info / json / stderr).
func (dl *DynamicLogger) Reload(level, format, path string) {
	dl.mu.Lock()
	defer dl.mu.Unlock()
	if level != "" {
		dl.level = level
	}
	if format != "" {
		dl.format = format
	}
	if path != "" {
		dl.path = path
	}
	dl.ptr.Store(dl.build())
}

// SetForwarder enregistre le callback d'expédition des logs système vers l'Admin.
func (dl *DynamicLogger) SetForwarder(fn func([]ShipEntry)) {
	dl.mu.Lock()
	defer dl.mu.Unlock()
	dl.forwardFn = fn
	dl.shipOnce.Do(func() { go dl.shipLoop() })
	dl.ptr.Store(dl.build())
}

// SetNodeName associe le nom du nœud Core aux logs système expédiés.
func (dl *DynamicLogger) SetNodeName(name string) {
	dl.mu.Lock()
	defer dl.mu.Unlock()
	dl.nodeName = name
	dl.ptr.Store(dl.build())
}

func (dl *DynamicLogger) Info(msg string, args ...any)  { dl.ptr.Load().Info(msg, args...) }
func (dl *DynamicLogger) Warn(msg string, args ...any)  { dl.ptr.Load().Warn(msg, args...) }
func (dl *DynamicLogger) Error(msg string, args ...any) { dl.ptr.Load().Error(msg, args...) }
func (dl *DynamicLogger) Debug(msg string, args ...any) { dl.ptr.Load().Debug(msg, args...) }

func (dl *DynamicLogger) build() *slog.Logger {
	var lvl slog.Level
	switch dl.level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}
	w := logWriter(dl.path)
	var fileH slog.Handler
	if dl.format == "text" {
		fileH = slog.NewTextHandler(w, opts)
	} else {
		fileH = slog.NewJSONHandler(w, opts)
	}
	if dl.forwardFn == nil {
		return slog.New(fileH)
	}
	shipH := &shipHandler{
		level:    lvl,
		ch:       dl.shipCh,
		nodeName: dl.nodeName,
	}
	return slog.New(&fanoutHandler{handlers: []slog.Handler{fileH, shipH}})
}

// fanoutHandler diffuse chaque record à plusieurs handlers (équivalent MultiHandler).
type fanoutHandler struct {
	handlers []slog.Handler
}

func (f *fanoutHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, h := range f.handlers {
		if h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (f *fanoutHandler) Handle(ctx context.Context, r slog.Record) error {
	var first error
	for _, h := range f.handlers {
		if !h.Enabled(ctx, r.Level) {
			continue
		}
		if err := h.Handle(ctx, r.Clone()); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (f *fanoutHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	hs := make([]slog.Handler, len(f.handlers))
	for i, h := range f.handlers {
		hs[i] = h.WithAttrs(attrs)
	}
	return &fanoutHandler{handlers: hs}
}

func (f *fanoutHandler) WithGroup(name string) slog.Handler {
	hs := make([]slog.Handler, len(f.handlers))
	for i, h := range f.handlers {
		hs[i] = h.WithGroup(name)
	}
	return &fanoutHandler{handlers: hs}
}

func (dl *DynamicLogger) shipLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	batch := make([]ShipEntry, 0, 64)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		dl.mu.Lock()
		fn := dl.forwardFn
		dl.mu.Unlock()
		if fn == nil {
			batch = batch[:0]
			return
		}
		out := make([]ShipEntry, len(batch))
		copy(out, batch)
		batch = batch[:0]
		fn(out)
	}

	for {
		select {
		case e := <-dl.shipCh:
			batch = append(batch, e)
			if len(batch) >= 64 {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// shipHandler convertit les records slog en ShipEntry (status=0 = log système).
type shipHandler struct {
	level    slog.Level
	ch       chan<- ShipEntry
	nodeName string
	attrs    []slog.Attr
	groups   []string
}

func (h *shipHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *shipHandler) Handle(_ context.Context, r slog.Record) error {
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
			domain = stripHostPort(val)
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

	e := ShipEntry{
		Ts:        r.Time.UTC().Format(time.RFC3339Nano),
		Level:     lvl,
		Component: "core",
		NodeName:  h.nodeName,
		Domain:    domain,
		Message:   msg,
		// Status=0 → log système (distinct des access HTTP status>0).
	}
	select {
	case h.ch <- e:
	default:
		// drop si buffer plein — ne pas bloquer le hot path
	}
	return nil
}

func (h *shipHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	cp := *h
	cp.attrs = append(append([]slog.Attr{}, h.attrs...), attrs...)
	return &cp
}

func (h *shipHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	cp := *h
	cp.groups = append(append([]string{}, h.groups...), name)
	return &cp
}

func logWriter(path string) io.Writer {
	if path == "" {
		return os.Stderr
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return os.Stderr
	}
	rotated := &lumberjack.Logger{
		Filename:   path,
		MaxSize:    100,
		MaxBackups: 5,
		MaxAge:     30,
		Compress:   true,
	}
	return io.MultiWriter(os.Stderr, rotated)
}
