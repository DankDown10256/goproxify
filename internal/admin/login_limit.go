// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net"
	"strings"
	"sync"
	"time"
)

const (
	loginMaxFails   = 5
	loginWindowSecs = 5 * time.Minute
	loginLockSecs   = 15 * time.Minute
)

type loginBucket struct {
	fails       int
	windowAt    time.Time
	lockedUntil time.Time
}

// loginLimiter limite les tentatives de login Admin par IP+email (mémoire process).
type loginLimiter struct {
	mu    sync.Mutex
	byKey map[string]*loginBucket
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{byKey: map[string]*loginBucket{}}
}

func loginKey(ip, email string) string {
	return strings.ToLower(strings.TrimSpace(ip)) + "|" + strings.ToLower(strings.TrimSpace(email))
}

func clientIP(rRemote string) string {
	host, _, err := net.SplitHostPort(rRemote)
	if err != nil {
		return rRemote
	}
	return host
}

func (l *loginLimiter) blocked(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.byKey[key]
	if b == nil {
		return false, 0
	}
	now := time.Now()
	if now.Before(b.lockedUntil) {
		return true, b.lockedUntil.Sub(now)
	}
	if now.Sub(b.windowAt) > loginWindowSecs {
		b.fails = 0
		b.windowAt = now
	}
	return false, 0
}

func (l *loginLimiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b := l.byKey[key]
	if b == nil {
		b = &loginBucket{windowAt: now}
		l.byKey[key] = b
	}
	if now.Sub(b.windowAt) > loginWindowSecs {
		b.fails = 0
		b.windowAt = now
	}
	b.fails++
	if b.fails >= loginMaxFails {
		b.lockedUntil = now.Add(loginLockSecs)
		b.fails = 0
		b.windowAt = now
	}
}

func (l *loginLimiter) success(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.byKey, key)
}
