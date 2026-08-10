// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import "sync"

// BufPool est un pool de buffers 32 KB pour le proxy HTTP/TCP.
var BufPool = &sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

// GetBuf emprunte un buffer du pool.
func GetBuf() *[]byte { return BufPool.Get().(*[]byte) }

// PutBuf restitue un buffer au pool.
func PutBuf(b *[]byte) { BufPool.Put(b) }
