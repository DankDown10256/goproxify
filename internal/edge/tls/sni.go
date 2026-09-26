// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package tls

import (
	"fmt"
	"net"
)

const maxClientHelloRecord = 16 << 10 // 16 KiB — ClientHello TLS 1.3 + PQ dépasse souvent 1 KiB

// PeekSNI lit les premiers octets d'une connexion TCP pour extraire le SNI
// du ClientHello TLS sans consommer le flux — la connexion retournée
// (peekConn) rejoue les octets lus pour le prochain lecteur.
//
// Lit le record TLS Handshake en entier (pas seulement le premier segment TCP /
// un buffer fixe) : un ClientHello moderne (Chrome, Edge, PQ) fait souvent
// 1.2–2+ KiB ; un peek tronqué renvoyait SNI vide → passthrough ignoré.
//
// Retourne ("", peeked, nil) si la connexion n'est pas TLS ou si le SNI est absent.
func PeekSNI(conn net.Conn) (sni string, peeked net.Conn, err error) {
	buf := make([]byte, 0, 2048)
	tmp := make([]byte, 2048)

	// En-tête record TLS : type(1) + version(2) + length(2)
	for len(buf) < 5 {
		n, rerr := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if rerr != nil {
			return "", &peekConn{Conn: conn, buf: buf}, rerr
		}
	}

	if buf[0] != 0x16 { // ContentType: Handshake
		return "", &peekConn{Conn: conn, buf: buf}, nil
	}
	recLen := int(buf[3])<<8 | int(buf[4])
	need := 5 + recLen
	if need > maxClientHelloRecord {
		return "", &peekConn{Conn: conn, buf: buf}, fmt.Errorf("tls ClientHello trop grand: %d octets", recLen)
	}

	for len(buf) < need {
		n, rerr := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if rerr != nil {
			return "", &peekConn{Conn: conn, buf: buf}, rerr
		}
	}

	sni = extractSNI(buf[:need])
	return sni, &peekConn{Conn: conn, buf: buf}, nil
}

// extractSNI parse manuellement le ClientHello TLS pour trouver le SNI.
func extractSNI(data []byte) string {
	if len(data) < 5 || data[0] != 0x16 { // ContentType: Handshake
		return ""
	}
	// Record layer : [type(1)] [version(2)] [length(2)] [handshake...]
	if len(data) < 9 {
		return ""
	}
	recLen := int(data[3])<<8 | int(data[4])
	if len(data) < 5+recLen {
		return ""
	}
	hs := data[5 : 5+recLen]
	if len(hs) < 4 || hs[0] != 0x01 { // HandshakeType: ClientHello
		return ""
	}
	// Handshake header : [type(1)] [length(3)] [body...]
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+hsLen {
		return ""
	}
	body := hs[4 : 4+hsLen]

	// ClientHello : [version(2)] [random(32)] [session_id_len(1)] ...
	pos := 2 + 32
	if len(body) < pos+1 {
		return ""
	}
	sidLen := int(body[pos])
	pos += 1 + sidLen

	if len(body) < pos+2 {
		return ""
	}
	csLen := int(body[pos])<<8 | int(body[pos+1])
	pos += 2 + csLen

	if len(body) < pos+1 {
		return ""
	}
	compLen := int(body[pos])
	pos += 1 + compLen

	// Extensions
	if len(body) < pos+2 {
		return ""
	}
	extLen := int(body[pos])<<8 | int(body[pos+1])
	pos += 2
	end := pos + extLen
	for pos+4 <= end {
		extType := int(body[pos])<<8 | int(body[pos+1])
		extDataLen := int(body[pos+2])<<8 | int(body[pos+3])
		pos += 4
		if extType == 0x0000 && pos+extDataLen <= end { // server_name
			return parseSNIExtension(body[pos : pos+extDataLen])
		}
		pos += extDataLen
	}
	return ""
}

func parseSNIExtension(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	listLen := int(data[0])<<8 | int(data[1])
	if len(data) < 2+listLen {
		return ""
	}
	data = data[2 : 2+listLen]
	for len(data) >= 3 {
		nameType := data[0]
		nameLen := int(data[1])<<8 | int(data[2])
		data = data[3:]
		if len(data) < nameLen {
			return ""
		}
		if nameType == 0x00 {
			return string(data[:nameLen])
		}
		data = data[nameLen:]
	}
	return ""
}

// peekConn est une net.Conn qui rejoue les octets déjà lus avant de
// déléguer au flux réseau sous-jacent.
type peekConn struct {
	net.Conn
	buf []byte
	pos int
}

func (c *peekConn) Read(b []byte) (int, error) {
	if c.pos < len(c.buf) {
		n := copy(b, c.buf[c.pos:])
		c.pos += n
		return n, nil
	}
	return c.Conn.Read(b)
}
