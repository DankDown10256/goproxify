// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package raft

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Transport abstrait les appels RPC Raft vers les pairs.
type Transport interface {
	RequestVote(peerURL string, args RequestVoteArgs) (RequestVoteReply, error)
	AppendEntries(peerURL string, args AppendEntriesArgs) (AppendEntriesReply, error)
}

// HTTPTransport implémente Transport via HTTP JSON.
type HTTPTransport struct {
	client *http.Client
}

// NewHTTPTransport crée un transport HTTP avec timeout court.
func NewHTTPTransport() *HTTPTransport {
	return &HTTPTransport{
		client: &http.Client{Timeout: 200 * time.Millisecond},
	}
}

func (t *HTTPTransport) RequestVote(peerURL string, args RequestVoteArgs) (RequestVoteReply, error) {
	var reply RequestVoteReply
	if err := t.post(peerURL+"/raft/vote", args, &reply); err != nil {
		return reply, err
	}
	return reply, nil
}

func (t *HTTPTransport) AppendEntries(peerURL string, args AppendEntriesArgs) (AppendEntriesReply, error) {
	var reply AppendEntriesReply
	if err := t.post(peerURL+"/raft/append", args, &reply); err != nil {
		return reply, err
	}
	return reply, nil
}

func (t *HTTPTransport) post(url string, body, out any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := t.client.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("raft: peer returned %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
