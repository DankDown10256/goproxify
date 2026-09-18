// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"regexp"
	"testing"

	"github.com/vincamok/goproxify/internal/core/router"
)

func resp(ct, body string) *http.Response {
	return &http.Response{
		Header:        http.Header{"Content-Type": []string{ct}},
		Body:          io.NopCloser(bytes.NewBufferString(body)),
		ContentLength: int64(len(body)),
	}
}

func respGzip(ct, body string) *http.Response {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write([]byte(body))
	gz.Close()
	return &http.Response{
		Header:        http.Header{"Content-Type": []string{ct}, "Content-Encoding": []string{"gzip"}},
		Body:          io.NopCloser(&buf),
		ContentLength: int64(buf.Len()),
	}
}

func readBody(r *http.Response) string {
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	return string(b)
}

func TestApplySubFilters_Simple(t *testing.T) {
	r := resp("text/html", "<a href='http://backend:8080/path'>link</a>")
	filters := []router.SubFilter{{From: "http://backend:8080", To: "https://app.example.fr"}}
	if err := applySubFilters(r, filters, nil); err != nil {
		t.Fatal(err)
	}
	got := readBody(r)
	want := "<a href='https://app.example.fr/path'>link</a>"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestApplySubFilters_Regex(t *testing.T) {
	r := resp("text/html", "src=\"http://old.com/img/logo.png\"")
	filters := []router.SubFilter{{From: `http://old\.com(/[^"]+)`, To: "https://new.com$1", Regex: true}}
	re := regexp.MustCompile(filters[0].From)
	if err := applySubFilters(r, filters, []*regexp.Regexp{re}); err != nil {
		t.Fatal(err)
	}
	got := readBody(r)
	want := "src=\"https://new.com/img/logo.png\""
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestApplySubFilters_Gzip(t *testing.T) {
	r := respGzip("text/html", "hello world")
	filters := []router.SubFilter{{From: "world", To: "GoProxify"}}
	if err := applySubFilters(r, filters, nil); err != nil {
		t.Fatal(err)
	}
	if r.Header.Get("Content-Encoding") != "" {
		t.Error("Content-Encoding should be removed after decompression")
	}
	got := readBody(r)
	if got != "hello GoProxify" {
		t.Errorf("got %q", got)
	}
}

func TestApplySubFilters_SkipsBinary(t *testing.T) {
	r := resp("image/png", "binary data")
	filters := []router.SubFilter{{From: "binary", To: "replaced"}}
	if err := applySubFilters(r, filters, nil); err != nil {
		t.Fatal(err)
	}
	got := readBody(r)
	if got != "binary data" {
		t.Errorf("binary content should not be modified, got %q", got)
	}
}

func TestApplySubFilters_MultipleRules(t *testing.T) {
	r := resp("application/json", `{"host":"http://a.com","other":"http://b.com"}`)
	filters := []router.SubFilter{
		{From: "http://a.com", To: "https://a.example.fr"},
		{From: "http://b.com", To: "https://b.example.fr"},
	}
	if err := applySubFilters(r, filters, nil); err != nil {
		t.Fatal(err)
	}
	got := readBody(r)
	want := `{"host":"https://a.example.fr","other":"https://b.example.fr"}`
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}
