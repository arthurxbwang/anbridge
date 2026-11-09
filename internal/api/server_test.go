package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"anbridge/internal/deploy"
	"anbridge/internal/testutil"
)

type backendStub struct {
	calls []deploy.Request
	err   error
}

func (b *backendStub) Activate(req deploy.Request) (deploy.Result, error) {
	b.calls = append(b.calls, req)
	return deploy.Result{SiteID: req.SiteID, Active: deploy.Active{CertID: req.CertID}}, b.err
}
func (b *backendStub) Status(site string) (deploy.Status, error) {
	return deploy.Status{SiteID: site, Ready: true}, b.err
}

func call(t *testing.T, handler http.Handler, method, path, token string, body any) (int, map[string]any) {
	t.Helper()
	var data []byte
	if body != nil {
		var err error
		data, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(data))
	if token != "" {
		req.Header.Set(TokenHeader, token)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	var response map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("non-JSON protocol response: %s", w.Body.String())
	}
	if _, ok := response["msg"].(string); !ok {
		t.Fatal("AllinSSL requires msg to be a string in every response")
	}
	if strings.Contains(w.Body.String(), "PRIVATE KEY") || strings.Contains(w.Body.String(), token) && token != "" {
		t.Fatal("response leaked a credential")
	}
	return w.Code, response
}

func TestAllinSSLContractAndTenantIsolation(t *testing.T) {
	dir := t.TempDir()
	pki := testutil.NewPKI(t, dir)
	cfg := testutil.Config(t, dir, pki, "zabbix", "other")
	backend := &backendStub{}
	server, err := New(cfg, backend, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	token := testutil.Token("zabbix")
	code, _ := call(t, server, "GET", "/api/open/site/group", "", nil)
	if code != http.StatusUnauthorized {
		t.Fatal("anonymous management request accepted")
	}
	code, response := call(t, server, "GET", "/api/open/site/group", token, nil)
	if code != http.StatusOK || response["msg"] != "" {
		t.Fatalf("connection test failed: %v", response)
	}
	cert, key := pki.Issue(t, cfg.Sites[0].Domains, nil)
	payload := map[string]any{"type": 2, "crt": string(cert), "key": string(key)}
	code, response = call(t, server, "POST", "/api/open/cert", token, payload)
	id, ok := response["data"].(float64)
	if code != http.StatusOK || !ok || int64(id) < 1 || id > float64(deploy.MaxCertID) {
		t.Fatalf("upload must return a JSON-safe numeric ID: %v", response)
	}
	if len(backend.calls) != 0 {
		t.Fatal("upload activated a certificate before binding")
	}
	code, _ = call(t, server, "PUT", "/api/open/system", testutil.Token("other"), map[string]any{"cert_id": id})
	if code != http.StatusNotFound || len(backend.calls) != 0 {
		t.Fatal("another site's certificate ID was accepted")
	}
	// Restarting the receiver retains staged certificate IDs.
	server, err = New(cfg, backend, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	code, response = call(t, server, "PUT", "/api/open/system", token, map[string]any{"cert_id": id})
	if code != http.StatusOK || response["msg"] != "" || len(backend.calls) != 1 || backend.calls[0].SiteID != "zabbix" {
		t.Fatalf("binding failed: %v", response)
	}
	backend.err = errors.New("internal paths and diagnostic detail")
	code, response = call(t, server, "PUT", "/api/open/system", token, map[string]any{"cert_id": id})
	if code != http.StatusBadGateway || strings.Contains(response["msg"].(string), "internal paths") {
		t.Fatal("backend failure was not safely translated")
	}
}

func TestStagingQuotaExpirationAndInputValidation(t *testing.T) {
	dir := t.TempDir()
	pki := testutil.NewPKI(t, dir)
	cfg := testutil.Config(t, dir, pki, "zabbix")
	cfg.MaxStagedPerSite = 1
	server, err := New(cfg, &backendStub{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	token := testutil.Token("zabbix")
	cert, key := pki.Issue(t, cfg.Sites[0].Domains, nil)
	payload := map[string]any{"type": 2, "crt": string(cert), "key": string(key)}
	code, response := call(t, server, "POST", "/api/open/cert", token, payload)
	if code != http.StatusOK {
		t.Fatal(response)
	}
	id := int64(response["data"].(float64))
	code, _ = call(t, server, "POST", "/api/open/cert", token, payload)
	if code != http.StatusTooManyRequests {
		t.Fatal("staging quota not enforced")
	}
	path := filepath.Join(cfg.APIStateDir, "zabbix", strconv.FormatInt(id, 10)+".json")
	data, _ := os.ReadFile(path)
	var entry staged
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatal(err)
	}
	entry.CreatedAt = time.Now().Add(-100 * time.Hour)
	data, _ = json.Marshal(entry)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	code, _ = call(t, server, "PUT", "/api/open/system", token, map[string]any{"cert_id": id})
	if code != http.StatusBadRequest {
		t.Fatal("expired staging accepted")
	}
	code, _ = call(t, server, "POST", "/api/open/cert", token, payload)
	if code != http.StatusOK {
		t.Fatal("expired staging was not pruned")
	}
	for _, id := range []any{-1, "../other", float64(1 << 54)} {
		code, _ = call(t, server, "PUT", "/api/open/system", token, map[string]any{"cert_id": id})
		if code != http.StatusBadRequest {
			t.Fatal("invalid ID accepted")
		}
	}
	payload["command"] = "something"
	code, _ = call(t, server, "POST", "/api/open/cert", token, payload)
	if code != http.StatusBadRequest {
		t.Fatal("unknown command field accepted")
	}
	req := httptest.NewRequest("POST", "/api/open/cert", strings.NewReader(`{"type":2,"crt":"`+strings.Repeat("x", MaxBodyBytes)+`","key":""}`))
	req.Header.Set(TokenHeader, token)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatal("oversized body accepted")
	}
}

func TestDuplicateAndWorldReadableTokensRejected(t *testing.T) {
	dir := t.TempDir()
	pki := testutil.NewPKI(t, dir)
	cfg := testutil.Config(t, dir, pki, "a", "b")
	if err := os.WriteFile(cfg.Sites[1].TokenFile, []byte(testutil.Token("a")), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(cfg, &backendStub{}, nil); err == nil {
		t.Fatal("duplicate tokens accepted")
	}
	if err := os.Chmod(cfg.Sites[0].TokenFile, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := New(cfg, &backendStub{}, nil); err == nil {
		t.Fatal("world-readable token accepted")
	}
}
