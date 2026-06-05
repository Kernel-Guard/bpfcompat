package api

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestIntegrationServeSmoke stands up the full Serve() stack on a random
// loopback port, exercises the four infra endpoints (livez, readyz,
// /api/v1/health, legacy /api/health), and proves the middleware chain
// (security headers, request-id, CSP) is wired together end-to-end. This
// is the test that would have caught any of the "I split server.go and
// forgot to register a route" bugs that the unit tests can't see.
func TestIntegrationServeSmoke(t *testing.T) {
	// Reserve a loopback port from the OS to avoid races between tests.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved port: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	cfg := Config{
		Addr:               addr,
		WorkDir:            t.TempDir(),
		DefaultConcurrency: 1,
		DefaultTimeout:     30 * time.Second,
	}
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- Serve(ctx, cfg)
	}()

	// Wait for the server to start accepting connections. We dial in a tight
	// loop with a hard deadline so a hung Serve doesn't park the whole
	// test suite.
	deadline := time.Now().Add(3 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server failed to come up on %s", addr)
		}
		time.Sleep(50 * time.Millisecond)
	}

	client := &http.Client{Timeout: 2 * time.Second}
	base := "http://" + addr

	t.Run("livez_returns_ok", func(t *testing.T) {
		body := requireGet(t, client, base+"/livez", http.StatusOK)
		if strings.TrimSpace(string(body)) != "ok" {
			t.Fatalf("expected livez body 'ok', got %q", body)
		}
	})

	t.Run("readyz_returns_structured_payload", func(t *testing.T) {
		body := requireGet(t, client, base+"/readyz", http.StatusOK)
		var payload struct {
			Status  string `json:"status"`
			Checks  []struct {
				Name string `json:"name"`
				OK   bool   `json:"ok"`
			} `json:"checks"`
			Version string `json:"version"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("decode readyz: %v body=%s", err, body)
		}
		if payload.Status != "OK" {
			t.Fatalf("expected readyz status OK, got %q", payload.Status)
		}
		if len(payload.Checks) == 0 {
			t.Fatalf("expected at least one readiness check")
		}
		// workdir must be reported and OK because we created a fresh tempdir.
		found := false
		for _, c := range payload.Checks {
			if c.Name == "workdir" && c.OK {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected workdir check to be OK, got %+v", payload.Checks)
		}
	})

	t.Run("health_v1_and_legacy_both_route", func(t *testing.T) {
		// Both the canonical v1 path and the legacy alias must reach the
		// same handler. This is the regression test for the
		// registerAPIRoute helper.
		for _, path := range []string{"/api/v1/health", "/api/health"} {
			body := requireGet(t, client, base+path, http.StatusOK)
			var got map[string]string
			if err := json.Unmarshal(body, &got); err != nil {
				t.Fatalf("decode %s: %v body=%s", path, err, body)
			}
			if got["status"] != "ok" {
				t.Fatalf("%s expected {status:ok}, got %+v", path, got)
			}
		}
	})

	t.Run("request_id_round_trips", func(t *testing.T) {
		// withRequestLogging must echo X-Request-Id back in the response.
		// A propagated incoming ID stays as-is; absence triggers a fresh
		// crypto-random ID.
		req, err := http.NewRequest(http.MethodGet, base+"/api/v1/health", nil)
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		req.Header.Set("X-Request-Id", "integration-trace-1")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		_ = resp.Body.Close()
		if got := resp.Header.Get("X-Request-Id"); got != "integration-trace-1" {
			t.Fatalf("expected propagated X-Request-Id, got %q", got)
		}
	})

	t.Run("security_headers_present", func(t *testing.T) {
		resp, err := client.Get(base + "/livez")
		if err != nil {
			t.Fatalf("GET livez: %v", err)
		}
		_ = resp.Body.Close()
		for _, h := range []string{"X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Content-Security-Policy"} {
			if resp.Header.Get(h) == "" {
				t.Fatalf("expected security header %s on /livez response, got none", h)
			}
		}
		// We're plain HTTP in this test; HSTS must NOT be emitted.
		if resp.Header.Get("Strict-Transport-Security") != "" {
			t.Fatalf("HSTS must only be emitted over TLS, got header on plain HTTP")
		}
	})

	t.Run("html_index_includes_nonce_csp", func(t *testing.T) {
		// The root HTML route gets a per-response CSP with nonce, not the
		// 'unsafe-inline' fallback. The nonce attribute MUST be substituted
		// into the inline <style>/<script> tags.
		resp, err := client.Get(base + "/")
		if err != nil {
			t.Fatalf("GET /: %v", err)
		}
		defer resp.Body.Close()
		csp := resp.Header.Get("Content-Security-Policy")
		if !strings.Contains(csp, "'nonce-") {
			t.Fatalf("expected nonce-based CSP on HTML route, got %q", csp)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read html: %v", err)
		}
		if strings.Contains(string(body), "__CSP_NONCE__") {
			t.Fatalf("expected __CSP_NONCE__ placeholder to be substituted; raw placeholder still present")
		}
	})

	// Initiate shutdown and wait for Serve to return cleanly so the goroutine
	// doesn't leak across tests.
	cancel()
	select {
	case err := <-serveErr:
		if err != nil {
			t.Fatalf("Serve returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("Serve did not shut down within 5s after context cancel")
	}
}

func requireGet(t *testing.T, client *http.Client, url string, wantStatus int) []byte {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	if resp.StatusCode != wantStatus {
		t.Fatalf("GET %s status=%d want=%d body=%s", url, resp.StatusCode, wantStatus, body)
	}
	return body
}
