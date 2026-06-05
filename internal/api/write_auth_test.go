package api

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRequireWriteAuthorizationIdentityRequiredMissingToken(t *testing.T) {
	setWriteIdentityEnvBaseline(t)
	t.Setenv(envWriteJWTSecret, "identity-secret")
	t.Setenv(envWriteRequireIdentity, "true")
	req := httptest.NewRequest(http.MethodPost, "/api/compare", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	if _, ok := requireWriteAuthorization(rec, req); ok {
		t.Fatalf("expected auth failure when identity token is missing")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing identity token, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRequireWriteAuthorizationIdentityRequiredWithoutVerifierConfig(t *testing.T) {
	setWriteIdentityEnvBaseline(t)
	t.Setenv(envWriteJWTSecret, "")
	t.Setenv(envWriteJWTJWKSPath, "")
	t.Setenv(envWriteJWTJWKSURL, "")
	t.Setenv(envWriteJWTOIDCIssuerURL, "")
	t.Setenv(envWriteJWTIssuer, "")
	t.Setenv(envWriteRequireIdentity, "true")
	req := httptest.NewRequest(http.MethodPost, "/api/compare", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	if _, ok := requireWriteAuthorization(rec, req); ok {
		t.Fatalf("expected auth failure when identity verifier config is missing")
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for missing identity verifier config, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), envWriteJWTJWKSPath) {
		t.Fatalf("expected response to reference %s, got body=%s", envWriteJWTJWKSPath, rec.Body.String())
	}
}

func TestRequireWriteAuthorizationIdentityJWTSuccess(t *testing.T) {
	setWriteIdentityEnvBaseline(t)
	t.Setenv(envWriteJWTSecret, "identity-secret")
	t.Setenv(envWriteRequireIdentity, "true")
	token := mustHS256JWT(t, "identity-secret", map[string]any{
		"sub":      "svc-acme-demo",
		"tenant":   "acme",
		"projects": []string{"demo"},
		"exp":      time.Now().Add(10 * time.Minute).Unix(),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/compare", strings.NewReader(`{}`))
	req.Header.Set(headerIdentityToken, token)
	rec := httptest.NewRecorder()
	identity, ok := requireWriteAuthorization(rec, req)
	if !ok {
		t.Fatalf("expected identity write auth to pass, got code=%d body=%s", rec.Code, rec.Body.String())
	}
	if identity.AuthType != "jwt" {
		t.Fatalf("expected auth type jwt, got %q", identity.AuthType)
	}
	if identity.Subject != "svc-acme-demo" {
		t.Fatalf("expected subject svc-acme-demo, got %q", identity.Subject)
	}
}

func TestRequireWriteAuthorizationIdentityJWTRequiredScopes(t *testing.T) {
	setWriteIdentityEnvBaseline(t)
	t.Setenv(envWriteJWTSecret, "identity-secret")
	t.Setenv(envWriteRequireIdentity, "true")
	t.Setenv(envWriteJWTRequiredScopes, "api.write runtime.select")
	token := mustHS256JWT(t, "identity-secret", map[string]any{
		"sub":   "svc-acme-demo",
		"scope": "api.write runtime.select",
		"exp":   time.Now().Add(10 * time.Minute).Unix(),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/compare", strings.NewReader(`{}`))
	req.Header.Set(headerIdentityToken, token)
	rec := httptest.NewRecorder()
	if _, ok := requireWriteAuthorization(rec, req); !ok {
		t.Fatalf("expected scope-authorized token to pass, code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRequireWriteAuthorizationIdentityJWTRequiredScopesDenied(t *testing.T) {
	setWriteIdentityEnvBaseline(t)
	t.Setenv(envWriteJWTSecret, "identity-secret")
	t.Setenv(envWriteRequireIdentity, "true")
	t.Setenv(envWriteJWTRequiredScopes, "api.write runtime.select")
	token := mustHS256JWT(t, "identity-secret", map[string]any{
		"sub":   "svc-acme-demo",
		"scope": "api.write",
		"exp":   time.Now().Add(10 * time.Minute).Unix(),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/compare", strings.NewReader(`{}`))
	req.Header.Set(headerIdentityToken, token)
	rec := httptest.NewRecorder()
	if _, ok := requireWriteAuthorization(rec, req); ok {
		t.Fatalf("expected missing-scope token to fail")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for missing required scope, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRequireWriteAuthorizationIdentityJWTRequiredRoles(t *testing.T) {
	setWriteIdentityEnvBaseline(t)
	t.Setenv(envWriteJWTSecret, "identity-secret")
	t.Setenv(envWriteRequireIdentity, "true")
	t.Setenv(envWriteJWTRequiredRoles, "api-writer")
	token := mustHS256JWT(t, "identity-secret", map[string]any{
		"sub":   "svc-acme-demo",
		"roles": []string{"api-writer", "other"},
		"exp":   time.Now().Add(10 * time.Minute).Unix(),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/compare", strings.NewReader(`{}`))
	req.Header.Set(headerIdentityToken, token)
	rec := httptest.NewRecorder()
	if _, ok := requireWriteAuthorization(rec, req); !ok {
		t.Fatalf("expected role-authorized token to pass, code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestEnforceWriteIdentityActionClaims(t *testing.T) {
	setWriteIdentityEnvBaseline(t)
	action := "runtime_select"
	t.Setenv(writeJWTRequiredScopesEnvForAction(action), "runtime.select")
	t.Setenv(writeJWTRequiredRolesEnvForAction(action), "selector")

	identity := writeAuthIdentity{
		AuthType: "jwt",
		Scopes:   []string{"runtime.select", "api.write"},
		Roles:    []string{"selector"},
	}
	if err := enforceWriteIdentityActionClaims(identity, action); err != nil {
		t.Fatalf("expected action claims to pass: %v", err)
	}
	identityMissingScope := identity
	identityMissingScope.Scopes = []string{"api.write"}
	if err := enforceWriteIdentityActionClaims(identityMissingScope, action); err == nil {
		t.Fatalf("expected missing action scope to fail")
	}
	identityMissingRole := identity
	identityMissingRole.Roles = []string{"viewer"}
	if err := enforceWriteIdentityActionClaims(identityMissingRole, action); err == nil {
		t.Fatalf("expected missing action role to fail")
	}
}

func TestRequireWriteAuthorizationForActionValidateAllowsAnonymous(t *testing.T) {
	setWriteIdentityEnvBaseline(t)
	t.Setenv(envAllowAnonymousValidate, "true")
	t.Setenv(envWriteAPIKey, "")

	req := httptest.NewRequest(http.MethodPost, "/api/validate", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	identity, ok := requireWriteAuthorizationForAction(rec, req, "validate")
	if !ok {
		t.Fatalf("expected anonymous validate action auth to pass, code=%d body=%s", rec.Code, rec.Body.String())
	}
	if identity.AuthType != "anonymous" {
		t.Fatalf("expected auth type anonymous, got %q", identity.AuthType)
	}
	if identity.Subject != "anonymous" {
		t.Fatalf("expected subject anonymous, got %q", identity.Subject)
	}
}

func TestRequireWriteAuthorizationForActionCompareStillRequiresAuth(t *testing.T) {
	setWriteIdentityEnvBaseline(t)
	t.Setenv(envAllowAnonymousValidate, "true")
	t.Setenv(envWriteAPIKey, "")

	req := httptest.NewRequest(http.MethodPost, "/api/compare", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	if _, ok := requireWriteAuthorizationForAction(rec, req, "compare"); ok {
		t.Fatalf("expected compare auth to fail without key")
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for missing write key, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRequireWriteAuthorizationForActionRuntimeDeliveryAllowsAnonymousNarrowly(t *testing.T) {
	setWriteIdentityEnvBaseline(t)
	t.Setenv(envAllowAnonymousRuntimeDelivery, "true")
	t.Setenv(envWriteAPIKey, "")

	for _, action := range []string{"runtime_select", "runtime_fetch"} {
		t.Run(action, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/"+strings.ReplaceAll(action, "_", "/"), strings.NewReader(`{}`))
			rec := httptest.NewRecorder()
			identity, ok := requireWriteAuthorizationForAction(rec, req, action)
			if !ok {
				t.Fatalf("expected anonymous %s auth to pass, code=%d body=%s", action, rec.Code, rec.Body.String())
			}
			if identity.AuthType != "anonymous" || identity.Subject != "anonymous" {
				t.Fatalf("expected anonymous identity, got %+v", identity)
			}
		})
	}

	for _, action := range []string{"compare", "runtime_execute", "registry_upload"} {
		t.Run(action, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/"+strings.ReplaceAll(action, "_", "/"), strings.NewReader(`{}`))
			rec := httptest.NewRecorder()
			if _, ok := requireWriteAuthorizationForAction(rec, req, action); ok {
				t.Fatalf("expected %s to still require write auth", action)
			}
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("expected 503 for missing write key on %s, got %d body=%s", action, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestRequireWriteAuthorizationForActionAllowsAnonymousWrite(t *testing.T) {
	setWriteIdentityEnvBaseline(t)
	t.Setenv(envAllowAnonymousWrite, "true")
	t.Setenv(envWriteAPIKey, "")

	req := httptest.NewRequest(http.MethodPost, "/api/compare", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	identity, ok := requireWriteAuthorizationForAction(rec, req, "compare")
	if !ok {
		t.Fatalf("expected compare auth to pass in anonymous-write mode, code=%d body=%s", rec.Code, rec.Body.String())
	}
	if identity.AuthType != "anonymous" {
		t.Fatalf("expected auth type anonymous, got %q", identity.AuthType)
	}
	if identity.Subject != "anonymous" {
		t.Fatalf("expected subject anonymous, got %q", identity.Subject)
	}
}

func TestRequireWriteAuthorizationIdentityJWKSRS256Success(t *testing.T) {
	resetWriteJWKSCache()
	t.Cleanup(resetWriteJWKSCache)
	setWriteIdentityEnvBaseline(t)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	workDir := t.TempDir()
	jwksPath := filepath.Join(workDir, "jwks.json")
	writeJWKSFile(t, jwksPath, []writeJWK{
		rsaPublicJWK("acme-key-1", &privateKey.PublicKey),
	})

	t.Setenv(envWriteJWTSecret, "")
	t.Setenv(envWriteJWTJWKSPath, jwksPath)
	t.Setenv(envWriteRequireIdentity, "true")
	t.Setenv(envWriteJWTIssuer, "https://issuer.example")
	t.Setenv(envWriteJWTAudience, "bpfcompat-api")

	token := mustRS256JWT(t, privateKey, "acme-key-1", map[string]any{
		"sub":      "svc-acme-demo",
		"iss":      "https://issuer.example",
		"aud":      "bpfcompat-api",
		"tenant":   "acme",
		"projects": []string{"demo"},
		"exp":      time.Now().Add(10 * time.Minute).Unix(),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/compare", strings.NewReader(`{}`))
	req.Header.Set(headerIdentityToken, token)
	rec := httptest.NewRecorder()
	identity, ok := requireWriteAuthorization(rec, req)
	if !ok {
		t.Fatalf("expected RS256 identity auth to pass, got code=%d body=%s", rec.Code, rec.Body.String())
	}
	if identity.Subject != "svc-acme-demo" {
		t.Fatalf("expected subject svc-acme-demo, got %q", identity.Subject)
	}
}

func TestRequireWriteAuthorizationIdentityJWKSRS256RejectsUnknownKid(t *testing.T) {
	resetWriteJWKSCache()
	t.Cleanup(resetWriteJWKSCache)
	setWriteIdentityEnvBaseline(t)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	workDir := t.TempDir()
	jwksPath := filepath.Join(workDir, "jwks.json")
	writeJWKSFile(t, jwksPath, []writeJWK{
		rsaPublicJWK("acme-key-1", &privateKey.PublicKey),
	})

	t.Setenv(envWriteJWTSecret, "")
	t.Setenv(envWriteJWTJWKSPath, jwksPath)
	t.Setenv(envWriteRequireIdentity, "true")

	token := mustRS256JWT(t, privateKey, "other-key", map[string]any{
		"sub": "svc-acme-demo",
		"exp": time.Now().Add(10 * time.Minute).Unix(),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/compare", strings.NewReader(`{}`))
	req.Header.Set(headerIdentityToken, token)
	rec := httptest.NewRecorder()
	if _, ok := requireWriteAuthorization(rec, req); ok {
		t.Fatalf("expected RS256 identity auth to fail for unknown kid")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unknown kid, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRequireWriteAuthorizationIdentityJWKSURLRS256RotationRefresh(t *testing.T) {
	resetWriteJWKSCache()
	t.Cleanup(resetWriteJWKSCache)
	setWriteIdentityEnvBaseline(t)
	enableInsecureJWKSForTests(t)

	keyA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key A: %v", err)
	}
	keyB, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key B: %v", err)
	}

	var (
		mu        sync.RWMutex
		current   = []writeJWK{rsaPublicJWK("key-a", &keyA.PublicKey)}
		fetchHits atomic.Int64
	)
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		mu.RLock()
		payload, err := json.Marshal(writeJWKS{Keys: current})
		mu.RUnlock()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	}))
	defer jwksServer.Close()

	t.Setenv(envWriteJWTSecret, "")
	t.Setenv(envWriteJWTJWKSPath, "")
	t.Setenv(envWriteJWTJWKSURL, jwksServer.URL)
	t.Setenv(envWriteJWTJWKSCacheTTL, "1h")
	t.Setenv(envWriteRequireIdentity, "true")

	reqA := httptest.NewRequest(http.MethodPost, "/api/compare", strings.NewReader(`{}`))
	reqA.Header.Set(headerIdentityToken, mustRS256JWT(t, keyA, "key-a", map[string]any{
		"sub": "svc-acme-demo",
		"exp": time.Now().Add(10 * time.Minute).Unix(),
	}))
	recA := httptest.NewRecorder()
	if _, ok := requireWriteAuthorization(recA, reqA); !ok {
		t.Fatalf("expected first RS256 URL auth to pass, code=%d body=%s", recA.Code, recA.Body.String())
	}

	mu.Lock()
	current = []writeJWK{rsaPublicJWK("key-b", &keyB.PublicKey)}
	mu.Unlock()

	reqB := httptest.NewRequest(http.MethodPost, "/api/compare", strings.NewReader(`{}`))
	reqB.Header.Set(headerIdentityToken, mustRS256JWT(t, keyB, "key-b", map[string]any{
		"sub": "svc-acme-demo",
		"exp": time.Now().Add(10 * time.Minute).Unix(),
	}))
	recB := httptest.NewRecorder()
	if _, ok := requireWriteAuthorization(recB, reqB); !ok {
		t.Fatalf("expected rotated RS256 URL auth to pass after refresh, code=%d body=%s", recB.Code, recB.Body.String())
	}
	if fetchHits.Load() < 2 {
		t.Fatalf("expected at least 2 JWKS URL fetches (initial + refresh), got %d", fetchHits.Load())
	}
}

func TestRequireWriteAuthorizationIdentityOIDCDiscoveryRS256Success(t *testing.T) {
	resetWriteJWKSCache()
	t.Cleanup(resetWriteJWKSCache)
	setWriteIdentityEnvBaseline(t)
	enableInsecureJWKSForTests(t)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	mux := http.NewServeMux()
	var discoveryHits atomic.Int64
	var jwksHits atomic.Int64
	var issuerURL string
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		discoveryHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		payload, err := json.Marshal(map[string]any{
			"issuer":   issuerURL,
			"jwks_uri": issuerURL + "/keys",
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		jwksHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		payload, err := json.Marshal(writeJWKS{Keys: []writeJWK{rsaPublicJWK("key-a", &privateKey.PublicKey)}})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	issuerURL = server.URL

	t.Setenv(envWriteJWTSecret, "")
	t.Setenv(envWriteJWTJWKSPath, "")
	t.Setenv(envWriteJWTJWKSURL, "")
	t.Setenv(envWriteJWTOIDCIssuerURL, issuerURL)
	t.Setenv(envWriteJWTIssuer, "")
	t.Setenv(envWriteRequireIdentity, "true")

	token := mustRS256JWT(t, privateKey, "key-a", map[string]any{
		"sub": "svc-acme-demo",
		"iss": issuerURL,
		"exp": time.Now().Add(10 * time.Minute).Unix(),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/compare", strings.NewReader(`{}`))
	req.Header.Set(headerIdentityToken, token)
	rec := httptest.NewRecorder()
	identity, ok := requireWriteAuthorization(rec, req)
	if !ok {
		t.Fatalf("expected OIDC discovery RS256 auth to pass, code=%d body=%s", rec.Code, rec.Body.String())
	}
	if identity.Subject != "svc-acme-demo" {
		t.Fatalf("expected subject svc-acme-demo, got %q", identity.Subject)
	}
	if discoveryHits.Load() == 0 {
		t.Fatalf("expected OIDC discovery endpoint to be called")
	}
	if jwksHits.Load() == 0 {
		t.Fatalf("expected JWKS endpoint to be called")
	}
}

func TestRequireWriteAuthorizationIdentityOIDCDiscoveryRejectsIssuerMismatch(t *testing.T) {
	resetWriteJWKSCache()
	t.Cleanup(resetWriteJWKSCache)
	setWriteIdentityEnvBaseline(t)
	enableInsecureJWKSForTests(t)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	mux := http.NewServeMux()
	var issuerURL string
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		payload, err := json.Marshal(map[string]any{
			"issuer":   issuerURL,
			"jwks_uri": issuerURL + "/keys",
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		payload, err := json.Marshal(writeJWKS{Keys: []writeJWK{rsaPublicJWK("key-a", &privateKey.PublicKey)}})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	issuerURL = server.URL

	t.Setenv(envWriteJWTSecret, "")
	t.Setenv(envWriteJWTJWKSPath, "")
	t.Setenv(envWriteJWTJWKSURL, "")
	t.Setenv(envWriteJWTOIDCIssuerURL, issuerURL)
	t.Setenv(envWriteJWTIssuer, "")
	t.Setenv(envWriteRequireIdentity, "true")

	token := mustRS256JWT(t, privateKey, "key-a", map[string]any{
		"sub": "svc-acme-demo",
		"iss": "https://evil.example",
		"exp": time.Now().Add(10 * time.Minute).Unix(),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/compare", strings.NewReader(`{}`))
	req.Header.Set(headerIdentityToken, token)
	rec := httptest.NewRecorder()
	if _, ok := requireWriteAuthorization(rec, req); ok {
		t.Fatalf("expected OIDC issuer mismatch to fail")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for issuer mismatch, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRequireWriteAuthorizationIdentityOIDCDiscoveryRejectsDiscoveryIssuerMismatch(t *testing.T) {
	resetWriteJWKSCache()
	t.Cleanup(resetWriteJWKSCache)
	setWriteIdentityEnvBaseline(t)
	enableInsecureJWKSForTests(t)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	mux := http.NewServeMux()
	var issuerURL string
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		payload, err := json.Marshal(map[string]any{
			"issuer":   issuerURL + "/wrong",
			"jwks_uri": issuerURL + "/keys",
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		payload, err := json.Marshal(writeJWKS{Keys: []writeJWK{rsaPublicJWK("key-a", &privateKey.PublicKey)}})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	issuerURL = server.URL

	t.Setenv(envWriteJWTSecret, "")
	t.Setenv(envWriteJWTJWKSPath, "")
	t.Setenv(envWriteJWTJWKSURL, "")
	t.Setenv(envWriteJWTOIDCIssuerURL, issuerURL)
	t.Setenv(envWriteJWTIssuer, "")
	t.Setenv(envWriteRequireIdentity, "true")

	token := mustRS256JWT(t, privateKey, "key-a", map[string]any{
		"sub": "svc-acme-demo",
		"iss": issuerURL,
		"exp": time.Now().Add(10 * time.Minute).Unix(),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/compare", strings.NewReader(`{}`))
	req.Header.Set(headerIdentityToken, token)
	rec := httptest.NewRecorder()
	if _, ok := requireWriteAuthorization(rec, req); ok {
		t.Fatalf("expected OIDC discovery issuer mismatch to fail")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for discovery issuer mismatch, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRequireWriteAuthorizationIdentityOIDCIssuerFallbackFromIssuerClaimEnv(t *testing.T) {
	resetWriteJWKSCache()
	t.Cleanup(resetWriteJWKSCache)
	setWriteIdentityEnvBaseline(t)
	enableInsecureJWKSForTests(t)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	mux := http.NewServeMux()
	var issuerURL string
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		payload, err := json.Marshal(map[string]any{
			"issuer":   issuerURL,
			"jwks_uri": issuerURL + "/keys",
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		payload, err := json.Marshal(writeJWKS{Keys: []writeJWK{rsaPublicJWK("key-a", &privateKey.PublicKey)}})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	issuerURL = server.URL

	t.Setenv(envWriteJWTSecret, "")
	t.Setenv(envWriteJWTJWKSPath, "")
	t.Setenv(envWriteJWTJWKSURL, "")
	t.Setenv(envWriteJWTOIDCIssuerURL, "")
	t.Setenv(envWriteJWTIssuer, issuerURL)
	t.Setenv(envWriteRequireIdentity, "true")

	token := mustRS256JWT(t, privateKey, "key-a", map[string]any{
		"sub": "svc-acme-demo",
		"iss": issuerURL,
		"exp": time.Now().Add(10 * time.Minute).Unix(),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/compare", strings.NewReader(`{}`))
	req.Header.Set(headerIdentityToken, token)
	rec := httptest.NewRecorder()
	if _, ok := requireWriteAuthorization(rec, req); !ok {
		t.Fatalf("expected issuer-env fallback OIDC discovery auth to pass, code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestEnforceWriteIdentityTenantProject(t *testing.T) {
	identity := writeAuthIdentity{
		Subject:  "svc-acme-demo",
		AuthType: "jwt",
		Tenant:   "acme",
		Projects: []string{"demo"},
	}
	if err := enforceWriteIdentityTenantProject(identity, "acme", "demo"); err != nil {
		t.Fatalf("expected tenant/project scope to pass: %v", err)
	}
	if err := enforceWriteIdentityTenantProject(identity, "acme", "other"); err == nil {
		t.Fatalf("expected project mismatch to fail")
	}
	if err := enforceWriteIdentityTenantProject(identity, "otherco", "demo"); err == nil {
		t.Fatalf("expected tenant mismatch to fail")
	}
}

func setWriteIdentityEnvBaseline(t *testing.T) {
	t.Helper()
	t.Setenv(envWriteJWTSecret, "")
	t.Setenv(envWriteJWTJWKSPath, "")
	t.Setenv(envWriteJWTJWKSURL, "")
	t.Setenv(envWriteJWTOIDCIssuerURL, "")
	t.Setenv(envWriteJWTOIDCDiscoveryCacheTTL, "")
	t.Setenv(envWriteJWTJWKSCacheTTL, "")
	t.Setenv(envWriteJWTJWKSHTTPTimeout, "")
	t.Setenv(envWriteRequireIdentity, "false")
	t.Setenv(envAllowAnonymousRuntimeDelivery, "")
	t.Setenv(envWriteJWTIssuer, "")
	t.Setenv(envWriteJWTAudience, "")
	t.Setenv(envWriteJWTRequiredScopes, "")
	t.Setenv(envWriteJWTRequiredRoles, "")
	t.Setenv(envRuntimeExecJWTRequiredScopes, "")
	t.Setenv(envRuntimeExecJWTRequiredRoles, "")
	t.Setenv(envClientCAPath, "")
	t.Setenv(envMTLSIdentityMapPath, "")
	clearWriteActionClaimEnv(t, "compare")
	clearWriteActionClaimEnv(t, "runtime_select")
	clearWriteActionClaimEnv(t, "runtime_fetch")
	clearWriteActionClaimEnv(t, "runtime_execute")
	clearWriteActionClaimEnv(t, "validate")
}

func clearWriteActionClaimEnv(t *testing.T, action string) {
	t.Helper()
	t.Setenv(writeJWTRequiredScopesEnvForAction(action), "")
	t.Setenv(writeJWTRequiredRolesEnvForAction(action), "")
}

// enableInsecureJWKSForTests flips the writeJWKSAllowInsecureForTests hook so
// httptest.NewServer (http://) loopback URLs are accepted as JWKS/OIDC
// sources for the duration of the test. Production binaries cannot reach
// this — it is only callable from inside the api package's tests.
func enableInsecureJWKSForTests(t *testing.T) {
	t.Helper()
	prev := writeJWKSAllowInsecureForTests
	writeJWKSAllowInsecureForTests = true
	t.Cleanup(func() {
		writeJWKSAllowInsecureForTests = prev
	})
}

func mustRS256JWT(t *testing.T, privateKey *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{
		"alg": "RS256",
		"typ": "JWT",
		"kid": kid,
	}
	headerRaw, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal jwt header: %v", err)
	}
	claimsRaw, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal jwt claims: %v", err)
	}
	headerPart := base64.RawURLEncoding.EncodeToString(headerRaw)
	claimsPart := base64.RawURLEncoding.EncodeToString(claimsRaw)
	signingInput := headerPart + "." + claimsPart
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	signaturePart := base64.RawURLEncoding.EncodeToString(signature)
	return fmt.Sprintf("%s.%s", signingInput, signaturePart)
}

func rsaPublicJWK(kid string, pub *rsa.PublicKey) writeJWK {
	eBytes := bigIntFromInt(pub.E).Bytes()
	return writeJWK{
		Kty: "RSA",
		Kid: kid,
		Use: "sig",
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(eBytes),
	}
}

func bigIntFromInt(value int) *big.Int {
	return new(big.Int).SetInt64(int64(value))
}

func writeJWKSFile(t *testing.T, path string, keys []writeJWK) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create jwks dir: %v", err)
	}
	payload, err := json.MarshalIndent(writeJWKS{Keys: keys}, "", "  ")
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	payload = append(payload, '\n')
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		t.Fatalf("write jwks: %v", err)
	}
}
