package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestMTLSConfigDisabledByDefault asserts the env-flag drives mTLS on/off.
// This is the load-bearing default: a misconfigured deployment must not
// silently enable mTLS (which would lock every legitimate client out) and
// must not silently disable it (which would fail the original security
// requirement). The flag is the single source of truth.
func TestMTLSConfigDisabledByDefault(t *testing.T) {
	t.Setenv(envClientCAPath, "")
	cfg, err := tlsConfigForServer()
	if err != nil {
		t.Fatalf("build tls config without mTLS: %v", err)
	}
	if cfg.ClientAuth != tls.NoClientCert {
		t.Fatalf("expected NoClientCert when env unset, got %v", cfg.ClientAuth)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("expected TLS 1.2 minimum, got %d", cfg.MinVersion)
	}
}

// TestMTLSConfigEnabledLoadsCAPool covers the on path: when the env points
// at a real PEM bundle the config must require + verify client certs and
// expose the parsed pool. A failure here would cause the server to start
// without mTLS even though the operator asked for it — the exact silent
// downgrade we built the env-validation around.
func TestMTLSConfigEnabledLoadsCAPool(t *testing.T) {
	caPath := writeTestCAToFile(t)
	t.Setenv(envClientCAPath, caPath)

	cfg, err := tlsConfigForServer()
	if err != nil {
		t.Fatalf("build tls config: %v", err)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("expected RequireAndVerifyClientCert, got %v", cfg.ClientAuth)
	}
	if cfg.ClientCAs == nil {
		t.Fatalf("expected client CA pool to be populated")
	}
}

// TestMTLSConfigErrorsOnUnreadablePath covers the loud-failure path: the
// server must refuse to come up if the bundle file is missing rather than
// degrade to plain TLS. Silent fallback would defeat the entire control.
func TestMTLSConfigErrorsOnUnreadablePath(t *testing.T) {
	t.Setenv(envClientCAPath, filepath.Join(t.TempDir(), "does-not-exist.pem"))
	if _, err := tlsConfigForServer(); err == nil {
		t.Fatalf("expected error for missing CA bundle")
	}
}

// TestMTLSConfigErrorsOnEmptyBundle protects against the "operator wrote
// 0 bytes" misconfig. PEM bundles without parseable certs return false
// from AppendCertsFromPEM; we need to surface that as a startup error.
func TestMTLSConfigErrorsOnEmptyBundle(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(empty, []byte("# nothing here\n"), 0o600); err != nil {
		t.Fatalf("write empty bundle: %v", err)
	}
	t.Setenv(envClientCAPath, empty)
	if _, err := tlsConfigForServer(); err == nil {
		t.Fatalf("expected error for empty PEM bundle")
	}
}

// TestMTLSIdentityFromRequestNoTLSReturnsFalse covers the defensive branch
// where a handler runs under plain HTTP (e.g., probe behind a TLS-terminating
// LB). We must NOT synthesize an mtls identity from nothing — that would
// allow a forged proxy header path to grant write access.
func TestMTLSIdentityFromRequestNoTLSReturnsFalse(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	if _, ok := mtlsIdentityFromRequest(req); ok {
		t.Fatalf("expected no mTLS identity on plain HTTP request")
	}
}

func TestRequireWriteAuthorizationDoesNotTrustMTLSCAAlone(t *testing.T) {
	setWriteIdentityEnvBaseline(t)
	t.Setenv(envWriteAPIKey, "")
	req := requestWithVerifiedClientCert("svc-mtls", "42", []string{"Platform"})
	rec := httptest.NewRecorder()

	if _, ok := requireWriteAuthorization(rec, req); ok {
		t.Fatalf("expected unmapped mTLS client cert to fail")
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 without write auth configuration, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRequireWriteAuthorizationMTLSIdentityMap(t *testing.T) {
	setWriteIdentityEnvBaseline(t)
	t.Setenv(envWriteAPIKey, "")
	t.Setenv(envMTLSIdentityMapPath, writeMTLSIdentityMap(t, mtlsIdentityMap{
		SchemaVersion: "mtls_identity_map.v0.1",
		Identities: []mtlsIdentityGrant{
			{
				CommonName:   "svc-mtls",
				Organization: []string{"Platform"},
				Subject:      "svc-acme-demo",
				Tenant:       "acme",
				Projects:     []string{"demo"},
				Scopes:       []string{"api.write", "runtime.select"},
				Roles:        []string{"selector"},
			},
		},
	}))
	t.Setenv(envWriteRequireIdentity, "true")
	t.Setenv(envWriteJWTRequiredScopes, "api.write")
	t.Setenv(writeJWTRequiredScopesEnvForAction("runtime_select"), "runtime.select")
	t.Setenv(writeJWTRequiredRolesEnvForAction("runtime_select"), "selector")

	req := requestWithVerifiedClientCert("svc-mtls", "42", []string{"Platform"})
	rec := httptest.NewRecorder()
	identity, ok := requireWriteAuthorizationForAction(rec, req, "runtime_select")
	if !ok {
		t.Fatalf("expected mapped mTLS identity to pass, got %d body=%s", rec.Code, rec.Body.String())
	}
	if identity.AuthType != "mtls" || identity.Subject != "svc-acme-demo" || identity.Tenant != "acme" {
		t.Fatalf("unexpected identity: %+v", identity)
	}
	if len(identity.Projects) != 1 || identity.Projects[0] != "demo" {
		t.Fatalf("unexpected projects: %+v", identity.Projects)
	}
}

func TestRequireWriteAuthorizationMTLSIdentityMapDeniesUnmappedCert(t *testing.T) {
	setWriteIdentityEnvBaseline(t)
	t.Setenv(envWriteAPIKey, "")
	t.Setenv(envMTLSIdentityMapPath, writeMTLSIdentityMap(t, mtlsIdentityMap{
		SchemaVersion: "mtls_identity_map.v0.1",
		Identities: []mtlsIdentityGrant{
			{
				CommonName: "svc-allowed",
				Subject:    "svc-allowed",
				Tenant:     "acme",
				Projects:   []string{"demo"},
			},
		},
	}))

	req := requestWithVerifiedClientCert("svc-denied", "42", nil)
	rec := httptest.NewRecorder()
	if _, ok := requireWriteAuthorization(rec, req); ok {
		t.Fatalf("expected unmapped mTLS cert to fail")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for unmapped cert, got %d body=%s", rec.Code, rec.Body.String())
	}
}

// writeTestCAToFile generates a self-signed CA cert and writes it to disk
// so the mTLS config can load it. We only need the pool to populate — no
// client handshake — so the cert itself doesn't have to be issuance-valid
// in the usual sense, just well-formed PEM.
func writeTestCAToFile(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "bpfcompat-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write ca file: %v", err)
	}
	return path
}

func requestWithVerifiedClientCert(commonName, serialHex string, orgs []string) *http.Request {
	serial := new(big.Int)
	if _, ok := serial.SetString(serialHex, 16); !ok {
		serial = big.NewInt(1)
	}
	cert := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: orgs,
		},
	}
	req := httptest.NewRequest(http.MethodPost, "/api/compare", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
		VerifiedChains:   [][]*x509.Certificate{{cert}},
	}
	return req
}

func writeMTLSIdentityMap(t *testing.T, identityMap mtlsIdentityMap) string {
	t.Helper()
	body, err := json.MarshalIndent(identityMap, "", "  ")
	if err != nil {
		t.Fatalf("marshal identity map: %v", err)
	}
	path := filepath.Join(t.TempDir(), "mtls-identities.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write identity map: %v", err)
	}
	return path
}
