package api

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// envClientCAPath, when set, turns on mutual TLS. The file must contain one
// or more PEM-encoded X.509 CA certificates; every accepted client cert
// chain must verify against this pool. We require RequireAndVerifyClientCert
// rather than VerifyClientCertIfGiven so a misconfigured client gets a hard
// TLS handshake error instead of silently downgrading to unauthenticated
// HTTPS — that downgrade was the load-bearing wrong default in several real
// outages we want to avoid by construction.
//
// Operators who want to allow some routes to bypass mTLS should run two
// listeners or terminate mTLS at an upstream proxy; the server itself does
// not support per-route mTLS exemptions.
const envClientCAPath = "BPFCOMPAT_API_CLIENT_CA_PATH"

// envMTLSIdentityMapPath, when set, enables mTLS as an API authentication
// mechanism. CA membership alone is only transport authentication; this map
// is the explicit authorization layer that turns a verified certificate into
// a scoped bpfcompat identity.
const envMTLSIdentityMapPath = "BPFCOMPAT_API_MTLS_IDENTITY_MAP_PATH"

const maxMTLSIdentityMapBytes = 1 << 20

// mtlsContextKey carries the verified client cert subject from middleware
// to handlers. Unexported to prevent context-value collisions.
type mtlsContextKey struct{}

// mtlsIdentity is the redacted view of the verified peer that handlers can
// safely log or use as the actor in audit records. We deliberately do NOT
// expose the raw certificate — handlers should reason about identity, not
// X.509 material.
type mtlsIdentity struct {
	Subject      string
	CommonName   string
	Organization []string
	SerialHex    string
}

type mtlsIdentityMap struct {
	SchemaVersion string              `json:"schema_version,omitempty"`
	Identities    []mtlsIdentityGrant `json:"identities"`
}

type mtlsIdentityGrant struct {
	CertificateSubject string   `json:"certificate_subject,omitempty"`
	CommonName         string   `json:"common_name,omitempty"`
	SerialHex          string   `json:"serial_hex,omitempty"`
	Organization       []string `json:"organization,omitempty"`

	Subject  string   `json:"subject"`
	Tenant   string   `json:"tenant"`
	Projects []string `json:"projects"`
	Scopes   []string `json:"scopes,omitempty"`
	Roles    []string `json:"roles,omitempty"`
}

// clientCAEnabled reports whether the operator opted into mTLS.
func clientCAEnabled() bool {
	return strings.TrimSpace(os.Getenv(envClientCAPath)) != ""
}

func mtlsIdentityMapConfigured() bool {
	return strings.TrimSpace(os.Getenv(envMTLSIdentityMapPath)) != ""
}

// loadClientCAPool reads the CA bundle from envClientCAPath. Returns an
// error rather than panicking so server startup fails loudly on a typo'd
// path — silently disabling mTLS would defeat the whole point.
func loadClientCAPool() (*x509.CertPool, error) {
	path := strings.TrimSpace(os.Getenv(envClientCAPath))
	if path == "" {
		return nil, fmt.Errorf("%s is not set", envClientCAPath)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read client CA bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("no PEM certificates found in %s", path)
	}
	return pool, nil
}

// tlsConfigForServer builds the tls.Config that the API server installs on
// http.Server.TLSConfig. When mTLS is on, the pool is attached and
// ClientAuth is set to RequireAndVerifyClientCert. When mTLS is off the
// returned config is still non-nil so we can pin the minimum TLS version
// (TLS 1.2) across the board.
func tlsConfigForServer() (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if !clientCAEnabled() {
		return cfg, nil
	}
	pool, err := loadClientCAPool()
	if err != nil {
		return nil, err
	}
	cfg.ClientCAs = pool
	cfg.ClientAuth = tls.RequireAndVerifyClientCert
	return cfg, nil
}

func loadMTLSIdentityMap(path string) (mtlsIdentityMap, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return mtlsIdentityMap{}, fmt.Errorf("%s is not set", envMTLSIdentityMapPath)
	}
	f, err := os.Open(path)
	if err != nil {
		return mtlsIdentityMap{}, fmt.Errorf("read mTLS identity map: %w", err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxMTLSIdentityMapBytes+1))
	if err != nil {
		return mtlsIdentityMap{}, fmt.Errorf("read mTLS identity map: %w", err)
	}
	if len(raw) > maxMTLSIdentityMapBytes {
		return mtlsIdentityMap{}, fmt.Errorf("mTLS identity map exceeds %d bytes", maxMTLSIdentityMapBytes)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var out mtlsIdentityMap
	if err := dec.Decode(&out); err != nil {
		return mtlsIdentityMap{}, fmt.Errorf("parse mTLS identity map: %w", err)
	}
	var extra struct{}
	if err := dec.Decode(&extra); err != io.EOF {
		return mtlsIdentityMap{}, fmt.Errorf("parse mTLS identity map: expected exactly one JSON document")
	}
	if len(out.Identities) == 0 {
		return mtlsIdentityMap{}, fmt.Errorf("mTLS identity map has no identities")
	}
	for i, grant := range out.Identities {
		if err := validateMTLSIdentityGrant(grant); err != nil {
			return mtlsIdentityMap{}, fmt.Errorf("invalid mTLS identity grant %d: %w", i, err)
		}
	}
	return out, nil
}

func mtlsWriteIdentityFromRequest(r *http.Request) (writeAuthIdentity, bool, int, error) {
	peer, ok := mtlsIdentityFromRequest(r)
	if !ok {
		return writeAuthIdentity{}, false, 0, nil
	}
	path := strings.TrimSpace(os.Getenv(envMTLSIdentityMapPath))
	if path == "" {
		return writeAuthIdentity{}, false, 0, nil
	}
	identityMap, err := loadMTLSIdentityMap(path)
	if err != nil {
		return writeAuthIdentity{}, true, http.StatusServiceUnavailable, err
	}
	for _, grant := range identityMap.Identities {
		if !mtlsGrantMatches(peer, grant) {
			continue
		}
		return writeAuthIdentity{
			Subject:  strings.TrimSpace(grant.Subject),
			AuthType: "mtls",
			Tenant:   strings.TrimSpace(grant.Tenant),
			Projects: cleanStringList(grant.Projects),
			Scopes:   cleanStringList(grant.Scopes),
			Roles:    cleanStringList(grant.Roles),
		}, true, 0, nil
	}
	return writeAuthIdentity{}, true, http.StatusForbidden, fmt.Errorf("mTLS client certificate is not mapped to an API identity")
}

func validateMTLSIdentityGrant(grant mtlsIdentityGrant) error {
	hasSelector := strings.TrimSpace(grant.CertificateSubject) != "" ||
		strings.TrimSpace(grant.CommonName) != "" ||
		strings.TrimSpace(grant.SerialHex) != "" ||
		len(cleanStringList(grant.Organization)) > 0
	if !hasSelector {
		return fmt.Errorf("at least one certificate selector is required")
	}
	if strings.TrimSpace(grant.Subject) == "" {
		return fmt.Errorf("subject is required")
	}
	if strings.TrimSpace(grant.Tenant) == "" {
		return fmt.Errorf("tenant is required")
	}
	if len(cleanStringList(grant.Projects)) == 0 {
		return fmt.Errorf("projects is required")
	}
	return nil
}

func mtlsGrantMatches(peer mtlsIdentity, grant mtlsIdentityGrant) bool {
	if expected := strings.TrimSpace(grant.CertificateSubject); expected != "" && peer.Subject != expected {
		return false
	}
	if expected := strings.TrimSpace(grant.CommonName); expected != "" && peer.CommonName != expected {
		return false
	}
	if expected := strings.TrimSpace(grant.SerialHex); expected != "" && !strings.EqualFold(peer.SerialHex, expected) {
		return false
	}
	for _, expectedOrg := range cleanStringList(grant.Organization) {
		found := false
		for _, actualOrg := range peer.Organization {
			if actualOrg == expectedOrg {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func cleanStringList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		out = append(out, value)
	}
	return dedupeSortedStrings(out)
}

// mtlsIdentityFromRequest extracts the verified peer identity from the TLS
// handshake. Returns (zero-value, false) when:
//   - the request was not TLS,
//   - mTLS is not configured, or
//   - the chain didn't verify (which shouldn't reach a handler — the
//     listener should have refused the handshake — but we double-check
//     defensively in case a future reverse proxy is interposed).
func mtlsIdentityFromRequest(r *http.Request) (mtlsIdentity, bool) {
	if r == nil || r.TLS == nil {
		return mtlsIdentity{}, false
	}
	if len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		return mtlsIdentity{}, false
	}
	cert := r.TLS.PeerCertificates[0]
	return mtlsIdentity{
		Subject:      cert.Subject.String(),
		CommonName:   cert.Subject.CommonName,
		Organization: append([]string(nil), cert.Subject.Organization...),
		SerialHex:    cert.SerialNumber.Text(16),
	}, true
}
