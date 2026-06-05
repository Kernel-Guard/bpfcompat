package api

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

type writeAuthIdentity struct {
	Subject  string
	AuthType string
	Tenant   string
	Projects []string
	Scopes   []string
	Roles    []string
}

type writeJWTVerificationConfig struct {
	HS256Secret       string
	JWKSPath          string
	JWKSURL           string
	OIDCIssuerURL     string
	JWKSCacheTTL      time.Duration
	JWKSHTTPTimeout   time.Duration
	OIDCCacheTTL      time.Duration
	NowFn             func() time.Time
	HTTPClientFactory func(timeout time.Duration) *http.Client
}

type writeJWKS struct {
	Keys []writeJWK `json:"keys"`
}

type writeJWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

type writeOIDCDiscoveryDocument struct {
	Issuer  string `json:"issuer,omitempty"`
	JWKSURI string `json:"jwks_uri"`
}

type writeJWKSCacheEntry struct {
	JWKS      writeJWKS
	ExpiresAt time.Time
}

type writeOIDCDiscoveryCacheEntry struct {
	JWKSURL   string
	ExpiresAt time.Time
}

type writeJWKSSource struct {
	Kind  string
	Value string
}

var writeJWKSCacheState = struct {
	mu      sync.Mutex
	entries map[string]writeJWKSCacheEntry
}{
	entries: map[string]writeJWKSCacheEntry{},
}

var writeOIDCDiscoveryCacheState = struct {
	mu      sync.Mutex
	entries map[string]writeOIDCDiscoveryCacheEntry
}{
	entries: map[string]writeOIDCDiscoveryCacheEntry{},
}

func (s writeJWKSSource) cacheKey() string {
	return strings.ToLower(strings.TrimSpace(s.Kind)) + ":" + strings.TrimSpace(s.Value)
}

func (s writeJWKSSource) label() string {
	switch strings.ToLower(strings.TrimSpace(s.Kind)) {
	case "url":
		return "JWKS URL " + strconv.Quote(strings.TrimSpace(s.Value))
	case "path":
		return "JWKS path " + strconv.Quote(strings.TrimSpace(s.Value))
	case "oidc":
		return "OIDC issuer " + strconv.Quote(strings.TrimSpace(s.Value))
	default:
		return "JWKS source " + strconv.Quote(strings.TrimSpace(s.Value))
	}
}

func requireWriteAuthorization(w http.ResponseWriter, r *http.Request) (writeAuthIdentity, bool) {
	requireIdentity := parseBoolEnv(envWriteRequireIdentity, false)
	identityToken := strings.TrimSpace(r.Header.Get(headerIdentityToken))
	jwtCfg := writeJWTVerificationConfigFromEnv()
	_, hasVerifiedMTLSPeer := mtlsIdentityFromRequest(r)
	mtlsIdentityConfigured := mtlsIdentityMapConfigured()

	if requireIdentity {
		if !writeIdentityVerifierConfigured(jwtCfg) && !(hasVerifiedMTLSPeer && mtlsIdentityConfigured) {
			writeError(
				w,
				http.StatusServiceUnavailable,
				fmt.Sprintf(
					"write identity auth is required; set %s, %s, %s, %s, or %s",
					envWriteJWTSecret,
					envWriteJWTJWKSPath,
					envWriteJWTJWKSURL,
					envWriteJWTOIDCIssuerURL,
					envMTLSIdentityMapPath,
				),
			)
			return writeAuthIdentity{}, false
		}
		if identityToken == "" && !(hasVerifiedMTLSPeer && mtlsIdentityConfigured) {
			writeError(w, http.StatusUnauthorized, fmt.Sprintf("missing write identity; set %s header or present an authorized mTLS client certificate", headerIdentityToken))
			return writeAuthIdentity{}, false
		}
	}

	if identityToken != "" {
		if !writeIdentityVerifierConfigured(jwtCfg) {
			writeError(
				w,
				http.StatusServiceUnavailable,
				fmt.Sprintf(
					"write identity token provided but none of %s, %s, %s, or %s is configured",
					envWriteJWTSecret,
					envWriteJWTJWKSPath,
					envWriteJWTJWKSURL,
					envWriteJWTOIDCIssuerURL,
				),
			)
			return writeAuthIdentity{}, false
		}
		identity, err := parseWriteIdentityJWTContext(r.Context(), identityToken, jwtCfg, jwtCfg.now())
		if err != nil {
			writeError(w, http.StatusUnauthorized, fmt.Sprintf("invalid write identity token: %v", err))
			return writeAuthIdentity{}, false
		}
		if err := enforceWriteIdentityRequiredClaims(identity); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return writeAuthIdentity{}, false
		}
		return identity, true
	}

	expected := strings.TrimSpace(os.Getenv(envWriteAPIKey))
	provided := writeCredentialFromRequest(r)
	if provided != "" {
		if expected == "" {
			writeError(w, http.StatusServiceUnavailable, fmt.Sprintf("write API key auth is not configured; set %s", envWriteAPIKey))
			return writeAuthIdentity{}, false
		}
		if subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) != 1 {
			writeError(w, http.StatusUnauthorized, "invalid API key")
			return writeAuthIdentity{}, false
		}
		return writeAuthIdentity{
			Subject:  tokenSubject(provided),
			AuthType: "api_key",
		}, true
	}

	// mTLS path: CA verification is necessary but not sufficient. A client
	// certificate becomes an API identity only when it matches an explicit
	// identity-map grant with tenant/project scope.
	if identity, handled, status, err := mtlsWriteIdentityFromRequest(r); handled {
		if err != nil {
			writeError(w, status, err.Error())
			return writeAuthIdentity{}, false
		}
		if err := enforceWriteIdentityRequiredClaims(identity); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return writeAuthIdentity{}, false
		}
		return identity, true
	}

	if expected == "" {
		writeError(w, http.StatusServiceUnavailable, fmt.Sprintf("write API is not configured; set %s, %s, or a JWT verifier", envWriteAPIKey, envMTLSIdentityMapPath))
		return writeAuthIdentity{}, false
	}
	writeError(w, http.StatusUnauthorized, "missing API key")
	return writeAuthIdentity{}, false
}

func requireWriteAuthorizationForAction(w http.ResponseWriter, r *http.Request, action string) (writeAuthIdentity, bool) {
	if allowAnonymousWriteEnabled() {
		return writeAuthIdentity{
			Subject:  "anonymous",
			AuthType: "anonymous",
		}, true
	}
	if normalizeWriteActionName(action) == "validate" && allowAnonymousValidateEnabled() {
		return writeAuthIdentity{
			Subject:  "anonymous",
			AuthType: "anonymous",
		}, true
	}
	if actionAllowsAnonymousRuntimeDelivery(action) {
		return writeAuthIdentity{
			Subject:  "anonymous",
			AuthType: "anonymous",
		}, true
	}
	identity, ok := requireWriteAuthorization(w, r)
	if !ok {
		return writeAuthIdentity{}, false
	}
	if err := enforceWriteIdentityActionClaims(identity, action); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return writeAuthIdentity{}, false
	}
	return identity, true
}

// requireAuthenticatedAuthorizationForAction is for sensitive operator-only
// read surfaces that must never be opened by the public demo switches. It
// accepts the same API-key/JWT credentials as write endpoints, but ignores
// BPFCOMPAT_API_ALLOW_ANONYMOUS_READ/WRITE/VALIDATE.
func requireAuthenticatedAuthorizationForAction(w http.ResponseWriter, r *http.Request, action string) (writeAuthIdentity, bool) {
	identity, ok := requireWriteAuthorization(w, r)
	if !ok {
		return writeAuthIdentity{}, false
	}
	if err := enforceWriteIdentityActionClaims(identity, action); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return writeAuthIdentity{}, false
	}
	return identity, true
}

func allowAnonymousValidateEnabled() bool {
	return parseBoolEnv(envAllowAnonymousValidate, false)
}

func allowAnonymousWriteEnabled() bool {
	return parseBoolEnv(envAllowAnonymousWrite, false)
}

func allowAnonymousRuntimeDeliveryEnabled() bool {
	return parseBoolEnv(envAllowAnonymousRuntimeDelivery, false) || allowAnonymousWriteEnabled()
}

func actionAllowsAnonymousRuntimeDelivery(action string) bool {
	if !allowAnonymousRuntimeDeliveryEnabled() {
		return false
	}
	switch normalizeWriteActionName(action) {
	case "runtime_select", "runtime_fetch":
		return true
	default:
		return false
	}
}

func allowAnonymousReadEnabled() bool {
	// Read endpoints inherit anonymous access from the broader anonymous-write
	// switch, but can also be opened independently. Either env=true keeps the
	// old "anyone can scrape" posture without forcing operators to also open
	// write traffic.
	return parseBoolEnv(envAllowAnonymousRead, false) || allowAnonymousWriteEnabled()
}

// requireReadAuthorizationForAction gates read-only endpoints (validate job
// status, history listings, runtime probe/decisions). Anonymous access is
// permitted only when explicitly enabled via env; otherwise we accept any
// valid write credential (API key or JWT) without requiring write
// capabilities. This closes the unauthenticated-enumeration window where a
// reachable :8080 leaked validation results, run reports, and host probe
// data to anyone who could guess (or enumerate) IDs.
func requireReadAuthorizationForAction(w http.ResponseWriter, r *http.Request, action string) (writeAuthIdentity, bool) {
	if allowAnonymousReadEnabled() {
		return writeAuthIdentity{
			Subject:  "anonymous",
			AuthType: "anonymous",
		}, true
	}
	// If a caller is allowed to start a validate job anonymously, they must
	// also be able to read that job's status — otherwise the async API is
	// useless. Restricting the relaxation to "validate_status" specifically
	// keeps the rest of the read surface (history/decisions/probe) locked
	// down even when anonymous validate is enabled.
	if normalizeWriteActionName(action) == "validate_status" && allowAnonymousValidateEnabled() {
		return writeAuthIdentity{
			Subject:  "anonymous",
			AuthType: "anonymous",
		}, true
	}
	identity, ok := requireWriteAuthorization(w, r)
	if !ok {
		return writeAuthIdentity{}, false
	}
	return identity, true
}

func requireRegistryIdentityForAction(w http.ResponseWriter, r *http.Request, action, tenant, project string) (*writeAuthIdentity, bool) {
	identityToken := strings.TrimSpace(r.Header.Get(headerIdentityToken))
	requireIdentity := parseBoolEnv(envRegistryRequireIdentity, false) || writeIdentityClaimsConfiguredForAction(action)
	if !requireIdentity && identityToken == "" {
		return nil, true
	}

	jwtCfg := writeJWTVerificationConfigFromEnv()
	if !writeIdentityVerifierConfigured(jwtCfg) {
		writeError(
			w,
			http.StatusServiceUnavailable,
			fmt.Sprintf(
				"registry identity auth is required; set %s, %s, %s, or %s",
				envWriteJWTSecret,
				envWriteJWTJWKSPath,
				envWriteJWTJWKSURL,
				envWriteJWTOIDCIssuerURL,
			),
		)
		return nil, false
	}
	if identityToken == "" {
		writeError(w, http.StatusUnauthorized, fmt.Sprintf("missing write identity token; set %s header", headerIdentityToken))
		return nil, false
	}
	identity, err := parseWriteIdentityJWTContext(r.Context(), identityToken, jwtCfg, jwtCfg.now())
	if err != nil {
		writeError(w, http.StatusUnauthorized, fmt.Sprintf("invalid write identity token: %v", err))
		return nil, false
	}
	if err := enforceWriteIdentityRequiredClaims(identity); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return nil, false
	}
	if err := enforceWriteIdentityActionClaims(identity, action); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return nil, false
	}
	if strings.TrimSpace(project) != "" {
		if err := enforceWriteIdentityTenantProject(identity, tenant, project); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return nil, false
		}
	} else if strings.TrimSpace(tenant) != "" {
		if err := enforceWriteIdentityTenant(identity, tenant); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return nil, false
		}
	}
	return &identity, true
}

func writeJWTVerificationConfigFromEnv() writeJWTVerificationConfig {
	cacheTTL := parseDurationEnv(envWriteJWTJWKSCacheTTL, 5*time.Minute)
	httpTimeout := parseDurationEnv(envWriteJWTJWKSHTTPTimeout, 5*time.Second)
	oidcCacheTTL := parseDurationEnv(envWriteJWTOIDCDiscoveryCacheTTL, 10*time.Minute)
	oidcIssuerURL := strings.TrimSpace(os.Getenv(envWriteJWTOIDCIssuerURL))
	if oidcIssuerURL == "" {
		issuer := strings.TrimSpace(os.Getenv(envWriteJWTIssuer))
		if isHTTPURL(issuer) {
			oidcIssuerURL = issuer
		}
	}
	return writeJWTVerificationConfig{
		HS256Secret:     strings.TrimSpace(os.Getenv(envWriteJWTSecret)),
		JWKSPath:        strings.TrimSpace(os.Getenv(envWriteJWTJWKSPath)),
		JWKSURL:         strings.TrimSpace(os.Getenv(envWriteJWTJWKSURL)),
		OIDCIssuerURL:   oidcIssuerURL,
		JWKSCacheTTL:    cacheTTL,
		JWKSHTTPTimeout: httpTimeout,
		OIDCCacheTTL:    oidcCacheTTL,
		NowFn:           time.Now,
		HTTPClientFactory: func(timeout time.Duration) *http.Client {
			return &http.Client{Timeout: timeout}
		},
	}
}

func parseWriteIdentityJWT(rawToken string, cfg writeJWTVerificationConfig, now time.Time) (writeAuthIdentity, error) {
	return parseWriteIdentityJWTContext(context.Background(), rawToken, cfg, now)
}

func parseWriteIdentityJWTContext(ctx context.Context, rawToken string, cfg writeJWTVerificationConfig, now time.Time) (writeAuthIdentity, error) {
	parts := strings.Split(strings.TrimSpace(rawToken), ".")
	if len(parts) != 3 {
		return writeAuthIdentity{}, fmt.Errorf("token must have 3 segments")
	}

	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return writeAuthIdentity{}, fmt.Errorf("decode header: %w", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		return writeAuthIdentity{}, fmt.Errorf("parse header JSON: %w", err)
	}
	alg := strings.TrimSpace(strings.ToUpper(anyToString(header["alg"])))
	switch alg {
	case "HS256":
		if cfg.HS256Secret == "" {
			return writeAuthIdentity{}, fmt.Errorf("HS256 secret is not configured")
		}
		if err := verifyJWTSignatureHS256(parts, cfg.HS256Secret); err != nil {
			return writeAuthIdentity{}, err
		}
	case "RS256":
		if cfg.JWKSPath == "" && cfg.JWKSURL == "" && cfg.OIDCIssuerURL == "" {
			return writeAuthIdentity{}, fmt.Errorf("RS256 verification key set is not configured")
		}
		if err := verifyJWTSignatureRS256(ctx, parts, header, cfg); err != nil {
			return writeAuthIdentity{}, err
		}
	default:
		return writeAuthIdentity{}, fmt.Errorf("unsupported alg %q", anyToString(header["alg"]))
	}

	claimsRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return writeAuthIdentity{}, fmt.Errorf("decode claims: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(claimsRaw, &claims); err != nil {
		return writeAuthIdentity{}, fmt.Errorf("parse claims JSON: %w", err)
	}

	subject := strings.TrimSpace(anyToString(claims["sub"]))
	if subject == "" {
		return writeAuthIdentity{}, fmt.Errorf("sub claim is required")
	}

	expUnix, ok, err := readNumericClaim(claims, "exp")
	if err != nil {
		return writeAuthIdentity{}, err
	}
	if !ok {
		return writeAuthIdentity{}, fmt.Errorf("exp claim is required")
	}
	nowUnix := now.Unix()
	if nowUnix >= expUnix {
		return writeAuthIdentity{}, fmt.Errorf("token expired")
	}

	nbfUnix, hasNBF, err := readNumericClaim(claims, "nbf")
	if err != nil {
		return writeAuthIdentity{}, err
	}
	if hasNBF && nowUnix < nbfUnix {
		return writeAuthIdentity{}, fmt.Errorf("token not active yet")
	}

	issuer := normalizeIssuerURL(os.Getenv(envWriteJWTIssuer))
	if issuer == "" && strings.TrimSpace(cfg.OIDCIssuerURL) != "" {
		issuer = normalizeIssuerURL(cfg.OIDCIssuerURL)
	}
	if issuer != "" {
		tokenIssuer := normalizeIssuerURL(anyToString(claims["iss"]))
		if tokenIssuer != issuer {
			return writeAuthIdentity{}, fmt.Errorf("issuer mismatch")
		}
	}
	audience := strings.TrimSpace(os.Getenv(envWriteJWTAudience))
	if audience != "" {
		if !jwtAudienceMatches(claims["aud"], audience) {
			return writeAuthIdentity{}, fmt.Errorf("audience mismatch")
		}
	}

	if canWrite, hasCanWrite := claims["can_write"]; hasCanWrite {
		value, ok := canWrite.(bool)
		if !ok {
			return writeAuthIdentity{}, fmt.Errorf("can_write claim must be boolean")
		}
		if !value {
			return writeAuthIdentity{}, fmt.Errorf("token is not authorized for write actions")
		}
	}

	return writeAuthIdentity{
		Subject:  subject,
		AuthType: "jwt",
		Tenant:   strings.TrimSpace(anyToString(claims["tenant"])),
		Projects: normalizeJWTProjectsClaim(claims["projects"]),
		Scopes:   normalizeJWTScopesClaim(claims),
		Roles:    normalizeJWTRolesClaim(claims),
	}, nil
}

func writeIdentityVerifierConfigured(cfg writeJWTVerificationConfig) bool {
	return strings.TrimSpace(cfg.HS256Secret) != "" ||
		strings.TrimSpace(cfg.JWKSPath) != "" ||
		strings.TrimSpace(cfg.JWKSURL) != "" ||
		strings.TrimSpace(cfg.OIDCIssuerURL) != ""
}

func verifyJWTSignatureHS256(parts []string, hs256Secret string) error {
	sigRaw, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	mac := hmac.New(sha256.New, []byte(hs256Secret))
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	expectedSig := mac.Sum(nil)
	if subtle.ConstantTimeCompare(sigRaw, expectedSig) != 1 {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

func verifyJWTSignatureRS256(ctx context.Context, parts []string, header map[string]any, cfg writeJWTVerificationConfig) error {
	sources := jwksSourcesFromConfig(cfg)
	if len(sources) == 0 {
		return fmt.Errorf("RS256 verification key set is not configured")
	}
	kid := strings.TrimSpace(anyToString(header["kid"]))
	errorsBySource := make([]string, 0, len(sources))
	for _, source := range sources {
		jwks, err := loadWriteJWKSFromSource(ctx, cfg, source, false)
		if err != nil {
			errorsBySource = append(errorsBySource, fmt.Sprintf("%s: %v", source.label(), err))
			continue
		}
		verifyErr := verifyJWTSignatureRS256WithJWKS(parts, kid, jwks)
		if verifyErr == nil {
			return nil
		}
		// Retry once with forced refresh to support key rotation without
		// restart. Bounded by writeJWKSForceRefreshAllowed so a token-storm
		// against an unknown kid can't hammer the upstream JWKS endpoint —
		// we let one refresh through per source per refreshCooldown window.
		if writeJWKSForceRefreshAllowed(cfg, source) {
			jwksRefreshed, refreshErr := loadWriteJWKSFromSource(ctx, cfg, source, true)
			if refreshErr == nil {
				verifyErr = verifyJWTSignatureRS256WithJWKS(parts, kid, jwksRefreshed)
				if verifyErr == nil {
					return nil
				}
			}
		}
		errorsBySource = append(errorsBySource, fmt.Sprintf("%s: %v", source.label(), verifyErr))
	}
	return fmt.Errorf("RS256 verification failed: %s", strings.Join(errorsBySource, "; "))
}

// writeJWKSForceRefreshCooldown caps how often we'll forcibly refresh a
// JWKS source on signature-failure retries. Without this, every bad token
// (a brute-force or simply a stale client) triggered an upstream HTTP fetch
// — perfect for amplifying a DoS into the identity provider. 30s gives key
// rotations propagation room without enabling the amplifier.
const writeJWKSForceRefreshCooldown = 30 * time.Second

// jwksForceRefreshState tracks the last time each source was force-refreshed.
// We key by source.cacheKey() so URL and OIDC entries don't share state.
var jwksForceRefreshState = struct {
	mu   sync.Mutex
	last map[string]time.Time
}{last: map[string]time.Time{}}

func writeJWKSForceRefreshAllowed(cfg writeJWTVerificationConfig, source writeJWKSSource) bool {
	jwksForceRefreshState.mu.Lock()
	defer jwksForceRefreshState.mu.Unlock()
	key := source.cacheKey()
	now := cfg.now()
	if last, ok := jwksForceRefreshState.last[key]; ok {
		if now.Sub(last) < writeJWKSForceRefreshCooldown {
			return false
		}
	}
	jwksForceRefreshState.last[key] = now
	return true
}

func verifyJWTSignatureRS256WithJWKS(parts []string, kid string, jwks writeJWKS) error {
	key, err := selectWriteJWKRS256(jwks, kid)
	if err != nil {
		return err
	}
	pub, err := rsaPublicKeyFromJWK(key)
	if err != nil {
		return err
	}
	sigRaw, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sigRaw); err != nil {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

func loadWriteJWKSFromSource(ctx context.Context, cfg writeJWTVerificationConfig, source writeJWKSSource, forceRefresh bool) (writeJWKS, error) {
	now := cfg.now()
	cacheTTL := cfg.cacheTTL()
	key := source.cacheKey()
	if !forceRefresh {
		writeJWKSCacheState.mu.Lock()
		entry, ok := writeJWKSCacheState.entries[key]
		writeJWKSCacheState.mu.Unlock()
		if ok && now.Before(entry.ExpiresAt) {
			return entry.JWKS, nil
		}
	}
	doc, err := fetchWriteJWKS(ctx, cfg, source, forceRefresh)
	if err != nil {
		return writeJWKS{}, err
	}
	writeJWKSCacheState.mu.Lock()
	writeJWKSCacheState.entries[key] = writeJWKSCacheEntry{
		JWKS:      doc,
		ExpiresAt: now.Add(cacheTTL),
	}
	writeJWKSCacheState.mu.Unlock()
	return doc, nil
}

func fetchWriteJWKS(ctx context.Context, cfg writeJWTVerificationConfig, source writeJWKSSource, forceRefresh bool) (writeJWKS, error) {
	switch strings.ToLower(strings.TrimSpace(source.Kind)) {
	case "path":
		return loadWriteJWKSFromPath(source.Value)
	case "url":
		return loadWriteJWKSFromURL(ctx, cfg, source.Value)
	case "oidc":
		issuer := strings.TrimSpace(source.Value)
		jwksURL, err := resolveWriteOIDCJWKSURL(ctx, cfg, issuer, forceRefresh)
		if err != nil {
			return writeJWKS{}, err
		}
		return loadWriteJWKSFromURL(ctx, cfg, jwksURL)
	default:
		return writeJWKS{}, fmt.Errorf("unsupported JWKS source kind %q", source.Kind)
	}
}

func loadWriteJWKSFromPath(path string) (writeJWKS, error) {
	cleanPath := filepath.Clean(strings.TrimSpace(path))
	raw, err := os.ReadFile(cleanPath)
	if err != nil {
		return writeJWKS{}, fmt.Errorf("read JWKS %q: %w", cleanPath, err)
	}
	return parseWriteJWKSRaw(raw, cleanPath)
}

func loadWriteJWKSFromURL(ctx context.Context, cfg writeJWTVerificationConfig, rawURL string) (writeJWKS, error) {
	target := strings.TrimSpace(rawURL)
	if !jwksTransportAllowed(target) {
		return writeJWKS{}, fmt.Errorf("JWKS URL %q must use https://", target)
	}
	client := cfg.httpClient()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, http.NoBody)
	if err != nil {
		return writeJWKS{}, fmt.Errorf("build JWKS request %q: %w", target, err)
	}
	// httpDoWithRetry retries on transient failures (5xx, 429, connection
	// errors) so a brief upstream blip doesn't surface as a 401 to a
	// real client. Backoff is jittered exponential, bounded by the
	// configured HTTP timeout.
	resp, err := httpDoWithRetry(ctx, client, req, defaultHTTPRetry)
	if err != nil {
		return writeJWKS{}, fmt.Errorf("fetch JWKS URL %q: %w", target, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return writeJWKS{}, fmt.Errorf("fetch JWKS URL %q: unexpected status %d", target, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return writeJWKS{}, fmt.Errorf("read JWKS URL %q response: %w", target, err)
	}
	return parseWriteJWKSRaw(body, target)
}

func parseWriteJWKSRaw(raw []byte, sourceLabel string) (writeJWKS, error) {
	var doc writeJWKS
	if err := json.Unmarshal(raw, &doc); err != nil {
		return writeJWKS{}, fmt.Errorf("parse JWKS %q: %w", sourceLabel, err)
	}
	if len(doc.Keys) == 0 {
		return writeJWKS{}, fmt.Errorf("JWKS %q has no keys", sourceLabel)
	}
	return doc, nil
}

func resolveWriteOIDCJWKSURL(ctx context.Context, cfg writeJWTVerificationConfig, issuer string, forceRefresh bool) (string, error) {
	cleanIssuer := normalizeIssuerURL(issuer)
	if cleanIssuer == "" {
		return "", fmt.Errorf("OIDC issuer URL is empty")
	}
	if !jwksTransportAllowed(cleanIssuer) {
		return "", fmt.Errorf("OIDC issuer URL %q must use https://", cleanIssuer)
	}
	now := cfg.now()
	cacheKey := cleanIssuer
	if !forceRefresh {
		writeOIDCDiscoveryCacheState.mu.Lock()
		entry, ok := writeOIDCDiscoveryCacheState.entries[cacheKey]
		writeOIDCDiscoveryCacheState.mu.Unlock()
		if ok && now.Before(entry.ExpiresAt) {
			return entry.JWKSURL, nil
		}
	}

	discoveryURL := cleanIssuer + "/.well-known/openid-configuration"
	client := cfg.httpClient()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, http.NoBody)
	if err != nil {
		return "", fmt.Errorf("build OIDC discovery request %q: %w", discoveryURL, err)
	}
	resp, err := httpDoWithRetry(ctx, client, req, defaultHTTPRetry)
	if err != nil {
		return "", fmt.Errorf("fetch OIDC discovery URL %q: %w", discoveryURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch OIDC discovery URL %q: unexpected status %d", discoveryURL, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read OIDC discovery URL %q response: %w", discoveryURL, err)
	}
	var doc writeOIDCDiscoveryDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", fmt.Errorf("parse OIDC discovery URL %q: %w", discoveryURL, err)
	}
	docIssuer := normalizeIssuerURL(doc.Issuer)
	if docIssuer == "" {
		return "", fmt.Errorf("OIDC discovery URL %q returned empty issuer", discoveryURL)
	}
	if docIssuer != cleanIssuer {
		return "", fmt.Errorf("OIDC discovery URL %q issuer mismatch: got %q want %q", discoveryURL, docIssuer, cleanIssuer)
	}
	jwksURL := strings.TrimSpace(doc.JWKSURI)
	if !jwksTransportAllowed(jwksURL) {
		return "", fmt.Errorf("OIDC discovery URL %q returned invalid (non-https) jwks_uri %q", discoveryURL, jwksURL)
	}

	writeOIDCDiscoveryCacheState.mu.Lock()
	writeOIDCDiscoveryCacheState.entries[cacheKey] = writeOIDCDiscoveryCacheEntry{
		JWKSURL:   jwksURL,
		ExpiresAt: now.Add(cfg.oidcCacheTTL()),
	}
	writeOIDCDiscoveryCacheState.mu.Unlock()
	return jwksURL, nil
}

func jwksSourcesFromConfig(cfg writeJWTVerificationConfig) []writeJWKSSource {
	sources := make([]writeJWKSSource, 0, 3)
	if strings.TrimSpace(cfg.JWKSURL) != "" {
		sources = append(sources, writeJWKSSource{Kind: "url", Value: strings.TrimSpace(cfg.JWKSURL)})
	}
	if strings.TrimSpace(cfg.JWKSPath) != "" {
		sources = append(sources, writeJWKSSource{Kind: "path", Value: strings.TrimSpace(cfg.JWKSPath)})
	}
	if strings.TrimSpace(cfg.OIDCIssuerURL) != "" {
		sources = append(sources, writeJWKSSource{Kind: "oidc", Value: strings.TrimSpace(cfg.OIDCIssuerURL)})
	}
	return sources
}

func (cfg writeJWTVerificationConfig) now() time.Time {
	if cfg.NowFn != nil {
		return cfg.NowFn().UTC()
	}
	return time.Now().UTC()
}

func (cfg writeJWTVerificationConfig) cacheTTL() time.Duration {
	if cfg.JWKSCacheTTL <= 0 {
		return 5 * time.Minute
	}
	return cfg.JWKSCacheTTL
}

func (cfg writeJWTVerificationConfig) oidcCacheTTL() time.Duration {
	if cfg.OIDCCacheTTL <= 0 {
		return 10 * time.Minute
	}
	return cfg.OIDCCacheTTL
}

func (cfg writeJWTVerificationConfig) httpClient() *http.Client {
	timeout := cfg.JWKSHTTPTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if cfg.HTTPClientFactory != nil {
		return cfg.HTTPClientFactory(timeout)
	}
	return &http.Client{Timeout: timeout}
}

func parseDurationEnv(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := time.ParseDuration(raw)
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func resetWriteJWKSCache() {
	writeJWKSCacheState.mu.Lock()
	writeJWKSCacheState.entries = map[string]writeJWKSCacheEntry{}
	writeJWKSCacheState.mu.Unlock()
	writeOIDCDiscoveryCacheState.mu.Lock()
	writeOIDCDiscoveryCacheState.entries = map[string]writeOIDCDiscoveryCacheEntry{}
	writeOIDCDiscoveryCacheState.mu.Unlock()
	jwksForceRefreshState.mu.Lock()
	jwksForceRefreshState.last = map[string]time.Time{}
	jwksForceRefreshState.mu.Unlock()
}

func normalizeIssuerURL(rawIssuer string) string {
	issuer := strings.TrimSpace(rawIssuer)
	issuer = strings.TrimSuffix(issuer, "/")
	return issuer
}

func isHTTPURL(raw string) bool {
	value := strings.ToLower(strings.TrimSpace(raw))
	return strings.HasPrefix(value, "https://") || strings.HasPrefix(value, "http://")
}

// isHTTPSURL reports whether the URL uses https:// specifically. We use this
// for security-critical fetches (JWKS, OIDC discovery) where a plaintext
// transport would let a network attacker swap the signing key set and forge
// JWTs.
func isHTTPSURL(raw string) bool {
	value := strings.ToLower(strings.TrimSpace(raw))
	return strings.HasPrefix(value, "https://")
}

// writeJWKSAllowInsecureForTests, when true, relaxes the JWKS/OIDC HTTPS
// requirement so unit tests can use httptest.NewServer (http://) loopback
// servers. This is package-private and NOT controlled by env on purpose:
// production binaries can never flip it, so the H-2 hardening still applies
// to every real deployment.
var writeJWKSAllowInsecureForTests bool

// jwksTransportAllowed reports whether a URL is acceptable for JWKS/OIDC
// fetches given the current safety posture. Production always requires https.
func jwksTransportAllowed(raw string) bool {
	if isHTTPSURL(raw) {
		return true
	}
	return writeJWKSAllowInsecureForTests && isHTTPURL(raw)
}

func selectWriteJWKRS256(jwks writeJWKS, kid string) (writeJWK, error) {
	matches := make([]writeJWK, 0, len(jwks.Keys))
	for _, key := range jwks.Keys {
		if strings.TrimSpace(strings.ToUpper(key.Kty)) != "RSA" {
			continue
		}
		alg := strings.TrimSpace(strings.ToUpper(key.Alg))
		if alg != "" && alg != "RS256" {
			continue
		}
		use := strings.TrimSpace(strings.ToLower(key.Use))
		if use != "" && use != "sig" {
			continue
		}
		if strings.TrimSpace(kid) != "" && strings.TrimSpace(key.Kid) != kid {
			continue
		}
		matches = append(matches, key)
	}
	if len(matches) == 0 {
		if strings.TrimSpace(kid) != "" {
			return writeJWK{}, fmt.Errorf("no RSA signing key matched kid %q", kid)
		}
		return writeJWK{}, fmt.Errorf("no RSA signing key matched")
	}
	if strings.TrimSpace(kid) == "" && len(matches) > 1 {
		return writeJWK{}, fmt.Errorf("multiple RSA signing keys found; token kid is required")
	}
	return matches[0], nil
}

func rsaPublicKeyFromJWK(key writeJWK) (*rsa.PublicKey, error) {
	nRaw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(key.N))
	if err != nil {
		return nil, fmt.Errorf("decode RSA modulus: %w", err)
	}
	eRaw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(key.E))
	if err != nil {
		return nil, fmt.Errorf("decode RSA exponent: %w", err)
	}
	if len(nRaw) == 0 || len(eRaw) == 0 {
		return nil, fmt.Errorf("RSA key material is incomplete")
	}
	eBig := new(big.Int).SetBytes(eRaw)
	if !eBig.IsInt64() {
		return nil, fmt.Errorf("RSA exponent is too large")
	}
	e := int(eBig.Int64())
	if e < 2 {
		return nil, fmt.Errorf("RSA exponent is invalid")
	}
	n := new(big.Int).SetBytes(nRaw)
	if n.Sign() <= 0 {
		return nil, fmt.Errorf("RSA modulus is invalid")
	}
	// SECURITY: reject weak RSA keys. NIST SP 800-131A retires <2048-bit keys
	// and modern JWKS providers should never publish anything smaller. An
	// attacker who substitutes a small modulus could factor it and mint
	// arbitrary tokens.
	if n.BitLen() < 2048 {
		return nil, fmt.Errorf("RSA modulus is too small (%d bits, minimum 2048)", n.BitLen())
	}
	return &rsa.PublicKey{
		N: n,
		E: e,
	}, nil
}

func enforceWriteIdentityTenantProject(identity writeAuthIdentity, tenant, project string) error {
	if !identityCarriesClaims(identity) {
		return nil
	}
	tenant = strings.TrimSpace(tenant)
	project = strings.TrimSpace(project)
	if tenant == "" || project == "" {
		return nil
	}
	identityTenant := strings.TrimSpace(identity.Tenant)
	// SECURITY: a JWT with neither tenant nor projects claim must not be
	// treated as an org-wide wildcard. Previously, both checks returned nil
	// when their claim was empty, so a token containing only {sub, exp,
	// can_write} authenticated against every tenant/project. Require either
	// an explicit tenant claim match or an explicit projects entry covering
	// this project.
	if identityTenant == "" && len(identity.Projects) == 0 {
		return fmt.Errorf("identity has no tenant or projects claim; cannot authorize tenant %q project %q", tenant, project)
	}
	if identityTenant != "" && identityTenant != tenant {
		return fmt.Errorf("identity tenant %q is not authorized for tenant %q", identityTenant, tenant)
	}
	if len(identity.Projects) > 0 {
		allowed := false
		for _, candidate := range identity.Projects {
			candidate = strings.TrimSpace(candidate)
			if candidate == "" {
				continue
			}
			if candidate == "*" || candidate == project {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("identity token is not authorized for project %q", project)
		}
	}
	return nil
}

func writeIdentitySubject(identity writeAuthIdentity, r *http.Request) string {
	subject := strings.TrimSpace(identity.Subject)
	if subject != "" {
		return subject
	}
	return tokenSubject(writeCredentialFromRequest(r))
}

func readNumericClaim(claims map[string]any, key string) (int64, bool, error) {
	raw, ok := claims[key]
	if !ok {
		return 0, false, nil
	}
	switch value := raw.(type) {
	case float64:
		return int64(value), true, nil
	case json.Number:
		n, err := value.Int64()
		if err != nil {
			return 0, true, fmt.Errorf("%s claim must be an integer: %w", key, err)
		}
		return n, true, nil
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		if err != nil {
			return 0, true, fmt.Errorf("%s claim must be numeric: %w", key, err)
		}
		return n, true, nil
	default:
		return 0, true, fmt.Errorf("%s claim must be numeric", key)
	}
}

func anyToString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	default:
		return ""
	}
}

func jwtAudienceMatches(raw any, expected string) bool {
	expected = strings.TrimSpace(expected)
	if expected == "" {
		return true
	}
	switch value := raw.(type) {
	case string:
		return strings.TrimSpace(value) == expected
	case []any:
		for _, entry := range value {
			if strings.TrimSpace(anyToString(entry)) == expected {
				return true
			}
		}
	case []string:
		for _, entry := range value {
			if strings.TrimSpace(entry) == expected {
				return true
			}
		}
	}
	return false
}

func normalizeJWTProjectsClaim(raw any) []string {
	switch value := raw.(type) {
	case string:
		if strings.TrimSpace(value) == "" {
			return nil
		}
		return collectMultiValues([]string{value})
	case []any:
		values := make([]string, 0, len(value))
		for _, entry := range value {
			entryStr := strings.TrimSpace(anyToString(entry))
			if entryStr == "" {
				continue
			}
			values = append(values, entryStr)
		}
		return collectMultiValues(values)
	case []string:
		return collectMultiValues(value)
	default:
		return nil
	}
}

func normalizeJWTScopesClaim(claims map[string]any) []string {
	values := make([]string, 0)
	values = append(values, claimValueStrings(claims["scope"], true)...)
	values = append(values, claimValueStrings(claims["scp"], true)...)
	return dedupeSortedStrings(values)
}

func normalizeJWTRolesClaim(claims map[string]any) []string {
	values := make([]string, 0)
	values = append(values, claimValueStrings(claims["roles"], false)...)
	values = append(values, claimValueStrings(claims["role"], false)...)
	return dedupeSortedStrings(values)
}

func claimValueStrings(raw any, splitSpaces bool) []string {
	switch value := raw.(type) {
	case string:
		if splitSpaces {
			return splitScopeValues(value)
		}
		return collectMultiValues([]string{value})
	case []string:
		if splitSpaces {
			out := make([]string, 0, len(value))
			for _, entry := range value {
				out = append(out, splitScopeValues(entry)...)
			}
			return dedupeSortedStrings(out)
		}
		return collectMultiValues(value)
	case []any:
		out := make([]string, 0, len(value))
		for _, entry := range value {
			text := strings.TrimSpace(anyToString(entry))
			if text == "" {
				continue
			}
			if splitSpaces {
				out = append(out, splitScopeValues(text)...)
				continue
			}
			out = append(out, text)
		}
		return dedupeSortedStrings(out)
	default:
		return nil
	}
}

func splitScopeValues(raw string) []string {
	parts := strings.Fields(strings.TrimSpace(raw))
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return dedupeSortedStrings(out)
}

func dedupeSortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	joined := collectMultiValues(values)
	return joined
}

func requiredClaimListFromEnv(key string) []string {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return nil
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == '\t' || r == '\n' || r == ' '
	})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return dedupeSortedStrings(out)
}

func containsAllClaims(have []string, want []string) []string {
	if len(want) == 0 {
		return nil
	}
	lookup := make(map[string]struct{}, len(have))
	for _, entry := range have {
		lookup[strings.TrimSpace(entry)] = struct{}{}
	}
	missing := make([]string, 0)
	for _, required := range want {
		required = strings.TrimSpace(required)
		if required == "" {
			continue
		}
		if _, ok := lookup[required]; !ok {
			missing = append(missing, required)
		}
	}
	return dedupeSortedStrings(missing)
}

func enforceWriteIdentityRequiredClaims(identity writeAuthIdentity) error {
	if !identityCarriesClaims(identity) {
		return nil
	}
	requiredScopes := requiredClaimListFromEnv(envWriteJWTRequiredScopes)
	missingScopes := containsAllClaims(identity.Scopes, requiredScopes)
	if len(missingScopes) > 0 {
		return fmt.Errorf("identity token is missing required scopes: %s", strings.Join(missingScopes, ","))
	}
	requiredRoles := requiredClaimListFromEnv(envWriteJWTRequiredRoles)
	missingRoles := containsAllClaims(identity.Roles, requiredRoles)
	if len(missingRoles) > 0 {
		return fmt.Errorf("identity token is missing required roles: %s", strings.Join(missingRoles, ","))
	}
	return nil
}

func enforceWriteIdentityActionClaims(identity writeAuthIdentity, action string) error {
	if !identityCarriesClaims(identity) {
		return nil
	}
	action = normalizeWriteActionName(action)
	if action == "" {
		return nil
	}
	requiredScopes, requiredRoles := requiredClaimsForAction(action)

	missingScopes := containsAllClaims(identity.Scopes, requiredScopes)
	if len(missingScopes) > 0 {
		if action == "runtime_execute" {
			return fmt.Errorf("identity token is missing required runtime execute scopes: %s", strings.Join(missingScopes, ","))
		}
		return fmt.Errorf("identity token is missing required %s scopes: %s", strings.ReplaceAll(action, "_", " "), strings.Join(missingScopes, ","))
	}
	missingRoles := containsAllClaims(identity.Roles, requiredRoles)
	if len(missingRoles) > 0 {
		if action == "runtime_execute" {
			return fmt.Errorf("identity token is missing required runtime execute roles: %s", strings.Join(missingRoles, ","))
		}
		return fmt.Errorf("identity token is missing required %s roles: %s", strings.ReplaceAll(action, "_", " "), strings.Join(missingRoles, ","))
	}
	return nil
}

func identityCarriesClaims(identity writeAuthIdentity) bool {
	switch strings.TrimSpace(identity.AuthType) {
	case "jwt", "mtls":
		return true
	default:
		return false
	}
}

func requiredClaimsForAction(action string) (scopes []string, roles []string) {
	action = normalizeWriteActionName(action)
	if action == "" {
		return nil, nil
	}
	scopes = append(scopes, requiredClaimListFromEnv(envWriteJWTRequiredScopes)...)
	roles = append(roles, requiredClaimListFromEnv(envWriteJWTRequiredRoles)...)
	scopes = append(scopes, requiredClaimListFromEnv(writeJWTRequiredScopesEnvForAction(action))...)
	roles = append(roles, requiredClaimListFromEnv(writeJWTRequiredRolesEnvForAction(action))...)

	// Backward compatibility with existing dedicated runtime execute env controls.
	if action == "runtime_execute" {
		scopes = append(scopes, requiredClaimListFromEnv(envRuntimeExecJWTRequiredScopes)...)
		roles = append(roles, requiredClaimListFromEnv(envRuntimeExecJWTRequiredRoles)...)
	}
	return dedupeSortedStrings(scopes), dedupeSortedStrings(roles)
}

func writeIdentityClaimsConfiguredForAction(action string) bool {
	scopes, roles := requiredClaimsForAction(action)
	return len(scopes) > 0 || len(roles) > 0
}

func writeJWTRequiredScopesEnvForAction(action string) string {
	action = normalizeWriteActionName(action)
	if action == "" {
		return ""
	}
	return "BPFCOMPAT_API_WRITE_JWT_REQUIRED_SCOPES_" + strings.ToUpper(action)
}

func writeJWTRequiredRolesEnvForAction(action string) string {
	action = normalizeWriteActionName(action)
	if action == "" {
		return ""
	}
	return "BPFCOMPAT_API_WRITE_JWT_REQUIRED_ROLES_" + strings.ToUpper(action)
}

func normalizeWriteActionName(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return ""
	}
	var b strings.Builder
	lastUnderscore := false
	for _, r := range raw {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			lastUnderscore = false
			continue
		}
		if !lastUnderscore {
			b.WriteRune('_')
			lastUnderscore = true
		}
	}
	action := strings.Trim(b.String(), "_")
	return action
}

func enforceWriteIdentityTenant(identity writeAuthIdentity, tenant string) error {
	if !identityCarriesClaims(identity) {
		return nil
	}
	tenant = strings.TrimSpace(tenant)
	if tenant == "" {
		return nil
	}
	identityTenant := strings.TrimSpace(identity.Tenant)
	// SECURITY: same posture as enforceWriteIdentityTenantProject — a JWT
	// without an explicit tenant claim must not be treated as authorized for
	// every tenant. The previous behavior returned nil when the claim was
	// empty, which let bare {sub, exp} tokens cross tenant boundaries.
	if identityTenant == "" {
		return fmt.Errorf("identity has no tenant claim; cannot authorize tenant %q", tenant)
	}
	if identityTenant != tenant {
		return fmt.Errorf("identity tenant %q is not authorized for tenant %q", identityTenant, tenant)
	}
	return nil
}
