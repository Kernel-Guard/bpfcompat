package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kernel-guard/bpfcompat/internal/artifact"
	"github.com/kernel-guard/bpfcompat/internal/registry"
	"github.com/kernel-guard/bpfcompat/internal/safepath"
)

const fetchSchemaVersion = "runtime_fetch.v0.1"
const (
	fetchMaxBytesEnv            = "BPFCOMPAT_FETCH_MAX_BYTES"
	defaultRuntimeFetchMaxBytes = int64(128 << 20)
	fetchAllowInternalEnv       = "BPFCOMPAT_FETCH_ALLOW_INTERNAL_HOSTS"
	fetchAllowFileURIEnv        = "BPFCOMPAT_FETCH_ALLOW_FILE_URI"
	fetchMaxRedirects           = 5
)

// errSSRFBlocked is returned when an artifact URL or a redirect target resolves
// to a host the runtime is configured to reject (loopback, link-local, private
// ranges, etc.). Keeping it as a sentinel lets the API layer recognize the
// class of failure for clearer error mapping.
var errSSRFBlocked = errors.New("artifact URL host is not allowed")

func FetchArtifact(record registry.ArtifactVersionRecord, outDir string) (FetchResult, error) {
	if strings.TrimSpace(outDir) == "" {
		return FetchResult{}, fmt.Errorf("output directory is required")
	}

	source, remote, err := resolveFetchSource(record)
	if err != nil {
		return FetchResult{}, err
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return FetchResult{}, fmt.Errorf("create output directory: %w", err)
	}

	targetName := record.ArtifactName + "-" + record.ArtifactVersion
	if record.ArtifactVariant != "" {
		targetName += "-" + sanitizeFragment(record.ArtifactVariant)
	}
	ext := artifactExtensionFromSource(source, remote)
	if ext == "" {
		ext = ".bpf.o"
	}
	// targetName/ext derive from registry record fields, so contain the
	// resulting filename to a single component under outDir.
	targetPath, err := safepath.LocalJoin(outDir, sanitizeFragment(targetName)+ext)
	if err != nil {
		return FetchResult{}, fmt.Errorf("resolve artifact target path: %w", err)
	}

	stagedPath := targetPath
	if remote {
		if err := fetchRemoteArtifact(source, targetPath); err != nil {
			return FetchResult{}, err
		}
	} else {
		localPath, err := copyLocalArtifactToPath(source, targetPath)
		if err != nil {
			return FetchResult{}, err
		}
		stagedPath = localPath
	}

	meta, err := artifact.Inspect(stagedPath)
	if err != nil {
		return FetchResult{}, fmt.Errorf("inspect fetched artifact: %w", err)
	}
	expected := strings.TrimSpace(record.ArtifactSHA256)
	actual := strings.TrimSpace(meta.SHA256)
	if expected != "" && actual != expected {
		return FetchResult{}, fmt.Errorf("fetched artifact hash mismatch: expected=%s got=%s", expected, actual)
	}

	return FetchResult{
		SchemaVersion:   fetchSchemaVersion,
		ArtifactName:    record.ArtifactName,
		ArtifactVersion: record.ArtifactVersion,
		ArtifactVariant: record.ArtifactVariant,
		SourcePath:      source,
		OutputPath:      stagedPath,
		ExpectedSHA256:  expected,
		ActualSHA256:    actual,
	}, nil
}

func resolveFetchSource(record registry.ArtifactVersionRecord) (string, bool, error) {
	artifactPath := strings.TrimSpace(record.ArtifactPath)
	if artifactPath != "" {
		scheme, err := fetchURIScheme(artifactPath)
		if err != nil {
			return "", false, fmt.Errorf("parse artifact_path URI: %w", err)
		}
		switch scheme {
		case "http", "https":
			return artifactPath, true, nil
		case "file":
			if !fetchAllowFileURIEnabled() {
				return "", false, fmt.Errorf("file artifact_path URI is disabled; set %s=true only for local-dev proof runs", fetchAllowFileURIEnv)
			}
			return artifactPath, true, nil
		case "":
		default:
			return "", false, fmt.Errorf("artifact_path URI scheme %q is not supported (use http, https; file requires %s=true)", scheme, fetchAllowFileURIEnv)
		}

		cleanPath := filepath.Clean(artifactPath)
		if _, err := os.Stat(cleanPath); err == nil {
			return cleanPath, false, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", false, fmt.Errorf("stat artifact source path: %w", err)
		}
	}

	artifactURI := strings.TrimSpace(record.ArtifactURI)
	if artifactURI != "" {
		scheme, err := fetchURIScheme(artifactURI)
		if err != nil {
			return "", false, fmt.Errorf("parse artifact_uri: %w", err)
		}
		switch scheme {
		case "http", "https":
			return artifactURI, true, nil
		case "file":
			if !fetchAllowFileURIEnabled() {
				return "", false, fmt.Errorf("file artifact_uri is disabled; set %s=true only for local-dev proof runs", fetchAllowFileURIEnv)
			}
			return artifactURI, true, nil
		default:
			return "", false, fmt.Errorf("artifact_uri must use one of: http, https (file requires %s=true)", fetchAllowFileURIEnv)
		}
	}

	if artifactPath == "" {
		return "", false, fmt.Errorf("record has empty artifact source metadata (artifact_path/artifact_uri)")
	}
	return "", false, fmt.Errorf("artifact source not found at %q and no artifact_uri provided", filepath.Clean(artifactPath))
}

func fetchURIScheme(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	return strings.ToLower(strings.TrimSpace(u.Scheme)), nil
}

func artifactExtensionFromSource(source string, remote bool) string {
	if !remote {
		return filepath.Ext(filepath.Base(source))
	}
	u, err := url.Parse(source)
	if err != nil {
		return ""
	}
	return path.Ext(path.Base(u.Path))
}

func copyLocalArtifactToPath(sourcePath, targetPath string) (string, error) {
	stagedPath, err := artifact.Stage(sourcePath, filepath.Dir(targetPath))
	if err != nil {
		return "", fmt.Errorf("copy artifact to output directory: %w", err)
	}
	if filepath.Base(stagedPath) == filepath.Base(targetPath) {
		return stagedPath, nil
	}
	renamedPath := filepath.Join(filepath.Dir(stagedPath), filepath.Base(targetPath))
	if err := os.Rename(stagedPath, renamedPath); err != nil {
		return "", fmt.Errorf("rename fetched artifact: %w", err)
	}
	return renamedPath, nil
}

func fetchRemoteArtifact(sourceURI, targetPath string) error {
	u, err := url.Parse(sourceURI)
	if err != nil {
		return fmt.Errorf("parse remote artifact URI: %w", err)
	}
	switch strings.ToLower(strings.TrimSpace(u.Scheme)) {
	case "http", "https":
		return fetchHTTPArtifact(sourceURI, targetPath)
	case "file":
		if !fetchAllowFileURIEnabled() {
			return fmt.Errorf("file artifact URI is disabled; set %s=true only for local-dev proof runs", fetchAllowFileURIEnv)
		}
		if strings.TrimSpace(u.Host) != "" && strings.TrimSpace(u.Host) != "localhost" {
			return fmt.Errorf("file URI host %q is not supported", u.Host)
		}
		if strings.TrimSpace(u.Path) == "" {
			return fmt.Errorf("file URI path is empty")
		}
		localPath := filepath.Clean(u.Path)
		if _, err := os.Stat(localPath); err != nil {
			return fmt.Errorf("artifact file URI source not found: %w", err)
		}
		_, err := copyLocalArtifactToPath(localPath, targetPath)
		return err
	default:
		return fmt.Errorf("unsupported artifact URI scheme %q", u.Scheme)
	}
}

func fetchHTTPArtifact(sourceURI, targetPath string) error {
	parsed, err := url.Parse(strings.TrimSpace(sourceURI))
	if err != nil {
		return fmt.Errorf("parse remote artifact URI: %w", err)
	}
	// SECURITY: SSRF guard. The artifact URI travels from a registry record
	// uploaded by a write-authorized caller into an outbound request made by
	// this server. Without filtering, an upload pointing at cloud-metadata
	// (169.254.169.254), loopback, or RFC1918 ranges would be silently
	// proxied by this process. Resolve every host on every hop and reject
	// internal targets unless the operator opts in via env.
	allowInternal := fetchAllowInternalHostsEnabled()
	if err := validateOutboundHost(parsed, allowInternal); err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodGet, sourceURI, nil)
	if err != nil {
		return fmt.Errorf("build fetch request: %w", err)
	}
	client := secureHTTPFetchClient(allowInternal)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download artifact: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("download artifact unexpected HTTP status %d", resp.StatusCode)
	}

	tmpPath := targetPath + ".partial"
	f, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("create artifact temp file: %w", err)
	}
	maxBytes := runtimeFetchMaxBytes()
	limited := &io.LimitedReader{R: resp.Body, N: maxBytes + 1}
	written, copyErr := io.Copy(f, limited)
	closeErr := f.Close()
	if copyErr != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write downloaded artifact: %w", copyErr)
	}
	if closeErr != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close downloaded artifact file: %w", closeErr)
	}
	if written > maxBytes {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("downloaded artifact exceeds %d bytes limit (set %s to override)", maxBytes, fetchMaxBytesEnv)
	}
	if err := os.Rename(tmpPath, targetPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("move downloaded artifact into place: %w", err)
	}
	return nil
}

// validateOutboundHost rejects URIs whose resolved IPs would be considered
// "internal" — loopback, link-local, private, multicast, unspecified, or the
// cloud-metadata service IP 169.254.169.254. The operator can disable this
// check (e.g., for an internal artifact mirror) by setting
// BPFCOMPAT_FETCH_ALLOW_INTERNAL_HOSTS=true. Returns errSSRFBlocked on
// rejection so callers can recognize the failure class.
func validateOutboundHost(u *url.URL, allowInternal bool) error {
	if u == nil {
		return errSSRFBlocked
	}
	scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("%w: unsupported scheme %q", errSSRFBlocked, scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("%w: missing host in %q", errSSRFBlocked, u.String())
	}
	if allowInternal {
		return nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(context.Background(), host)
	if err != nil {
		return fmt.Errorf("resolve fetch host %q: %w", host, err)
	}
	return validateResolvedIPs(host, addrs, allowInternal)
}

func secureHTTPFetchClient(allowInternal bool) *http.Client {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialValidatedHost(ctx, dialer, network, address, allowInternal)
		},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &http.Client{
		Timeout:   2 * time.Minute,
		Transport: transport,
		CheckRedirect: func(redirReq *http.Request, via []*http.Request) error {
			if len(via) >= fetchMaxRedirects {
				return fmt.Errorf("artifact fetch exceeded %d redirects", fetchMaxRedirects)
			}
			if err := validateOutboundHost(redirReq.URL, allowInternal); err != nil {
				return err
			}
			return nil
		},
	}
}

func dialValidatedHost(ctx context.Context, dialer *net.Dialer, network, address string, allowInternal bool) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("parse outbound address %q: %w", address, err)
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve fetch host %q: %w", host, err)
	}
	if err := validateResolvedIPs(host, addrs, allowInternal); err != nil {
		return nil, err
	}
	var lastErr error
	for _, addr := range addrs {
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(addr.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("host %q resolved to no addresses", host)
}

func validateResolvedIPs(host string, addrs []net.IPAddr, allowInternal bool) error {
	if allowInternal {
		return nil
	}
	if len(addrs) == 0 {
		return fmt.Errorf("%w: host %q resolved to no addresses", errSSRFBlocked, host)
	}
	for _, addr := range addrs {
		if isInternalIP(addr.IP) {
			return fmt.Errorf("%w: host %q resolves to internal address %s (set %s=true to override)", errSSRFBlocked, host, addr.IP.String(), fetchAllowInternalEnv)
		}
	}
	return nil
}

func isInternalIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsPrivate() ||
		ip.IsInterfaceLocalMulticast() {
		return true
	}
	// 169.254.169.254 is link-local already; keep explicit cloud-metadata
	// hardening in case downstream IsLinkLocalUnicast behavior diverges.
	if v4 := ip.To4(); v4 != nil && v4[0] == 169 && v4[1] == 254 {
		return true
	}
	// Carrier-grade NAT 100.64.0.0/10 (RFC 6598) is not "Private" per Go but
	// behaves like an internal range for SSRF purposes on cloud VPCs.
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
		return true
	}
	return false
}

func fetchAllowFileURIEnabled() bool {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv(fetchAllowFileURIEnv)))
	switch raw {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func fetchAllowInternalHostsEnabled() bool {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv(fetchAllowInternalEnv)))
	if raw == "" {
		return false
	}
	switch raw {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func runtimeFetchMaxBytes() int64 {
	raw := strings.TrimSpace(os.Getenv(fetchMaxBytesEnv))
	if raw == "" {
		return defaultRuntimeFetchMaxBytes
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n <= 0 {
		return defaultRuntimeFetchMaxBytes
	}
	return n
}

func sanitizeFragment(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return "artifact"
	}
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_' || r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "artifact"
	}
	return out
}
