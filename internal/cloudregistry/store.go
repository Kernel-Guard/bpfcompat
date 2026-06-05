package cloudregistry

import (
	"bufio"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/erenari/bpfcompat/internal/registry"
	"github.com/erenari/bpfcompat/pkg/schema"
)

// readSecureRandom fills b with cryptographically secure random bytes.
// Defined as a thin wrapper so tests can swap it out via a build-time
// indirection if needed.
func readSecureRandom(b []byte) (int, error) {
	return cryptorand.Read(b)
}

const (
	projectSchemaVersion       = "cloud_registry_project.v0.1"
	authSchemaVersion          = "cloud_registry_auth.v0.1"
	auditEventSchemaVersion    = "cloud_registry_audit_event.v0.1"
	uploadSummarySchemaVersion = "cloud_registry_upload_summary.v0.1"
	bootstrapTokenEnv          = "BPFCOMPAT_REGISTRY_AUTH_TOKEN"
	bootstrapTokenNotBeforeEnv = "BPFCOMPAT_REGISTRY_AUTH_TOKEN_NOT_BEFORE"
	bootstrapTokenExpiresAtEnv = "BPFCOMPAT_REGISTRY_AUTH_TOKEN_EXPIRES_AT"
)

var (
	ErrNotFound      = errors.New("cloud registry record not found")
	ErrUnauthorized  = errors.New("cloud registry unauthorized")
	ErrForbidden     = errors.New("cloud registry forbidden")
	ErrConflict      = errors.New("cloud registry conflict")
	ErrQuotaExceeded = errors.New("cloud registry quota exceeded")

	idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

const (
	maxArtifactBytesEnv           = "BPFCOMPAT_REGISTRY_MAX_ARTIFACT_BYTES"
	maxArtifactVersionsPerNameEnv = "BPFCOMPAT_REGISTRY_MAX_ARTIFACT_VERSIONS_PER_NAME"
	maxProjectStorageBytesEnv     = "BPFCOMPAT_REGISTRY_MAX_PROJECT_STORAGE_BYTES"
	// Audit rotation knobs. The cloud-registry audit stream is append-only
	// and would otherwise grow unbounded. Production operators should tune
	// these from defaults to match their retention policy and disk budget.
	auditMaxBytesEnv = "BPFCOMPAT_REGISTRY_AUDIT_MAX_BYTES"
	auditMaxFilesEnv = "BPFCOMPAT_REGISTRY_AUDIT_MAX_FILES"
	// defaultAuditMaxBytes triggers rotation when the active log reaches
	// 64 MiB. ~1 KiB per event, so this is ~65k events per file.
	defaultAuditMaxBytes int64 = 64 << 20
	// defaultAuditMaxFiles keeps the active file + 9 rotations (~10 * 64 MiB
	// worst case). Older rotations are evicted oldest-first.
	defaultAuditMaxFiles = 10
)

type quotaLimits struct {
	MaxArtifactBytes           int64
	MaxArtifactVersionsPerName int
	MaxProjectStorageBytes     int64
}

type Store struct {
	workDir string
	rootDir string
	nowFn   func() time.Time
}

type Project struct {
	SchemaVersion     string `json:"schema_version"`
	Tenant            string `json:"tenant"`
	Project           string `json:"project"`
	Visibility        string `json:"visibility"`
	DefaultMatrixPath string `json:"default_matrix_path,omitempty"`
	CreatedAt         string `json:"created_at"`
	UpdatedAt         string `json:"updated_at"`
}

type CreateProjectInput struct {
	Tenant            string `json:"tenant"`
	Project           string `json:"project"`
	Visibility        string `json:"visibility"`
	DefaultMatrixPath string `json:"default_matrix_path,omitempty"`
}

type TokenGrant struct {
	// Token is the legacy plaintext token. Existing deployments may still
	// have this populated; it is preserved for backward compatibility but
	// SHOULD be replaced with TokenHash + TokenHashSalt at rest.
	Token string `json:"token,omitempty"`
	// TokenHash is the hex-encoded HMAC-SHA256(salt, plaintextToken). When
	// non-empty it takes precedence over Token at compare time so deployments
	// can rotate by adding the hashed entry and deleting the plaintext one.
	TokenHash string `json:"token_hash,omitempty"`
	// TokenHashSalt is a per-grant base64 random salt mixed into TokenHash.
	// Required when TokenHash is set; ignored otherwise.
	TokenHashSalt string `json:"token_hash_salt,omitempty"`
	// NotBefore is an optional RFC3339 timestamp before which the grant
	// MUST NOT authorize. Empty means "valid immediately".
	NotBefore string `json:"not_before,omitempty"`
	// ExpiresAt is an optional RFC3339 timestamp at/after which the grant
	// MUST NOT authorize. Empty means "never expires" — explicit so we keep
	// backward compatibility with existing tokens.json files that pre-date
	// expiry support. Operators rotating to expiring credentials should set
	// this on every new grant.
	ExpiresAt string   `json:"expires_at,omitempty"`
	Subject   string   `json:"subject"`
	Tenant    string   `json:"tenant"`
	Projects  []string `json:"projects"`
	CanRead   bool     `json:"can_read"`
	CanWrite  bool     `json:"can_write"`
}

// errTokenExpired is returned from grantValidityWindow when a grant is outside
// its NotBefore/ExpiresAt window. Treated as ErrUnauthorized by callers so we
// don't leak which specific grant matched (timing oracle).
var errTokenExpired = errors.New("token grant outside validity window")

// grantValidityWindow checks NotBefore/ExpiresAt against now. Empty fields
// are treated as unbounded. Malformed timestamps produce errTokenExpired so a
// corrupt file can't accidentally authorize.
func grantValidityWindow(grant TokenGrant, now time.Time) error {
	if nbf := strings.TrimSpace(grant.NotBefore); nbf != "" {
		t, err := time.Parse(time.RFC3339, nbf)
		if err != nil {
			return errTokenExpired
		}
		if now.Before(t) {
			return errTokenExpired
		}
	}
	if exp := strings.TrimSpace(grant.ExpiresAt); exp != "" {
		t, err := time.Parse(time.RFC3339, exp)
		if err != nil {
			return errTokenExpired
		}
		if !now.Before(t) {
			return errTokenExpired
		}
	}
	return nil
}

// tokenGrantMatches returns true if the presented plaintext token matches the
// grant. It prefers the hashed form (HMAC-SHA256 with the grant's salt) and
// falls back to a constant-time compare against the legacy plaintext Token
// field when no hash is configured. Returns false on any decode/length
// mismatch — the caller should treat it as "no match" and move on.
func tokenGrantMatches(grant TokenGrant, presented string) bool {
	presented = strings.TrimSpace(presented)
	if presented == "" {
		return false
	}
	hashHex := strings.TrimSpace(grant.TokenHash)
	if hashHex != "" {
		salt, err := base64.StdEncoding.DecodeString(strings.TrimSpace(grant.TokenHashSalt))
		if err != nil || len(salt) == 0 {
			return false
		}
		want, err := hex.DecodeString(hashHex)
		if err != nil || len(want) == 0 {
			return false
		}
		mac := hmac.New(sha256.New, salt)
		_, _ = mac.Write([]byte(presented))
		got := mac.Sum(nil)
		return subtle.ConstantTimeCompare(got, want) == 1
	}
	plaintext := strings.TrimSpace(grant.Token)
	if plaintext == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(plaintext), []byte(presented)) == 1
}

func bootstrapTokenValidityWindow(now time.Time) error {
	return grantValidityWindow(TokenGrant{
		NotBefore: strings.TrimSpace(os.Getenv(bootstrapTokenNotBeforeEnv)),
		ExpiresAt: strings.TrimSpace(os.Getenv(bootstrapTokenExpiresAtEnv)),
	}, now)
}

// HashTokenGrant returns a TokenGrant with the plaintext Token field replaced
// by TokenHash + TokenHashSalt. Useful for one-shot migration scripts or new
// grants. Exported because the bpfcompat CLI may want to surface it later;
// today it's primarily a building block for tests and admin tooling.
func HashTokenGrant(grant TokenGrant, plaintext string) (TokenGrant, error) {
	plaintext = strings.TrimSpace(plaintext)
	if plaintext == "" {
		return TokenGrant{}, fmt.Errorf("plaintext token is required")
	}
	salt := make([]byte, 16)
	if _, err := readSecureRandom(salt); err != nil {
		return TokenGrant{}, fmt.Errorf("generate token salt: %w", err)
	}
	mac := hmac.New(sha256.New, salt)
	_, _ = mac.Write([]byte(plaintext))
	out := grant
	out.Token = ""
	out.TokenHashSalt = base64.StdEncoding.EncodeToString(salt)
	out.TokenHash = hex.EncodeToString(mac.Sum(nil))
	return out, nil
}

type AuthConfig struct {
	SchemaVersion string       `json:"schema_version"`
	Tokens        []TokenGrant `json:"tokens"`
}

type Principal struct {
	Subject  string `json:"subject"`
	Tenant   string `json:"tenant"`
	Project  string `json:"project"`
	CanRead  bool   `json:"can_read"`
	CanWrite bool   `json:"can_write"`
}

type CompatibilityMetadata struct {
	SummaryStatus      string   `json:"summary_status,omitempty"`
	RequiredPassed     int      `json:"required_passed,omitempty"`
	RequiredFailed     int      `json:"required_failed,omitempty"`
	TotalProfiles      int      `json:"total_profiles,omitempty"`
	SupportedProfiles  []string `json:"supported_profiles,omitempty"`
	FailedProfiles     []string `json:"failed_profiles,omitempty"`
	ClassificationCode []string `json:"classification_codes,omitempty"`
	MatrixPath         string   `json:"matrix_path,omitempty"`
	MatrixName         string   `json:"matrix_name,omitempty"`
	MarkdownPath       string   `json:"markdown_path,omitempty"`
}

type UploadInput struct {
	Tenant          string
	Project         string
	ArtifactName    string
	ArtifactVersion string
	ArtifactVariant string
	ArtifactURI     string
	ManifestPath    string
	ExpectedSHA256  string
	SourceRunID     string
	ArtifactReader  io.Reader
	Compatibility   CompatibilityMetadata
	Report          *schema.ReportV01
}

type UploadResult struct {
	Project           Project                        `json:"project"`
	Record            registry.ArtifactVersionRecord `json:"record"`
	StoredArtifact    string                         `json:"stored_artifact_path"`
	StoredArtifactURI string                         `json:"stored_artifact_uri"`
	ArtifactSizeBytes int64                          `json:"artifact_size_bytes"`
}

type AuditEvent struct {
	SchemaVersion   string         `json:"schema_version"`
	EventID         string         `json:"event_id"`
	CreatedAt       string         `json:"created_at"`
	Action          string         `json:"action"`
	Actor           string         `json:"actor,omitempty"`
	Tenant          string         `json:"tenant,omitempty"`
	Project         string         `json:"project,omitempty"`
	ArtifactName    string         `json:"artifact_name,omitempty"`
	ArtifactVersion string         `json:"artifact_version,omitempty"`
	Status          string         `json:"status"`
	Message         string         `json:"message,omitempty"`
	Metadata        map[string]any `json:"metadata,omitempty"`
}

func NewStore(workDir string) Store {
	clean := filepath.Clean(strings.TrimSpace(workDir))
	if clean == "" || clean == "." {
		clean = ".bpfcompat"
	}
	return Store{
		workDir: clean,
		rootDir: filepath.Join(clean, "cloud-registry"),
		nowFn:   time.Now,
	}
}

func (s Store) UpsertProject(input CreateProjectInput) (Project, error) {
	tenant, err := validateID("tenant", input.Tenant)
	if err != nil {
		return Project{}, err
	}
	projectID, err := validateID("project", input.Project)
	if err != nil {
		return Project{}, err
	}
	visibility, err := normalizeVisibility(input.Visibility)
	if err != nil {
		return Project{}, err
	}

	projectPath := s.projectMetadataPath(tenant, projectID)
	now := s.nowFn().UTC().Format(time.RFC3339)

	existing, err := s.GetProject(tenant, projectID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return Project{}, err
	}
	out := Project{
		SchemaVersion:     projectSchemaVersion,
		Tenant:            tenant,
		Project:           projectID,
		Visibility:        visibility,
		DefaultMatrixPath: strings.TrimSpace(input.DefaultMatrixPath),
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	if err == nil {
		out.CreatedAt = existing.CreatedAt
	}

	if err := os.MkdirAll(filepath.Dir(projectPath), 0o755); err != nil {
		return Project{}, fmt.Errorf("create project directory: %w", err)
	}
	payload, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return Project{}, fmt.Errorf("marshal project metadata: %w", err)
	}
	payload = append(payload, '\n')
	if err := os.WriteFile(projectPath, payload, 0o644); err != nil {
		return Project{}, fmt.Errorf("write project metadata: %w", err)
	}
	return out, nil
}

func (s Store) GetProject(tenant, project string) (Project, error) {
	tenant, err := validateID("tenant", tenant)
	if err != nil {
		return Project{}, err
	}
	project, err = validateID("project", project)
	if err != nil {
		return Project{}, err
	}
	path := s.projectMetadataPath(tenant, project)
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Project{}, ErrNotFound
	}
	if err != nil {
		return Project{}, fmt.Errorf("read project metadata: %w", err)
	}
	var out Project
	if err := json.Unmarshal(raw, &out); err != nil {
		return Project{}, fmt.Errorf("parse project metadata: %w", err)
	}
	if out.SchemaVersion == "" {
		out.SchemaVersion = projectSchemaVersion
	}
	return out, nil
}

func (s Store) ListProjects(tenant string, limit int) ([]Project, error) {
	root := filepath.Join(s.rootDir, "tenants")
	if strings.TrimSpace(tenant) != "" {
		cleanTenant, err := validateID("tenant", tenant)
		if err != nil {
			return nil, err
		}
		root = filepath.Join(root, cleanTenant, "projects")
	}

	projects := make([]Project, 0)
	walkRoot := filepath.Clean(root)
	err := filepath.WalkDir(walkRoot, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if d.Name() != "project.json" {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var project Project
		if err := json.Unmarshal(raw, &project); err != nil {
			return err
		}
		if project.SchemaVersion == "" {
			project.SchemaVersion = projectSchemaVersion
		}
		projects = append(projects, project)
		return nil
	})
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list projects: %w", err)
	}

	sort.SliceStable(projects, func(i, j int) bool {
		if projects[i].Tenant == projects[j].Tenant {
			return projects[i].Project < projects[j].Project
		}
		return projects[i].Tenant < projects[j].Tenant
	})
	if limit > 0 && len(projects) > limit {
		projects = projects[:limit]
	}
	return projects, nil
}

func (s Store) AuthorizeToken(token, tenant, project string, write bool) (Principal, error) {
	tenant, err := validateID("tenant", tenant)
	if err != nil {
		return Principal{}, err
	}
	if strings.TrimSpace(project) != "" {
		project, err = validateID("project", project)
		if err != nil {
			return Principal{}, err
		}
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return Principal{}, ErrUnauthorized
	}

	if bootstrap := strings.TrimSpace(os.Getenv(bootstrapTokenEnv)); bootstrap != "" {
		if subtle.ConstantTimeCompare([]byte(bootstrap), []byte(token)) == 1 {
			if err := bootstrapTokenValidityWindow(s.nowFn().UTC()); err != nil {
				return Principal{}, ErrUnauthorized
			}
			return Principal{
				Subject:  "bootstrap-token",
				Tenant:   tenant,
				Project:  project,
				CanRead:  true,
				CanWrite: true,
			}, nil
		}
	}

	auth, err := s.loadAuthConfig()
	if err != nil {
		return Principal{}, err
	}
	matchedToken := false
	now := s.nowFn().UTC()
	for _, grant := range auth.Tokens {
		// SECURITY: tokenGrantMatches prefers a hashed-at-rest comparison and
		// falls back to the legacy plaintext compare so existing deployments
		// keep working while operators migrate to TokenHash + TokenHashSalt.
		if !tokenGrantMatches(grant, token) {
			continue
		}
		// Expiry check after the hash compare so we don't reveal anything
		// about non-matching grants. We mark "matched token but unusable"
		// distinctly from "no match" so callers can return the right code.
		if err := grantValidityWindow(grant, now); err != nil {
			matchedToken = true
			continue
		}
		matchedToken = true
		if !matchScope(tenant, strings.TrimSpace(grant.Tenant)) {
			continue
		}
		if project == "" {
			if !tenantWideAccess(grant.Projects) {
				continue
			}
		} else {
			if !matchProject(project, grant.Projects) {
				continue
			}
		}
		canRead := grant.CanRead || grant.CanWrite
		canWrite := grant.CanWrite
		if write && !canWrite {
			continue
		}
		if !write && !canRead {
			continue
		}
		subject := strings.TrimSpace(grant.Subject)
		if subject == "" {
			subject = "token"
		}
		return Principal{
			Subject:  subject,
			Tenant:   tenant,
			Project:  project,
			CanRead:  canRead,
			CanWrite: canWrite,
		}, nil
	}

	if matchedToken {
		return Principal{}, ErrForbidden
	}
	return Principal{}, ErrUnauthorized
}

func (s Store) AuthorizeRead(token, tenant, project string) (Principal, error) {
	principal, err := s.AuthorizeToken(token, tenant, project, false)
	if err == nil {
		return principal, nil
	}
	if !errors.Is(err, ErrUnauthorized) && !errors.Is(err, ErrForbidden) {
		return Principal{}, err
	}
	projectMeta, projectErr := s.GetProject(tenant, project)
	if projectErr != nil {
		return Principal{}, err
	}
	if projectMeta.Visibility != "public" {
		return Principal{}, err
	}
	return Principal{
		Subject: "anonymous",
		Tenant:  projectMeta.Tenant,
		Project: projectMeta.Project,
		CanRead: true,
	}, nil
}

func (s Store) UploadArtifact(input UploadInput) (UploadResult, error) {
	tenant, err := validateID("tenant", input.Tenant)
	if err != nil {
		return UploadResult{}, err
	}
	projectID, err := validateID("project", input.Project)
	if err != nil {
		return UploadResult{}, err
	}
	artifactName, err := validateID("artifact_name", input.ArtifactName)
	if err != nil {
		return UploadResult{}, err
	}
	artifactVersion, err := validateID("artifact_version", input.ArtifactVersion)
	if err != nil {
		return UploadResult{}, err
	}
	if input.ArtifactReader == nil {
		return UploadResult{}, fmt.Errorf("artifact reader is required")
	}
	projectMeta, err := s.GetProject(tenant, projectID)
	if err != nil {
		return UploadResult{}, err
	}
	limits := readQuotaLimits()

	existing, err := registry.ListArtifactVersions(s.projectRootDir(tenant, projectID), artifactName, 0)
	if err != nil {
		return UploadResult{}, fmt.Errorf("list existing artifact versions: %w", err)
	}
	if limits.MaxArtifactVersionsPerName > 0 && len(existing) >= limits.MaxArtifactVersionsPerName {
		return UploadResult{}, fmt.Errorf(
			"%w: artifact %s reached max versions per name (%d)",
			ErrQuotaExceeded,
			artifactName,
			limits.MaxArtifactVersionsPerName,
		)
	}
	for _, rec := range existing {
		if rec.ArtifactVersion == artifactVersion {
			return UploadResult{}, fmt.Errorf("%w: artifact %s version %s already exists", ErrConflict, artifactName, artifactVersion)
		}
	}

	projectRoot := s.projectRootDir(tenant, projectID)
	tempDir := filepath.Join(projectRoot, "artifacts", ".tmp")
	if err := os.MkdirAll(tempDir, 0o755); err != nil {
		return UploadResult{}, fmt.Errorf("create temp artifact directory: %w", err)
	}
	tempPath := filepath.Join(tempDir, fmt.Sprintf("upload-%d.bin", s.nowFn().UnixNano()))
	tempFile, err := os.Create(tempPath)
	if err != nil {
		return UploadResult{}, fmt.Errorf("create temp artifact file: %w", err)
	}

	hasher := sha256.New()
	size, copyErr := io.Copy(io.MultiWriter(tempFile, hasher), input.ArtifactReader)
	closeErr := tempFile.Close()
	if copyErr != nil {
		_ = os.Remove(tempPath)
		return UploadResult{}, fmt.Errorf("write artifact payload: %w", copyErr)
	}
	if closeErr != nil {
		_ = os.Remove(tempPath)
		return UploadResult{}, fmt.Errorf("close temp artifact file: %w", closeErr)
	}
	if limits.MaxArtifactBytes > 0 && size > limits.MaxArtifactBytes {
		_ = os.Remove(tempPath)
		return UploadResult{}, fmt.Errorf(
			"%w: artifact size %d exceeds max artifact bytes %d",
			ErrQuotaExceeded,
			size,
			limits.MaxArtifactBytes,
		)
	}
	if limits.MaxProjectStorageBytes > 0 {
		currentStorage, err := s.projectStorageUsage(projectRoot)
		if err != nil {
			_ = os.Remove(tempPath)
			return UploadResult{}, fmt.Errorf("compute project storage usage: %w", err)
		}
		if currentStorage+size > limits.MaxProjectStorageBytes {
			_ = os.Remove(tempPath)
			return UploadResult{}, fmt.Errorf(
				"%w: project storage would exceed max bytes (%d + %d > %d)",
				ErrQuotaExceeded,
				currentStorage,
				size,
				limits.MaxProjectStorageBytes,
			)
		}
	}

	artifactSHA := hex.EncodeToString(hasher.Sum(nil))
	expected := strings.TrimSpace(strings.ToLower(input.ExpectedSHA256))
	if expected != "" && expected != artifactSHA {
		_ = os.Remove(tempPath)
		return UploadResult{}, fmt.Errorf("artifact sha256 mismatch: expected %s got %s", expected, artifactSHA)
	}

	finalDir := filepath.Join(projectRoot, "artifacts", artifactName, artifactVersion)
	if err := os.MkdirAll(finalDir, 0o755); err != nil {
		_ = os.Remove(tempPath)
		return UploadResult{}, fmt.Errorf("create artifact version directory: %w", err)
	}
	finalPath := filepath.Join(finalDir, artifactSHA+".bpf.o")
	if _, statErr := os.Stat(finalPath); statErr == nil {
		_ = os.Remove(tempPath)
	} else {
		if err := os.Rename(tempPath, finalPath); err != nil {
			_ = os.Remove(tempPath)
			return UploadResult{}, fmt.Errorf("move artifact into project storage: %w", err)
		}
	}

	compat := normalizeCompatibility(input.Compatibility)
	if input.Report != nil {
		compat = metadataFromReport(*input.Report)
	}
	if compat.TotalProfiles == 0 {
		compat.TotalProfiles = compat.RequiredPassed + compat.RequiredFailed
	}
	if compat.SummaryStatus == "" {
		compat.SummaryStatus = "unknown"
	}

	reportPath, err := s.writeUploadSummary(projectRoot, artifactName, artifactVersion, artifactSHA, size, compat, input.Report)
	if err != nil {
		return UploadResult{}, err
	}

	now := s.nowFn().UTC().Format(time.RFC3339)
	runID := strings.TrimSpace(input.SourceRunID)
	if runID == "" {
		runID = "upload-" + s.nowFn().UTC().Format("20060102T150405Z")
	}

	record := registry.ArtifactVersionRecord{
		RunID:              runID,
		RunStartedAt:       now,
		CreatedAt:          now,
		ArtifactName:       artifactName,
		ArtifactVersion:    artifactVersion,
		ArtifactVariant:    strings.TrimSpace(input.ArtifactVariant),
		ArtifactPath:       finalPath,
		ArtifactURI:        strings.TrimSpace(input.ArtifactURI),
		ArtifactSHA256:     artifactSHA,
		ManifestPath:       strings.TrimSpace(input.ManifestPath),
		MatrixPath:         compat.MatrixPath,
		MatrixName:         compat.MatrixName,
		SummaryStatus:      compat.SummaryStatus,
		RequiredPassed:     compat.RequiredPassed,
		RequiredFailed:     compat.RequiredFailed,
		TotalProfiles:      compat.TotalProfiles,
		SupportedProfiles:  compat.SupportedProfiles,
		FailedProfiles:     compat.FailedProfiles,
		ClassificationCode: compat.ClassificationCode,
		JSONReportPath:     reportPath,
		MarkdownPath:       compat.MarkdownPath,
	}

	if err := registry.PersistArtifactVersion(projectRoot, record); err != nil {
		return UploadResult{}, fmt.Errorf("persist project artifact metadata: %w", err)
	}

	storedRecord, err := registry.FindArtifactVersion(projectRoot, artifactName, artifactVersion)
	if err != nil {
		return UploadResult{}, fmt.Errorf("resolve stored artifact metadata: %w", err)
	}

	return UploadResult{
		Project:           projectMeta,
		Record:            storedRecord,
		StoredArtifact:    finalPath,
		StoredArtifactURI: storedRecord.ArtifactURI,
		ArtifactSizeBytes: size,
	}, nil
}

func (s Store) ListArtifactVersions(tenant, project, artifactName string, limit int) ([]registry.ArtifactVersionRecord, error) {
	tenant, err := validateID("tenant", tenant)
	if err != nil {
		return nil, err
	}
	project, err = validateID("project", project)
	if err != nil {
		return nil, err
	}
	if _, err := s.GetProject(tenant, project); err != nil {
		return nil, err
	}
	return registry.ListArtifactVersions(s.projectRootDir(tenant, project), strings.TrimSpace(artifactName), limit)
}

func (s Store) ResolveArtifactVersion(tenant, project, artifactName, version string) (registry.ArtifactVersionRecord, error) {
	tenant, err := validateID("tenant", tenant)
	if err != nil {
		return registry.ArtifactVersionRecord{}, err
	}
	project, err = validateID("project", project)
	if err != nil {
		return registry.ArtifactVersionRecord{}, err
	}
	artifactName, err = validateID("artifact_name", artifactName)
	if err != nil {
		return registry.ArtifactVersionRecord{}, err
	}
	version, err = validateID("version", version)
	if err != nil {
		return registry.ArtifactVersionRecord{}, err
	}
	record, err := registry.FindArtifactVersion(s.projectRootDir(tenant, project), artifactName, version)
	if errors.Is(err, registry.ErrNotFound) {
		return registry.ArtifactVersionRecord{}, ErrNotFound
	}
	if err != nil {
		return registry.ArtifactVersionRecord{}, err
	}
	return record, nil
}

func (s Store) VerifyHistory(tenant, project string) ([]registry.ArtifactVersionVerification, error) {
	tenant, err := validateID("tenant", tenant)
	if err != nil {
		return nil, err
	}
	project, err = validateID("project", project)
	if err != nil {
		return nil, err
	}
	if _, err := s.GetProject(tenant, project); err != nil {
		return nil, err
	}
	return registry.VerifyArtifactVersionHistory(s.projectRootDir(tenant, project))
}

func (s Store) AppendAudit(event AuditEvent) (AuditEvent, error) {
	event.Action = strings.TrimSpace(strings.ToLower(event.Action))
	if event.Action == "" {
		return AuditEvent{}, fmt.Errorf("audit action is required")
	}
	if event.Status == "" {
		event.Status = "success"
	}
	if event.SchemaVersion == "" {
		event.SchemaVersion = auditEventSchemaVersion
	}
	if event.CreatedAt == "" {
		event.CreatedAt = s.nowFn().UTC().Format(time.RFC3339)
	}
	if event.EventID == "" {
		event.EventID = s.nowFn().UTC().Format("20060102T150405.000000000Z")
	}

	if strings.TrimSpace(event.Tenant) != "" {
		tenant, err := validateID("tenant", event.Tenant)
		if err != nil {
			return AuditEvent{}, err
		}
		event.Tenant = tenant
	}
	if strings.TrimSpace(event.Project) != "" {
		project, err := validateID("project", event.Project)
		if err != nil {
			return AuditEvent{}, err
		}
		event.Project = project
	}

	path := filepath.Join(s.rootDir, "audit", "events.jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return AuditEvent{}, fmt.Errorf("create cloud registry audit directory: %w", err)
	}
	line, err := json.Marshal(event)
	if err != nil {
		return AuditEvent{}, fmt.Errorf("marshal cloud registry audit event: %w", err)
	}
	// Rotate before write so a single oversized payload can't push us past
	// the cap on a fresh file. Rotation failures are surfaced — losing audit
	// data silently is worse than a noisy 5xx, and the upstream caller
	// already treats AppendAudit best-effort via appendRegistryAuditBestEffort.
	if err := rotateAuditLogIfNeeded(path, auditRotationLimits()); err != nil {
		return AuditEvent{}, fmt.Errorf("rotate cloud registry audit stream: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return AuditEvent{}, fmt.Errorf("open cloud registry audit stream: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return AuditEvent{}, fmt.Errorf("append cloud registry audit event: %w", err)
	}
	return event, nil
}

// auditRotationConfig captures the operator-tunable rotation knobs in one
// place so AppendAudit and ListAuditEvents stay consistent.
type auditRotationConfig struct {
	MaxBytes int64
	MaxFiles int
}

// auditRotationLimits resolves rotation knobs from env with safe defaults.
// A non-positive max bytes disables rotation (preserves legacy behaviour for
// callers that explicitly opt out).
func auditRotationLimits() auditRotationConfig {
	cfg := auditRotationConfig{
		MaxBytes: defaultAuditMaxBytes,
		MaxFiles: defaultAuditMaxFiles,
	}
	if raw := strings.TrimSpace(os.Getenv(auditMaxBytesEnv)); raw != "" {
		if n, err := strconv.ParseInt(raw, 10, 64); err == nil {
			cfg.MaxBytes = n
		}
	}
	if raw := strings.TrimSpace(os.Getenv(auditMaxFilesEnv)); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 1 {
			cfg.MaxFiles = n
		}
	}
	return cfg
}

// rotateAuditLogIfNeeded checks the active log and, if it exceeds MaxBytes,
// shifts the file ring (path.N-1 -> path.N, ..., path.1 -> path.2, path -> path.1)
// dropping the oldest rotation. A non-positive MaxBytes is a no-op so tests
// and "infinite retention" deployments can opt out.
func rotateAuditLogIfNeeded(path string, cfg auditRotationConfig) error {
	if cfg.MaxBytes <= 0 {
		return nil
	}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat audit stream: %w", err)
	}
	if info.Size() < cfg.MaxBytes {
		return nil
	}
	// Walk from the oldest retained slot backward so we never overwrite a
	// file we still need. The oldest file is dropped; the active file is
	// moved into slot .1 last.
	maxFiles := cfg.MaxFiles
	if maxFiles < 1 {
		maxFiles = 1
	}
	for i := maxFiles - 1; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", path, i)
		dst := fmt.Sprintf("%s.%d", path, i+1)
		if i == maxFiles-1 {
			// The slot one before the last is being shifted into the last
			// slot; the file currently at the last slot must be removed
			// first to make room.
			if _, err := os.Stat(dst); err == nil {
				if err := os.Remove(dst); err != nil {
					return fmt.Errorf("remove oldest audit rotation %q: %w", dst, err)
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("stat oldest audit rotation %q: %w", dst, err)
			}
		}
		if _, err := os.Stat(src); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return fmt.Errorf("stat audit rotation %q: %w", src, err)
		}
		if err := os.Rename(src, dst); err != nil {
			return fmt.Errorf("rotate audit %q -> %q: %w", src, dst, err)
		}
	}
	if err := os.Rename(path, path+".1"); err != nil {
		return fmt.Errorf("rotate active audit log to .1: %w", err)
	}
	return nil
}

func (s Store) ListAuditEvents(tenant, project string, limit int) ([]AuditEvent, error) {
	if strings.TrimSpace(tenant) != "" {
		var err error
		tenant, err = validateID("tenant", tenant)
		if err != nil {
			return nil, err
		}
	}
	if strings.TrimSpace(project) != "" {
		var err error
		project, err = validateID("project", project)
		if err != nil {
			return nil, err
		}
	}

	basePath := filepath.Join(s.rootDir, "audit", "events.jsonl")

	events := make([]AuditEvent, 0)
	// Read active file first, then rotated files in numeric order (.1, .2, ...).
	// All shards merge into one slice and sort at the end.
	paths := auditLogShardPaths(basePath, auditRotationLimits().MaxFiles)
	for _, p := range paths {
		shardEvents, err := readAuditShard(p, tenant, project)
		if err != nil {
			return nil, err
		}
		events = append(events, shardEvents...)
	}

	sort.SliceStable(events, func(i, j int) bool {
		if events[i].CreatedAt == events[j].CreatedAt {
			return events[i].EventID > events[j].EventID
		}
		return events[i].CreatedAt > events[j].CreatedAt
	})
	if limit > 0 && len(events) > limit {
		events = events[:limit]
	}
	return events, nil
}

// auditLogShardPaths returns the audit shard files in priority order: the
// active log first, then rotated copies oldest to newest by suffix index.
// Callers merge and re-sort by CreatedAt so the on-disk order doesn't have
// to be authoritative.
func auditLogShardPaths(basePath string, maxFiles int) []string {
	paths := []string{basePath}
	if maxFiles < 1 {
		maxFiles = 1
	}
	for i := 1; i <= maxFiles; i++ {
		paths = append(paths, fmt.Sprintf("%s.%d", basePath, i))
	}
	return paths
}

// readAuditShard reads a single audit-log file applying the tenant/project
// filters. A missing file is treated as empty (a rotation may have removed
// the oldest shard between the dir listing and the read).
func readAuditShard(path, tenant, project string) ([]AuditEvent, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open cloud registry audit stream %q: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	// SECURITY: raise the per-line cap so audit records with rich metadata
	// don't silently truncate the audit stream when read.
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	events := make([]AuditEvent, 0)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var event AuditEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			return nil, fmt.Errorf("parse cloud registry audit event in %q: %w", path, err)
		}
		if tenant != "" && event.Tenant != tenant {
			continue
		}
		if project != "" && event.Project != project {
			continue
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan cloud registry audit stream %q: %w", path, err)
	}
	return events, nil
}

// LoadAuthConfig exposes the parsed tokens.json for admin tooling
// (bpfcompat admin list-tokens / revoke-token). Mirrors loadAuthConfig but
// is exported deliberately so cmd/bpfcompat can read the file via the
// store's path conventions instead of duplicating filepath.Join. Returns a
// zero-value AuthConfig with no error when the file doesn't exist — a
// brand-new install legitimately has no tokens.
func (s Store) LoadAuthConfig() (AuthConfig, error) {
	return s.loadAuthConfig()
}

// WriteAuthConfig atomically replaces tokens.json with cfg. Uses the
// rename-into-place pattern so a crash mid-write never leaves operators
// staring at a truncated tokens file (which would break authentication
// for every project). Fails if cfg.SchemaVersion is empty so we never
// downgrade an existing file's schema by accident.
func (s Store) WriteAuthConfig(cfg AuthConfig) error {
	if strings.TrimSpace(cfg.SchemaVersion) == "" {
		return fmt.Errorf("auth config schema_version is required")
	}
	dir := filepath.Join(s.rootDir, "auth")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create auth dir: %w", err)
	}
	payload, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal auth config: %w", err)
	}
	payload = append(payload, '\n')
	finalPath := filepath.Join(dir, "tokens.json")
	tmp, err := os.CreateTemp(dir, "tokens.json-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp auth config: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		if tmpPath != "" {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp auth config: %w", err)
	}
	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp auth config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp auth config: %w", err)
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return fmt.Errorf("install auth config: %w", err)
	}
	tmpPath = ""
	return nil
}

func (s Store) loadAuthConfig() (AuthConfig, error) {
	path := filepath.Join(s.rootDir, "auth", "tokens.json")
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return AuthConfig{}, nil
	}
	if err != nil {
		return AuthConfig{}, fmt.Errorf("read cloud registry auth config: %w", err)
	}
	var cfg AuthConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return AuthConfig{}, fmt.Errorf("parse cloud registry auth config: %w", err)
	}
	if cfg.SchemaVersion == "" {
		cfg.SchemaVersion = authSchemaVersion
	}
	return cfg, nil
}

func (s Store) projectRootDir(tenant, project string) string {
	return filepath.Join(s.rootDir, "tenants", tenant, "projects", project)
}

func (s Store) projectMetadataPath(tenant, project string) string {
	return filepath.Join(s.projectRootDir(tenant, project), "project.json")
}

func (s Store) writeUploadSummary(
	projectRoot, artifactName, artifactVersion, artifactSHA string,
	size int64,
	compat CompatibilityMetadata,
	report *schema.ReportV01,
) (string, error) {
	reportDir := filepath.Join(projectRoot, "reports")
	if err := os.MkdirAll(reportDir, 0o755); err != nil {
		return "", fmt.Errorf("create project report directory: %w", err)
	}
	reportPath := filepath.Join(reportDir, fmt.Sprintf("%s-%s-%s.json", artifactName, artifactVersion, artifactSHA[:12]))

	var payload any
	if report != nil {
		payload = report
	} else {
		payload = map[string]any{
			"schema_version": uploadSummarySchemaVersion,
			"artifact": map[string]any{
				"name":       artifactName,
				"version":    artifactVersion,
				"sha256":     artifactSHA,
				"size_bytes": size,
			},
			"compatibility": compat,
		}
	}
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal upload summary report: %w", err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(reportPath, raw, 0o644); err != nil {
		return "", fmt.Errorf("write upload summary report: %w", err)
	}
	return reportPath, nil
}

func validateID(field, value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("%s is required", field)
	}
	if !idPattern.MatchString(value) {
		return "", fmt.Errorf("%s must match %s", field, idPattern.String())
	}
	return value, nil
}

func normalizeVisibility(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "private", nil
	}
	switch value {
	case "private", "public":
		return value, nil
	default:
		return "", fmt.Errorf("visibility must be private or public")
	}
}

func normalizeCompatibility(meta CompatibilityMetadata) CompatibilityMetadata {
	meta.SummaryStatus = strings.TrimSpace(strings.ToLower(meta.SummaryStatus))
	if meta.SummaryStatus == "" {
		meta.SummaryStatus = "unknown"
	}
	meta.SupportedProfiles = dedupeSorted(meta.SupportedProfiles)
	meta.FailedProfiles = dedupeSorted(meta.FailedProfiles)
	meta.ClassificationCode = dedupeSorted(meta.ClassificationCode)
	meta.MatrixPath = strings.TrimSpace(meta.MatrixPath)
	meta.MatrixName = strings.TrimSpace(meta.MatrixName)
	meta.MarkdownPath = strings.TrimSpace(meta.MarkdownPath)
	return meta
}

func metadataFromReport(report schema.ReportV01) CompatibilityMetadata {
	meta := CompatibilityMetadata{
		SummaryStatus: strings.TrimSpace(strings.ToLower(report.Summary.Status)),
		MatrixPath:    strings.TrimSpace(report.Matrix.Path),
		MatrixName:    strings.TrimSpace(report.Matrix.Name),
		MarkdownPath:  strings.TrimSpace(report.Paths.Markdown),
		TotalProfiles: len(report.Targets),
	}
	classificationCodes := make([]string, 0)
	supported := make([]string, 0)
	failed := make([]string, 0)
	for _, target := range report.Targets {
		if target.Required {
			if target.Status == "pass" {
				meta.RequiredPassed++
			} else {
				meta.RequiredFailed++
			}
		}
		if target.Status == "pass" {
			supported = append(supported, strings.TrimSpace(target.ProfileID))
		} else {
			failed = append(failed, strings.TrimSpace(target.ProfileID))
		}
		if code := strings.TrimSpace(target.ClassificationCode); code != "" {
			classificationCodes = append(classificationCodes, code)
		}
	}
	meta.SupportedProfiles = dedupeSorted(supported)
	meta.FailedProfiles = dedupeSorted(failed)
	meta.ClassificationCode = dedupeSorted(classificationCodes)
	if meta.SummaryStatus == "" {
		meta.SummaryStatus = "unknown"
	}
	return meta
}

func dedupeSorted(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func matchScope(value, pattern string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" || pattern == "*" {
		return true
	}
	return value == pattern
}

func matchProject(project string, patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" || pattern == "*" {
			return true
		}
		if project == pattern {
			return true
		}
	}
	return false
}

func tenantWideAccess(patterns []string) bool {
	for _, pattern := range patterns {
		if strings.TrimSpace(pattern) == "*" {
			return true
		}
	}
	return false
}

func readQuotaLimits() quotaLimits {
	limits := quotaLimits{
		MaxArtifactBytes:           64 << 20, // 64 MiB
		MaxArtifactVersionsPerName: 200,
		MaxProjectStorageBytes:     2 << 30, // 2 GiB
	}
	limits.MaxArtifactBytes = parseEnvInt64(maxArtifactBytesEnv, limits.MaxArtifactBytes)
	limits.MaxArtifactVersionsPerName = parseEnvInt(maxArtifactVersionsPerNameEnv, limits.MaxArtifactVersionsPerName)
	limits.MaxProjectStorageBytes = parseEnvInt64(maxProjectStorageBytesEnv, limits.MaxProjectStorageBytes)
	return limits
}

func parseEnvInt(name string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 0 {
		return fallback
	}
	return value
}

func parseEnvInt64(name string, fallback int64) int64 {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value < 0 {
		return fallback
	}
	return value
}

func (s Store) projectStorageUsage(projectRoot string) (int64, error) {
	records, err := registry.ListArtifactVersions(projectRoot, "", 0)
	if err != nil {
		return 0, err
	}
	seen := make(map[string]struct{}, len(records))
	var total int64
	for _, record := range records {
		artifactPath := strings.TrimSpace(record.ArtifactPath)
		if artifactPath == "" {
			continue
		}
		if _, ok := seen[artifactPath]; ok {
			continue
		}
		seen[artifactPath] = struct{}{}
		info, err := os.Stat(filepath.Clean(artifactPath))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return 0, err
		}
		total += info.Size()
	}
	return total, nil
}
