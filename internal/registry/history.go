package registry

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

const artifactHistorySchemaVersion = "artifact_history.v0.1"
const (
	artifactHistorySignatureAlgorithm = "ed25519"
	artifactSigningPrivateKeyPath     = "keys/artifact-registry-signing-key.ed25519"
	artifactSigningPublicKeyPath      = "keys/artifact-registry-signing-key.pub"
	artifactTrustedKeyringPath        = "keys/trusted-signing-keys.pub"
	artifactSigningModeEnv            = "BPFCOMPAT_SIGNING_MODE"
	artifactSigningModeExternalCmd    = "external-cmd"
	artifactSigningExternalCmdEnv     = "BPFCOMPAT_SIGNING_EXTERNAL_CMD"
	artifactSigningExternalArgsEnv    = "BPFCOMPAT_SIGNING_EXTERNAL_ARGS"
	artifactTrustedKeysEnv            = "BPFCOMPAT_TRUSTED_SIGNING_PUBLIC_KEYS"
	artifactTrustedKeyringPathEnv     = "BPFCOMPAT_TRUSTED_SIGNING_KEYS_PATH"
)

var ErrNotFound = errors.New("registry record not found")

type ArtifactVersionRecord struct {
	SchemaVersion      string   `json:"schema_version"`
	RunID              string   `json:"run_id"`
	RunStartedAt       string   `json:"run_started_at"`
	CreatedAt          string   `json:"created_at"`
	ArtifactName       string   `json:"artifact_name"`
	ArtifactVersion    string   `json:"artifact_version"`
	ArtifactVariant    string   `json:"artifact_variant,omitempty"`
	ArtifactPath       string   `json:"artifact_path"`
	ArtifactURI        string   `json:"artifact_uri,omitempty"`
	ArtifactSHA256     string   `json:"artifact_sha256"`
	RecordSHA256       string   `json:"record_sha256,omitempty"`
	PrevRecordSHA256   string   `json:"prev_record_sha256,omitempty"`
	SignatureAlg       string   `json:"signature_alg,omitempty"`
	SignatureKeyID     string   `json:"signature_key_id,omitempty"`
	SignaturePublicKey string   `json:"signature_public_key,omitempty"`
	Signature          string   `json:"signature,omitempty"`
	ManifestPath       string   `json:"manifest_path,omitempty"`
	MatrixPath         string   `json:"matrix_path"`
	MatrixName         string   `json:"matrix_name,omitempty"`
	SummaryStatus      string   `json:"summary_status"`
	RequiredPassed     int      `json:"required_passed"`
	RequiredFailed     int      `json:"required_failed"`
	TotalProfiles      int      `json:"total_profiles"`
	SupportedProfiles  []string `json:"supported_profiles,omitempty"`
	FailedProfiles     []string `json:"failed_profiles,omitempty"`
	ClassificationCode []string `json:"classification_codes,omitempty"`
	JSONReportPath     string   `json:"json_report_path"`
	MarkdownPath       string   `json:"markdown_path,omitempty"`
}

func PersistArtifactVersion(workDir string, record ArtifactVersionRecord) error {
	if workDir == "" {
		return fmt.Errorf("workdir is required")
	}
	if strings.TrimSpace(record.ArtifactName) == "" {
		return fmt.Errorf("artifact_name is required")
	}
	if strings.TrimSpace(record.ArtifactVersion) == "" {
		return fmt.Errorf("artifact_version is required")
	}
	if strings.TrimSpace(record.ArtifactSHA256) == "" {
		return fmt.Errorf("artifact_sha256 is required")
	}
	if strings.TrimSpace(record.JSONReportPath) == "" {
		return fmt.Errorf("json_report_path is required")
	}
	if record.SchemaVersion == "" {
		record.SchemaVersion = artifactHistorySchemaVersion
	}
	record.SupportedProfiles = dedupeSorted(record.SupportedProfiles)
	record.FailedProfiles = dedupeSorted(record.FailedProfiles)
	record.ClassificationCode = dedupeSorted(record.ClassificationCode)
	if err := applyArtifactRecordProvenance(workDir, &record); err != nil {
		return err
	}

	registryDir := filepath.Join(filepath.Clean(workDir), "registry")
	if err := os.MkdirAll(registryDir, 0o755); err != nil {
		return fmt.Errorf("create registry directory: %w", err)
	}

	indexPath := filepath.Join(registryDir, "artifact_versions.jsonl")
	f, err := os.OpenFile(indexPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open artifact history index: %w", err)
	}
	defer f.Close()

	line, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal artifact history record: %w", err)
	}
	line = append(line, '\n')
	if _, err := f.Write(line); err != nil {
		return fmt.Errorf("append artifact history record: %w", err)
	}
	return nil
}

type ArtifactVersionVerification struct {
	Index              int      `json:"index"`
	RunID              string   `json:"run_id"`
	ArtifactName       string   `json:"artifact_name"`
	ArtifactVersion    string   `json:"artifact_version"`
	RecordSHA256       string   `json:"record_sha256,omitempty"`
	ComputedSHA256     string   `json:"computed_sha256"`
	PrevRecordSHA256   string   `json:"prev_record_sha256,omitempty"`
	ExpectedPrevSHA256 string   `json:"expected_prev_sha256,omitempty"`
	SignatureAlg       string   `json:"signature_alg,omitempty"`
	SignatureKeyID     string   `json:"signature_key_id,omitempty"`
	SignatureValid     bool     `json:"signature_valid"`
	Verified           bool     `json:"verified"`
	Issues             []string `json:"issues,omitempty"`
}

func VerifyArtifactVersionHistory(workDir string) ([]ArtifactVersionVerification, error) {
	indexPath := filepath.Join(filepath.Clean(workDir), "registry", "artifact_versions.jsonl")
	records, err := readArtifactVersionRecords(indexPath)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, nil
	}

	out := make([]ArtifactVersionVerification, 0, len(records))
	prevComputedHash := ""
	for i, record := range records {
		verification := ArtifactVersionVerification{
			Index:            i,
			RunID:            record.RunID,
			ArtifactName:     record.ArtifactName,
			ArtifactVersion:  record.ArtifactVersion,
			RecordSHA256:     strings.TrimSpace(record.RecordSHA256),
			PrevRecordSHA256: strings.TrimSpace(record.PrevRecordSHA256),
			SignatureAlg:     strings.TrimSpace(record.SignatureAlg),
			SignatureKeyID:   strings.TrimSpace(record.SignatureKeyID),
		}
		canonicalPayload, computedHash, err := artifactRecordCanonicalPayloadAndHash(record)
		if err != nil {
			verification.Issues = append(verification.Issues, fmt.Sprintf("compute canonical hash: %v", err))
		} else {
			verification.ComputedSHA256 = computedHash
			if verification.RecordSHA256 == "" {
				verification.Issues = append(verification.Issues, "record_sha256 is missing")
			} else if verification.RecordSHA256 != computedHash {
				verification.Issues = append(verification.Issues, "record_sha256 mismatch")
			}
		}

		if i == 0 {
			if verification.PrevRecordSHA256 != "" {
				verification.Issues = append(verification.Issues, "first record should not have prev_record_sha256")
			}
		} else {
			verification.ExpectedPrevSHA256 = prevComputedHash
			if verification.PrevRecordSHA256 == "" {
				verification.Issues = append(verification.Issues, "prev_record_sha256 is missing")
			} else if verification.PrevRecordSHA256 != prevComputedHash {
				verification.Issues = append(verification.Issues, "prev_record_sha256 mismatch")
			}
		}

		signatureValid, sigErr := verifyArtifactRecordSignature(workDir, record, canonicalPayload)
		if sigErr != nil {
			verification.Issues = append(verification.Issues, sigErr.Error())
		}
		verification.SignatureValid = signatureValid

		if len(verification.Issues) == 0 {
			verification.Verified = true
		}
		out = append(out, verification)

		if verification.ComputedSHA256 != "" {
			prevComputedHash = verification.ComputedSHA256
		}
	}
	return out, nil
}

func BackfillArtifactVersionProvenance(workDir string) (int, error) {
	indexPath := filepath.Join(filepath.Clean(workDir), "registry", "artifact_versions.jsonl")
	records, err := readArtifactVersionRecords(indexPath)
	if err != nil {
		return 0, err
	}
	if len(records) == 0 {
		return 0, nil
	}

	signer, err := ensureArtifactRecordSigner(workDir)
	if err != nil {
		return 0, err
	}

	prevHash := ""
	for i := range records {
		record := records[i]
		record.PrevRecordSHA256 = prevHash
		canonicalPayload, computedHash, err := artifactRecordCanonicalPayloadAndHash(record)
		if err != nil {
			return 0, fmt.Errorf("compute canonical hash for record index %d: %w", i, err)
		}
		record.RecordSHA256 = computedHash
		envelope, err := signer.Sign(canonicalPayload)
		if err != nil {
			return 0, fmt.Errorf("sign record index %d: %w", i, err)
		}
		record.SignatureAlg = envelope.SignatureAlg
		record.SignatureKeyID = envelope.SignatureKeyID
		record.SignaturePublicKey = envelope.SignaturePublicKey
		record.Signature = envelope.Signature
		records[i] = record
		prevHash = computedHash
	}

	if err := os.MkdirAll(filepath.Dir(indexPath), 0o755); err != nil {
		return 0, fmt.Errorf("create registry directory: %w", err)
	}
	tmpPath := indexPath + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return 0, fmt.Errorf("create temporary artifact history file: %w", err)
	}
	for _, record := range records {
		line, err := json.Marshal(record)
		if err != nil {
			_ = f.Close()
			_ = os.Remove(tmpPath)
			return 0, fmt.Errorf("marshal artifact history record for backfill: %w", err)
		}
		if _, err := f.Write(append(line, '\n')); err != nil {
			_ = f.Close()
			_ = os.Remove(tmpPath)
			return 0, fmt.Errorf("write temporary artifact history record: %w", err)
		}
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return 0, fmt.Errorf("close temporary artifact history file: %w", err)
	}
	if err := os.Rename(tmpPath, indexPath); err != nil {
		_ = os.Remove(tmpPath)
		return 0, fmt.Errorf("replace artifact history index: %w", err)
	}
	return len(records), nil
}

func ListArtifactVersions(workDir, artifactName string, limit int) ([]ArtifactVersionRecord, error) {
	indexPath := filepath.Join(filepath.Clean(workDir), "registry", "artifact_versions.jsonl")
	records, err := readArtifactVersionRecords(indexPath)
	if err != nil {
		return nil, err
	}

	filtered := make([]ArtifactVersionRecord, 0, len(records))
	for _, record := range records {
		if artifactName != "" && record.ArtifactName != artifactName {
			continue
		}
		filtered = append(filtered, record)
	}

	sort.SliceStable(filtered, func(i, j int) bool {
		if filtered[i].CreatedAt == filtered[j].CreatedAt {
			return filtered[i].RunID > filtered[j].RunID
		}
		return filtered[i].CreatedAt > filtered[j].CreatedAt
	})

	if limit > 0 && len(filtered) > limit {
		filtered = filtered[:limit]
	}
	return filtered, nil
}

func FindArtifactVersion(workDir, artifactName, version string) (ArtifactVersionRecord, error) {
	if artifactName == "" || version == "" {
		return ArtifactVersionRecord{}, fmt.Errorf("artifact name and version are required")
	}
	records, err := ListArtifactVersions(workDir, artifactName, 0)
	if err != nil {
		return ArtifactVersionRecord{}, err
	}
	for _, record := range records {
		if record.ArtifactVersion == version {
			return record, nil
		}
	}
	return ArtifactVersionRecord{}, ErrNotFound
}

func ListRunRecords(workDir string, limit int) ([]RunRecord, error) {
	indexPath := filepath.Join(filepath.Clean(workDir), "registry", "runs.jsonl")
	records, err := readRunRecords(indexPath)
	if err != nil {
		return nil, err
	}

	sort.SliceStable(records, func(i, j int) bool {
		if records[i].StartedAt == records[j].StartedAt {
			return records[i].RunID > records[j].RunID
		}
		return records[i].StartedAt > records[j].StartedAt
	})

	if limit > 0 && len(records) > limit {
		records = records[:limit]
	}
	return records, nil
}

func GetRunRecord(workDir, runID string) (RunRecord, error) {
	if runID == "" {
		return RunRecord{}, fmt.Errorf("run_id is required")
	}
	records, err := ListRunRecords(workDir, 0)
	if err != nil {
		return RunRecord{}, err
	}
	for _, record := range records {
		if record.RunID == runID {
			return record, nil
		}
	}
	return RunRecord{}, ErrNotFound
}

func readArtifactVersionRecords(path string) ([]ArtifactVersionRecord, error) {
	lines, err := readJSONLLines(path)
	if err != nil {
		return nil, err
	}
	records := make([]ArtifactVersionRecord, 0, len(lines))
	for _, line := range lines {
		var record ArtifactVersionRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			return nil, fmt.Errorf("parse artifact history jsonl line: %w", err)
		}
		records = append(records, record)
	}
	return records, nil
}

func readRunRecords(path string) ([]RunRecord, error) {
	lines, err := readJSONLLines(path)
	if err != nil {
		return nil, err
	}
	records := make([]RunRecord, 0, len(lines))
	for _, line := range lines {
		var record RunRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			return nil, fmt.Errorf("parse run registry jsonl line: %w", err)
		}
		records = append(records, record)
	}
	return records, nil
}

func readJSONLLines(path string) ([]string, error) {
	f, err := os.Open(filepath.Clean(path))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open jsonl file %q: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	// SECURITY: bufio.NewScanner defaults to a 64KB max-token size. A single
	// record exceeding that would silently halt scanning, returning a
	// truncated history. Raise the cap to a comfortable margin so registry
	// records with rich metadata still parse.
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	lines := make([]string, 0)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan jsonl file %q: %w", path, err)
	}
	return lines, nil
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

func applyArtifactRecordProvenance(workDir string, record *ArtifactVersionRecord) error {
	if record == nil {
		return fmt.Errorf("record is required")
	}
	prevHash, err := previousArtifactRecordHash(workDir)
	if err != nil {
		return err
	}
	record.PrevRecordSHA256 = prevHash

	canonicalPayload, computedHash, err := artifactRecordCanonicalPayloadAndHash(*record)
	if err != nil {
		return fmt.Errorf("compute artifact record hash: %w", err)
	}
	record.RecordSHA256 = computedHash

	signer, err := ensureArtifactRecordSigner(workDir)
	if err != nil {
		return err
	}
	envelope, err := signer.Sign(canonicalPayload)
	if err != nil {
		return err
	}
	record.SignatureAlg = envelope.SignatureAlg
	record.SignatureKeyID = envelope.SignatureKeyID
	record.SignaturePublicKey = envelope.SignaturePublicKey
	record.Signature = envelope.Signature
	return nil
}

func previousArtifactRecordHash(workDir string) (string, error) {
	indexPath := filepath.Join(filepath.Clean(workDir), "registry", "artifact_versions.jsonl")
	records, err := readArtifactVersionRecords(indexPath)
	if err != nil {
		return "", err
	}
	if len(records) == 0 {
		return "", nil
	}
	last := records[len(records)-1]
	if strings.TrimSpace(last.RecordSHA256) != "" {
		return strings.TrimSpace(last.RecordSHA256), nil
	}
	_, computedHash, err := artifactRecordCanonicalPayloadAndHash(last)
	if err != nil {
		return "", fmt.Errorf("compute previous artifact record hash: %w", err)
	}
	return computedHash, nil
}

type artifactRegistrySigner struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
	KeyID      string
}

type artifactSignatureEnvelope struct {
	SignatureAlg       string `json:"signature_alg"`
	SignatureKeyID     string `json:"signature_key_id"`
	SignaturePublicKey string `json:"signature_public_key"`
	Signature          string `json:"signature"`
}

type trustedSigningKey struct {
	KeyID     string
	PublicKey ed25519.PublicKey
}

type artifactRecordSigner interface {
	Sign(payload []byte) (artifactSignatureEnvelope, error)
}

type localArtifactRecordSigner struct {
	signer artifactRegistrySigner
}

func (l localArtifactRecordSigner) Sign(payload []byte) (artifactSignatureEnvelope, error) {
	signature := ed25519.Sign(l.signer.PrivateKey, payload)
	return artifactSignatureEnvelope{
		SignatureAlg:       artifactHistorySignatureAlgorithm,
		SignatureKeyID:     l.signer.KeyID,
		SignaturePublicKey: base64.StdEncoding.EncodeToString(l.signer.PublicKey),
		Signature:          base64.StdEncoding.EncodeToString(signature),
	}, nil
}

type externalCommandArtifactRecordSigner struct {
	command string
	args    []string
}

func (s externalCommandArtifactRecordSigner) Sign(payload []byte) (artifactSignatureEnvelope, error) {
	if strings.TrimSpace(s.command) == "" {
		return artifactSignatureEnvelope{}, fmt.Errorf("external signer command is empty")
	}
	cmd := exec.Command(s.command, s.args...)
	cmd.Stdin = bytes.NewReader(payload)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return artifactSignatureEnvelope{}, fmt.Errorf("external signer command failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	var envelope artifactSignatureEnvelope
	if err := json.Unmarshal(output, &envelope); err != nil {
		return artifactSignatureEnvelope{}, fmt.Errorf("decode external signer output: %w", err)
	}
	if strings.TrimSpace(envelope.SignatureAlg) == "" {
		envelope.SignatureAlg = artifactHistorySignatureAlgorithm
	}
	if err := validateArtifactSignatureEnvelope(envelope, payload); err != nil {
		return artifactSignatureEnvelope{}, fmt.Errorf("invalid external signer envelope: %w", err)
	}
	return envelope, nil
}

func ensureArtifactRegistrySigner(workDir string) (artifactRegistrySigner, error) {
	privatePath := filepath.Join(filepath.Clean(workDir), artifactSigningPrivateKeyPath)
	publicPath := filepath.Join(filepath.Clean(workDir), artifactSigningPublicKeyPath)

	if raw, err := os.ReadFile(privatePath); err == nil {
		privateKey, err := decodeEd25519PrivateKey(strings.TrimSpace(string(raw)))
		if err != nil {
			return artifactRegistrySigner{}, fmt.Errorf("decode artifact registry signing private key: %w", err)
		}
		publicKey := ed25519.PublicKey(privateKey.Public().(ed25519.PublicKey))
		keyID := keyIDFromPublicKey(publicKey)
		return artifactRegistrySigner{
			PrivateKey: privateKey,
			PublicKey:  publicKey,
			KeyID:      keyID,
		}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return artifactRegistrySigner{}, fmt.Errorf("read artifact registry signing private key: %w", err)
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return artifactRegistrySigner{}, fmt.Errorf("generate artifact registry signing key: %w", err)
	}
	keyID := keyIDFromPublicKey(publicKey)

	if err := os.MkdirAll(filepath.Dir(privatePath), 0o700); err != nil {
		return artifactRegistrySigner{}, fmt.Errorf("create artifact registry key directory: %w", err)
	}
	if err := os.WriteFile(privatePath, []byte(base64.StdEncoding.EncodeToString(privateKey)+"\n"), 0o600); err != nil {
		return artifactRegistrySigner{}, fmt.Errorf("write artifact registry signing private key: %w", err)
	}
	publicPayload := fmt.Sprintf("%s %s\n", keyID, base64.StdEncoding.EncodeToString(publicKey))
	if err := os.WriteFile(publicPath, []byte(publicPayload), 0o644); err != nil {
		return artifactRegistrySigner{}, fmt.Errorf("write artifact registry signing public key: %w", err)
	}

	return artifactRegistrySigner{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		KeyID:      keyID,
	}, nil
}

func ensureArtifactRecordSigner(workDir string) (artifactRecordSigner, error) {
	mode := strings.TrimSpace(os.Getenv(artifactSigningModeEnv))
	switch mode {
	case "", "local":
		signer, err := ensureArtifactRegistrySigner(workDir)
		if err != nil {
			return nil, err
		}
		return localArtifactRecordSigner{signer: signer}, nil
	case artifactSigningModeExternalCmd:
		command := strings.TrimSpace(os.Getenv(artifactSigningExternalCmdEnv))
		if command == "" {
			return nil, fmt.Errorf("%s=external-cmd requires %s to be set", artifactSigningModeEnv, artifactSigningExternalCmdEnv)
		}
		args := splitExternalSignerArgs(os.Getenv(artifactSigningExternalArgsEnv))
		return externalCommandArtifactRecordSigner{
			command: command,
			args:    args,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported signing mode %q in %s", mode, artifactSigningModeEnv)
	}
}

func splitExternalSignerArgs(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	fields := strings.Fields(raw)
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		out = append(out, f)
	}
	return out
}

func decodeEd25519PrivateKey(raw string) (ed25519.PrivateKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	switch len(decoded) {
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(decoded), nil
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(decoded), nil
	default:
		return nil, fmt.Errorf("unexpected ed25519 private key length %d", len(decoded))
	}
}

func keyIDFromPublicKey(publicKey ed25519.PublicKey) string {
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:6])
}

func artifactRecordCanonicalPayloadAndHash(record ArtifactVersionRecord) ([]byte, string, error) {
	canonical := record
	canonical.RecordSHA256 = ""
	canonical.SignatureAlg = ""
	canonical.SignatureKeyID = ""
	canonical.SignaturePublicKey = ""
	canonical.Signature = ""
	payload, err := json.Marshal(canonical)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(payload)
	return payload, hex.EncodeToString(sum[:]), nil
}

func verifyArtifactRecordSignature(workDir string, record ArtifactVersionRecord, payload []byte) (bool, error) {
	signatureAlg := strings.TrimSpace(record.SignatureAlg)
	signatureRaw := strings.TrimSpace(record.Signature)
	pubRaw := strings.TrimSpace(record.SignaturePublicKey)
	keyID := strings.TrimSpace(record.SignatureKeyID)

	if signatureAlg == "" && signatureRaw == "" && pubRaw == "" && keyID == "" {
		return false, fmt.Errorf("signature metadata is missing")
	}
	if signatureAlg != artifactHistorySignatureAlgorithm {
		return false, fmt.Errorf("unsupported signature_alg %q", signatureAlg)
	}

	trustedKeys, err := loadTrustedSigningKeys(workDir)
	if err != nil {
		return false, err
	}
	if len(trustedKeys) == 0 {
		return false, fmt.Errorf(
			"no trusted signing keys configured (check %s, %s, or %s/%s)",
			artifactTrustedKeysEnv,
			artifactTrustedKeyringPathEnv,
			filepath.Clean(workDir),
			artifactSigningPublicKeyPath,
		)
	}

	if pubRaw != "" {
		recordPublicKey, err := decodeEd25519PublicKey(pubRaw)
		if err != nil {
			return false, fmt.Errorf("decode signature_public_key: %w", err)
		}
		for _, trusted := range trustedKeys {
			if keyID != "" && trusted.KeyID != "" && trusted.KeyID != keyID {
				continue
			}
			if string(trusted.PublicKey) != string(recordPublicKey) {
				continue
			}
			return verifyRecordSignatureWithKey(record, payload, trusted.PublicKey)
		}
		return false, fmt.Errorf("signature_public_key is not in trusted keyring")
	}

	for _, trusted := range trustedKeys {
		if keyID != "" && trusted.KeyID != "" && trusted.KeyID != keyID {
			continue
		}
		ok, err := verifyRecordSignatureWithKey(record, payload, trusted.PublicKey)
		if err != nil {
			continue
		}
		if ok {
			return true, nil
		}
	}
	return false, fmt.Errorf("signature verification failed with trusted keys")
}

func verifyRecordSignatureWithKey(record ArtifactVersionRecord, payload []byte, publicKey ed25519.PublicKey) (bool, error) {
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(record.Signature))
	if err != nil {
		return false, fmt.Errorf("decode signature: %w", err)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return false, fmt.Errorf("invalid trusted public key length %d", len(publicKey))
	}
	keyID := strings.TrimSpace(record.SignatureKeyID)
	if keyID != "" && keyIDFromPublicKey(publicKey) != keyID {
		return false, fmt.Errorf("signature_key_id mismatch")
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return false, fmt.Errorf("signature verification failed")
	}
	return true, nil
}

func decodeEd25519PublicKey(raw string) (ed25519.PublicKey, error) {
	publicKeyRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	if len(publicKeyRaw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid signature_public_key length %d", len(publicKeyRaw))
	}
	return ed25519.PublicKey(publicKeyRaw), nil
}

func loadTrustedSigningKeys(workDir string) ([]trustedSigningKey, error) {
	seen := make(map[string]struct{})
	keys := make([]trustedSigningKey, 0, 4)
	addKey := func(key trustedSigningKey) {
		if len(key.PublicKey) != ed25519.PublicKeySize {
			return
		}
		if key.KeyID == "" {
			key.KeyID = keyIDFromPublicKey(key.PublicKey)
		}
		encoded := base64.StdEncoding.EncodeToString(key.PublicKey)
		if _, ok := seen[encoded]; ok {
			return
		}
		seen[encoded] = struct{}{}
		keys = append(keys, key)
	}

	addFromFile := func(path string) error {
		raw, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read trusted signing key file %q: %w", path, err)
		}
		parsed, err := parseTrustedSigningKeysLines(string(raw))
		if err != nil {
			return fmt.Errorf("parse trusted signing key file %q: %w", path, err)
		}
		for _, key := range parsed {
			addKey(key)
		}
		return nil
	}

	if err := addFromFile(filepath.Join(filepath.Clean(workDir), artifactSigningPublicKeyPath)); err != nil {
		return nil, err
	}
	if err := addFromFile(filepath.Join(filepath.Clean(workDir), artifactTrustedKeyringPath)); err != nil {
		return nil, err
	}
	if externalPath := strings.TrimSpace(os.Getenv(artifactTrustedKeyringPathEnv)); externalPath != "" {
		if err := addFromFile(filepath.Clean(externalPath)); err != nil {
			return nil, err
		}
	}
	if inlineKeys := strings.TrimSpace(os.Getenv(artifactTrustedKeysEnv)); inlineKeys != "" {
		for _, raw := range splitInlineTrustedKeys(inlineKeys) {
			key, err := parseInlineTrustedKey(raw)
			if err != nil {
				return nil, fmt.Errorf("parse %s entry %q: %w", artifactTrustedKeysEnv, raw, err)
			}
			addKey(key)
		}
	}
	return keys, nil
}

func splitInlineTrustedKeys(raw string) []string {
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}

func parseInlineTrustedKey(raw string) (trustedSigningKey, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return trustedSigningKey{}, fmt.Errorf("empty trusted key entry")
	}
	keyID := ""
	publicRaw := raw
	if i := strings.Index(raw, ":"); i > 0 {
		keyID = strings.TrimSpace(raw[:i])
		publicRaw = strings.TrimSpace(raw[i+1:])
	}
	publicKey, err := decodeEd25519PublicKey(publicRaw)
	if err != nil {
		return trustedSigningKey{}, err
	}
	if keyID == "" {
		keyID = keyIDFromPublicKey(publicKey)
	}
	return trustedSigningKey{KeyID: keyID, PublicKey: publicKey}, nil
}

func parseTrustedSigningKeysLines(raw string) ([]trustedSigningKey, error) {
	lines := strings.Split(raw, "\n")
	keys := make([]trustedSigningKey, 0, len(lines))
	for idx, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		keyID := ""
		publicRaw := ""
		if len(fields) == 1 {
			publicRaw = fields[0]
		} else {
			keyID = strings.TrimSpace(fields[0])
			publicRaw = strings.TrimSpace(fields[1])
		}
		publicKey, err := decodeEd25519PublicKey(publicRaw)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", idx+1, err)
		}
		if keyID == "" {
			keyID = keyIDFromPublicKey(publicKey)
		}
		keys = append(keys, trustedSigningKey{
			KeyID:     keyID,
			PublicKey: publicKey,
		})
	}
	return keys, nil
}

func validateArtifactSignatureEnvelope(envelope artifactSignatureEnvelope, payload []byte) error {
	if strings.TrimSpace(envelope.SignatureAlg) == "" {
		return fmt.Errorf("signature_alg is missing")
	}
	if strings.TrimSpace(envelope.Signature) == "" {
		return fmt.Errorf("signature is missing")
	}
	if strings.TrimSpace(envelope.SignaturePublicKey) == "" {
		return fmt.Errorf("signature_public_key is missing")
	}
	record := ArtifactVersionRecord{
		SignatureAlg:       strings.TrimSpace(envelope.SignatureAlg),
		SignatureKeyID:     strings.TrimSpace(envelope.SignatureKeyID),
		SignaturePublicKey: strings.TrimSpace(envelope.SignaturePublicKey),
		Signature:          strings.TrimSpace(envelope.Signature),
	}
	publicKey, err := decodeEd25519PublicKey(record.SignaturePublicKey)
	if err != nil {
		return err
	}
	ok, err := verifyRecordSignatureWithKey(record, payload, publicKey)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}
