package conformance

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/kernel-guard/bpfcompat/internal/matrix"
	"gopkg.in/yaml.v3"
)

const (
	RuleReportSchema           = "report.schema"
	RuleReportFreshness        = "report.freshness"
	RuleSubjectLoaderIdentity  = "subject.loader_identity"
	RuleCommandContract        = "command.contract"
	RuleMatrixRequiredProfiles = "matrix.required_profiles"
	RuleEnvironmentIdentity    = "environment.actual_identity"
	RuleEnvironmentImageDigest = "environment.image_digest"
	RuleBehaviorCommandPass    = "behavior.command_pass"
)

var (
	profileIDPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,127}$`)
	assertionIDPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_-]{2,127}$`)
	propertyPattern    = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,127}$`)
	knownRules         = map[string]struct{}{
		RuleReportSchema:           {},
		RuleReportFreshness:        {},
		RuleSubjectLoaderIdentity:  {},
		RuleCommandContract:        {},
		RuleMatrixRequiredProfiles: {},
		RuleEnvironmentIdentity:    {},
		RuleEnvironmentImageDigest: {},
		RuleBehaviorCommandPass:    {},
	}
)

type ProfileDocument struct {
	Profile      Profile
	Raw          []byte
	SHA256       string
	Path         string
	Matrix       matrix.Matrix
	MatrixRaw    []byte
	MatrixSHA256 string
	MatrixPath   string
}

func LoadProfile(path string) (ProfileDocument, error) {
	profilePath, err := filepath.Abs(path)
	if err != nil {
		return ProfileDocument{}, fmt.Errorf("resolve conformance profile path: %w", err)
	}
	raw, err := os.ReadFile(profilePath)
	if err != nil {
		return ProfileDocument{}, fmt.Errorf("read conformance profile: %w", err)
	}

	var profile Profile
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	if err := decoder.Decode(&profile); err != nil {
		if !errors.Is(err, io.EOF) {
			return ProfileDocument{}, fmt.Errorf("parse conformance profile YAML: %w", err)
		}
	}
	var extraProfileDocument any
	if err := decoder.Decode(&extraProfileDocument); !errors.Is(err, io.EOF) {
		if err != nil {
			return ProfileDocument{}, fmt.Errorf("parse conformance profile YAML: %w", err)
		}
		return ProfileDocument{}, errors.New("conformance profile must contain exactly one YAML document")
	}
	if err := validateProfile(profile); err != nil {
		return ProfileDocument{}, err
	}

	matrixPath, err := resolveProfileResource(profilePath, profile.Matrix.Path)
	if err != nil {
		return ProfileDocument{}, err
	}
	matrixRaw, err := os.ReadFile(matrixPath)
	if err != nil {
		return ProfileDocument{}, fmt.Errorf("read conformance matrix: %w", err)
	}
	if err := requireSingleYAMLDocument(matrixRaw, "conformance matrix"); err != nil {
		return ProfileDocument{}, err
	}
	mx, err := matrix.LoadBytes(matrixRaw)
	if err != nil {
		return ProfileDocument{}, fmt.Errorf("load conformance matrix: %w", err)
	}
	for i := range mx.Profiles {
		if !mx.Profiles[i].RequiredBool() {
			return ProfileDocument{}, fmt.Errorf("conformance matrix profile %q must be required", mx.Profiles[i].ID)
		}
	}
	if err := validateEnvironmentMatrix(profile.Environments, mx); err != nil {
		return ProfileDocument{}, err
	}

	return ProfileDocument{
		Profile:      profile,
		Raw:          raw,
		SHA256:       digestBytes(raw),
		Path:         profilePath,
		Matrix:       mx,
		MatrixRaw:    matrixRaw,
		MatrixSHA256: digestBytes(matrixRaw),
		MatrixPath:   matrixPath,
	}, nil
}

func requireSingleYAMLDocument(raw []byte, label string) error {
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	var document any
	if err := decoder.Decode(&document); err != nil {
		return fmt.Errorf("parse %s YAML: %w", label, err)
	}
	if err := decoder.Decode(&document); !errors.Is(err, io.EOF) {
		if err != nil {
			return fmt.Errorf("parse %s YAML: %w", label, err)
		}
		return fmt.Errorf("%s must contain exactly one YAML document", label)
	}
	return nil
}

func validateProfile(profile Profile) error {
	if profile.SchemaVersion != ProfileSchemaVersion {
		return fmt.Errorf("unsupported conformance profile schema_version %q", profile.SchemaVersion)
	}
	if !profileIDPattern.MatchString(profile.ID) {
		return fmt.Errorf("profile id %q must match %s", profile.ID, profileIDPattern.String())
	}
	if strings.TrimSpace(profile.Title) == "" {
		return errors.New("profile title is required")
	}
	if profile.ProgramStatus != "preview" && profile.ProgramStatus != "active" {
		return fmt.Errorf("profile program_status %q must be preview or active", profile.ProgramStatus)
	}
	if err := validateHTTPSURI("profile_uri", profile.ProfileURI); err != nil {
		return err
	}
	if strings.TrimSpace(profile.Claim) == "" {
		return errors.New("profile claim is required")
	}
	if len(profile.ReportSchemaVersions) == 0 {
		return errors.New("profile report_schema_versions must not be empty")
	}
	if err := validateUniqueNonEmpty("report_schema_versions", profile.ReportSchemaVersions); err != nil {
		return err
	}
	if profile.Subject.Kind != "command_loader" {
		return fmt.Errorf("unsupported profile subject kind %q", profile.Subject.Kind)
	}
	if strings.TrimSpace(profile.Subject.BinaryBaseName) == "" {
		return errors.New("profile subject.binary_basename is required")
	}
	if strings.TrimSpace(profile.Subject.Command) == "" {
		return errors.New("profile subject.command is required")
	}
	if strings.TrimSpace(profile.Matrix.Path) == "" {
		return errors.New("profile matrix.path is required")
	}
	if err := validateHTTPSURI("matrix.uri", profile.Matrix.URI); err != nil {
		return err
	}
	if len(profile.Environments) == 0 {
		return errors.New("profile environments must not be empty")
	}
	environmentIDs := make(map[string]struct{}, len(profile.Environments))
	for i, environment := range profile.Environments {
		if !profileIDPattern.MatchString(environment.ProfileID) {
			return fmt.Errorf("environments[%d].profile_id %q must match %s", i, environment.ProfileID, profileIDPattern.String())
		}
		if _, exists := environmentIDs[environment.ProfileID]; exists {
			return fmt.Errorf("duplicate environment profile_id %q", environment.ProfileID)
		}
		environmentIDs[environment.ProfileID] = struct{}{}
		if strings.TrimSpace(environment.Distro) == "" || strings.TrimSpace(environment.Version) == "" ||
			strings.TrimSpace(environment.KernelFamily) == "" || strings.TrimSpace(environment.Arch) == "" {
			return fmt.Errorf("environments[%d] must define distro, version, kernel_family, and arch", i)
		}
	}
	if profile.Validity.SnapshotDays <= 0 {
		return errors.New("profile validity.snapshot_days must be greater than zero")
	}
	if profile.Validity.ContinuousMaxAgeDays <= 0 {
		return errors.New("profile validity.continuous_max_age_days must be greater than zero")
	}
	if profile.Validity.ContinuousMaxAgeDays > profile.Validity.SnapshotDays {
		return errors.New("profile continuous_max_age_days must not exceed snapshot_days")
	}
	if len(profile.Assertions) == 0 {
		return errors.New("profile assertions must not be empty")
	}
	assertionIDs := make(map[string]struct{}, len(profile.Assertions))
	rules := make(map[string]struct{}, len(profile.Assertions))
	for i := range profile.Assertions {
		assertion := profile.Assertions[i]
		if !assertionIDPattern.MatchString(assertion.ID) {
			return fmt.Errorf("assertions[%d].id %q must match %s", i, assertion.ID, assertionIDPattern.String())
		}
		if _, exists := assertionIDs[assertion.ID]; exists {
			return fmt.Errorf("duplicate assertion id %q", assertion.ID)
		}
		assertionIDs[assertion.ID] = struct{}{}
		if _, ok := knownRules[assertion.Rule]; !ok {
			return fmt.Errorf("assertions[%d].rule %q is unsupported", i, assertion.Rule)
		}
		if _, exists := rules[assertion.Rule]; exists {
			return fmt.Errorf("duplicate assertion rule %q", assertion.Rule)
		}
		rules[assertion.Rule] = struct{}{}
		if strings.TrimSpace(assertion.Description) == "" {
			return fmt.Errorf("assertions[%d].description is required", i)
		}
	}
	for rule := range knownRules {
		if _, ok := rules[rule]; !ok {
			return fmt.Errorf("profile is missing required assertion rule %q", rule)
		}
	}
	if len(profile.Properties) == 0 {
		return errors.New("profile properties must not be empty")
	}
	if err := validateUniqueNonEmpty("properties", profile.Properties); err != nil {
		return err
	}
	for i, property := range profile.Properties {
		if !propertyPattern.MatchString(property) {
			return fmt.Errorf("properties[%d] %q must match %s", i, property, propertyPattern.String())
		}
	}
	return nil
}

func validateEnvironmentMatrix(environments []EnvironmentContract, mx matrix.Matrix) error {
	matrixIDs := make(map[string]struct{}, len(mx.Profiles))
	for _, profile := range mx.Profiles {
		matrixIDs[profile.ID] = struct{}{}
	}
	environmentIDs := make(map[string]struct{}, len(environments))
	for _, environment := range environments {
		environmentIDs[environment.ProfileID] = struct{}{}
		if _, ok := matrixIDs[environment.ProfileID]; !ok {
			return fmt.Errorf("environment profile_id %q is not present in the conformance matrix", environment.ProfileID)
		}
	}
	for _, profile := range mx.Profiles {
		if _, ok := environmentIDs[profile.ID]; !ok {
			return fmt.Errorf("conformance matrix profile %q has no expected environment", profile.ID)
		}
	}
	return nil
}

func resolveProfileResource(profilePath, resourcePath string) (string, error) {
	if filepath.IsAbs(resourcePath) {
		return "", errors.New("profile matrix.path must be relative to the profile")
	}
	baseDir := filepath.Dir(profilePath)
	resolved := filepath.Clean(filepath.Join(baseDir, resourcePath))
	rel, err := filepath.Rel(baseDir, resolved)
	if err != nil {
		return "", fmt.Errorf("resolve profile matrix path: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("profile matrix.path must stay inside the profile directory")
	}
	return resolved, nil
}

func validateHTTPSURI(field, raw string) error {
	parsed, err := url.ParseRequestURI(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("profile %s must be an absolute https URI", field)
	}
	return nil
}

func validateUniqueNonEmpty(field string, values []string) error {
	seen := make(map[string]struct{}, len(values))
	for i, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			return fmt.Errorf("%s[%d] must not be empty", field, i)
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("%s contains duplicate value %q", field, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func digestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
