package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/erenari/bpfcompat/internal/cloudregistry"
	"github.com/erenari/bpfcompat/internal/registry"
	"github.com/erenari/bpfcompat/internal/runner"
)

// runAdmin dispatches the bpfcompat admin subcommands. These are operator
// tools meant to be invoked on the host that owns the work directory — they
// read/write the same files the server reads, so they cannot run against a
// remote install. The subcommands favor safe-by-default behavior: token
// listing never prints plaintext secrets, revoke supports --dry-run, audit
// export is read-only by design.
func runAdmin(args []string) int {
	if len(args) == 0 {
		printAdminUsage()
		return runner.ExitToolError
	}
	switch args[0] {
	case "list-tokens":
		return runAdminListTokens(args[1:])
	case "revoke-token":
		return runAdminRevokeToken(args[1:])
	case "verify-chain":
		return runAdminVerifyChain(args[1:])
	case "audit-export":
		return runAdminAuditExport(args[1:])
	case "audit-verify":
		return runAdminAuditVerify(args[1:])
	case "-h", "--help", "help":
		printAdminUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown admin subcommand: %s\n\n", args[0])
		printAdminUsage()
		return runner.ExitToolError
	}
}

func printAdminUsage() {
	fmt.Fprintf(os.Stderr, "Usage:\n"+
		"  bpfcompat admin list-tokens   [--workdir DIR] [--json]\n"+
		"  bpfcompat admin revoke-token  [--workdir DIR] --subject SUBJ --tenant T [--project P] [--dry-run]\n"+
		"  bpfcompat admin revoke-token  [--workdir DIR] --subject SUBJ --all-tenants [--dry-run]\n"+
		"  bpfcompat admin verify-chain  [--workdir DIR] [--json]  # local artifact history only\n"+
		"  bpfcompat admin audit-export  [--workdir DIR] [--tenant T] [--project P] [--limit N]\n"+
		"                                [--out FILE] [--sign-key FILE --sig-out FILE]\n"+
		"  bpfcompat admin audit-verify  --input FILE --sig FILE --pubkey FILE\n\n")
}

// adminTokenSummary is the redacted view we emit from list-tokens. Plaintext
// tokens and hash material are deliberately omitted — operators can confirm
// a grant exists without the listing turning into a credential dump.
type adminTokenSummary struct {
	Subject     string   `json:"subject"`
	Tenant      string   `json:"tenant"`
	Projects    []string `json:"projects"`
	CanRead     bool     `json:"can_read"`
	CanWrite    bool     `json:"can_write"`
	Hashed      bool     `json:"hashed"`
	HashPrefix  string   `json:"hash_prefix,omitempty"`
	NotBefore   string   `json:"not_before,omitempty"`
	ExpiresAt   string   `json:"expires_at,omitempty"`
	HasPlainTxt bool     `json:"has_plaintext"`
}

func summarizeTokens(cfg cloudregistry.AuthConfig) []adminTokenSummary {
	out := make([]adminTokenSummary, 0, len(cfg.Tokens))
	for _, g := range cfg.Tokens {
		s := adminTokenSummary{
			Subject:     g.Subject,
			Tenant:      g.Tenant,
			Projects:    append([]string(nil), g.Projects...),
			CanRead:     g.CanRead,
			CanWrite:    g.CanWrite,
			Hashed:      strings.TrimSpace(g.TokenHash) != "",
			NotBefore:   g.NotBefore,
			ExpiresAt:   g.ExpiresAt,
			HasPlainTxt: strings.TrimSpace(g.Token) != "",
		}
		if s.Hashed && len(g.TokenHash) >= 8 {
			// Short prefix is enough for operators to tell two grants apart
			// in incident review without leaking enough material to brute
			// force.
			s.HashPrefix = g.TokenHash[:8]
		}
		out = append(out, s)
	}
	return out
}

func runAdminListTokens(args []string) int {
	fs := flag.NewFlagSet("admin list-tokens", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	workDir := fs.String("workdir", defaultWorkDir(), "Server work directory containing cloud-registry/auth/tokens.json")
	asJSON := fs.Bool("json", false, "Emit JSON instead of a table")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return runner.ExitToolError
	}

	store := cloudregistry.NewStore(*workDir)
	cfg, err := store.LoadAuthConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load auth config: %v\n", err)
		return runner.ExitToolError
	}
	summary := summarizeTokens(cfg)

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(map[string]any{
			"schema_version": cfg.SchemaVersion,
			"tokens":         summary,
		}); err != nil {
			fmt.Fprintf(os.Stderr, "encode json: %v\n", err)
			return runner.ExitToolError
		}
		return 0
	}

	if len(summary) == 0 {
		fmt.Println("No tokens configured.")
		return 0
	}
	fmt.Printf("%-24s  %-12s  %-8s  %-8s  %-8s  %-20s  %s\n",
		"SUBJECT", "TENANT", "READ", "WRITE", "HASHED", "EXPIRES_AT", "HASH_PREFIX")
	for _, s := range summary {
		exp := s.ExpiresAt
		if exp == "" {
			exp = "never"
		}
		fmt.Printf("%-24s  %-12s  %-8t  %-8t  %-8t  %-20s  %s\n",
			truncate(s.Subject, 24),
			truncate(s.Tenant, 12),
			s.CanRead, s.CanWrite, s.Hashed,
			truncate(exp, 20),
			s.HashPrefix,
		)
	}
	return 0
}

func runAdminRevokeToken(args []string) int {
	fs := flag.NewFlagSet("admin revoke-token", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	workDir := fs.String("workdir", defaultWorkDir(), "Server work directory")
	subject := fs.String("subject", "", "Subject of the grant to remove (required)")
	tenant := fs.String("tenant", "", "Tenant scope of the grant to remove (required unless --all-tenants)")
	project := fs.String("project", "", "Optional project scope; removes grants for this project only")
	allTenants := fs.Bool("all-tenants", false, "Remove matching subject grants across all tenants")
	dryRun := fs.Bool("dry-run", false, "Print what would change without writing tokens.json")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return runner.ExitToolError
	}
	subj := strings.TrimSpace(*subject)
	if subj == "" {
		fmt.Fprintln(os.Stderr, "--subject is required")
		return runner.ExitToolError
	}
	tenantScope := strings.TrimSpace(*tenant)
	projectScope := strings.TrimSpace(*project)
	if *allTenants && tenantScope != "" {
		fmt.Fprintln(os.Stderr, "--tenant cannot be combined with --all-tenants")
		return runner.ExitToolError
	}
	if !*allTenants && tenantScope == "" {
		fmt.Fprintln(os.Stderr, "--tenant is required unless --all-tenants is set")
		return runner.ExitToolError
	}
	if *allTenants && projectScope != "" {
		fmt.Fprintln(os.Stderr, "--project requires --tenant; use tenant-scoped revoke for project-specific grants")
		return runner.ExitToolError
	}

	store := cloudregistry.NewStore(*workDir)
	cfg, err := store.LoadAuthConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load auth config: %v\n", err)
		return runner.ExitToolError
	}

	kept := make([]cloudregistry.TokenGrant, 0, len(cfg.Tokens))
	removed := 0
	for _, g := range cfg.Tokens {
		if tokenGrantMatchesRevokeScope(g, subj, tenantScope, projectScope, *allTenants) {
			removed++
			continue
		}
		kept = append(kept, g)
	}
	if removed == 0 {
		fmt.Fprintf(os.Stderr, "no token grant found for %s\n", revokeScopeLabel(subj, tenantScope, projectScope, *allTenants))
		return runner.ExitToolError
	}
	cfg.Tokens = kept
	if cfg.SchemaVersion == "" {
		// LoadAuthConfig synthesizes the schema version on read for legacy
		// files, but the in-memory copy may have been zeroed before; restore
		// the canonical value before we write it back.
		cfg.SchemaVersion = "cloud_registry_auth.v0.1"
	}

	if *dryRun {
		fmt.Printf("dry-run: would remove %d grant(s) for %s; %d remaining\n", removed, revokeScopeLabel(subj, tenantScope, projectScope, *allTenants), len(kept))
		return 0
	}
	if err := store.WriteAuthConfig(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "write auth config: %v\n", err)
		return runner.ExitToolError
	}
	fmt.Printf("removed %d grant(s) for %s; %d remaining\n", removed, revokeScopeLabel(subj, tenantScope, projectScope, *allTenants), len(kept))
	return 0
}

func tokenGrantMatchesRevokeScope(grant cloudregistry.TokenGrant, subject, tenant, project string, allTenants bool) bool {
	if strings.TrimSpace(grant.Subject) != subject {
		return false
	}
	if !allTenants && strings.TrimSpace(grant.Tenant) != tenant {
		return false
	}
	if project == "" {
		return true
	}
	if len(grant.Projects) == 0 {
		return true
	}
	for _, candidate := range grant.Projects {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" || candidate == project {
			return true
		}
	}
	return false
}

func revokeScopeLabel(subject, tenant, project string, allTenants bool) string {
	if allTenants {
		return fmt.Sprintf("subject %q across all tenants", subject)
	}
	if project != "" {
		return fmt.Sprintf("subject %q tenant %q project %q", subject, tenant, project)
	}
	return fmt.Sprintf("subject %q tenant %q", subject, tenant)
}

func runAdminVerifyChain(args []string) int {
	fs := flag.NewFlagSet("admin verify-chain", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	workDir := fs.String("workdir", defaultWorkDir(), "Server work directory")
	asJSON := fs.Bool("json", false, "Emit JSON instead of a human-readable summary")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return runner.ExitToolError
	}
	verification, err := registry.VerifyArtifactVersionHistory(*workDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify history: %v\n", err)
		return runner.ExitToolError
	}
	bad := 0
	for _, v := range verification {
		if !v.Verified {
			bad++
		}
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(map[string]any{
			"scope":   "local_artifact_history",
			"records": len(verification),
			"invalid": bad,
			"results": verification,
		}); err != nil {
			fmt.Fprintf(os.Stderr, "encode json: %v\n", err)
			return runner.ExitToolError
		}
		if bad > 0 {
			return runner.ExitToolError
		}
		return 0
	}
	fmt.Printf("verified %d local artifact version record(s); %d invalid\n", len(verification), bad)
	if bad > 0 {
		for _, v := range verification {
			if !v.Verified {
				fmt.Printf("  INVALID: %s/%s issues=%s\n", v.ArtifactName, v.ArtifactVersion, strings.Join(v.Issues, "; "))
			}
		}
		return runner.ExitToolError
	}
	return 0
}

func runAdminAuditExport(args []string) int {
	fs := flag.NewFlagSet("admin audit-export", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	workDir := fs.String("workdir", defaultWorkDir(), "Server work directory")
	tenant := fs.String("tenant", "", "Restrict export to a single tenant")
	project := fs.String("project", "", "Restrict export to a single project")
	limit := fs.Int("limit", 0, "Max events to export (0 = no limit)")
	outPath := fs.String("out", "", "Write NDJSON to this file instead of stdout (required when --sig-out is set)")
	signKey := fs.String("sign-key", "", "Optional path to a base64-encoded ed25519 private key; produces a detached signature alongside the export")
	sigOut := fs.String("sig-out", "", "Path to write the detached signature envelope (required when --sign-key is set)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return runner.ExitToolError
	}
	// Signing requires writing to a real file: streaming to stdout means we
	// can't both sign the bytes and let the caller redirect at the same
	// time without buffering them somewhere predictable. We chose the
	// strict path — operators get a clear error instead of a sometimes-works
	// behavior.
	if strings.TrimSpace(*signKey) != "" && strings.TrimSpace(*sigOut) == "" {
		fmt.Fprintln(os.Stderr, "--sign-key requires --sig-out")
		return runner.ExitToolError
	}
	if strings.TrimSpace(*signKey) != "" && strings.TrimSpace(*outPath) == "" {
		fmt.Fprintln(os.Stderr, "--sign-key requires --out so the signed bytes are reproducible")
		return runner.ExitToolError
	}

	store := cloudregistry.NewStore(*workDir)
	events, err := store.ListAuditEvents(*tenant, *project, *limit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "list audit events: %v\n", err)
		return runner.ExitToolError
	}

	// Serialize the events once into a buffer so we can both write them and
	// hash them deterministically. NDJSON keeps each record self-delimiting
	// so downstream log shippers don't need a custom framer.
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	for _, e := range events {
		if err := enc.Encode(e); err != nil {
			fmt.Fprintf(os.Stderr, "encode event %q: %v\n", e.EventID, err)
			return runner.ExitToolError
		}
	}
	payload := buf.Bytes()

	// Choose destination. stdout is the default; --out switches to a file
	// (atomic via rename so a half-written file never poisons a verifier).
	if strings.TrimSpace(*outPath) == "" {
		bw := bufio.NewWriter(os.Stdout)
		defer bw.Flush()
		if _, err := bw.Write(payload); err != nil {
			fmt.Fprintf(os.Stderr, "write stdout: %v\n", err)
			return runner.ExitToolError
		}
		return 0
	}
	if err := writeFileAtomic(*outPath, payload, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write export: %v\n", err)
		return runner.ExitToolError
	}

	if strings.TrimSpace(*signKey) == "" {
		return 0
	}
	priv, err := auditPrivateKeyFromFile(*signKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load signing key: %v\n", err)
		return runner.ExitToolError
	}
	envelope := signAuditPayload(payload, priv)
	envBody, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal envelope: %v\n", err)
		return runner.ExitToolError
	}
	envBody = append(envBody, '\n')
	if err := writeFileAtomic(*sigOut, envBody, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write signature envelope: %v\n", err)
		return runner.ExitToolError
	}
	fmt.Fprintf(os.Stderr, "signed audit export: %s (%d bytes) -> %s\n", *outPath, len(payload), *sigOut)
	return 0
}

// writeFileAtomic writes data to path via a sibling .tmp file and rename,
// so a crashed/interrupted command never leaves a half-written export that
// would fail signature verification on the next run.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+"-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		if tmpPath != "" {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	tmpPath = ""
	return nil
}

func defaultWorkDir() string {
	if v := strings.TrimSpace(os.Getenv("BPFCOMPAT_WORKDIR")); v != "" {
		return v
	}
	return ".bpfcompat"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}
