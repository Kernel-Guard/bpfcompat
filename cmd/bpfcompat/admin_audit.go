package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/erenari/bpfcompat/internal/runner"
)

// auditSignatureEnvelope is the on-disk shape of the detached audit-log
// signature. The hash of the export bytes is included so a verifier can
// catch corruption even when the public key is trusted out-of-band: a
// mismatched sha256 means the export file was modified, full stop.
//
// The algorithm field exists so we can add new schemes (ECDSA, RSA-PSS)
// without forcing a parser change — but for now we only support Ed25519,
// the same primitive the artifact registry signs with.
type auditSignatureEnvelope struct {
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
	SHA256    string `json:"sha256"`
	Signature string `json:"signature"`
}

// auditPrivateKeyFromPEMOrRaw accepts either a base64-encoded ed25519
// private key (64 bytes) or seed (32 bytes), one per file. We deliberately
// don't accept PKCS#8 PEM yet — the simpler shape covers our internal use
// case and keeps the verification path trivially auditable. Adding PEM
// support later is non-breaking because we detect on raw length.
func auditPrivateKeyFromFile(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("decode signing key (expect base64-encoded ed25519 key or seed): %w", err)
	}
	switch len(decoded) {
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(decoded), nil
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(decoded), nil
	default:
		return nil, fmt.Errorf("unexpected key length %d (want %d or %d)", len(decoded), ed25519.PrivateKeySize, ed25519.SeedSize)
	}
}

func auditPublicKeyFromFile(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("decode public key (expect base64-encoded ed25519 pubkey): %w", err)
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("unexpected public key length %d (want %d)", len(decoded), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(decoded), nil
}

// signAuditPayload returns the detached envelope for the given bytes. The
// signature is over the sha256 digest, not the raw payload, so verifiers
// can stream a large export through a hash function without holding the
// whole file in memory.
func signAuditPayload(payload []byte, priv ed25519.PrivateKey) auditSignatureEnvelope {
	digest := sha256.Sum256(payload)
	sig := ed25519.Sign(priv, digest[:])
	pub := priv.Public().(ed25519.PublicKey)
	return auditSignatureEnvelope{
		Algorithm: "ed25519",
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		SHA256:    hex.EncodeToString(digest[:]),
		Signature: base64.StdEncoding.EncodeToString(sig),
	}
}

// verifyAuditPayload checks a payload against the envelope. If pinnedPub is
// non-nil it overrides the envelope's public key — that's the strongest
// mode of verification because it doesn't trust the signature file alone.
// Without a pinned key, the envelope is self-attesting and only proves the
// signer at export time controlled the matching private key.
func verifyAuditPayload(payload []byte, env auditSignatureEnvelope, pinnedPub ed25519.PublicKey) error {
	if strings.ToLower(env.Algorithm) != "ed25519" {
		return fmt.Errorf("unsupported signature algorithm %q", env.Algorithm)
	}
	digest := sha256.Sum256(payload)
	gotHex := hex.EncodeToString(digest[:])
	if gotHex != env.SHA256 {
		return fmt.Errorf("payload digest mismatch (signature is for a different export)")
	}
	pub := pinnedPub
	if pub == nil {
		decodedPub, err := base64.StdEncoding.DecodeString(env.PublicKey)
		if err != nil {
			return fmt.Errorf("decode envelope public key: %w", err)
		}
		if len(decodedPub) != ed25519.PublicKeySize {
			return fmt.Errorf("envelope public key length %d", len(decodedPub))
		}
		pub = ed25519.PublicKey(decodedPub)
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(pub, digest[:], sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

// runAdminAuditVerify checks a signed export. The command exits non-zero on
// any verification failure so operators can wire it into nightly cron and
// alert on the exit status — no JSON parsing required.
func runAdminAuditVerify(args []string) int {
	fs := flag.NewFlagSet("admin audit-verify", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	inputPath := fs.String("input", "", "Path to the signed audit export NDJSON (required)")
	sigPath := fs.String("sig", "", "Path to the detached signature envelope (required)")
	pubkeyPath := fs.String("pubkey", "", "Pinned ed25519 public key used to verify the envelope (required unless --trust-envelope-key is set)")
	trustEnvelopeKey := fs.Bool("trust-envelope-key", false, "Trust the public key embedded in the signature envelope (dev/demo only)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return runner.ExitToolError
	}
	if strings.TrimSpace(*inputPath) == "" || strings.TrimSpace(*sigPath) == "" {
		fmt.Fprintln(os.Stderr, "--input and --sig are required")
		return runner.ExitToolError
	}
	if strings.TrimSpace(*pubkeyPath) == "" && !*trustEnvelopeKey {
		fmt.Fprintln(os.Stderr, "--pubkey is required; use --trust-envelope-key only for dev/demo self-attesting verification")
		return runner.ExitToolError
	}
	payload, err := os.ReadFile(*inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read input: %v\n", err)
		return runner.ExitToolError
	}
	rawEnv, err := os.ReadFile(*sigPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read signature: %v\n", err)
		return runner.ExitToolError
	}
	var env auditSignatureEnvelope
	if err := json.Unmarshal(rawEnv, &env); err != nil {
		fmt.Fprintf(os.Stderr, "parse signature envelope: %v\n", err)
		return runner.ExitToolError
	}
	var pinned ed25519.PublicKey
	if strings.TrimSpace(*pubkeyPath) != "" {
		pinned, err = auditPublicKeyFromFile(*pubkeyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "load pinned public key: %v\n", err)
			return runner.ExitToolError
		}
	}
	if err := verifyAuditPayload(payload, env, pinned); err != nil {
		fmt.Fprintf(os.Stderr, "verification failed: %v\n", err)
		return runner.ExitToolError
	}
	fmt.Printf("verified audit export %s (%d bytes) against signature %s\n", *inputPath, len(payload), *sigPath)
	return 0
}
