# Verifying bpfcompat releases

Every tagged release of bpfcompat ships with a full supply-chain bundle so you can
prove a binary came from this repository's build workflow before you run it:

| Artifact | What it is |
|---|---|
| `bpfcompat-linux-amd64`, `bpfcompat-validator-static-linux-amd64` | the binaries |
| `SHA256SUMS` (+ `.sig`, `.crt`) | checksums, cosign-signed (keyless) |
| `bpfcompat.sbom.cdx.json` | CycloneDX SBOM |
| `release-candidate-evidence.json` | Tag, commit, workflow run, exact image digest, and positive/negative VM report hashes |
| **SLSA provenance attestation** | provenance bound to the artifact digest, repository, commit, and release workflow |
| **SBOM attestation** | the SBOM bound to the binary's digest |

Signing is **keyless** (Sigstore Fulcio + Rekor) via GitHub Actions OIDC — there is no
long-lived private key. The signer identity is the release workflow itself.

## 1. Verify build provenance (recommended)

Requires the GitHub CLI (`gh`). This is the strongest check — it proves the binary
was built by *this repo's* release workflow:

```bash
gh attestation verify ./bpfcompat-linux-amd64 --repo Kernel-Guard/bpfcompat
```

A pass confirms the artifact's digest matches an attestation produced by the
`release-artifacts` workflow on a `v*` tag. To pin the exact workflow identity:

```bash
gh attestation verify ./bpfcompat-linux-amd64 \
  --repo Kernel-Guard/bpfcompat \
  --signer-workflow Kernel-Guard/bpfcompat/.github/workflows/release-artifacts.yml
```

The promotion evidence is independently attested by the same workflow:

```bash
gh attestation verify ./release-candidate-evidence.json \
  --repo Kernel-Guard/bpfcompat \
  --signer-workflow Kernel-Guard/bpfcompat/.github/workflows/release-artifacts.yml
```

Offline / air-gapped verification is supported by downloading the attestation
bundle first (`gh attestation download`) and verifying with `--bundle`.

## 2. Verify checksums + cosign signature

```bash
# 1) integrity
sha256sum -c SHA256SUMS

# 2) authenticity of SHA256SUMS (keyless cosign)
cosign verify-blob SHA256SUMS \
  --signature SHA256SUMS.sig \
  --certificate SHA256SUMS.crt \
  --certificate-identity-regexp '^https://github.com/Kernel-Guard/bpfcompat/.github/workflows/release-artifacts.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## 3. Inspect the SBOM

```bash
# human-readable component list
cat bpfcompat.sbom.cdx.json | jq '.components[].name' | sort -u
# or verify the SBOM attestation is bound to the binary
gh attestation verify ./bpfcompat-linux-amd64 --repo Kernel-Guard/bpfcompat --predicate-type https://cyclonedx.org/bom
```

## What this gives you

- **Integrity** — the bytes weren't altered (checksums).
- **Authenticity** — they were signed by this repo's workflow, not a fork or attacker
  (cosign cert identity).
- **Provenance** — a tamper-evident record of *which commit and workflow*
  built them.
- **Promotion binding** — one attested record connects the release tag and
  commit to the tested VM reports and promoted container digest.

The GitHub Action consumes prebuilt release binaries only after both
`sha256sum -c` and `gh attestation verify` succeed for the CLI and validator.
Attestation verification is restricted to
`.github/workflows/release-artifacts.yml`; a checksum or attestation mismatch
is a hard failure. When attestation verification is unavailable, the Action
builds from its pinned source instead of trusting unverifiable release bytes.
