# Verifying bpfcompat releases

Every tagged release of bpfcompat ships with a full supply-chain bundle so you can
prove a binary came from this repository's build workflow before you run it.
Rows that name a version are not in earlier releases:

| Artifact | What it is |
|---|---|
| `bpfcompat-linux-amd64`, `bpfcompat-linux-arm64`, `bpfcompat-validator-static-linux-amd64` | the binaries (the static validator is published for amd64 only) |
| `SHA256SUMS` (+ `.sig`, `.crt`) | checksums, cosign-signed (keyless) |
| `bpfcompat.sbom.cdx.json` | CycloneDX SBOM |
| `release-candidate-evidence.json` | Tag, commit, workflow run, exact image digest, and positive/negative VM report hashes (from v0.4.0-rc.2 and v0.3.8-rc.1; not in v0.3.7) |
| `bpfcompat-third-party-licenses.tar.gz` | verbatim license/notice/patent texts of the third-party code in the binaries, with `INVENTORY.json` (from v0.4.0-rc.5) |
| `bpfcompat-validator-relink-kit-linux-amd64.tar.gz` | the validator's `main.o`, link commands, linker trace and map, inputs with owning packages, the validator's own C sources and `relink.sh` (from v0.4.0-rc.5) |
| `validator-build-inputs.json` | the validator's build record: builder image digest, package snapshot, package versions, sha256 (from v0.4.0-rc.5) |
| **SLSA provenance attestation** | provenance bound to the artifact digest, repository, commit, and release workflow |
| **SBOM attestation** | the SBOM bound to the `bpfcompat-linux-amd64` digest (the arm64 CLI and the validator carry SLSA provenance only) |

Signing is **keyless** (Sigstore Fulcio + Rekor) via GitHub Actions OIDC — there is no
long-lived private key. The signer identity is the release workflow itself.

## 1. Verify build provenance (recommended)

Requires the GitHub CLI (`gh`) 2.68.0 or later: `--signer-workflow` was added
in gh 2.51.0 and `--source-ref` in gh 2.68.0. An older gh stops without
verifying anything, with `unknown flag` (before 2.68.0) or
`unknown command "attestation"` (before 2.49.0); upgrade it, or use the cosign
check in section 2. How strictly gh matches these values also depends on its
version: gh 2.97.0 and 2.102.0 fixed published advisories in that matching
(GHSA-mm27-mwq9-fr5g, GHSA-wjmr-j3rp-mh2g, GHSA-4mq3-hpgx-9cx8), so 2.102.0 or
later is recommended.

This is the strongest check — it proves the binary was built by *this repo's*
release workflow for the tag you downloaded. Pin the workflow and the exact
tag, as `scripts/install.sh` does:

```bash
VER=v0.3.7   # the exact release tag you downloaded
gh attestation verify ./bpfcompat-linux-amd64 \
  --repo Kernel-Guard/bpfcompat \
  --signer-workflow Kernel-Guard/bpfcompat/.github/workflows/release-artifacts.yml \
  --source-ref "refs/tags/$VER"
```

A pass confirms the artifact's digest matches an attestation produced by the
`release-artifacts` workflow on the tag `$VER`. Without `--source-ref`, an
attestation from another tag's release run (for example a prerelease) also
passes, and `gh attestation verify ./bpfcompat-linux-amd64 --repo Kernel-Guard/bpfcompat`
alone accepts an attestation from any workflow in this repository.

From v0.4.0-rc.2 and v0.3.8-rc.1 (v0.3.7 has no such asset), the promotion
evidence is independently attested by the same workflow:

```bash
gh attestation verify ./release-candidate-evidence.json \
  --repo Kernel-Guard/bpfcompat \
  --signer-workflow Kernel-Guard/bpfcompat/.github/workflows/release-artifacts.yml \
  --source-ref "refs/tags/$VER"
```

Offline / air-gapped verification is supported by downloading the attestation
bundle first (`gh attestation download`) and verifying with `--bundle`.

## 2. Verify checksums + cosign signature

```bash
VER=v0.3.7   # the exact release tag you downloaded

# 1) integrity of the assets you downloaded
sha256sum -c --ignore-missing SHA256SUMS

# 2) authenticity of SHA256SUMS (keyless cosign), bound to the exact tag
cosign verify-blob SHA256SUMS \
  --signature SHA256SUMS.sig \
  --certificate SHA256SUMS.crt \
  --certificate-identity "https://github.com/Kernel-Guard/bpfcompat/.github/workflows/release-artifacts.yml@refs/tags/$VER" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The identity names the exact tag, as `scripts/install.sh` does, so a signature
made by another tag's release run (for example a prerelease) is refused.

## 3. Inspect the SBOM

```bash
# human-readable component list
cat bpfcompat.sbom.cdx.json | jq '.components[].name' | sort -u
# or verify the SBOM attestation is bound to the binary
gh attestation verify ./bpfcompat-linux-amd64 \
  --repo Kernel-Guard/bpfcompat \
  --signer-workflow Kernel-Guard/bpfcompat/.github/workflows/release-artifacts.yml \
  --source-ref "refs/tags/$VER" \
  --predicate-type https://cyclonedx.org/bom
```

## 4. Third-party license material and the relink kit

These assets are listed in `SHA256SUMS` and attested like the binaries, so the
checks above cover them (`gh attestation verify bpfcompat-third-party-licenses.tar.gz ...`).
Each archive also carries its own `SHA256SUMS` over its contents:

```bash
tar -xzf bpfcompat-third-party-licenses.tar.gz
(cd bpfcompat-third-party-licenses && sha256sum -c SHA256SUMS)
jq '.observed.go.modules[] | "\(.module) \(.version)"' bpfcompat-third-party-licenses/INVENTORY.json
jq '.recorded_decisions' bpfcompat-third-party-licenses/INVENTORY.json

tar -xzf bpfcompat-validator-relink-kit-linux-amd64.tar.gz
cd bpfcompat-validator-relink-kit && sha256sum -c SHA256SUMS
./relink.sh   # pinned builder (docker); reproduces the shipped validator byte for byte
```

`INVENTORY.json` separates observed facts (what was linked, from where, with
which texts), recorded distribution decisions (`undecided` until made) and what
it does not establish. The bundle is not a statement that any license condition
is met. Releases before v0.4.0-rc.5 do not have these assets; the repository's
`LICENSE`, `NOTICE` and `THIRD_PARTY_NOTICES.md` at that tag remain the
reference for those.

## What this gives you

- **Integrity** — the bytes weren't altered (checksums).
- **Authenticity** — they were signed by this repo's workflow, not a fork or attacker
  (cosign cert identity).
- **Provenance** — a tamper-evident record of *which commit and workflow*
  built them.
- **Promotion binding** — one attested record connects the release tag and
  commit to the tested VM reports and promoted container digest (from
  v0.4.0-rc.2 and v0.3.8-rc.1; not in v0.3.7).

From v0.4.0-rc.2 and v0.3.8-rc.1 (the v0.3.7 Action verifies checksums only),
the GitHub Action consumes prebuilt release binaries only after both
`sha256sum -c` and `gh attestation verify` succeed for the CLI and validator,
and, from v0.4.0-rc.5, for the third-party license bundle when `SHA256SUMS`
lists it.
Attestation verification is restricted to
`.github/workflows/release-artifacts.yml`; a checksum or attestation mismatch
is a hard failure. When attestation verification is unavailable (no `gh` with
attestation support), the v0.4.0 release candidates' Action builds from its
pinned source instead of trusting unverifiable release bytes; the v0.3.8
release candidates' Action fails the job instead.

From v0.4.0-rc.5, after verification the Action runs that validator by path
and pinned digest (`BPFCOMPAT_VALIDATOR_BIN` / `BPFCOMPAT_VALIDATOR_SHA256`),
so a validator left in `/usr/local/libexec` or `/usr/libexec` on a self-hosted
runner is not selected instead. While the Action is pinned to a release, every
fallback to a source build is a `::warning::` annotation: that run does not use
the attested release validator, and the CLI's normal search order
(`/usr/local/libexec`, `/usr/libexec`, then the action checkout) applies to it.
A workflow that sets `BPFCOMPAT_VALIDATOR_BIN` or `BPFCOMPAT_VALIDATOR_SHA256`
keeps its own settings, with a warning. With v0.3.7 and v0.4.0-rc.4 that normal
search order applies to every run, so a validator installed in those
directories is used before the verified one.
