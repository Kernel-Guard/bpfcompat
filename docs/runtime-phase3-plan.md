# Runtime Delivery (Phase 3 Start)

This document tracks the initial runtime-delivery implementation.

## Implemented in this step

1. `runtime probe`:
   - captures host distro/version/kernel/arch
   - detects kernel BTF presence
   - provides map/program/attach capability hints with:
     - heuristic kernel-version estimates
     - optional `bpftool ... unprivileged` signal merge
     - optional privileged probe path (`bpftool feature probe kernel`) with sudo fallback
2. `runtime select`:
   - picks best artifact version from `.bpfcompat/registry/artifact_versions.jsonl`
   - scores candidates by:
     - required pass/fail counts
     - host profile alignment
     - known compatibility risks (`MISSING_BTF`, `UNSUPPORTED_MAP_TYPE`)
3. `runtime fetch`:
   - retrieves selected artifact to local output directory
   - supports local-path history records and remote `artifact_uri` / URI-backed sources (`http`, `https`); `file://` requires `BPFCOMPAT_FETCH_ALLOW_FILE_URI=true` for local proof runs
   - verifies SHA-256 against recorded history metadata
4. `runtime execute`:
   - selects/fetches artifact and executes validator on current host
   - requires explicit host safety gate (`allow_host_load`)
   - captures validator result, stderr, and classification summary
5. strict selector policy constraints:
   - summary/required-pass gates
   - classification allow/deny lists
   - optional feature/attach risk constraints
6. artifact-history provenance chain:
   - each artifact version record is now linked by `prev_record_sha256`
   - records are signed with an Ed25519 key stored in workdir key material
   - optional enterprise signer mode is available via `BPFCOMPAT_SIGNING_MODE=external-cmd`
   - `bpfcompat history verify` validates hash chain + signatures and reports tamper evidence

## Commands

```bash
./bin/bpfcompat runtime probe
./bin/bpfcompat runtime probe --probe-prefer-privileged --probe-use-sudo=true --probe-sudo-non-interactive=true
./bin/bpfcompat runtime select --artifact-name aegis-bpf --workdir .bpfcompat
./bin/bpfcompat runtime fetch --artifact-name aegis-bpf --workdir .bpfcompat
./bin/bpfcompat runtime execute --artifact-name aegis-bpf --workdir .bpfcompat --allow-host-load
./bin/bpfcompat history sign --workdir .bpfcompat
./bin/bpfcompat history verify --workdir .bpfcompat
```

Enterprise signer mode (example):

```bash
export BPFCOMPAT_SIGNING_MODE=external-cmd
export BPFCOMPAT_SIGNING_EXTERNAL_CMD=/usr/local/bin/bpfcompat-signer
export BPFCOMPAT_SIGNING_EXTERNAL_ARGS="--key-id prod-signing-key"
```

## Remaining to reach fuller Phase 3

- deploy and operate an organization-specific external signer backend (KMS/HSM wrapper) in production
