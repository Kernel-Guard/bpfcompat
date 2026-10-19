#!/usr/bin/env bash
# Regression for the evidence and identity checks that run inside the release
# workflows themselves. A tag's own copy of these workflows is what executes
# for that release, so a check missing here cannot be added for a release
# after it is tagged.
#
#   1. Stable gate (release-artifacts.yml, "Stage production readiness
#      evidence"): a ready readiness record must carry a completed rollback
#      drill of this release's own candidate (drill alias and image digest),
#      like the incident section, and the canary run lookups the attested
#      report records (each canary's run attempt and its start, and the
#      release's publication time), so a record written by a report that did
#      not make those lookups is refused. The gate's jq program is extracted
#      from the workflow and run against real production-readiness-report.sh
#      output.
#   2. Promotion (promote-release.yml): the exact run: bodies of the
#      re-verification and image steps run against stub cosign/gh/docker. The
#      draft's signature files and SBOM must be the candidate run's own
#      copies; every cosign identity is the exact
#      release-artifacts.yml@refs/tags/<tag> of this repository (a signature
#      made by another v* tag's run, by a tag whose name extends or resembles
#      the release tag, by the tag in another repository or by another
#      workflow is refused); attestation checks are bound to the tag ref and
#      the expected commit.
#   3. Every workflow call of scripts/verify-release-assets.sh supplies the
#      source commit and tag ref that script requires.
#
# Hermetic: no network, no real release assets.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELEASE_WF="${RELEASE_WF:-$ROOT/.github/workflows/release-artifacts.yml}"
PROMOTE_WF="${PROMOTE_WF:-$ROOT/.github/workflows/promote-release.yml}"
MAINTENANCE_WF="${MAINTENANCE_WF:-$ROOT/.github/workflows/maintenance-evidence.yml}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

failures=0
ok() { echo "[release-workflow-gates-test] ok: $*"; }
bad() {
  echo "[release-workflow-gates-test] FAIL: $*" >&2
  failures=$((failures + 1))
}

# ------------------------------------------------------------------ 1. stable gate
# The same extraction production-readiness-report_test.sh uses, so both tests
# judge the program the workflow actually runs.
gate="$(awk '
  /jq -e --arg version "\$version" .$/ {f=1; next}
  f && /^ *. --argjson c / {exit}
  f {print}
' "$RELEASE_WF")"
[[ "$gate" == *'.gate_status == "ready"'* ]] || {
  echo "[release-workflow-gates-test] could not extract the stable gate from ${RELEASE_WF}" >&2
  exit 1
}
run_gate() {
  jq -e --arg version 0.4.0 --argjson c "$(jq -c '.candidate' "$1")" "$gate" "$1" >/dev/null 2>&1
}

# Unedited production-readiness-report.sh output (attested mode) for the
# fixture input of production-readiness-report_test.sh, which also runs the
# extracted gate against freshly generated output. In attested mode the report
# looks up the candidate release and every canary run and records
# candidate.published_at and each canary's workflow_run_attempt,
# attempt_started_at and head_branch; with the attestation bypass they are
# null, and a report from before those lookups has none of them.
cat >"$tmp/attested.json" <<'JSON'
{
  "schema_version": "v0.2",
  "campaign_binding": "candidate-bound-v2",
  "attestations_verified": true,
  "gate_status": "ready",
  "release_version": "0.4.0",
  "supported_boundary": "CLI + GitHub Action + disposable QEMU/KVM validation",
  "generated_at": "2026-10-19T19:24:43Z",
  "campaigns": [
    {"workflow_run_id": 1000, "candidate_tag": "v0.4.0-rc.1", "candidate_commit": "cccccccccccccccccccccccccccccccccccccccc", "executed": {"cli_sha256": "8888888888888888888888888888888888888888888888888888888888888888", "validator_sha256": "7777777777777777777777777777777777777777777777777777777777777777"}, "workflow_sha": "0000000000000000000000000000000000000001", "started_at": "2026-08-03T03:21:00Z", "report_sha256": "0291d23025530eccf75e3e2b5922edbb6c7f39aee1e48688213a668866cc795c", "target_count": 1},
    {"workflow_run_id": 1001, "candidate_tag": "v0.4.0-rc.1", "candidate_commit": "cccccccccccccccccccccccccccccccccccccccc", "executed": {"cli_sha256": "8888888888888888888888888888888888888888888888888888888888888888", "validator_sha256": "7777777777777777777777777777777777777777777777777777777777777777"}, "workflow_sha": "0000000000000000000000000000000000000002", "started_at": "2026-08-10T03:21:00Z", "report_sha256": "2247827b5fe5a0a2a5abd4aa27729809e9fe0ab4dfc4ae3a1eb3a5ffe337806d", "target_count": 1},
    {"workflow_run_id": 1002, "candidate_tag": "v0.4.0-rc.1", "candidate_commit": "cccccccccccccccccccccccccccccccccccccccc", "executed": {"cli_sha256": "8888888888888888888888888888888888888888888888888888888888888888", "validator_sha256": "7777777777777777777777777777777777777777777777777777777777777777"}, "workflow_sha": "0000000000000000000000000000000000000003", "started_at": "2026-08-17T03:21:00Z", "report_sha256": "3acb06c0c5086a1bf756c6af91dc911ea324b862596b7283aa877d9f554adca7", "target_count": 1},
    {"workflow_run_id": 1003, "candidate_tag": "v0.4.0-rc.1", "candidate_commit": "cccccccccccccccccccccccccccccccccccccccc", "executed": {"cli_sha256": "8888888888888888888888888888888888888888888888888888888888888888", "validator_sha256": "7777777777777777777777777777777777777777777777777777777777777777"}, "workflow_sha": "0000000000000000000000000000000000000004", "started_at": "2026-08-24T03:21:00Z", "report_sha256": "dbfeaf53a9af3d5951b354d2d6a057e7010f49fee52d79742dceedfd3e1a4af0", "target_count": 1}
  ],
  "slo": {
    "campaign_count": 4,
    "target_executions": 4,
    "infrastructure_errors": 0,
    "target_duration_p95_ms": 1000,
    "target_timeout_ms": 720000
  },
  "falco": {
    "workflow_run_id": 2000,
    "commit_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "started_at": "2026-08-03T06:00:00Z",
    "report_sha256": "477b3159399a5eec5be74073d087fa48982fb3501ebc320f6a61169fcce9cbd0",
    "report_run_id": "falco-run",
    "run_identity": "operator-asserted",
    "started_after_candidate": true,
    "validator_sha256": "7777777777777777777777777777777777777777777777777777777777777777",
    "candidate_bound": true,
    "required_profiles": ["ubuntu-22.04-5.15", "debian-12-6.1", "ubuntu-24.04-6.8", "almalinux-8-4.18", "almalinux-9-5.14"]
  },
  "candidate": {
    "tag": "v0.4.0-rc.1",
    "commit_sha": "cccccccccccccccccccccccccccccccccccccccc",
    "image": "ghcr.io/kernel-guard/bpfcompat@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "evidence_sha256": "01463694049c7ae9040e4957ae63b2109a3a689ee53f5e1f7355bfd7825cd94b",
    "published_at": "2026-07-30T14:50:00Z"
  },
  "canaries": [
    {"milestone": "manual", "workflow_run_id": 3000, "workflow_run_attempt": 1, "attempt_started_at": "2026-07-30T14:59:00Z", "head_branch": "main", "completed_at": "2026-07-30T15:05:34Z", "minutes_after_candidate_generated": 65, "components_verified": true, "evidence_sha256": "9c600cc50ac1ad95d5b2eac72cd7e9bd64209e02527df5f9e23f6366db49e813"},
    {"milestone": "t-plus-24h", "workflow_run_id": 3001, "workflow_run_attempt": 1, "attempt_started_at": "2026-07-31T14:59:00Z", "head_branch": "main", "completed_at": "2026-07-31T15:05:34Z", "minutes_after_candidate_generated": 1505, "components_verified": true, "evidence_sha256": "ba0b104f1f0d6715fb4948d3109431426a00c1725b439f370068d94ab6b99323"},
    {"milestone": "t-plus-72h", "workflow_run_id": 3002, "workflow_run_attempt": 1, "attempt_started_at": "2026-08-02T14:59:00Z", "head_branch": "main", "completed_at": "2026-08-02T15:05:34Z", "minutes_after_candidate_generated": 4385, "components_verified": true, "evidence_sha256": "3f7fdf3d7c1a45e6f7dba2a644575d7bb3776737d3e438640878ed0a8695b53e"}
  ],
  "rollback": {
    "completed": true,
    "workflow_run_id": 5000,
    "completed_at": "2026-07-30T16:00:00Z",
    "alias": "ghcr.io/kernel-guard/bpfcompat:rollback-drill-v0.4.0-rc.1",
    "known_good_digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    "candidate_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "candidate_bound": true,
    "evidence_sha256": "5ef1ac927828ee6b35d8fd048b2e0b5d6666fdee48f42dc205691b8d1b670d66"
  },
  "incident": {
    "completed": true,
    "promotion_run_id": 6000,
    "candidate_bound": true,
    "evidence_sha256": "a72acc9b473bfb1d12f9aec7127f384a2d0b1cec7e9dbed7ee734bbd47bed6ba"
  },
  "operator": {
    "login": "ErenAri",
    "approval_mode": "solo-maintainer",
    "confirmed": true,
    "candidate_evidence_sha256": "01463694049c7ae9040e4957ae63b2109a3a689ee53f5e1f7355bfd7825cd94b",
    "evidence_sha256": "f54e8b7556deb6c44501acd61b384ee0c3447b6bcf7d7d3ba1bd78adda6f8fb0"
  },
  "excluded_surfaces": ["runtime-loading", "agent", "api", "registry", "saas", "firecracker", "virtme-ng"]
}
JSON

if run_gate "$tmp/attested.json"; then
  ok "stable gate accepts unedited attested readiness output"
else
  bad "stable gate refused unedited attested readiness output"
fi

# A genuine drill of another candidate: the v0.3.8-rc.2 drill alias and that
# candidate's image digest (docs/engineering/workstream-status.md).
other_alias="ghcr.io/kernel-guard/bpfcompat:rollback-drill-v0.3.8-rc.2"
other_digest="sha256:046effcfe3575c89663cc925042278e0da0804afe4199fff1abf9e13fea26f1d"
# <label>|<jq edit of the attested output>; the edit itself may contain '|'.
while IFS='|' read -r label edit; do
  jq --arg alias "$other_alias" --arg digest "$other_digest" "$edit" \
    "$tmp/attested.json" >"$tmp/gate-case.json"
  if run_gate "$tmp/gate-case.json"; then
    bad "stable gate accepted readiness with ${label}"
  else
    ok "stable gate refuses readiness with ${label}"
  fi
done <<'CASES'
no rollback section|del(.rollback)
a null rollback section|.rollback = null
an empty rollback section|.rollback = {}
rollback.completed false|.rollback.completed = false
rollback.completed as the string "true"|.rollback.completed = "true"
a rollback section holding only completed true|.rollback = {completed: true}
the drill of another candidate (v0.3.8-rc.2 alias and digest)|.rollback.alias = $alias | .rollback.candidate_digest = $digest
another candidate's drill alias|.rollback.alias = $alias
another candidate's image digest|.rollback.candidate_digest = $digest
this tag's drill alias in another image repository|.rollback.alias = "ghcr.io/example/bpfcompat:rollback-drill-v0.4.0-rc.1"
no incident section (control)|del(.incident)
incident.completed false (control)|.incident.completed = false
none of the canary run lookups (a report from before they were made)|del(.canaries[].workflow_run_attempt, .canaries[].attempt_started_at, .canaries[].head_branch, .candidate.published_at)
the attestation bypass's null lookups, with attestations_verified true|.canaries[] |= (.workflow_run_attempt = null | .attempt_started_at = null | .head_branch = null) | .candidate.published_at = null
no canary run attempts|del(.canaries[].workflow_run_attempt)
null canary run attempts|.canaries[].workflow_run_attempt = null
one canary without its run attempt|.canaries[2].workflow_run_attempt = null
a canary run attempt as the string "1"|.canaries[1].workflow_run_attempt = "1"
canary run attempt 0|.canaries[0].workflow_run_attempt = 0
a fractional canary run attempt|.canaries[0].workflow_run_attempt = 1.5
no canary attempt start times|del(.canaries[].attempt_started_at)
one canary without its attempt start|.canaries[1].attempt_started_at = null
a canary attempt start that is not a UTC timestamp|.canaries[1].attempt_started_at = "2026-07-31 14:59:00"
no release publication time|del(.candidate.published_at)
a null release publication time|.candidate.published_at = null
a release publication time that is not a UTC timestamp|.candidate.published_at = "2026-07-30T14:50:00+00:00"
CASES

# Canary records the attested report writes for runs it accepts. The manual
# canary's branch is recorded, not enforced, so the gate does not read it.
while IFS='|' read -r label edit; do
  jq "$edit" "$tmp/attested.json" >"$tmp/gate-case.json"
  if run_gate "$tmp/gate-case.json"; then
    ok "stable gate accepts readiness with ${label}"
  else
    bad "stable gate refused readiness with ${label}"
  fi
done <<'CASES'
a T+24h re-run recorded as attempt 2|.canaries[1].workflow_run_attempt = 2 | .canaries[1].attempt_started_at = "2026-07-31T21:49:59Z"
a manual canary dispatched on a branch|.canaries[0].head_branch = "rc5-shakeout"
CASES

# ------------------------------------------------------------------ 2. promotion
repo=Kernel-Guard/bpfcompat
tag=v0.4.0-rc.5
commit="$(printf 'c%.0s' {1..40})"
other_commit="$(printf 'e%.0s' {1..40})"
digest="sha256:$(printf 'd%.0s' {1..64})"
image=ghcr.io/kernel-guard/bpfcompat
san="https://github.com/${repo}/.github/workflows/release-artifacts.yml@refs/tags/"
# Signer identities that are close to, but not exactly, this tag's release
# run. cosign matches an identity regexp unanchored (the stub's grep -E does
# too), so only the exact identity refuses all of them: a regexp of the
# identity accepts the first even when start-anchored, and the second even
# when anchored at both ends, because its dots are unescaped.
declare -A ROGUE_SIGNER=(
  # A newly created tag whose name starts with the release tag (v0.4.0-rc.50-rogue).
  [a-tag-extending-the-release-tag]="${san}${tag}0-rogue"
  # A tag that differs from the release tag only where it has a dot (v0.4.0-rc-5).
  [a-tag-differing-at-a-dot]="${san}${tag%.*}-${tag##*.}"
  # The release tag's name in another repository's release workflow.
  [the-tag-in-another-repository]="https://github.com/rogue/bpfcompat/.github/workflows/release-artifacts.yml@refs/tags/${tag}"
  # Another workflow of this repository, run on the release tag.
  [another-workflow-on-the-tag]="https://github.com/${repo}/.github/workflows/ci.yml@refs/tags/${tag}"
)
work="$tmp/promote"
mkdir -p "$work/stubs"

# The exact run: bodies of the two steps, and where the draft's signature
# files and SBOM are compared with the candidate run's copies.
python3 - "$PROMOTE_WF" "$work" <<'PY'
import re
import sys

import yaml

wf = yaml.safe_load(open(sys.argv[1], encoding="utf-8"))
steps = {s.get("name", ""): s for s in wf["jobs"]["promote"]["steps"]}
bodies = {
    "Re-verify evidence, draft assets, signatures, and channel": "verify-step.sh",
    "Verify candidate image immediately before promotion": "image-step.sh",
}
for name, out in bodies.items():
    if name not in steps:
        sys.exit(f"promote-release.yml has no step {name!r}")
    with open(f"{sys.argv[2]}/{out}", "w", encoding="utf-8") as fh:
        fh.write(steps[name]["run"])
body = steps["Re-verify evidence, draft assets, signatures, and channel"]["run"]
compared = set(re.findall(r'cmp "?candidate/run-assets/([^"\s/]+)"? "?candidate/draft-assets/\1"?', body))
for var, names in re.findall(r'for (\w+) in ([^;]*); do', body):
    if re.search(r'cmp "candidate/run-assets/\$\{%s\}" "candidate/draft-assets/\$\{%s\}"' % (var, var), body):
        compared.update(names.replace("\\\n", " ").split())
with open(f"{sys.argv[2]}/compared.txt", "w", encoding="utf-8") as fh:
    fh.write("\n".join(sorted(compared)) + "\n")
PY

for signed in SHA256SUMS.sig SHA256SUMS.crt \
  bpfcompat.sbom.cdx.json bpfcompat.sbom.cdx.sig bpfcompat.sbom.cdx.crt; do
  if grep -Fxq "$signed" "$work/compared.txt"; then
    ok "promotion compares the draft's ${signed} with the candidate run's copy"
  else
    bad "promotion does not compare the draft's ${signed} with the candidate run's copy"
  fi
done

cat >"$work/stubs/cosign" <<'EOF'
#!/usr/bin/env bash
# Certificate file: SAN=<identity>, KEY=<signing key>, SERIAL=<n>. Signature
# file: SIG:<sha256 of the blob>:<key>:<nonce>. A signature verifies only for
# the same bytes and a certificate of the same key; SERIAL and the nonce model
# a re-issued certificate and a fresh signature, which both still verify.
# Image signatures: "<image@digest> <identity> <key>" lines in $IMAGE_SIGS.
set -euo pipefail
sub="$1"
shift
cert="" sig="" ident="" identre="" issuer="" pos=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --certificate) cert="$2"; shift 2 ;;
    --signature) sig="$2"; shift 2 ;;
    --certificate-identity) ident="$2"; shift 2 ;;
    --certificate-identity-regexp) identre="$2"; shift 2 ;;
    --certificate-oidc-issuer) issuer="$2"; shift 2 ;;
    --*) echo "stub cosign: unexpected flag $1" >&2; exit 64 ;;
    *) pos+=("$1"); shift ;;
  esac
done
[[ "$issuer" == https://token.actions.githubusercontent.com ]] ||
  { echo "stub cosign: wrong issuer" >&2; exit 1; }
matches() {
  if [[ -n "$ident" ]]; then
    [[ "$1" == "$ident" ]]
  elif [[ -n "$identre" ]]; then
    grep -Eq -- "$identre" <<<"$1"
  else
    return 1
  fi
}
case "$sub" in
  verify-blob)
    san="$(sed -n 's/^SAN=//p' "$cert")"
    key="$(sed -n 's/^KEY=//p' "$cert")"
    IFS=: read -r kind blob_sha sig_key _ <"$sig" || true
    [[ "$kind" == SIG && "$sig_key" == "$key" &&
       "$blob_sha" == "$(sha256sum "${pos[0]}" | awk '{print $1}')" ]] ||
      { echo "stub cosign: invalid signature" >&2; exit 1; }
    matches "$san" || { echo "stub cosign: none of the expected identities matched: $san" >&2; exit 1; }
    echo "Verified OK" >&2
    ;;
  verify)
    while read -r ref id _; do
      if [[ "$ref" == "${pos[0]}" ]] && matches "$id"; then exit 0; fi
    done <"$IMAGE_SIGS"
    echo "stub cosign: no matching signatures" >&2
    exit 1
    ;;
  *) echo "stub cosign: unexpected subcommand $sub" >&2; exit 64 ;;
esac
EOF
cat >"$work/stubs/gh" <<'EOF'
#!/usr/bin/env bash
# gh attestation verify backed by $ATTEST_DB: one "<sha256> <source ref>
# <source commit>" line per release-workflow attestation. Like gh, a check
# whose flag is absent accepts any value.
set -euo pipefail
case "$1 ${2:-}" in
  "attestation verify")
    shift 2
    file="" repo="" signer="" ref="" source=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --repo) repo="$2"; shift 2 ;;
        --signer-workflow) signer="$2"; shift 2 ;;
        --source-ref) ref="$2"; shift 2 ;;
        --source-digest) source="$2"; shift 2 ;;
        --*) echo "stub gh: unexpected flag $1" >&2; exit 64 ;;
        *) file="$1"; shift ;;
      esac
    done
    [[ "$repo" == Kernel-Guard/bpfcompat &&
       "$signer" == Kernel-Guard/bpfcompat/.github/workflows/release-artifacts.yml ]] ||
      { echo "stub gh: wrong repository or signer workflow" >&2; exit 1; }
    sha="$(sha256sum "$file" | awk '{print $1}')"
    while read -r s r c; do
      if [[ "$s" == "$sha" && ( -z "$ref" || "$ref" == "$r" ) && ( -z "$source" || "$source" == "$c" ) ]]; then
        exit 0
      fi
    done <"$ATTEST_DB"
    echo "stub gh: no attestation of ${file##*/} matched" >&2
    exit 1
    ;;
  "release view")
    printf '{"tagName":"%s","isDraft":true,"isPrerelease":true}\n' "$RELEASE_TAG"
    ;;
  *) echo "stub gh: unexpected $*" >&2; exit 64 ;;
esac
EOF
cat >"$work/stubs/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1 $2" == "run --rm" ]] || { echo "stub docker: unexpected $*" >&2; exit 64; }
printf '{"version":"%s"}\n' "$STUB_IMAGE_VERSION"
EOF
chmod +x "$work/stubs/"*

mkcert() { printf 'SAN=%s\nKEY=%s\nSERIAL=%s\n' "$2" "$3" "${4:-1}" >"$1"; }
mksig() { printf 'SIG:%s:%s:%s\n' "$(sha256sum "$2" | awk '{print $1}')" "$3" "${4:-1}" >"$1"; }
sbom() { printf '{"bomFormat":"CycloneDX","serialNumber":"%s"}\n' "$2" >"$1"; }

fixture() { # $1 = case directory: an untouched rc.5 candidate and draft
  local d="$1" r="$1/candidate/run-assets" evidence_sha
  mkdir -p "$r" "$d/candidate/run-evidence" "$d/scripts"
  printf 'release_version: 0.4.0-rc.5\nrelease_channel: prerelease\n' >"$d/release.yaml"
  # Both scripts have their own regressions. Here they are neutral, and the
  # asset verifier records the identity it is given (asserted below).
  printf '#!/usr/bin/env bash\nexit 0\n' >"$d/scripts/verify-promotion-inputs.sh"
  cat >"$d/scripts/verify-release-assets.sh" <<'EOF'
#!/usr/bin/env bash
printf 'SHA=%s REF=%s\n' "${BPFCOMPAT_EXPECTED_SOURCE_SHA-<unset>}" \
  "${BPFCOMPAT_EXPECTED_SOURCE_REF-<unset>}" >>"$VRA_LOG"
EOF
  printf '%s  bpfcompat-linux-amd64\n' "$(printf 'a%.0s' {1..64})" >"$r/SHA256SUMS"
  sbom "$r/bpfcompat.sbom.cdx.json" candidate-run
  mkcert "$r/SHA256SUMS.crt" "${san}${tag}" rc5-sums
  mksig "$r/SHA256SUMS.sig" "$r/SHA256SUMS" rc5-sums
  mkcert "$r/bpfcompat.sbom.cdx.crt" "${san}${tag}" rc5-sbom
  mksig "$r/bpfcompat.sbom.cdx.sig" "$r/bpfcompat.sbom.cdx.json" rc5-sbom
  printf '{"tag":"%s","commit_sha":"%s"}\n' "$tag" "$commit" \
    >"$d/candidate/run-evidence/release-candidate-evidence.json"
  # stage-draft-release uploads the same run's files.
  cp -R "$r" "$d/candidate/draft-assets"
  cp "$d/candidate/run-evidence/release-candidate-evidence.json" "$d/candidate/draft-assets/"
  printf '%s@%s %s%s rc5-image\n' "$image" "$digest" "$san" "$tag" >"$d/image-sigs"
  evidence_sha="$(sha256sum "$d/candidate/run-evidence/release-candidate-evidence.json" | awk '{print $1}')"
  printf '%s refs/tags/%s %s\n' "$evidence_sha" "$tag" "$commit" >"$d/attest-db"
}

tamper() { # $1 = case, $2 = case directory
  local draft="$2/candidate/draft-assets" run="$2/candidate/run-assets" f
  case "$1" in
    untouched-draft) ;;
    sbom-from-another-tag-run)
      # The public v0.4.0-rc.4 SBOM, signature and certificate.
      sbom "$draft/bpfcompat.sbom.cdx.json" rc4-run
      mkcert "$draft/bpfcompat.sbom.cdx.crt" "${san}v0.4.0-rc.4" rc4-sbom
      mksig "$draft/bpfcompat.sbom.cdx.sig" "$draft/bpfcompat.sbom.cdx.json" rc4-sbom ;;
    checksums-signed-by-a-new-tag)
      # The same SHA256SUMS bytes signed by a run on a newly created v* tag.
      mkcert "$draft/SHA256SUMS.crt" "${san}v9.9.9-rogue" rogue
      mksig "$draft/SHA256SUMS.sig" "$draft/SHA256SUMS" rogue ;;
    same-tag-sbom-not-from-candidate-run)
      sbom "$draft/bpfcompat.sbom.cdx.json" other-run
      mkcert "$draft/bpfcompat.sbom.cdx.crt" "${san}${tag}" other-run-sbom
      mksig "$draft/bpfcompat.sbom.cdx.sig" "$draft/bpfcompat.sbom.cdx.json" other-run-sbom ;;
    image-signed-only-by-another-tag)
      printf '%s@%s %sv0.4.0-rc.4 rc4-image\n' "$image" "$digest" "$san" >"$2/image-sigs" ;;
    checksums-signature-not-from-run)
      mksig "$draft/SHA256SUMS.sig" "$draft/SHA256SUMS" rc5-sums 2 ;;
    checksums-certificate-not-from-run)
      mkcert "$draft/SHA256SUMS.crt" "${san}${tag}" rc5-sums 2 ;;
    sbom-signature-not-from-run)
      mksig "$draft/bpfcompat.sbom.cdx.sig" "$draft/bpfcompat.sbom.cdx.json" rc5-sbom 2 ;;
    sbom-certificate-not-from-run)
      mkcert "$draft/bpfcompat.sbom.cdx.crt" "${san}${tag}" rc5-sbom 2 ;;
    run-checksums-signed-by-another-tag)
      # Identity is the only barrier: run artifact and draft agree.
      for f in "$run" "$draft"; do
        mkcert "$f/SHA256SUMS.crt" "${san}v0.4.0-rc.4" rc4-sums
        mksig "$f/SHA256SUMS.sig" "$f/SHA256SUMS" rc4-sums
      done ;;
    run-sbom-signed-by-another-tag)
      for f in "$run" "$draft"; do
        mkcert "$f/bpfcompat.sbom.cdx.crt" "${san}v0.4.0-rc.4" rc4-sbom
        mksig "$f/bpfcompat.sbom.cdx.sig" "$f/bpfcompat.sbom.cdx.json" rc4-sbom
      done ;;
    evidence-attested-by-another-tag-at-the-commit)
      awk -v c="$commit" '{print $1, "refs/tags/v0.4.0-rc.4", c}' "$2/attest-db" >"$2/attest-db.new"
      mv "$2/attest-db.new" "$2/attest-db" ;;
    evidence-attested-for-the-tag-at-another-commit)
      awk -v c="$other_commit" '{print $1, $2, c}' "$2/attest-db" >"$2/attest-db.new"
      mv "$2/attest-db.new" "$2/attest-db" ;;
    tampered-sbom-bytes-control)
      sbom "$draft/bpfcompat.sbom.cdx.json" tampered ;;
    run-checksums-signed-by-* | run-sbom-signed-by-* | image-signed-only-by-*)
      # A ROGUE_SIGNER identity. For the blobs the run artifact and the draft
      # agree, so the exact identity is the only barrier.
      local who="${1#*-by-}" id
      id="${ROGUE_SIGNER[$who]-}"
      [[ -n "$id" ]] || { echo "unknown signer in case $1" >&2; exit 1; }
      case "$1" in
        run-checksums-*)
          for f in "$run" "$draft"; do
            mkcert "$f/SHA256SUMS.crt" "$id" rogue-sums
            mksig "$f/SHA256SUMS.sig" "$f/SHA256SUMS" rogue-sums
          done ;;
        run-sbom-*)
          for f in "$run" "$draft"; do
            mkcert "$f/bpfcompat.sbom.cdx.crt" "$id" rogue-sbom
            mksig "$f/bpfcompat.sbom.cdx.sig" "$f/bpfcompat.sbom.cdx.json" rogue-sbom
          done ;;
        image-*)
          printf '%s@%s %s rogue-image\n' "$image" "$digest" "$id" >"$2/image-sigs" ;;
      esac ;;
    *) echo "unknown case $1" >&2; exit 1 ;;
  esac
}

promote() { # $1 = case directory; the two steps in job order
  local d="$1"
  (
    cd "$d"
    export PATH="$work/stubs:$PATH" GITHUB_REPOSITORY="$repo" RELEASE_TAG="$tag" \
      CANDIDATE_RUN_ID=38600000000 CANDIDATE_RUN_ATTEMPT=1 EXPECTED_COMMIT="$commit" \
      EXPECTED_DIGEST="$digest" GH_TOKEN=stub IMAGE="$image" IMAGE_SIGS="$d/image-sigs" \
      ATTEST_DB="$d/attest-db" VRA_LOG="$d/vra.log" STUB_IMAGE_VERSION="$tag"
    # The runner's shell for run: steps; && because an if suspends set -e.
    bash --noprofile --norc -eo pipefail "$work/verify-step.sh" >"$d/verify.log" 2>&1 &&
      bash --noprofile --norc -eo pipefail "$work/image-step.sh" >"$d/image.log" 2>&1
  )
}

# A refusal counts only for the reason the case is about (an ERE matched
# against the step logs): the draft differs from the candidate run's copy
# (cmp), the signer identity is not this tag's run, the evidence attestation
# is not this tag at this commit, or the signature does not cover the bytes.
declare -A REASON=(
  [CMP]='differ'
  [ID]='none of the expected identities matched|no matching signatures'
  [ATT]='no attestation of release-candidate-evidence.json matched'
  [SIG]='invalid signature'
)
REASON[CMP_OR_ID]="${REASON[CMP]}|${REASON[ID]}"
REASON[CMP_OR_SIG]="${REASON[CMP]}|${REASON[SIG]}"
while read -r name expect reason; do
  d="$work/$name"
  fixture "$d"
  tamper "$name" "$d"
  if promote "$d" </dev/null; then got=pass; else got=refuse; fi
  if [[ "$got" == "$expect" && "$got" == pass ]] ||
    { [[ "$got" == "$expect" ]] && grep -Eqs -- "${REASON[$reason]}" "$d/verify.log" "$d/image.log"; }; then
    ok "promotion of ${tag}, ${name}: ${got}${reason:+ (${reason})}"
  else
    bad "promotion of ${tag}, ${name}: expected ${expect}${reason:+ (${reason})}, got ${got}"
    cat "$d/verify.log" "$d/image.log" 2>/dev/null >&2 || true
  fi
done <<'CASES'
untouched-draft pass
sbom-from-another-tag-run refuse CMP_OR_ID
checksums-signed-by-a-new-tag refuse CMP_OR_ID
same-tag-sbom-not-from-candidate-run refuse CMP
image-signed-only-by-another-tag refuse ID
checksums-signature-not-from-run refuse CMP
checksums-certificate-not-from-run refuse CMP
sbom-signature-not-from-run refuse CMP
sbom-certificate-not-from-run refuse CMP
run-checksums-signed-by-another-tag refuse ID
run-sbom-signed-by-another-tag refuse ID
evidence-attested-by-another-tag-at-the-commit refuse ATT
evidence-attested-for-the-tag-at-another-commit refuse ATT
tampered-sbom-bytes-control refuse CMP_OR_SIG
run-checksums-signed-by-a-tag-extending-the-release-tag refuse ID
run-sbom-signed-by-a-tag-extending-the-release-tag refuse ID
image-signed-only-by-a-tag-extending-the-release-tag refuse ID
run-checksums-signed-by-a-tag-differing-at-a-dot refuse ID
run-sbom-signed-by-a-tag-differing-at-a-dot refuse ID
image-signed-only-by-a-tag-differing-at-a-dot refuse ID
run-checksums-signed-by-the-tag-in-another-repository refuse ID
run-sbom-signed-by-the-tag-in-another-repository refuse ID
image-signed-only-by-the-tag-in-another-repository refuse ID
run-checksums-signed-by-another-workflow-on-the-tag refuse ID
run-sbom-signed-by-another-workflow-on-the-tag refuse ID
image-signed-only-by-another-workflow-on-the-tag refuse ID
CASES

# Every ROGUE_SIGNER identity is used at all three cosign sites above.
for who in "${!ROGUE_SIGNER[@]}"; do
  for site in run-checksums-signed-by run-sbom-signed-by image-signed-only-by; do
    [[ -d "$work/${site}-${who}" ]] || bad "no promotion case ${site}-${who}"
  done
done

want="SHA=${commit} REF=refs/tags/${tag}"
if [[ "$(cat "$work/untouched-draft/vra.log" 2>/dev/null)" == "$want" ]]; then
  ok "promotion verifies the draft assets for ${tag} at the expected commit"
else
  bad "promotion passed verify-release-assets.sh '$(cat "$work/untouched-draft/vra.log" 2>/dev/null)', not '${want}'"
fi

# ------------------------------------------------------------------ 3. wiring
# The tag build's gates verify the run's own artifact; maintenance evidence
# verifies the published prerelease of the dispatched rc tag. Each passes the
# commit and tag ref it runs on, which verify-release-assets.sh requires.
wiring="$(python3 - "$RELEASE_WF" "$MAINTENANCE_WF" <<'PY'
import sys

import yaml

want = {
    "BPFCOMPAT_EXPECTED_SOURCE_SHA": "${{ github.sha }}",
    "BPFCOMPAT_EXPECTED_SOURCE_REF": "${{ github.ref }}",
}
expected_calls = {sys.argv[1]: 2, sys.argv[2]: 1}
for path, count in expected_calls.items():
    wf = yaml.safe_load(open(path, encoding="utf-8"))
    name = path.rsplit("/", 1)[-1]
    calls = 0
    for job_id, job in wf["jobs"].items():
        for step in job.get("steps", []):
            if "scripts/verify-release-assets.sh" not in (step.get("run") or ""):
                continue
            calls += 1
            env = step.get("env") or {}
            good = all(env.get(k) == v for k, v in want.items())
            print(("ok " if good else "FAIL ") +
                  f"{name} {job_id} / {step.get('name')}: verify-release-assets.sh gets the run's commit and tag ref")
    print(("ok " if calls == count else "FAIL ") + f"{name}: {calls} verify-release-assets.sh call(s), expected {count}")
PY
)"
while IFS= read -r line; do
  case "$line" in
    ok\ *) ok "${line#ok }" ;;
    *) bad "${line#FAIL }" ;;
  esac
done <<<"$wiring"

if [[ "$failures" -ne 0 ]]; then
  echo "[release-workflow-gates-test] ${failures} check(s) FAILED" >&2
  exit 1
fi
echo "[release-workflow-gates-test] PASS"
