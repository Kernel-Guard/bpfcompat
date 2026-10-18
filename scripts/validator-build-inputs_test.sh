#!/usr/bin/env bash
# Regression tests for the pinned validator build and the stable == RC gate.
#
# v0.4.0-rc.4's validator (e0e7fcf8...) was built on the moving ubuntu-latest
# label with whatever libbpf/zlib/glibc the runner image had. rc.3 and rc.4
# share the validator/c-libbpf tree but not their bytes, and Ubuntu 26.04 (the
# next ubuntu-latest) links libbpf 1.6 + GCC 15. These tests pin:
#   1. the release workflow builds the validator from validator/build-inputs.lock
#      on ubuntu-24.04, and a stable tag refuses a validator that is not the
#      qualified candidate's;
#   2. the lock is digest-pinned and pins every statically linked package;
#   3. check-validator-build-inputs.sh catches libbpf/compiler/static drift;
#   4. check-validator-matches-candidate.sh enforces the evidence -> SHA256SUMS
#      -> validator chain, using real v0.4.0-rc.4 release data.
#
# Env: WORKFLOW overrides the workflow under test (to show the old one fails).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOW="${WORKFLOW:-$ROOT/.github/workflows/release-artifacts.yml}"
LOCK="$ROOT/validator/build-inputs.lock"
INPUTS="$ROOT/scripts/check-validator-build-inputs.sh"
MATCH="$ROOT/scripts/check-validator-matches-candidate.sh"
BUILDER="$ROOT/scripts/build-validator-pinned.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
failures=0
pass() { printf 'ok:   %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; failures=$((failures + 1)); }

# expect <want-exit> <name> <cmd...>
expect() {
  local want="$1" name="$2" got=0
  shift 2
  "$@" >"$tmp/out" 2>&1 || got=$?
  if [[ "$got" -eq "$want" ]]; then
    pass "$name (exit $got)"
  else
    fail "$name: exit $got, want $want"
    sed 's/^/      /' "$tmp/out" >&2
  fi
}

# ---------------------------------------------------------------- 1. workflow
python3 - "$WORKFLOW" >"$tmp/wf" <<'PY'
import sys, yaml
wf = yaml.safe_load(open(sys.argv[1]))
for name, job in (wf.get("jobs") or {}).items():
    print(f"runs-on\t{name}\t{job.get('runs-on')}")
    for step in job.get("steps") or []:
        run = step.get("run") or ""
        print(f"step\t{name}\t{step.get('name', '')}\t{step.get('if', '')}\t" + " ".join(run.replace("\\\n", " ").split()))
PY
while IFS=$'\t' read -r kind job label; do
  [[ "$kind" == "runs-on" ]] || continue
  case "$label" in
    ubuntu-24.04 | ubuntu-24.04-arm) pass "workflow job $job runs on pinned $label" ;;
    *) fail "workflow job $job runs on '$label'; release jobs must pin ubuntu-24.04[-arm]" ;;
  esac
done <"$tmp/wf"
build_steps="$(awk -F'\t' '$1 == "step" && $2 == "build-and-sign"' "$tmp/wf")"
if grep -q 'scripts/build-validator-pinned.sh dist/bpfcompat-validator-static-linux-amd64' <<<"$(tr -s ' ' <<<"$build_steps")"; then
  pass "build-and-sign builds the validator with scripts/build-validator-pinned.sh"
else
  fail "build-and-sign does not build the validator with scripts/build-validator-pinned.sh"
fi
if grep -Eq 'apt-get install[^\t]*libbpf-dev' <<<"$build_steps" || grep -q 'make validator-static' <<<"$build_steps"; then
  fail "build-and-sign still builds the validator against the runner's own libbpf-dev"
else
  pass "build-and-sign does not link the runner image's libbpf"
fi
gate="$(awk -F'\t' '$1 == "step" && $2 == "build-and-sign" && $5 ~ /check-validator-matches-candidate\.sh/' "$tmp/wf")"
if [[ -n "$gate" ]] && grep -q "channel == 'stable'" <<<"$gate"; then
  pass "stable tags must ship the qualified candidate's validator"
else
  fail "no stable-only check-validator-matches-candidate.sh step in build-and-sign"
fi

subjects="$(python3 - "$WORKFLOW" <<'PY'
import sys, yaml
job = (yaml.safe_load(open(sys.argv[1])).get("jobs") or {}).get("build-and-sign") or {}
for step in job.get("steps") or []:
    if step.get("name") == "Attest candidate provenance":
        print((step.get("with") or {}).get("subject-path", ""))
PY
)"
if grep -qx '[[:space:]]*dist/validator-build-inputs.json' <<<"$subjects"; then
  pass "validator build-input record is a provenance subject"
else
  fail "dist/validator-build-inputs.json is not in the candidate provenance subjects"
fi
if grep -q "'.sha256 == \$sha' dist/validator-build-inputs.json" <<<"$build_steps"; then
  pass "build-and-sign binds the build-input record to the shipped validator sha256"
else
  fail "build-and-sign does not check the build-input record against the shipped validator"
fi

# ---------------------------------------------------------------- 2. lock
expect 0 "repository lock is well-formed" bash "$BUILDER" --check-lock
bad_lock() {
  local name="$1" sed_expr="$2"
  sed -E "$sed_expr" "$LOCK" >"$tmp/bad.lock"
  expect 2 "lock refused: $name" env BPFCOMPAT_VALIDATOR_LOCK="$tmp/bad.lock" bash "$BUILDER" --check-lock
}
bad_lock "builder image by tag" 's#^builder_image=.*#builder_image=docker.io/library/ubuntu:24.04#'
bad_lock "unpinned libbpf-dev" 's#^pkg=libbpf-dev=.*#pkg=libbpf-dev#'
bad_lock "libbpf-dev missing" '/^pkg=libbpf-dev=/d'
bad_lock "zlib1g-dev missing" '/^pkg=zlib1g-dev=/d'
bad_lock "libc6-dev missing" '/^pkg=libc6-dev=/d'
bad_lock "no compiler" '/^pkg=gcc-[0-9]+=/d'
bad_lock "malformed reproduces" 's#^reproduces=.*#reproduces=e0e7fcf8#'
bad_lock "apt_snapshot missing (moving archive)" '/^apt_snapshot=/d'
bad_lock "apt_snapshot not a fixed timestamp" 's#^apt_snapshot=.*#apt_snapshot=latest#'
bad_lock "apt_snapshot not a real date" 's#^apt_snapshot=.*#apt_snapshot=20261399T254800Z#'
# snapshot.ubuntu.com serves a future id as "the newest state so far": a lock
# naming one silently follows the moving archive until that date.
sed -E 's#^apt_snapshot=.*#apt_snapshot=20990101T000000Z#' "$LOCK" >"$tmp/future.lock"
expect 1 "lock refused: apt_snapshot in the future (moving archive in disguise)" \
  env BPFCOMPAT_VALIDATOR_LOCK="$tmp/future.lock" bash "$BUILDER" --check-lock
expect 1 "future apt_snapshot refused before any apt configuration is written" \
  env BPFCOMPAT_VALIDATOR_LOCK="$tmp/future.lock" bash "$BUILDER" --render-apt-config "$tmp/future-apt"

# The archive keeps only the newest version per pocket: resolving the lock from
# it breaks at the next SRU of any pinned package (and lets unpinned transitive
# packages drift). Every package must come from the lock's fixed snapshot, with
# apt's signature verification intact.
snapshot="$(awk -F= '$1 == "apt_snapshot" { print $2 }' "$LOCK")"
# Print every line of <sources> <apt.conf> that relaxes TLS or signature
# checks. The only tolerated one is the documented fallback: peer verification
# off for snapshot.ubuntu.com when no CA bundle is available.
tls_relaxations() {
  {
    grep -Ei 'trusted *= *yes|allow-insecure *= *yes|allow-weak *= *yes|allow-downgrade-to-insecure *= *yes' <<<"$1" || true
    grep -Ei 'Verify-Host|Check-Valid-Until|Check-Date|AllowReleaseInfoChange|::SslForceVersion|::IssuerCert|::CrlFile' <<<"$2" || true
    grep -Ei 'Verify-Peer' <<<"$2" | grep -vx 'Acquire::https::snapshot.ubuntu.com::Verify-Peer "false";' || true
    grep -Ei 'AllowInsecureRepositories|AllowDowngradeToInsecureRepositories|AllowUnauthenticated|AllowWeakRepositories' <<<"$2" |
      grep -Evi '"(false|0|no)";$' || true
  } | sed '/^$/d'
}
if bash "$BUILDER" --render-apt-config "$tmp/apt" >"$tmp/out" 2>&1; then
  src="$(cat "$tmp/apt/sources.list.d/"*.sources 2>/dev/null || true)"
  conf="$(cat "$tmp/apt/apt.conf.d/"* 2>/dev/null || true)"
  if [[ "$(grep '^URIs:' <<<"$src")" == "URIs: https://snapshot.ubuntu.com/ubuntu/${snapshot}/" ]]; then
    pass "apt resolves only from snapshot ${snapshot}"
  else
    fail "apt sources are not exactly the lock's snapshot: $(grep '^URIs:' <<<"$src" | tr '\n' ' ')"
  fi
  if grep -qx 'Suites: noble noble-updates noble-security' <<<"$src" &&
    grep -qx 'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg' <<<"$src"; then
    pass "snapshot covers noble/-updates/-security and is signature-checked"
  else
    fail "snapshot sources lack the noble pockets or Signed-By"
  fi
  if grep -Eq 'archive\.ubuntu\.com|security\.ubuntu\.com' <<<"$src$conf"; then
    fail "apt configuration still names the moving archive"
  else
    pass "apt configuration never names the moving archive"
  fi
  if [[ -n "$(tls_relaxations "$src" "$conf")" ]]; then
    fail "apt configuration weakens signature/TLS checks: $(tls_relaxations "$src" "$conf" | tr '\n' ';')"
  else
    pass "no host CA bundle: signature verification kept; TLS relaxed for snapshot.ubuntu.com only"
  fi
  if grep -qx 'Acquire::https::snapshot.ubuntu.com::Verify-Peer "false";' <<<"$conf"; then
    pass "no host CA bundle: documented signature-only fallback is used"
  else
    fail "no host CA bundle: expected the snapshot-scoped Verify-Peer fallback"
  fi
else
  fail "build-validator-pinned.sh --render-apt-config failed: $(cat "$tmp/out")"
fi
# With the runner's CA bundle mounted, TLS to the snapshot is verified too.
if bash "$BUILDER" --render-apt-config "$tmp/apt-ca" /etc/bpfcompat-snapshot-ca.crt >"$tmp/out" 2>&1; then
  src="$(cat "$tmp/apt-ca/sources.list.d/"*.sources 2>/dev/null || true)"
  conf="$(cat "$tmp/apt-ca/apt.conf.d/"* 2>/dev/null || true)"
  if grep -qx 'Acquire::https::snapshot.ubuntu.com::CaInfo "/etc/bpfcompat-snapshot-ca.crt";' <<<"$conf" &&
    ! grep -q 'Verify-Peer' <<<"$conf" && [[ -z "$(tls_relaxations "$src" "$conf")" ]]; then
    pass "host CA bundle: TLS to snapshot.ubuntu.com verified against it, nothing relaxed"
  else
    fail "host CA bundle: expected CaInfo and no TLS/auth relaxation, got: $(tr '\n' ';' <<<"$conf")"
  fi
else
  fail "build-validator-pinned.sh --render-apt-config <dir> <ca> failed: $(cat "$tmp/out")"
fi
if grep -Eq -- '--allow-unauthenticated|--allow-insecure-repositories|--allow-releaseinfo-change|trusted=yes|-o +[A-Za-z:]*(Verify|Allow|Check)' "$BUILDER"; then
  fail "builder passes an apt option that weakens verification on the command line"
else
  pass "builder passes no verification-weakening apt options on the command line"
fi
inside="$(awk '/"--inside"/,/^fi$/' "$BUILDER")"
if awk '/rm -f \/etc\/apt\/sources.list/ { r = NR } /apt-get update/ && !u { u = NR } END { exit !(r && u && r < u) }' <<<"$inside" &&
  grep -q 'render_apt_config /etc/apt' <<<"$inside"; then
  pass "--inside drops the image's archive sources before apt-get update"
else
  fail "--inside does not replace the image's archive sources with the snapshot before apt-get update"
fi
# apt-get update exits 0 when an index fetch fails (TLS error, 5xx): without
# --error-on=any the retry never runs and the snapshot failure surfaces later.
if grep -Eq 'apt-get update[^#]*--error-on=any' <<<"$inside"; then
  pass "--inside treats any failed snapshot index fetch as an apt-get update failure"
else
  fail "--inside apt-get update ignores failed index fetches (needs --error-on=any)"
fi

# ---------------------------------------------------------------- 3. binary identity
if command -v cc >/dev/null && command -v readelf >/dev/null && command -v objdump >/dev/null; then
  make_elf() { # make_elf <out> <major> <minor> [extra cc flags...]
    local out="$1" major="$2" minor="$3"
    shift 3
    cat >"$tmp/v.c" <<EOF
__attribute__((noinline)) unsigned int libbpf_major_version(void) { return $major; }
__attribute__((noinline)) unsigned int libbpf_minor_version(void) { return $minor; }
int main(void) { return (int)(libbpf_major_version() + libbpf_minor_version()) - $((major + minor)); }
EOF
    cc -O2 "$tmp/v.c" -o "$out" "$@"
  }
  if make_elf "$tmp/ok" 1 3 -static 2>"$tmp/cc.err"; then
    host_comment="$(readelf -p .comment "$tmp/ok" | awk '/^ *\[ *[0-9a-f]+\]/ { sub(/^ *\[ *[0-9a-f]+\] +/, ""); print }' | sort -u)"
    sed -E "s#^expect_gcc_comment=.*#expect_gcc_comment=${host_comment//#/\\#}#; s#^expect_libbpf=.*#expect_libbpf=1.3#" "$LOCK" >"$tmp/host.lock"
    expect 0 "static libbpf 1.3 binary matches the lock" bash "$INPUTS" "$tmp/ok" "$tmp/host.lock"
    make_elf "$tmp/drift" 1 6 -static
    expect 1 "libbpf 1.6 (ubuntu 26.04) binary refused" bash "$INPUTS" "$tmp/drift" "$tmp/host.lock"
    make_elf "$tmp/dyn" 1 3
    expect 1 "dynamically linked binary refused" bash "$INPUTS" "$tmp/dyn" "$tmp/host.lock"
    sed -E 's#^expect_gcc_comment=.*#expect_gcc_comment=GCC: (Ubuntu 15.2.0-16ubuntu1) 15.2.0#' "$tmp/host.lock" >"$tmp/gcc15.lock"
    expect 1 "other compiler than the lock refused" bash "$INPUTS" "$tmp/ok" "$tmp/gcc15.lock"
    printf 'not an elf\n' >"$tmp/text"
    expect 1 "non-ELF refused" bash "$INPUTS" "$tmp/text" "$tmp/host.lock"
    expect 1 "missing binary refused" bash "$INPUTS" "$tmp/nope" "$tmp/host.lock"
  else
    fail "cannot build a static test ELF (need cc and static libc): $(cat "$tmp/cc.err")"
  fi
else
  fail "cc, readelf and objdump are required for the binary-identity tests"
fi

# ---------------------------------------------------------------- 4. stable == candidate
# Real v0.4.0-rc.4 release assets (byte-identical copies). Evidence sha256
# 4b0e47c9... is the value bound in .github/campaign-candidate.json.
mkdir -p "$tmp/rc4"
printf '%s\n' \
  '2771604c62ed01df6839ffe461ca98ce3ad47da1ca36ed4c2a670af066f71ca1  bpfcompat-linux-amd64' \
  'bc85e7c6084fd899419c2acf152324be792a8b3310e3c0451a81cd2d3fdff0e3  bpfcompat-linux-arm64' \
  'e0e7fcf8bd8384be3f85e4716d7330bdc0d3ae4d5de4070e815fa07c278be03a  bpfcompat-validator-static-linux-amd64' \
  >"$tmp/rc4/SHA256SUMS"
cat >"$tmp/rc4/release-candidate-evidence.json" <<'EOF'
{
  "schema_version": "v0.1",
  "repository": "Kernel-Guard/bpfcompat",
  "workflow": "Kernel-Guard/bpfcompat/.github/workflows/release-artifacts.yml@refs/tags/v0.4.0-rc.4",
  "workflow_run_id": 38592617383,
  "workflow_run_attempt": 1,
  "commit_sha": "222c3f38a5361fca7c43c33df841290f8bef0021",
  "tag": "v0.4.0-rc.4",
  "channel": "prerelease",
  "image": "ghcr.io/kernel-guard/bpfcompat@sha256:65f780f381e42b712459745350d248080304f2531695b606d5560eb7a78fb624",
  "checksums_sha256": "fbbcddbf0d621bbf5c79ee25cb5492022b9bb46de1b5645bba2df348d3f0a87c",
  "positive_report_sha256": "b65f73e267754c8654ec82e1dfc89183bed1bf1ec07780d60d81fe8c450dd538",
  "negative_report_sha256": "0c85c7490d2aa1db4473403104a97ece1efc294d9b5412e333aba51f0166241d",
  "generated_at": "2026-10-14T15:55:37Z"
}
EOF
rc4_evidence=4b0e47c9a44578d721fe9d5f47f93dd5aa0987da88f4818bfaf5e7a1fb34ad98
if [[ "$(sha256sum "$tmp/rc4/release-candidate-evidence.json" | awk '{print $1}')" == "$rc4_evidence" &&
  "$(sha256sum "$tmp/rc4/SHA256SUMS" | awk '{print $1}')" == fbbcddbf0d621bbf5c79ee25cb5492022b9bb46de1b5645bba2df348d3f0a87c ]]; then
  pass "rc.4 fixtures are byte-identical to the published assets"
else
  fail "rc.4 fixtures drifted from the published assets"
fi
printf 'a rebuilt validator that is not rc.4\n' >"$tmp/rebuilt"
expect 1 "real rc.4 chain: a different stable validator is refused" \
  bash "$MATCH" "$tmp/rebuilt" "$tmp/rc4/SHA256SUMS" "$tmp/rc4/release-candidate-evidence.json" "$rc4_evidence"
if grep -q 'differs from candidate v0.4.0-rc.4 validator e0e7fcf8' "$tmp/out"; then
  pass "refusal names the qualified rc.4 validator"
else
  fail "refusal does not name the rc.4 validator"
fi

# Synthetic candidate whose validator bytes we control.
mkdir -p "$tmp/syn"
printf 'qualified validator bytes\n' >"$tmp/syn/validator"
v_sha="$(sha256sum "$tmp/syn/validator" | awk '{print $1}')"
printf '%s  %s\n' "$v_sha" bpfcompat-validator-static-linux-amd64 >"$tmp/syn/SHA256SUMS"
jq -n --arg s "$(sha256sum "$tmp/syn/SHA256SUMS" | awk '{print $1}')" \
  '{schema_version: "v0.1", tag: "v9.9.9-rc.1", checksums_sha256: $s}' >"$tmp/syn/evidence.json"
syn_evidence="$(sha256sum "$tmp/syn/evidence.json" | awk '{print $1}')"
expect 0 "identical validator accepted" \
  bash "$MATCH" "$tmp/syn/validator" "$tmp/syn/SHA256SUMS" "$tmp/syn/evidence.json" "$syn_evidence"
expect 1 "evidence not bound to the expected sha256 refused" \
  bash "$MATCH" "$tmp/syn/validator" "$tmp/syn/SHA256SUMS" "$tmp/syn/evidence.json" "$rc4_evidence"
printf '%s  %s\n' "$v_sha" bpfcompat-validator-static-linux-amd64 >"$tmp/syn/SUBST"
printf '%s  %s\n' "$v_sha" bpfcompat-linux-amd64 >>"$tmp/syn/SUBST"
expect 1 "substituted SHA256SUMS refused" \
  bash "$MATCH" "$tmp/syn/validator" "$tmp/syn/SUBST" "$tmp/syn/evidence.json" "$syn_evidence"
mkdir -p "$tmp/dup"
printf '%s  %s\n' "$v_sha" bpfcompat-validator-static-linux-amd64 "$v_sha" bpfcompat-validator-static-linux-amd64 >"$tmp/dup/SHA256SUMS"
jq -n --arg s "$(sha256sum "$tmp/dup/SHA256SUMS" | awk '{print $1}')" '{tag: "v9.9.9-rc.1", checksums_sha256: $s}' >"$tmp/dup/evidence.json"
expect 1 "duplicate validator entries refused" \
  bash "$MATCH" "$tmp/syn/validator" "$tmp/dup/SHA256SUMS" "$tmp/dup/evidence.json" "$(sha256sum "$tmp/dup/evidence.json" | awk '{print $1}')"
expect 1 "missing built validator refused" \
  bash "$MATCH" "$tmp/syn/none" "$tmp/syn/SHA256SUMS" "$tmp/syn/evidence.json" "$syn_evidence"
expect 2 "malformed expected evidence sha256 is a usage error" \
  bash "$MATCH" "$tmp/syn/validator" "$tmp/syn/SHA256SUMS" "$tmp/syn/evidence.json" not-a-sha

if [[ "$failures" -ne 0 ]]; then
  echo "validator-build-inputs_test: $failures FAILED" >&2
  exit 1
fi
echo "validator-build-inputs_test: all checks passed"
