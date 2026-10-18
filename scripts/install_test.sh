#!/usr/bin/env bash
# Regression cover for scripts/install.sh, the README's one-command installer.
#
# Every case runs the real installer against a fake GitHub served by a local
# python http.server on 127.0.0.1. curl, gh, cosign, uname and sudo are PATH
# shims and the PATH is otherwise a curated tool directory, so the real gh,
# cosign and network are never reachable:
#   * curl rewrites https://github.com and https://api.github.com to the local
#     server and refuses any other https:// URL;
#   * cosign accepts a signature only when the certificate identity flags match
#     the identity baked into SHA256SUMS.crt (the release tag that signed it)
#     and the signature covers this exact SHA256SUMS;
#   * gh accepts an attestation only for a binary the fake release pipeline
#     attested, and honours --source-ref like the real CLI does; with
#     FAKE_GH_LACKS it plays an older gh that has no `attestation` command or
#     no --signer-workflow / --source-ref flag, failing like cobra does;
#   * sudo pretends to be root by unlocking the test's read-only tree.
#
# Cases: latest -> stable, arch mapping (incl. extra SHA256SUMS lines, the
# v0.3.6 bug class), fail-closed without sha tools / without cosign+gh / on a
# checksum mismatch, signatures bound to the requested tag, truncated
# `curl | sh` streams, custom install dirs, tag validation (the whole value,
# embedded newlines included), the third-party license bundle (installed when
# SHA256SUMS lists it, verified like the binaries, refused when
# corrupt/missing/unattested, absent in old releases), and a gh too old for
# the tag-bound check (refused naming what it lacks, never reported as a
# failed verification or a missing gh; cosign still preferred when present).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL="${ROOT_DIR}/scripts/install.sh"
tmp="$(mktemp -d)"
srv_pid=""
cleanup() {
  if [[ -n "$srv_pid" ]]; then kill "$srv_pid" 2>/dev/null || true; fi
  chmod -R u+w "$tmp" 2>/dev/null || true
  rm -rf "$tmp"
}
trap cleanup EXIT

REPO=Kernel-Guard/bpfcompat
WF="https://github.com/${REPO}/.github/workflows/release-artifacts.yml"
REAL_CURL="$(command -v curl)"
REAL_SHA="$(command -v sha256sum)"
WWW="$tmp/www"
SHIM="$tmp/shim"
TOOLS="$tmp/tools"
ATTEST_DB="$tmp/attestations"
CURL_LOG="$tmp/curl.log"
GH_LOG="$tmp/gh.log"
mkdir -p "$WWW" "$SHIM" "$TOOLS" "$tmp/home"
: >"$ATTEST_DB"

failures=0
fail() { echo "[install-test] FAIL: $*" >&2; failures=$((failures + 1)); }
ok() { echo "[install-test] ok: $*"; }

# ---------------------------------------------------------------- fake release
# release <scenario> <tag> [validator-arches] [bundle]: builds a signed,
# attested release under the scenario's fake github.com tree, the way
# release-artifacts.yml does. bundle: "yes" adds the third-party license
# bundle; "unattested" adds it to SHA256SUMS without an attestation.
release() {
  local scen="$1" tag="$2" varches="${3:-amd64}" bundle="${4:-no}" d a b
  d="$WWW/$scen/gh/$REPO/releases/download/$tag"
  mkdir -p "$d"
  for a in amd64 arm64; do
    printf '#!/bin/sh\necho "fake bpfcompat %s %s"\n' "$tag" "$a" >"$d/bpfcompat-linux-$a"
  done
  for a in $varches; do
    printf 'validator %s %s\n' "$tag" "$a" >"$d/bpfcompat-validator-static-linux-$a"
  done
  if [[ "$bundle" != no ]]; then
    b="$tmp/bundle-$scen-$tag/bpfcompat-third-party-licenses"
    mkdir -p "$b/go/toolchain"
    # Unique per scenario: the attestation DB is keyed by digest.
    printf '{"bpfcompat": {"version": "%s"}, "fixture": "%s"}\n' "$tag" "$scen" >"$b/INVENTORY.json"
    printf 'Go license text\n' >"$b/go/toolchain/LICENSE"
    tar -C "$(dirname "$b")" -czf "$d/bpfcompat-third-party-licenses.tar.gz" bpfcompat-third-party-licenses
  fi
  (cd "$d" && "$REAL_SHA" bpfcompat-* >SHA256SUMS)
  for a in "$d"/bpfcompat-*; do
    [[ "$bundle" == unattested && "$a" == *third-party-licenses* ]] && continue
    printf '%s refs/tags/%s\n' "$("$REAL_SHA" <"$a" | cut -d' ' -f1)" "$tag" >>"$ATTEST_DB"
  done
  printf 'sig:%s\n' "$("$REAL_SHA" <"$d/SHA256SUMS" | cut -d' ' -f1)" >"$d/SHA256SUMS.sig"
  printf '%s@refs/tags/%s\n' "$WF" "$tag" >"$d/SHA256SUMS.crt"
}
latest() { # <scenario> <tag_name json value>
  mkdir -p "$WWW/$1/api/repos/$REPO/releases"
  printf '{\n  "url": "x",\n  "tag_name": "%s",\n  "prerelease": false\n}\n' "$2" \
    >"$WWW/$1/api/repos/$REPO/releases/latest"
}
# mirror <scenario> <from-tag> <to-tag>: serve one release's assets under another tag.
mirror() {
  local base="$WWW/$1/gh/$REPO/releases/download"
  mkdir -p "$base/$3"
  cp "$base/$2"/* "$base/$3/"
}
rel_dir() { echo "$WWW/$1/gh/$REPO/releases/download/$2"; }

# ---------------------------------------------------------------- shims
cat >"$SHIM/curl" <<EOF
#!/usr/bin/env bash
args=()
for a in "\$@"; do
  a="\${a//https:\/\/api.github.com/http://127.0.0.1:\${FAKE_PORT}/\${SCENARIO}/api}"
  a="\${a//https:\/\/github.com/http://127.0.0.1:\${FAKE_PORT}/\${SCENARIO}/gh}"
  case "\$a" in https://*|http://*) echo "\$a" >>"$CURL_LOG";; esac
  case "\$a" in https://*) echo "curl shim: refusing network URL \$a" >&2; exit 7;; esac
  args+=("\$a")
done
exec "$REAL_CURL" --noproxy '*' "\${args[@]}"
EOF
cat >"$SHIM/cosign" <<EOF
#!/usr/bin/env bash
# Fake cosign verify-blob: the certificate SAN is the content of --certificate.
[[ "\${1:-}" == "verify-blob" ]] || exit 2
shift
crt="" sig="" ident="" identre="" issuer="" blob=""
while [[ \$# -gt 0 ]]; do
  case "\$1" in
    --certificate) crt="\$2"; shift 2;;
    --signature) sig="\$2"; shift 2;;
    --certificate-identity) ident="\$2"; shift 2;;
    --certificate-identity-regexp) identre="\$2"; shift 2;;
    --certificate-oidc-issuer) issuer="\$2"; shift 2;;
    -*) echo "cosign shim: unknown flag \$1" >&2; exit 2;;
    *) blob="\$1"; shift;;
  esac
done
[[ "\$issuer" == "https://token.actions.githubusercontent.com" ]] || exit 1
san="\$(cat "\$crt")"
[[ "\$(cat "\$sig")" == "sig:\$("$REAL_SHA" <"\$blob" | cut -d' ' -f1)" ]] || exit 1
if [[ -n "\$ident" ]]; then [[ "\$san" == "\$ident" ]] || exit 1
elif [[ -n "\$identre" ]]; then printf '%s\n' "\$san" | grep -Eq -- "\$identre" || exit 1
else exit 1; fi
exit 0
EOF
cat >"$SHIM/gh" <<EOF
#!/usr/bin/env bash
# Fake gh attestation verify backed by the attestation DB the fake release wrote.
# FAKE_GH_LACKS plays an older gh (feature history from gh's release notes):
# "attestation" = gh < 2.49.0, "--signer-workflow" = gh < 2.51.0,
# "--source-ref" = gh < 2.68.0. FAKE_GH_VERSION is what --version reports.
echo "\$*" >>"$GH_LOG"
lacks=" \${FAKE_GH_LACKS:-} "
if [[ "\${1:-}" == "--version" ]]; then
  printf 'gh version %s (2026-01-01)\nhttps://github.com/cli/cli/releases/latest\n' "\${FAKE_GH_VERSION:-2.102.0}"
  exit 0
fi
if [[ "\${1:-}" == attestation && "\$lacks" == *" attestation "* ]]; then
  printf 'unknown command "attestation" for "gh"\n\nUsage:  gh <command> <subcommand> [flags]\n' >&2
  exit 1
fi
[[ "\${1:-} \${2:-}" == "attestation --help" ]] && exit 0
if [[ "\${1:-} \${2:-} \${3:-}" == "attestation verify --help" ]]; then
  echo 'Verify the integrity and provenance of an artifact using its associated'
  echo 'cryptographically signed attestations.'
  [[ "\$lacks" == *" --signer-workflow "* ]] ||
    echo 'When using reusable workflows, use the \`--signer-repo\` or \`--signer-workflow\` flags.'
  echo
  echo 'FLAGS'
  echo '  -o, --owner string             GitHub organization to scope attestation lookup by'
  echo '  -R, --repo string              Repository name in the format <owner>/<repo>'
  [[ "\$lacks" == *" --signer-workflow "* ]] ||
    echo '      --signer-workflow string   Workflow that signed attestation in the format [host/]<owner>/<repo>/<path>/<to>/<workflow>'
  [[ "\$lacks" == *" --source-ref "* ]] ||
    echo '      --source-ref string        Ref associated with the source workflow'
  exit 0
fi
[[ "\${1:-} \${2:-}" == "attestation verify" ]] || exit 1
shift 2
file="" repo="" signer="" ref=""
while [[ \$# -gt 0 ]]; do
  if [[ "\$1" == --* && "\$lacks" == *" \$1 "* ]]; then echo "unknown flag: \$1" >&2; exit 1; fi
  case "\$1" in
    --repo) repo="\$2"; shift 2;;
    --signer-workflow) signer="\$2"; shift 2;;
    --source-ref) ref="\$2"; shift 2;;
    -*) echo "gh shim: unknown flag \$1" >&2; exit 2;;
    *) file="\$1"; shift;;
  esac
done
[[ "\$repo" == "$REPO" ]] || exit 1
[[ "\$signer" == "$REPO/.github/workflows/release-artifacts.yml" ]] || exit 1
sum="\$("$REAL_SHA" <"\$file" | cut -d' ' -f1)"
if [[ -n "\$ref" ]]; then grep -qx "\$sum \$ref" "$ATTEST_DB"
else grep -q "^\$sum " "$ATTEST_DB"; fi
EOF
cat >"$SHIM/uname" <<'EOF'
#!/bin/sh
case "$1" in -s) echo "${FAKE_OS:-Linux}";; -m) echo "${FAKE_ARCH:-x86_64}";; *) exit 1;; esac
EOF
cat >"$SHIM/sudo" <<EOF
#!/usr/bin/env bash
# Pretend to be root: unlock the test's read-only tree, then run the command.
echo "sudo \$*" >>"$tmp/sudo.log"
chmod -R u+w "$tmp/ro" 2>/dev/null || true
exec "\$@"
EOF
chmod 0755 "$SHIM"/*

# Curated tools: everything install.sh and the shims need, nothing else (no
# real gh/cosign/sudo). Variants drop sha tools or the signature verifiers.
for t in sh bash grep sed head cut cat mktemp rm install dirname chmod cp tr env sha256sum mkdir tar gzip; do
  p="$(command -v "$t")" || { echo "[install-test] missing tool $t" >&2; exit 1; }
  ln -s "$p" "$TOOLS/$t"
done
mkdir -p "$tmp/nosha" "$tmp/noverify"
for t in "$TOOLS"/*; do
  n="$(basename "$t")"
  [[ "$n" == sha256sum ]] || ln -s "$(readlink "$t")" "$tmp/nosha/$n"
done
for t in "$SHIM"/*; do
  n="$(basename "$t")"
  [[ "$n" == cosign || "$n" == gh ]] || ln -s "$t" "$tmp/noverify/$n"
done
mkdir -p "$tmp/notar"
for t in "$TOOLS"/*; do
  n="$(basename "$t")"
  [[ "$n" == tar ]] || ln -s "$(readlink "$t")" "$tmp/notar/$n"
done
mkdir -p "$tmp/ghonly"
for t in "$SHIM"/*; do
  n="$(basename "$t")"
  [[ "$n" == cosign ]] || ln -s "$t" "$tmp/ghonly/$n"
done

# ---------------------------------------------------------------- server
python3 -I -u -m http.server 0 --bind 127.0.0.1 --directory "$WWW" >"$tmp/http.log" 2>&1 &
srv_pid=$!
FAKE_PORT=""
for _ in $(seq 100); do
  FAKE_PORT="$(sed -nE 's/.*port ([0-9]+).*/\1/p' "$tmp/http.log" | head -1)"
  [[ -n "$FAKE_PORT" ]] && break
  sleep 0.1
done
[[ -n "$FAKE_PORT" ]] || { echo "[install-test] fake server did not start" >&2; exit 1; }

# run <scenario> <path> [VAR=value...] : run install.sh from a file.
OUT="$tmp/out"
run() {
  local scen="$1" path="$2"; shift 2
  : >"$CURL_LOG"; : >"$GH_LOG"; rm -f "$tmp/sudo.log"
  set +e
  env -i HOME="$tmp/home" PATH="$path" FAKE_PORT="$FAKE_PORT" SCENARIO="$scen" "$@" \
    sh "$INSTALL" >"$OUT" 2>&1
  rc=$?
  set -e
}
WITH_COSIGN="$SHIM:$TOOLS"
GH_ONLY="$tmp/ghonly:$TOOLS"
show() { sed 's/^/    | /' "$OUT" >&2; }

# ---------------------------------------------------------------- fixtures
for s in stable arm64 nosha noverify mismatch bindcosign bindgh trunc dirs badver badlatest ghcap; do
  release "$s" v0.3.7 amd64
  release "$s" v0.4.0-rc.4 amd64
  latest "$s" v0.3.7
done
for s in lic licbad licmissing licunattested; do
  release "$s" v0.3.7 amd64
  latest "$s" v0.3.7
done
release lic v0.4.0-rc.5 amd64 yes
release licbad v0.4.0-rc.5 amd64 yes
release licmissing v0.4.0-rc.5 amd64 yes
release licunattested v0.4.0-rc.5 amd64 unattested

# 1. latest resolves to the stable release, not the newer prerelease.
for path in "$WITH_COSIGN" "$GH_ONLY"; do
  d="$tmp/i-stable-${#path}"
  run stable "$path" BPFCOMPAT_BIN_DIR="$d/bin" BPFCOMPAT_LIBEXEC_DIR="$d/libexec"
  if [[ $rc -eq 0 ]] && grep -q 'fake bpfcompat v0.3.7 amd64' "$OUT" &&
    grep -qx 'validator v0.3.7 amd64' "$d/libexec/bpfcompat-validator" &&
    [[ ! -e "$d/share" ]] && grep -q 'publishes no third-party license bundle' "$OUT"; then
    ok "latest -> v0.3.7 (PATH=${path%%:*}), no license bundle in that release"
  else fail "latest did not install v0.3.7 (rc=$rc)"; show; fi
done

# 1b. a pinned prerelease still installs with both verifiers.
for path in "$WITH_COSIGN" "$GH_ONLY"; do
  d="$tmp/i-rc-${#path}"
  run stable "$path" BPFCOMPAT_VERSION=v0.4.0-rc.4 BPFCOMPAT_BIN_DIR="$d/bin" BPFCOMPAT_LIBEXEC_DIR="$d/libexec"
  if [[ $rc -eq 0 ]] && grep -q 'fake bpfcompat v0.4.0-rc.4 amd64' "$OUT"; then ok "pinned v0.4.0-rc.4"
  else fail "pinned prerelease did not install (rc=$rc)"; show; fi
done

# 2. arch mapping. SHA256SUMS always lists both arches' CLIs (v0.3.6 bug class).
d="$tmp/i-arm64"
run arm64 "$WITH_COSIGN" FAKE_ARCH=aarch64 BPFCOMPAT_BIN_DIR="$d/bin" BPFCOMPAT_LIBEXEC_DIR="$d/libexec"
if [[ $rc -eq 0 ]] && grep -q 'fake bpfcompat v0.3.7 arm64' "$OUT" && [[ ! -e "$d/libexec" ]] &&
  grep -q 'no prebuilt validator for arm64' "$OUT"; then ok "aarch64 -> arm64 CLI, no validator"
else fail "aarch64 mapping (rc=$rc)"; show; fi
d="$tmp/i-amd64"
run arm64 "$GH_ONLY" FAKE_ARCH=amd64 BPFCOMPAT_BIN_DIR="$d/bin" BPFCOMPAT_LIBEXEC_DIR="$d/libexec"
if [[ $rc -eq 0 ]] && grep -q 'fake bpfcompat v0.3.7 amd64' "$OUT" && [[ -x "$d/libexec/bpfcompat-validator" ]]; then
  ok "amd64 with extra SHA256SUMS entries"
else fail "amd64 with extra SHA256SUMS entries (rc=$rc)"; show; fi
d="$tmp/i-mips"
run arm64 "$WITH_COSIGN" FAKE_ARCH=mips64 BPFCOMPAT_BIN_DIR="$d/bin"
if [[ $rc -ne 0 && ! -e "$d" ]] && grep -q "unsupported arch" "$OUT"; then ok "unsupported arch refused"
else fail "unsupported arch (rc=$rc)"; show; fi

# 3. fail closed: no sha tool, no verifier, checksum mismatch.
d="$tmp/i-nosha"
run nosha "$SHIM:$tmp/nosha" BPFCOMPAT_BIN_DIR="$d/bin" BPFCOMPAT_LIBEXEC_DIR="$d/libexec"
if [[ $rc -ne 0 && ! -e "$d" ]] && grep -q 'need sha256sum or shasum' "$OUT"; then ok "no sha256sum/shasum refused"
else fail "missing sha tools (rc=$rc)"; show; fi
d="$tmp/i-noverify"
run noverify "$tmp/noverify:$TOOLS" BPFCOMPAT_BIN_DIR="$d/bin" BPFCOMPAT_LIBEXEC_DIR="$d/libexec"
if [[ $rc -ne 0 && ! -e "$d" ]] && grep -q 'requires cosign or GitHub CLI' "$OUT"; then ok "no cosign/gh refused"
else fail "missing cosign+gh (rc=$rc)"; show; fi
printf '#!/bin/sh\necho tampered\n' >"$(rel_dir mismatch v0.3.7)/bpfcompat-linux-amd64"
d="$tmp/i-mismatch"
run mismatch "$WITH_COSIGN" BPFCOMPAT_BIN_DIR="$d/bin" BPFCOMPAT_LIBEXEC_DIR="$d/libexec"
if [[ $rc -ne 0 && ! -e "$d" ]] && grep -q 'checksum verification failed' "$OUT"; then ok "checksum mismatch refused"
else fail "checksum mismatch (rc=$rc)"; show; fi

# 4. INST-1: a signature/attestation made by another tag's release run must
#    not vouch for the requested tag. The v0.3.7 URLs serve rc.4's assets.
mirror bindcosign v0.4.0-rc.4 v0.3.7
mirror bindgh v0.4.0-rc.4 v0.3.7
d="$tmp/i-bindcosign"
run bindcosign "$WITH_COSIGN" BPFCOMPAT_VERSION=v0.3.7 BPFCOMPAT_BIN_DIR="$d/bin" BPFCOMPAT_LIBEXEC_DIR="$d/libexec"
if [[ $rc -ne 0 && ! -e "$d" ]] && grep -q 'cosign signature verification FAILED' "$OUT"; then
  ok "cosign: rc.4 signature refused for v0.3.7"
else fail "cosign accepted a SHA256SUMS signed for another tag (rc=$rc)"; show; fi
d="$tmp/i-bindgh"
run bindgh "$GH_ONLY" BPFCOMPAT_VERSION=v0.3.7 BPFCOMPAT_BIN_DIR="$d/bin" BPFCOMPAT_LIBEXEC_DIR="$d/libexec"
if [[ $rc -ne 0 && ! -e "$d" ]] && grep -q 'attestation verification FAILED' "$OUT"; then
  ok "gh: rc.4 attestation refused for v0.3.7"
else fail "gh accepted a binary attested for another tag (rc=$rc)"; show; fi

# 5. INST-3: a truncated `curl | sh` stream must not run any part of the install.
total="$(wc -l <"$INSTALL")"
partial=0
for n in $(seq 1 $((total - 1))); do
  d="$tmp/i-trunc/$n"
  head -n "$n" "$INSTALL" | env -i HOME="$tmp/home" PATH="$WITH_COSIGN" FAKE_PORT="$FAKE_PORT" \
    SCENARIO=trunc BPFCOMPAT_BIN_DIR="$d/bin" BPFCOMPAT_LIBEXEC_DIR="$d/libexec" sh >/dev/null 2>&1 || true
  if [[ -e "$d" ]]; then partial=$((partial + 1)); echo "    truncated at line $n left $(find "$d" | tr '\n' ' ')" >&2; fi
done
if [[ $partial -eq 0 ]]; then ok "no truncation point (1..$((total - 1))) installs anything"
else fail "$partial truncation points performed a partial install"; fi
d="$tmp/i-trunc/full"
env -i HOME="$tmp/home" PATH="$WITH_COSIGN" FAKE_PORT="$FAKE_PORT" SCENARIO=trunc \
  BPFCOMPAT_BIN_DIR="$d/bin" BPFCOMPAT_LIBEXEC_DIR="$d/libexec" sh <"$INSTALL" >"$OUT" 2>&1 && rc=0 || rc=$?
if [[ $rc -eq 0 && -x "$d/bin/bpfcompat" ]]; then ok "full stream via stdin installs"
else fail "full stream via stdin (rc=$rc)"; show; fi

# 6. INST-2: custom dirs. Sudo is decided per target dir, both dirs are
#    preflighted before anything is installed, and a non-default validator
#    location is not claimed to be auto-discovered.
if [[ "$(id -u)" -eq 0 ]]; then
  echo "[install-test] skip: custom-dir permission cases need a non-root user" >&2
else
  mkdir -p "$tmp/ro"
  chmod 0555 "$tmp/ro"
  d="$tmp/i-dirs"
  run dirs "$WITH_COSIGN" BPFCOMPAT_BIN_DIR="$d/bin" BPFCOMPAT_LIBEXEC_DIR="$tmp/ro/libexec"
  if [[ $rc -eq 0 && -x "$d/bin/bpfcompat" && -x "$tmp/ro/libexec/bpfcompat-validator" ]] &&
    grep -q "install -m 0755 bpfcompat-validator-static-linux-amd64 $tmp/ro/libexec/bpfcompat-validator" "$tmp/sudo.log" &&
    ! grep -q 'bpfcompat-linux-amd64' "$tmp/sudo.log"; then
    ok "writable bin + unwritable libexec: sudo only for the validator"
  else fail "per-dir sudo (rc=$rc)"; show; cat "$tmp/sudo.log" >&2 2>/dev/null || true; fi
  if grep -q "BPFCOMPAT_VALIDATOR_BIN=$tmp/ro/libexec/bpfcompat-validator" "$OUT" &&
    ! grep -q 'auto-discovered' "$OUT"; then ok "non-default libexec tells the user to set BPFCOMPAT_VALIDATOR_BIN"
  else fail "non-default libexec claims auto-discovery"; show; fi

  chmod -R u+w "$tmp/ro"; rm -rf "$tmp/ro"; mkdir -p "$tmp/ro"; chmod 0555 "$tmp/ro"
  d="$tmp/i-dirs-nosudo"
  nosudo="$tmp/nosudo"; mkdir -p "$nosudo"
  for t in "$SHIM"/*; do n="$(basename "$t")"; [[ "$n" == sudo ]] || ln -s "$t" "$nosudo/$n"; done
  run dirs "$nosudo:$TOOLS" BPFCOMPAT_BIN_DIR="$d/bin" BPFCOMPAT_LIBEXEC_DIR="$tmp/ro/libexec"
  if [[ $rc -ne 0 && ! -e "$d" ]] && grep -q "no write access to $tmp/ro/libexec" "$OUT"; then
    ok "unwritable libexec without sudo: nothing installed"
  else fail "half-done install when libexec is unwritable and sudo missing (rc=$rc)"; show; ls -R "$d" >&2 2>/dev/null || true; fi
  chmod -R u+w "$tmp/ro"
fi

# 7. INST-5: BPFCOMPAT_VERSION and the resolved latest tag must look like a tag.
#    The whole value is checked: a valid tag on one line of a multi-line
#    value must not get through either.
for v in "../../../../evil/x/releases/download/v1" "v0.3.7/../v0.4.0-rc.4" "latest-ish" "v1.2" "v1.2.3-beta.1" "v1.2.3 " \
  $'v0.3.7\nx' $'x\nv0.3.7' $'v0.3.7\n'; do
  printf -v shown '%q' "$v"
  d="$tmp/i-badver"
  run badver "$WITH_COSIGN" BPFCOMPAT_VERSION="$v" BPFCOMPAT_BIN_DIR="$d/bin" BPFCOMPAT_NO_VALIDATOR=1
  if [[ $rc -ne 0 && ! -e "$d" && ! -s "$CURL_LOG" ]] && grep -q 'invalid release tag' "$OUT"; then
    ok "BPFCOMPAT_VERSION $shown refused before any download"
  else fail "BPFCOMPAT_VERSION $shown not refused up front (rc=$rc)"; show; fi
done
latest badlatest '../../evil'
d="$tmp/i-badlatest"
run badlatest "$WITH_COSIGN" BPFCOMPAT_BIN_DIR="$d/bin" BPFCOMPAT_NO_VALIDATOR=1
if [[ $rc -ne 0 && ! -e "$d" ]] && grep -q 'invalid release tag' "$OUT" &&
  ! grep -q '/releases/download/' "$CURL_LOG"; then ok "malformed latest tag refused"
else fail "malformed latest tag (rc=$rc)"; show; fi

# 8. Third-party license bundle: listed in SHA256SUMS -> required, verified
#    like the binaries, installed under <DOC_DIR>/<tag>/; never half-installed.
for path in "$WITH_COSIGN" "$GH_ONLY"; do
  d="$tmp/i-lic-${#path}"
  run lic "$path" BPFCOMPAT_VERSION=v0.4.0-rc.5 BPFCOMPAT_BIN_DIR="$d/bin" BPFCOMPAT_LIBEXEC_DIR="$d/libexec"
  if [[ $rc -eq 0 ]] && grep -q '"version": "v0.4.0-rc.5"' "$d/share/doc/bpfcompat/v0.4.0-rc.5/INVENTORY.json" &&
    [[ -s "$d/share/doc/bpfcompat/v0.4.0-rc.5/go/toolchain/LICENSE" ]] &&
    grep -q 'bpfcompat-third-party-licenses.tar.gz' "$OUT"; then
    ok "license bundle verified and installed next to the CLI (PATH=${path%%:*})"
  else fail "license bundle install (rc=$rc)"; show; fi
done
d="$tmp/i-lic-docdir"
run lic "$WITH_COSIGN" BPFCOMPAT_VERSION=v0.4.0-rc.5 BPFCOMPAT_BIN_DIR="$d/bin" BPFCOMPAT_LIBEXEC_DIR="$d/libexec" BPFCOMPAT_DOC_DIR="$d/docs"
if [[ $rc -eq 0 && -s "$d/docs/v0.4.0-rc.5/INVENTORY.json" && ! -e "$d/share" ]]; then ok "BPFCOMPAT_DOC_DIR honoured"
else fail "BPFCOMPAT_DOC_DIR (rc=$rc)"; show; fi
d="$tmp/i-lic-notar"
run lic "$SHIM:$tmp/notar" BPFCOMPAT_VERSION=v0.4.0-rc.5 BPFCOMPAT_BIN_DIR="$d/bin" BPFCOMPAT_LIBEXEC_DIR="$d/libexec"
if [[ $rc -eq 0 && -s "$d/share/doc/bpfcompat/v0.4.0-rc.5/bpfcompat-third-party-licenses.tar.gz" ]] &&
  grep -q 'unextracted archive' "$OUT"; then ok "without tar the verified bundle archive is installed as is"
else fail "license bundle without tar (rc=$rc)"; show; fi
printf 'tampered\n' >>"$(rel_dir licbad v0.4.0-rc.5)/bpfcompat-third-party-licenses.tar.gz"
d="$tmp/i-licbad"
run licbad "$WITH_COSIGN" BPFCOMPAT_VERSION=v0.4.0-rc.5 BPFCOMPAT_BIN_DIR="$d/bin" BPFCOMPAT_LIBEXEC_DIR="$d/libexec"
if [[ $rc -ne 0 && ! -e "$d" ]] && grep -q 'checksum verification failed' "$OUT"; then ok "corrupt license bundle: nothing installed"
else fail "corrupt license bundle (rc=$rc)"; show; fi
rm "$(rel_dir licmissing v0.4.0-rc.5)/bpfcompat-third-party-licenses.tar.gz"
d="$tmp/i-licmissing"
run licmissing "$WITH_COSIGN" BPFCOMPAT_VERSION=v0.4.0-rc.5 BPFCOMPAT_BIN_DIR="$d/bin" BPFCOMPAT_LIBEXEC_DIR="$d/libexec"
if [[ $rc -ne 0 && ! -e "$d" ]] && grep -q 'download failed: bpfcompat-third-party-licenses.tar.gz' "$OUT"; then
  ok "listed but missing license bundle: nothing installed"
else fail "missing license bundle (rc=$rc)"; show; fi
d="$tmp/i-licunattested"
run licunattested "$GH_ONLY" BPFCOMPAT_VERSION=v0.4.0-rc.5 BPFCOMPAT_BIN_DIR="$d/bin" BPFCOMPAT_LIBEXEC_DIR="$d/libexec"
if [[ $rc -ne 0 && ! -e "$d" ]] && grep -q 'attestation verification FAILED for bpfcompat-third-party-licenses.tar.gz' "$OUT"; then
  ok "unattested license bundle refused on the gh path"
else fail "unattested license bundle (rc=$rc)"; show; fi
if [[ "$(id -u)" -ne 0 ]]; then
  mkdir -p "$tmp/ro"; chmod 0555 "$tmp/ro"
  d="$tmp/i-lic-sudo"
  run lic "$WITH_COSIGN" BPFCOMPAT_VERSION=v0.4.0-rc.5 BPFCOMPAT_BIN_DIR="$d/bin" BPFCOMPAT_LIBEXEC_DIR="$d/libexec" BPFCOMPAT_DOC_DIR="$tmp/ro/doc"
  if [[ $rc -eq 0 && -s "$tmp/ro/doc/v0.4.0-rc.5/INVENTORY.json" ]] && grep -q "install -d $tmp/ro/doc/v0.4.0-rc.5" "$tmp/sudo.log" &&
    ! grep -q 'bpfcompat-linux-amd64' "$tmp/sudo.log"; then ok "unwritable doc dir: sudo only for the license texts"
  else fail "doc dir sudo (rc=$rc)"; show; cat "$tmp/sudo.log" >&2 2>/dev/null || true; fi
  chmod -R u+w "$tmp/ro"
fi

# 9. A gh too old for the tag-bound attestation check is refused, naming what
#    it lacks and the gh that has it, not reported as a failed verification
#    (which reads like tampering) or as a missing gh. It is judged by what its
#    help offers, so an unparsable version still gets the precise reason.
#    cosign, when present, is preferred and used as before.
# gh_lacking <FAKE_GH_LACKS> <FAKE_GH_VERSION> <text the refusal must contain>
gh_lacking() {
  local lacks="$1" ver="$2" want="$3" d="$tmp/i-ghcap" bad=""
  run ghcap "$GH_ONLY" FAKE_GH_LACKS="$lacks" FAKE_GH_VERSION="$ver" \
    BPFCOMPAT_BIN_DIR="$d/bin" BPFCOMPAT_LIBEXEC_DIR="$d/libexec"
  [[ $rc -ne 0 && ! -e "$d" ]] || bad="$bad installed-or-rc0"
  grep -qF -- "$want" "$OUT" || bad="$bad reason-not-named"
  grep -qF 'upgrade to gh >= 2.68.0 or install cosign - refusing checksum-only installation' "$OUT" ||
    bad="$bad no-remedy"
  ! grep -q 'requires cosign or GitHub CLI' "$OUT" || bad="$bad says-gh-missing"
  ! grep -q 'FAILED' "$OUT" || bad="$bad says-verification-failed"
  ! grep -qE '^attestation verify [^-]' "$GH_LOG" || bad="$bad verify-attempted"
  if [[ -z "$bad" ]]; then ok "gh $ver lacking '$lacks': refused, naming what it lacks"
  else fail "gh $ver lacking '$lacks' (rc=$rc):$bad"; show; fi
}
gh_lacking attestation 2.45.0 "installed gh 2.45.0 lacks the 'gh attestation' command, needed for tag-bound attestation verification"
gh_lacking --source-ref 2.67.0 "installed gh 2.67.0 lacks --source-ref in 'gh attestation verify', needed for"
gh_lacking "--signer-workflow --source-ref" 2.50.0 "installed gh 2.50.0 lacks --signer-workflow and --source-ref in 'gh attestation verify'"
gh_lacking --source-ref "custom-build" "installed gh lacks --source-ref in 'gh attestation verify'"
for lacks in attestation --source-ref; do
  d="$tmp/i-ghcap-cosign-${lacks#--}"
  run ghcap "$WITH_COSIGN" FAKE_GH_LACKS="$lacks" FAKE_GH_VERSION=2.45.0 \
    BPFCOMPAT_BIN_DIR="$d/bin" BPFCOMPAT_LIBEXEC_DIR="$d/libexec"
  if [[ $rc -eq 0 && -x "$d/bin/bpfcompat" && -x "$d/libexec/bpfcompat-validator" ]] &&
    grep -q 'cosign signature over SHA256SUMS verified' "$OUT"; then
    ok "gh lacking '$lacks' + cosign: verified with cosign and installed"
  else fail "gh lacking '$lacks' with cosign present (rc=$rc)"; show; fi
done

if [[ $failures -ne 0 ]]; then
  echo "[install-test] $failures failure(s)" >&2
  exit 1
fi
echo "[install-test] all install.sh cases passed"
