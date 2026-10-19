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
#     attested, and honours --source-ref like the real CLI does. It records
#     every verify call, so the gh-path cases check that each installed asset
#     was verified, bound to the release workflow and tag. With FAKE_GH_LACKS
#     it plays an older gh that has no `attestation` command or no
#     --signer-workflow / --source-ref flag, failing like cobra does; with
#     FAKE_GH_BROKEN=1, a gh that cannot run at all (say, a bad config). It
#     also answers the installer's read-only API probe (`gh api --include`)
#     from the attestation DB and records it, and can play a capable gh that
#     is not logged in, holds a rejected token, cannot reach the API or gets
#     a 5xx / 429 / rate-limited 403, modelled on real gh 2.68.0 / 2.102.0,
#     one probe attempt at a time. For `--format json --jq <the installer's
#     expression>` it prints, like real gh, the "<sha256>  <name>" subjects
#     of every attested statement that holds the verified digest;
#   * sleep only records how long the installer would have waited;
#   * sudo pretends to be root by unlocking the test's read-only tree.
#
# Cases: latest -> stable, arch mapping (incl. extra SHA256SUMS lines, the
# v0.3.6 bug class), fail-closed without sha tools / without cosign+gh / on a
# checksum mismatch, signatures bound to the requested tag, truncated
# `curl | sh` streams, custom install dirs, tag validation (the whole value,
# embedded newlines included), the third-party license bundle (installed when
# SHA256SUMS lists it, verified like the binaries, refused when
# corrupt/missing/unattested, absent in old releases), a gh too old for
# the tag-bound check (refused naming what it lacks, never reported as a
# failed verification or a missing gh; a gh that cannot run is reported as
# such; cosign still preferred when present), and a capable gh that cannot
# complete the check (not logged in / credentials rejected / GitHub API
# unavailable, each refused under its own name, never as a failed
# verification, while every refusal - including one whose stderr claims a
# network or auth problem - still reads "verification FAILED"), with gh's
# words reduced to printable ASCII and imported pipefail tolerated; the
# API probe retried only on a 5xx or no response, at most three times; and
# on the gh path, SHA256SUMS held to the CLI's attested provenance (it must
# agree on whether a validator and a license bundle exist, and each file is
# installed only under the name its bytes were attested as).
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
# One line per attested subject: "<statement> refs/tags/<tag> <sha256>  <name>".
SUBJ_DB="$tmp/subjects"
CURL_LOG="$tmp/curl.log"
GH_LOG="$tmp/gh.log"
GH_VERIFY_LOG="$tmp/gh-verify.log"
GH_API_LOG="$tmp/gh-api.log"
GH_FMT_LOG="$tmp/gh-format.log"
SLEEP_LOG="$tmp/sleep.log"
ITMP="$tmp/itmp"
# The installer's request for the CLI's attested subjects (gh --jq).
JQ_SUBJECTS='.[].verificationResult.statement.subject[] | "\(.digest.sha256)  \(.name)"'
mkdir -p "$WWW" "$SHIM" "$TOOLS" "$tmp/home"
: >"$ATTEST_DB"; : >"$SUBJ_DB"

failures=0
fail() { echo "[install-test] FAIL: $*" >&2; failures=$((failures + 1)); }
ok() { echo "[install-test] ok: $*"; }

# ---------------------------------------------------------------- fake release
# release <scenario> <tag> [validator-arches] [bundle]: builds a signed,
# attested release under the scenario's fake github.com tree, the way
# release-artifacts.yml does: one provenance statement ("<scenario>-<tag>")
# names every attested asset. bundle: "yes" adds the third-party license
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
    printf '%s-%s refs/tags/%s %s  %s\n' "$scen" "$tag" "$tag" "$("$REAL_SHA" <"$a" | cut -d' ' -f1)" "${a##*/}" >>"$SUBJ_DB"
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
# Fake gh attestation verify backed by the attestation DB the fake release
# wrote, and the installer's read-only API probe (gh api --method GET
# --include <path>), answered from the same DB: 200 when the digest is
# attested, 404 when it is not, as the real API does.
# FAKE_GH_LACKS plays an older gh (feature history from gh's source):
# "attestation" = gh < 2.47.0 (hidden in 2.47-2.48, public from 2.49.0),
# "--signer-workflow" = gh < 2.51.0, "--source-ref" = gh < 2.68.0.
# FAKE_GH_VERSION is what --version reports ("fail": --version fails).
# FAKE_GH_BROKEN=1 fails every command the way gh does with an unreadable
# config. A capable gh that cannot finish the check, modelled on real gh
# 2.68.0/2.102.0 runs (exit codes, --include output; help and --version
# are exempt, like gh's root auth check):
#   FAKE_GH_AUTH=none   no credentials: gh's login hint on stderr, exit 4
#   FAKE_GH_AUTH=bad    token rejected: HTTP 401
#   FAKE_GH_NET=down    no HTTP response (proxy/DNS/connect failure), exit 1
#   FAKE_GH_NET=503|429|403|403rl|403ra  that HTTP status; 403rl carries
#                       X-Ratelimit-Remaining: 0, 403ra a Retry-After header
#   FAKE_GH_PROBE_SEQ   what each API probe attempt gets, in turn (the last
#                       entry repeats): ok (the DB's answer), down, 401, 503,
#                       429, 403rl, crash (exit 2, no stdout) or garbage
#                       (exit 1, stdout that is no status line); the verify
#                       calls are not affected
#   FAKE_GH_PROTO=1.1   the API answers over HTTP/1.1 (default HTTP/2.0)
#   FAKE_GH_COLOR=1     header names coloured, as with CLICOLOR_FORCE
#   FAKE_GH_ERR_CTRL=1  C0 terminal control bytes in gh's error lines; =c1:
#                       C1 CSI bytes, raw (0x9b) and UTF-8 encoded (c2 9b)
#   FAKE_GH_VERIFY_RC=4 verify exits 4 even though the API probe answered;
#                     =2  verify exits 2 (gh's "cancelled" code): no refusal, no auth
#   FAKE_GH_VERIFY_ERR  text a failing verify prints instead of its error
#   FAKE_GH_ATTEST_SIGNER  workflow the stored attestations were signed by
# More than 10 probes in one run is an unbounded retry: exit 4 to stop it.
echo "\$*" >>"$GH_LOG"
ctl="" cr=""
if [[ "\${FAKE_GH_ERR_CTRL:-}" == c1 ]]; then ctl=\$'\x9b''31m'\$'\xc2\x9b''32m'
elif [[ -n "\${FAKE_GH_ERR_CTRL:-}" ]]; then ctl=\$'\e]0;PWNED\a\e[31m' cr=\$'\r'; fi
if [[ -n "\${FAKE_GH_BROKEN:-}" ]]; then
  echo "\${ctl}failed to create root command: failed to read configuration: invalid config file /home/u/.config/gh/config.yml: invalid yaml\$cr" >&2
  exit 1
fi
lacks=" \${FAKE_GH_LACKS:-} "
if [[ "\${1:-}" == "--help" ]]; then
  echo 'Work seamlessly with GitHub from the command line.'
  exit 0
fi
if [[ "\${1:-}" == "--version" ]]; then
  [[ "\${FAKE_GH_VERSION:-}" != fail ]] || exit 1
  printf 'gh version %s (2026-01-01)\nhttps://github.com/cli/cli/releases/latest\n' "\${FAKE_GH_VERSION:-2.102.0}"
  exit 0
fi
login_hint() {
  printf 'To get started with GitHub CLI, please run:  gh auth login\nAlternatively, populate the GH_TOKEN environment variable with a GitHub API authentication token.\n' >&2
  exit 4
}
# hdrs <status> <reason> [header...]: what gh api --include prints before the body.
hdrs() {
  local h c="" r=""
  if [[ -n "\${FAKE_GH_COLOR:-}" ]]; then c=\$'\e[1;34m' r=\$'\e[m'; fi
  printf 'HTTP/%s %s %s\n' "\${FAKE_GH_PROTO:-2.0}" "\$1" "\$2"; shift 2
  for h in "Content-Type: application/json; charset=utf-8" "\$@"; do
    printf '%s%s%s:%s\r\n' "\$c" "\${h%%:*}" "\$r" "\${h#*:}"
  done
  printf '\r\n'
}
if [[ "\${1:-}" == api ]]; then
  [[ \$# -eq 5 && "\$2 \$3 \$4" == "--method GET --include" ]] || { echo "gh shim: unexpected api call: \$*" >&2; exit 2; }
  path="\$5" st="" n="\$(grep -c . "$GH_API_LOG" || true)"
  if [[ \$n -ge 10 ]]; then echo "\$path stop" >>"$GH_API_LOG"; echo "gh shim: API probe made \$((n + 1)) times" >&2; exit 4; fi
  if [[ "\${FAKE_GH_AUTH:-}" == none ]]; then echo "\$path noauth" >>"$GH_API_LOG"; login_hint; fi
  net="\${FAKE_GH_NET:-}"
  if [[ -n "\${FAKE_GH_PROBE_SEQ:-}" ]]; then
    read -r -a seq <<<"\$FAKE_GH_PROBE_SEQ"
    [[ \$n -lt \${#seq[@]} ]] || n=\$((\${#seq[@]} - 1))
    net="\${seq[\$n]}"; [[ "\$net" != ok ]] || net=""
  fi
  if [[ "\${FAKE_GH_AUTH:-}" == bad || "\$net" == 401 ]]; then st=401
  else
    case "\$net" in
      down)
        echo "\$path -" >>"$GH_API_LOG"
        echo "\${ctl}Get \"https://api.github.com/\$path\": proxyconnect tcp: dial tcp 127.0.0.1:9: connect: connection refused\$cr" >&2
        exit 1;;
      crash)
        echo "\$path crash" >>"$GH_API_LOG"
        echo "panic: runtime error: invalid memory address or nil pointer dereference" >&2
        exit 2;;
      garbage)
        echo "\$path garbage" >>"$GH_API_LOG"
        echo "<html>proxy login page</html>"
        echo "gh: unexpected response" >&2
        exit 1;;
      5[0-9][0-9]|429|403|403rl|403ra) st="\$net";;
      "")
        d="\${path#repos/$REPO/attestations/sha256:}"; d="\${d%%\?*}"
        if [[ "\$path" == "repos/$REPO/attestations/sha256:\$d?per_page=1" && "\$d" =~ ^[0-9a-f]{64}\$ ]] &&
          grep -q "^\$d " "$ATTEST_DB"; then st=200; else st=404; fi;;
      *) echo "gh shim: unknown FAKE_GH_NET" >&2; exit 2;;
    esac
  fi
  echo "\$path \$st" >>"$GH_API_LOG"
  case "\$st" in
    200) hdrs 200 OK "X-Ratelimit-Remaining: 4999"; echo '{"attestations":[{"bundle":{}}]}'; exit 0;;
    404) hdrs 404 "Not Found" "X-Ratelimit-Remaining: 4998"
         echo '{"message":"Not Found","status":"404"}'; echo "gh: Not Found (HTTP 404)" >&2;;
    401) hdrs 401 Unauthorized
         echo '{"message":"Bad credentials","status":"401"}'; echo "gh: Bad credentials (HTTP 401)" >&2;;
    503) hdrs 503 "Service Unavailable"; echo 'unicorn'; echo "\${ctl}gh: HTTP 503\$cr" >&2;;
    5??) hdrs "\$st" "Bad Gateway"; echo '<html>bad gateway</html>'; echo "gh: HTTP \$st" >&2;;
    429) hdrs 429 "Too Many Requests" "Retry-After: 60"
         echo '{"message":"You have exceeded a secondary rate limit."}'
         echo "gh: You have exceeded a secondary rate limit. (HTTP 429)" >&2;;
    403rl) hdrs 403 Forbidden "X-Ratelimit-Remaining: 0" "X-Ratelimit-Reset: 1760000000"
         echo '{"message":"API rate limit exceeded for user ID 1."}'
         echo "gh: API rate limit exceeded for user ID 1. (HTTP 403)" >&2;;
    403ra) hdrs 403 Forbidden "Retry-After: 60" "X-Ratelimit-Remaining: 4000"
         echo '{"message":"You have exceeded a secondary rate limit."}'
         echo "gh: You have exceeded a secondary rate limit. (HTTP 403)" >&2;;
    403) hdrs 403 Forbidden "X-Ratelimit-Remaining: 4000"
         echo '{"message":"Resource not accessible by personal access token"}'
         echo "gh: Resource not accessible by personal access token (HTTP 403)" >&2;;
  esac
  exit 1
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
file="" repo="" signer="" ref="" fmt="" jq="" fmtset=""
while [[ \$# -gt 0 ]]; do
  if [[ "\$1" == --* && "\$lacks" == *" \$1 "* ]]; then echo "unknown flag: \$1" >&2; exit 1; fi
  case "\$1" in
    --repo) repo="\$2"; shift 2;;
    --signer-workflow) signer="\$2"; shift 2;;
    --source-ref) ref="\$2"; shift 2;;
    --format) fmt="\$2" fmtset=1; shift 2;;
    --jq) jq="\$2" fmtset=1; shift 2;;
    -*) echo "gh shim: unknown flag \$1" >&2; exit 2;;
    *) file="\$1"; shift;;
  esac
done
printf 'verify %s repo=%s signer=%s ref=%s\n' "\$file" "\$repo" "\$signer" "\$ref" >>"$GH_VERIFY_LOG"
[[ -z "\$fmtset" ]] || printf '%s fmt=%s jq=%s\n' "\$file" "\$fmt" "\$jq" >>"$GH_FMT_LOG"
if [[ "\${FAKE_GH_VERIFY_RC:-}" == 2 ]]; then echo "gh shim: verify ended with exit code 2" >&2; exit 2; fi
# refuse <error>: how gh reports a failed verify when stdout is not a TTY.
refuse() {
  if [[ -n "\${FAKE_GH_VERIFY_ERR:-}" ]]; then printf '%s\n' "\$FAKE_GH_VERIFY_ERR" >&2
  else printf '\nError: %s\n' "\$1" >&2; fi
  exit 1
}
[[ "\${FAKE_GH_AUTH:-}" != none && "\${FAKE_GH_VERIFY_RC:-}" != 4 ]] || login_hint
url="https://api.github.com/repos/\$repo/attestations/sha256:...?per_page=30"
[[ "\${FAKE_GH_AUTH:-}" != bad ]] || refuse "failed to fetch attestations from \$repo: HTTP 401: Bad credentials (\$url)"
case "\${FAKE_GH_NET:-}" in
  "") ;;
  down) refuse "failed to fetch attestations from \$repo: Get \"\$url\": proxyconnect tcp: dial tcp 127.0.0.1:9: connect: connection refused";;
  *) refuse "failed to fetch attestations from \$repo: HTTP \${FAKE_GH_NET:0:3} (\$url)";;
esac
[[ "\$repo" == "$REPO" ]] || refuse "no attestations found"
[[ "\$signer" == "$REPO/.github/workflows/release-artifacts.yml" &&
  "\$signer" == "\${FAKE_GH_ATTEST_SIGNER:-$REPO/.github/workflows/release-artifacts.yml}" ]] ||
  refuse "expected SAN to match signer workflow \$signer"
sum="\$("$REAL_SHA" <"\$file" | cut -d' ' -f1)"
if [[ -n "\$ref" ]]; then grep -qx "\$sum \$ref" "$ATTEST_DB" || refuse "expected SourceRepositoryRef to be \$ref"
else grep -q "^\$sum " "$ATTEST_DB" || refuse "no attestations found"; fi
[[ -n "\$fmtset" ]] || exit 0
[[ "\$fmt" == json && "\$jq" == '$JQ_SUBJECTS' ]] ||
  { echo "gh shim: unexpected --format/--jq: \$fmt \$jq" >&2; exit 2; }
# Like real gh: the subjects of every verified statement (one whose ref
# passed) that holds this digest, as "<sha256>  <name>" lines.
seen=" "
while read -r st sref sdig _; do
  [[ "\$sdig" == "\$sum" && ( -z "\$ref" || "\$sref" == "\$ref" ) && "\$seen" != *" \$st "* ]] || continue
  seen+="\$st "
  while read -r s2 _ d2 n2; do [[ "\$s2" != "\$st" ]] || printf '%s  %s\n' "\$d2" "\$n2"; done <"$SUBJ_DB"
done <"$SUBJ_DB"
EOF
cat >"$SHIM/sleep" <<EOF
#!/bin/sh
# Record the wait instead of waiting.
echo "\$*" >>"$SLEEP_LOG"
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

# run <scenario> <path> [VAR=value...] : run install.sh from a file, with
# "${RUN_SH[@]}" (default: sh) and TMPDIR pointing at an empty $ITMP, so a
# case can check that the installer removed its temp dir.
OUT="$tmp/out"
RUN_SH=(sh)
run() {
  local scen="$1" path="$2"; shift 2
  : >"$CURL_LOG"; : >"$GH_LOG"; : >"$GH_VERIFY_LOG"; : >"$GH_API_LOG"; : >"$GH_FMT_LOG"; : >"$SLEEP_LOG"
  rm -f "$tmp/sudo.log"
  rm -rf "$ITMP"; mkdir -p "$ITMP"
  set +e
  env -i HOME="$tmp/home" TMPDIR="$ITMP" PATH="$path" FAKE_PORT="$FAKE_PORT" SCENARIO="$scen" "$@" \
    "${RUN_SH[@]}" "$INSTALL" >"$OUT" 2>&1
  rc=$?
  set -e
}
WITH_COSIGN="$SHIM:$TOOLS"
GH_ONLY="$tmp/ghonly:$TOOLS"
show() { sed 's/^/    | /' "$OUT" >&2; }
# A shell that runs its own sleep (busybox's applet) bypasses the sleep
# shim: then the retry cases can check the attempts but not the waits.
: >"$SLEEP_LOG"
env -i PATH="$GH_ONLY" sh -c 'sleep 0' || true
SLEEP_SHIMMED=0
if [[ -s "$SLEEP_LOG" ]]; then SLEEP_SHIMMED=1
else echo "[install-test] note: this sh does not run sleep from PATH; waits between probe attempts are not checked" >&2; fi
# verified <PATH> <tag> <asset...>: on the gh-only PATH, gh verified exactly
# these assets, once each, bound to the release workflow and refs/tags/<tag>;
# with cosign on PATH, gh verified nothing. So a dropped, unbound or extra
# verify call fails the case.
verified() {
  local path="$1" tag="$2" a want=""; shift 2
  if [[ "$path" == "$GH_ONLY" ]]; then
    for a in "$@"; do
      want+="verify $a repo=$REPO signer=$REPO/.github/workflows/release-artifacts.yml ref=refs/tags/$tag"$'\n'
    done
  fi
  [[ "$(sort "$GH_VERIFY_LOG")" == "$(printf '%s' "$want" | sort)" ]] && return 0
  printf '%s' "$want" | sort | sed 's/^/    want gh | /' >&2
  sort "$GH_VERIFY_LOG" | sed 's/^/    got gh  | /' >&2
  return 1
}
CLI_AMD64=bpfcompat-linux-amd64
VAL_AMD64=bpfcompat-validator-static-linux-amd64

# ---------------------------------------------------------------- fixtures
for s in stable arm64 nosha noverify mismatch bindcosign bindgh bindghcli bindghval trunc dirs badver badlatest ghcap \
  ghapi ghrefuse ghnoatt; do
  release "$s" v0.3.7 amd64
  release "$s" v0.4.0-rc.4 amd64
  latest "$s" v0.3.7
done
for s in rbval037 rbcli rbval rbarm rbsep rbsepcli rbrerun; do
  release "$s" v0.3.7 amd64
  latest "$s" v0.3.7
done
for s in rbval5 rblic5; do release "$s" v0.4.0-rc.5 amd64 yes; done
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
    [[ ! -e "$d/share" ]] && grep -q 'publishes no third-party license bundle' "$OUT" &&
    verified "$path" v0.3.7 "$CLI_AMD64" "$VAL_AMD64"; then
    ok "latest -> v0.3.7 (PATH=${path%%:*}), no license bundle in that release"
  else fail "latest did not install v0.3.7 (rc=$rc)"; show; fi
done

# 1b. a pinned prerelease still installs with both verifiers.
for path in "$WITH_COSIGN" "$GH_ONLY"; do
  d="$tmp/i-rc-${#path}"
  run stable "$path" BPFCOMPAT_VERSION=v0.4.0-rc.4 BPFCOMPAT_BIN_DIR="$d/bin" BPFCOMPAT_LIBEXEC_DIR="$d/libexec"
  if [[ $rc -eq 0 ]] && grep -q 'fake bpfcompat v0.4.0-rc.4 amd64' "$OUT" &&
    verified "$path" v0.4.0-rc.4 "$CLI_AMD64" "$VAL_AMD64"; then ok "pinned v0.4.0-rc.4"
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
if [[ $rc -eq 0 ]] && grep -q 'fake bpfcompat v0.3.7 amd64' "$OUT" && [[ -x "$d/libexec/bpfcompat-validator" ]] &&
  verified "$GH_ONLY" v0.3.7 "$CLI_AMD64" "$VAL_AMD64"; then
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
# 4b. Each gh verify call stands on its own: swap only the CLI, or only the
#     validator, for rc.4's attested bytes and regenerate SHA256SUMS to match,
#     so the attestation is the only thing that can catch it. Dropping or
#     neutralising that asset's verify call makes this install succeed. (The
#     license bundle's call is covered by the unattested-bundle case in 8.)
for c in "bindghcli $CLI_AMD64" "bindghval $VAL_AMD64"; do
  scen="${c%% *}" asset="${c#* }"
  cp "$(rel_dir "$scen" v0.4.0-rc.4)/$asset" "$(rel_dir "$scen" v0.3.7)/$asset"
  (cd "$(rel_dir "$scen" v0.3.7)" && "$REAL_SHA" bpfcompat-* >SHA256SUMS)
  d="$tmp/i-$scen"
  run "$scen" "$GH_ONLY" BPFCOMPAT_VERSION=v0.3.7 BPFCOMPAT_BIN_DIR="$d/bin" BPFCOMPAT_LIBEXEC_DIR="$d/libexec"
  if [[ $rc -ne 0 && ! -e "$d" ]] && grep -q "attestation verification FAILED for $asset\$" "$OUT"; then
    ok "gh: only $asset attested for rc.4 -> refused for v0.3.7"
  else fail "gh accepted $asset attested for another tag (rc=$rc)"; show; fi
done

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
    grep -q 'bpfcompat-third-party-licenses.tar.gz' "$OUT" &&
    verified "$path" v0.4.0-rc.5 "$CLI_AMD64" "$VAL_AMD64" bpfcompat-third-party-licenses.tar.gz; then
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
# The bundle's own verify call refuses it (the whole line), before the
# comparison with the CLI's attested subjects in 11 would.
if [[ $rc -ne 0 && ! -e "$d" ]] && grep -q 'attestation verification FAILED for bpfcompat-third-party-licenses.tar.gz' "$OUT" &&
  grep -qx 'bpfcompat-install: GitHub attestation verification FAILED for bpfcompat-third-party-licenses.tar.gz' "$OUT"; then
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
  ! grep -q '^api ' "$GH_LOG" || bad="$bad api-probed"
  if [[ -z "$bad" ]]; then ok "gh $ver lacking '$lacks': refused, naming what it lacks"
  else fail "gh $ver lacking '$lacks' (rc=$rc):$bad"; show; fi
}
gh_lacking attestation 2.45.0 "installed gh 2.45.0 lacks the 'gh attestation' command, needed for tag-bound attestation verification"
gh_lacking --source-ref 2.67.0 "installed gh 2.67.0 lacks --source-ref in 'gh attestation verify', needed for"
gh_lacking "--signer-workflow --source-ref" 2.50.0 "installed gh 2.50.0 lacks --signer-workflow and --source-ref in 'gh attestation verify'"
gh_lacking --source-ref "custom-build" "installed gh lacks --source-ref in 'gh attestation verify'"
# A gh that cannot run at all (every command fails, as with an unreadable
# config) is reported as such, with gh's own error, not as lacking a command.
d="$tmp/i-ghbroken" bad=""
run ghcap "$GH_ONLY" FAKE_GH_BROKEN=1 BPFCOMPAT_BIN_DIR="$d/bin" BPFCOMPAT_LIBEXEC_DIR="$d/libexec"
[[ $rc -ne 0 && ! -e "$d" ]] || bad="$bad installed-or-rc0"
grep -qF "installed gh could not run 'gh --help' (failed to create root command: failed to read configuration: invalid config file" "$OUT" ||
  bad="$bad reason-not-named"
grep -qF 'fix gh or install cosign - refusing checksum-only installation' "$OUT" || bad="$bad no-remedy"
! grep -qE 'lacks|FAILED|requires cosign or GitHub CLI' "$OUT" || bad="$bad wrong-reason"
! grep -qE '^attestation verify [^-]' "$GH_LOG" || bad="$bad verify-attempted"
! grep -q '^api ' "$GH_LOG" || bad="$bad api-probed"
if [[ -z "$bad" ]]; then ok "gh that cannot run: refused, naming gh's own error"
else fail "gh that cannot run (rc=$rc):$bad"; show; fi
for ghenv in FAKE_GH_LACKS=attestation FAKE_GH_LACKS=--source-ref FAKE_GH_BROKEN=1; do
  d="$tmp/i-ghcap-cosign-${ghenv//[^A-Za-z]/}"
  run ghcap "$WITH_COSIGN" "$ghenv" FAKE_GH_VERSION=2.45.0 \
    BPFCOMPAT_BIN_DIR="$d/bin" BPFCOMPAT_LIBEXEC_DIR="$d/libexec"
  if [[ $rc -eq 0 && -x "$d/bin/bpfcompat" && -x "$d/libexec/bpfcompat-validator" ]] &&
    grep -q 'cosign signature over SHA256SUMS verified' "$OUT"; then
    ok "gh with $ghenv + cosign: verified with cosign and installed"
  else fail "gh with $ghenv and cosign present (rc=$rc)"; show; fi
done

# 10. S2: a capable gh that cannot complete the check is told apart from a
#     refused verification, and every outcome refuses. Before the first
#     verify call, one read-only probe of the attestation API the verify
#     uses decides "not authenticated" (gh's auth exit code 4, or HTTP 401)
#     and "GitHub API unavailable" (no HTTP response, 5xx, 429, rate-limited
#     403); any other answer hands over to the verify calls, whose failures
#     (other than exit code 4) always read "verification FAILED", whatever
#     gh prints. Each case: nonzero exit, nothing installed, the installer's
#     temp dir gone, only its own class named, no terminal control bytes.
C2='GitHub authentication needed for attestation verification'
C3='GitHub API unavailable for attestation verification'
C4='GitHub attestation verification FAILED for'
# ghrefuse: the v0.3.7 CLI is rc.4's attested binary (attested, other tag).
# ghnoatt: the v0.3.7 CLI has no attestation at all. SHA256SUMS matches both.
cp "$(rel_dir ghrefuse v0.4.0-rc.4)/$CLI_AMD64" "$(rel_dir ghrefuse v0.3.7)/$CLI_AMD64"
printf '#!/bin/sh\necho "unattested build"\n' >"$(rel_dir ghnoatt v0.3.7)/$CLI_AMD64"
for s in ghrefuse ghnoatt; do (cd "$(rel_dir "$s" v0.3.7)" && "$REAL_SHA" bpfcompat-* >SHA256SUMS); done
# probe_path <scenario> [tag] [cli asset]: the probe the installer must make
# for that release's CLI (default: v0.3.7's amd64 CLI).
probe_path() {
  echo "repos/$REPO/attestations/sha256:$("$REAL_SHA" <"$(rel_dir "$1" "${2:-v0.3.7}")/${3:-$CLI_AMD64}" | cut -d' ' -f1)?per_page=1"
}
# probes <scenario> <status...>: the probe log of one attempt per status.
probes() { local s="$1" st; shift; for st in "$@"; do echo "$(probe_path "$s") $st"; done; }
# waited <status...>: the installer waited 3 s before every attempt but the
# first, and at no other time (unchecked when sh bypasses the sleep shim).
waited() {
  local want="" i
  for ((i = 1; i < $#; i++)); do want+="3"$'\n'; done
  [[ $SLEEP_SHIMMED == 0 || "$(cat "$SLEEP_LOG")" == "${want%$'\n'}" ]]
}
itmp_clean() { [[ -d "$ITMP" && -z "$(ls -A "$ITMP")" ]]; }
no_ctl() { [[ -z "$(LC_ALL=C tr -d '\n[:print:]' <"$OUT")" ]]; }
# gh_class <title> <scenario> <class 2|3|4> <text> <verify calls> <probe statuses> [VAR=value...]
#   verify calls: how many `gh attestation verify` calls may have been made;
#   probe statuses: what each probe attempt got, in order ("-" = no HTTP
#   response); the waits between attempts are checked too.
gh_class() {
  local title="$1" scen="$2" cls="$3" want="$4" nver="$5" pst="$6" d="$tmp/i-ghclass" bad="" n
  shift 6
  run "$scen" "$GH_ONLY" BPFCOMPAT_VERSION=v0.3.7 BPFCOMPAT_BIN_DIR="$d/bin" BPFCOMPAT_LIBEXEC_DIR="$d/libexec" "$@"
  [[ $rc -ne 0 && ! -e "$d" ]] || bad+=" installed-or-rc0"
  itmp_clean || bad+=" tmpdir-left"
  grep -qF -- "$want" "$OUT" || bad+=" reason-not-named"
  case "$cls" in
    2) grep -qF 'or install cosign - refusing checksum-only installation' "$OUT" || bad+=" no-remedy"
       ! grep -qE "$C3|FAILED|lacks|requires cosign or GitHub CLI" "$OUT" || bad+=" other-class-named";;
    3) grep -qF 'then retry, or install cosign - refusing checksum-only installation' "$OUT" || bad+=" no-remedy"
       ! grep -qE "$C2|FAILED|lacks|requires cosign or GitHub CLI" "$OUT" || bad+=" other-class-named";;
    4) ! grep -qiE 'authenticat|logged in|credential|GH_TOKEN|network|proxy|unavailable|unreachable|rate.limit|refused|retry|HTTP [0-9]|lacks' "$OUT" ||
         bad+=" auth-or-network-wording"
       ! grep -qF -- "$C2" "$OUT" && ! grep -qF -- "$C3" "$OUT" || bad+=" other-class-named";;
  esac
  no_ctl || bad+=" control-bytes"
  # shellcheck disable=SC2086 # one probe attempt per word
  [[ "$(cat "$GH_API_LOG")" == "$(probes "$scen" $pst)" ]] || bad+=" probe($(tr '\n' '|' <"$GH_API_LOG"))"
  # shellcheck disable=SC2086
  waited $pst || bad+=" waits($(tr '\n' '|' <"$SLEEP_LOG"))"
  n="$(grep -c . "$GH_VERIFY_LOG" || true)"
  [[ "$n" == "$nver" ]] || bad+=" verify-calls=$n"
  if [[ -z "$bad" ]]; then ok "gh $title: class $cls, refused"
  else fail "gh $title (rc=$rc):$bad"; show; fi
}
gh_class "not logged in" ghapi 2 \
  "$C2: gh is not logged in (To get started with GitHub CLI, please run:  gh auth login); run 'gh auth login' or set a valid GH_TOKEN" \
  0 noauth FAKE_GH_AUTH=none
gh_class "token rejected (HTTP 401)" ghapi 2 \
  "$C2: GitHub rejected gh's credentials (HTTP 401) (gh: Bad credentials (HTTP 401)); run 'gh auth login' or set a valid GH_TOKEN" \
  0 401 FAKE_GH_AUTH=bad
gh_class "API unreachable" ghapi 3 \
  "$C3: no HTTP response (Get \"https://api.github.com/$(probe_path ghapi)\": proxyconnect tcp: dial tcp 127.0.0.1:9: connect: connection refused); check the network" \
  0 "- - -" FAKE_GH_NET=down
gh_class "API HTTP 503" ghapi 3 "$C3: HTTP 503 (gh: HTTP 503)" 0 "503 503 503" FAKE_GH_NET=503
gh_class "API HTTP 429" ghapi 3 "$C3: HTTP 429, rate limited (gh: You have exceeded a secondary rate limit. (HTTP 429))" 0 429 FAKE_GH_NET=429
gh_class "API rate limit (403, X-Ratelimit-Remaining: 0, coloured headers)" ghapi 3 \
  "$C3: HTTP 403, rate limited (gh: API rate limit exceeded for user ID 1. (HTTP 403))" 0 403rl FAKE_GH_NET=403rl FAKE_GH_COLOR=1
gh_class "API secondary rate limit (403, Retry-After)" ghapi 3 "$C3: HTTP 403, rate limited" 0 403ra FAKE_GH_NET=403ra
gh_class "API 403 without rate-limit headers" ghapi 4 "$C4 $CLI_AMD64" 1 403 FAKE_GH_NET=403
gh_class "no attestation for the CLI digest (API 404)" ghnoatt 4 "$C4 $CLI_AMD64" 1 404
gh_class "CLI attested for another tag (API answers)" ghrefuse 4 "$C4 $CLI_AMD64" 1 200
gh_class "attestation signed by another workflow (API answers)" ghapi 4 "$C4 $CLI_AMD64" 1 200 \
  FAKE_GH_ATTEST_SIGNER="$REPO/.github/workflows/ci.yml"
gh_class "refusal whose stderr claims a network error" ghrefuse 4 "$C4 $CLI_AMD64" 1 200 \
  FAKE_GH_VERIFY_ERR=$'error connecting to api.github.com\ncheck your internet connection or https://githubstatus.com'
gh_class "refusal whose stderr claims missing auth" ghrefuse 4 "$C4 $CLI_AMD64" 1 200 \
  FAKE_GH_VERIFY_ERR=$'To get started with GitHub CLI, please run:  gh auth login\nHTTP 401: Bad credentials'
gh_class "verify exits 4 after the API answered" ghapi 2 \
  "$C2: gh is not logged in (To get started with GitHub CLI, please run:  gh auth login)" 1 200 FAKE_GH_VERIFY_RC=4
gh_class "API unreachable, control bytes in gh's error" ghapi 3 "$C3: no HTTP response (]0;PWNED[31mGet \"https://api.github.com/" \
  0 "- - -" FAKE_GH_NET=down FAKE_GH_ERR_CTRL=1
# R2-N2: the "could not run 'gh --help'" line is stripped of control bytes too.
d="$tmp/i-ghbroken-ctl" bad=""
run ghcap "$GH_ONLY" FAKE_GH_BROKEN=1 FAKE_GH_ERR_CTRL=1 BPFCOMPAT_BIN_DIR="$d/bin" BPFCOMPAT_LIBEXEC_DIR="$d/libexec"
[[ $rc -ne 0 && ! -e "$d" ]] && itmp_clean || bad+=" installed-or-rc0-or-tmpdir"
grep -qF "installed gh could not run 'gh --help' (]0;PWNED[31mfailed to create root command: failed to read configuration: invalid config file /home/u/.config/gh/config.yml: invalid yaml); fix gh" "$OUT" ||
  bad+=" reason-not-named"
no_ctl || bad+=" control-bytes"
if [[ -z "$bad" ]]; then ok "gh that cannot run, control bytes in its error: stripped, refused"
else fail "gh that cannot run with control bytes (rc=$rc):$bad"; show; fi
# N2: gh's words keep printable ASCII only, so C1 controls go too - a raw
#     CSI byte (0x9b) and its UTF-8 form (c2 9b) - in both quoting places.
gh_class "API unreachable, C1 control bytes in gh's error" ghapi 3 "$C3: no HTTP response (31m32mGet \"https://api.github.com/" \
  0 "- - -" FAKE_GH_NET=down FAKE_GH_ERR_CTRL=c1
d="$tmp/i-ghbroken-c1" bad=""
run ghcap "$GH_ONLY" FAKE_GH_BROKEN=1 FAKE_GH_ERR_CTRL=c1 BPFCOMPAT_BIN_DIR="$d/bin" BPFCOMPAT_LIBEXEC_DIR="$d/libexec"
[[ $rc -ne 0 && ! -e "$d" ]] && itmp_clean || bad+=" installed-or-rc0-or-tmpdir"
grep -qF "installed gh could not run 'gh --help' (31m32mfailed to create root command: failed to read configuration: invalid config file /home/u/.config/gh/config.yml: invalid yaml); fix gh" "$OUT" ||
  bad+=" reason-not-named"
no_ctl || bad+=" control-bytes"
if [[ -z "$bad" ]]; then ok "gh that cannot run, C1 control bytes in its error: stripped, refused"
else fail "gh that cannot run with C1 control bytes (rc=$rc):$bad"; show; fi

# 10b. The probe on a good release: exactly one read-only GET of the CLI's
#      attestations, before the first verify call; with cosign present, gh
#      is never run. The cosign path is the same for every gh mode above.
d="$tmp/i-ghprobe" bad=""
run ghapi "$GH_ONLY" BPFCOMPAT_VERSION=v0.3.7 BPFCOMPAT_BIN_DIR="$d/bin" BPFCOMPAT_LIBEXEC_DIR="$d/libexec"
[[ $rc -eq 0 && -x "$d/bin/bpfcompat" ]] && itmp_clean || bad+=" not-installed-or-tmpdir"
verified "$GH_ONLY" v0.3.7 "$CLI_AMD64" "$VAL_AMD64" || bad+=" verify-calls"
[[ "$(cat "$GH_API_LOG")" == "$(probe_path ghapi) 200" ]] || bad+=" probe"
[[ "$(grep -nE '^(api |attestation verify [^-])' "$GH_LOG" | head -1)" == *":api --method GET --include $(probe_path ghapi)" ]] ||
  bad+=" probe-not-first"
# Only the CLI's verify call asks for its attested subjects (T4 R-B).
[[ "$(cat "$GH_FMT_LOG")" == "$CLI_AMD64 fmt=json jq=$JQ_SUBJECTS" ]] || bad+=" subjects-request($(tr '\n' '|' <"$GH_FMT_LOG"))"
waited 200 || bad+=" waited"
if [[ -z "$bad" ]]; then ok "gh path: one read-only API probe of the CLI digest, before the verify calls"
else fail "gh path probe (rc=$rc):$bad"; show; sed 's/^/    gh | /' "$GH_LOG" >&2; fi
for ghenv in FAKE_GH_AUTH=none FAKE_GH_AUTH=bad FAKE_GH_NET=down FAKE_GH_NET=503 FAKE_GH_NET=429 FAKE_GH_NET=403rl \
  FAKE_GH_NET=403 FAKE_GH_VERIFY_RC=4 FAKE_GH_VERIFY_ERR=x FAKE_GH_ERR_CTRL=1; do
  d="$tmp/i-ghclass-cosign"
  run ghapi "$WITH_COSIGN" "$ghenv" BPFCOMPAT_VERSION=v0.3.7 BPFCOMPAT_BIN_DIR="$d/bin" BPFCOMPAT_LIBEXEC_DIR="$d/libexec"
  if [[ $rc -eq 0 && -x "$d/bin/bpfcompat" && -x "$d/libexec/bpfcompat-validator" && ! -s "$GH_LOG" ]] && itmp_clean &&
    grep -q 'cosign signature over SHA256SUMS verified' "$OUT"; then
    ok "cosign path with $ghenv: gh never run, cosign verified, installed"
  else fail "cosign path with $ghenv (rc=$rc)"; show; fi
  rm -rf "$d"
done

# 10c. R2-N1: with pipefail imported (bash as sh, SHELLOPTS exported) every
#      refusal still prints its reason, and a good release still installs.
RUN_SH=(bash --posix)
PF=SHELLOPTS=braceexpand:hashall:interactive-comments:pipefail
for c in "FAKE_GH_BROKEN=1|installed gh could not run 'gh --help' (failed to create root command" \
  "FAKE_GH_VERSION=fail FAKE_GH_LACKS=attestation|installed gh lacks the 'gh attestation' command" \
  "FAKE_GH_NET=down|$C3: no HTTP response (Get " "FAKE_GH_NET=403rl|$C3: HTTP 403, rate limited" \
  "FAKE_GH_NET=403|$C4 $CLI_AMD64" "FAKE_GH_AUTH=none|$C2: gh is not logged in (To get started" \
  "FAKE_GH_AUTH=bad|$C2: GitHub rejected gh's credentials (HTTP 401) (gh: Bad credentials"; do
  d="$tmp/i-pipefail"
  read -r -a envs <<<"${c%%|*}"
  run ghapi "$GH_ONLY" "$PF" "${envs[@]}" BPFCOMPAT_VERSION=v0.3.7 BPFCOMPAT_BIN_DIR="$d/bin" BPFCOMPAT_LIBEXEC_DIR="$d/libexec"
  if [[ $rc -ne 0 && ! -e "$d" ]] && itmp_clean && grep -qF -- "${c#*|}" "$OUT"; then
    ok "pipefail imported, ${c%%|*}: refused with its reason"
  else fail "pipefail imported, ${c%%|*} (rc=$rc)"; show; fi
done
d="$tmp/i-pipefail-ok"
run ghapi "$GH_ONLY" "$PF" BPFCOMPAT_VERSION=v0.3.7 BPFCOMPAT_BIN_DIR="$d/bin" BPFCOMPAT_LIBEXEC_DIR="$d/libexec"
if [[ $rc -eq 0 && -x "$d/bin/bpfcompat" ]] && verified "$GH_ONLY" v0.3.7 "$CLI_AMD64" "$VAL_AMD64" &&
  [[ "$(cat "$GH_API_LOG")" == "$(probe_path ghapi) 200" ]]; then ok "pipefail imported: gh path installs a good release"
else fail "pipefail imported, good release (rc=$rc)"; show; fi
RUN_SH=(sh)

# 10d. N7: a 5xx or no HTTP response at the probe may be transient (gh's
#      own verify retries a 5xx), so the probe is made up to three times,
#      3 s apart, and the last attempt decides. Nothing else is retried: the
#      single-attempt expectations in 10 pin 401, 404, 200, a plain 403, a
#      429, rate-limited 403s and gh's auth exit code 4.
# gh_installs <title> <scenario> <probe statuses> [VAR=value...]: the good
#   v0.3.7 release still installs, verified, after exactly these attempts.
gh_installs() {
  local title="$1" scen="$2" pst="$3" d="$tmp/i-ghok" bad=""
  shift 3
  run "$scen" "$GH_ONLY" BPFCOMPAT_VERSION=v0.3.7 BPFCOMPAT_BIN_DIR="$d/bin" BPFCOMPAT_LIBEXEC_DIR="$d/libexec" "$@"
  [[ $rc -eq 0 && -x "$d/bin/bpfcompat" && -x "$d/libexec/bpfcompat-validator" ]] && itmp_clean || bad+=" not-installed-or-tmpdir"
  grep -q 'GitHub build attestations verified' "$OUT" || bad+=" not-verified"
  verified "$GH_ONLY" v0.3.7 "$CLI_AMD64" "$VAL_AMD64" || bad+=" verify-calls"
  # shellcheck disable=SC2086 # one probe attempt per word
  [[ "$(cat "$GH_API_LOG")" == "$(probes "$scen" $pst)" ]] || bad+=" probe($(tr '\n' '|' <"$GH_API_LOG"))"
  # shellcheck disable=SC2086
  waited $pst || bad+=" waits($(tr '\n' '|' <"$SLEEP_LOG"))"
  ! grep -qE "$C2|$C3|FAILED" "$OUT" || bad+=" refusal-wording"
  if [[ -z "$bad" ]]; then ok "gh $title: installed"
  else fail "gh $title (rc=$rc):$bad"; show; fi
  rm -rf "$d"
}
gh_installs "probe HTTP 503, then 200" ghapi "503 200" FAKE_GH_PROBE_SEQ="503 ok"
gh_installs "probe HTTP 502, 503, then 200 on the third and last attempt" ghapi "502 503 200" FAKE_GH_PROBE_SEQ="502 503 ok"
gh_installs "probe gets no HTTP response, then 200" ghapi "- 200" FAKE_GH_PROBE_SEQ="down ok"
gh_class "probe HTTP 503, then 401" ghapi 2 \
  "$C2: GitHub rejected gh's credentials (HTTP 401) (gh: Bad credentials (HTTP 401)); run 'gh auth login'" 0 "503 401" \
  FAKE_GH_PROBE_SEQ="503 401"
gh_class "probe HTTP 503, then 429 (not retried)" ghapi 3 "$C3: HTTP 429, rate limited (gh: You have exceeded" 0 "503 429" \
  FAKE_GH_PROBE_SEQ="503 429"
gh_class "probe: no HTTP response, then 403 rate-limited (not retried)" ghapi 3 "$C3: HTTP 403, rate limited" 0 "- 403rl" \
  FAKE_GH_PROBE_SEQ="down 403rl"
gh_class "probe HTTP 503, then 404: the verify calls decide" ghnoatt 4 "$C4 $CLI_AMD64" 1 "503 404" FAKE_GH_PROBE_SEQ="503 ok"
gh_class "probe: no HTTP response, then 200, CLI attested for another tag" ghrefuse 4 "$C4 $CLI_AMD64" 1 "- 200" \
  FAKE_GH_PROBE_SEQ="down ok"

# 10e. N1: ambiguous probe results go to the verify calls; a verify exit
#      code that is neither a refusal (1) nor gh's auth code (4) is a
#      failed verification; the status line is read for HTTP/1.1 too (as
#      behind a TLS-intercepting proxy).
gh_installs "probe exits 2 with no output (no status line): the verify calls decide" ghapi crash FAKE_GH_PROBE_SEQ=crash
gh_class "probe exits 2 with no output, CLI attested for another tag" ghrefuse 4 "$C4 $CLI_AMD64" 1 crash FAKE_GH_PROBE_SEQ=crash
gh_installs "probe exits 1 with output that is no status line: the verify calls decide" ghapi garbage FAKE_GH_PROBE_SEQ=garbage
gh_class "verify exits 2 after the API answered" ghapi 4 "$C4 $CLI_AMD64" 1 200 FAKE_GH_VERIFY_RC=2
gh_installs "API over HTTP/1.1" ghapi 200 FAKE_GH_PROTO=1.1
gh_class "token rejected over HTTP/1.1" ghapi 2 \
  "$C2: GitHub rejected gh's credentials (HTTP 401) (gh: Bad credentials (HTTP 401)); run 'gh auth login'" 0 401 \
  FAKE_GH_AUTH=bad FAKE_GH_PROTO=1.1
gh_class "HTTP/1.1 503, three times" ghapi 3 "$C3: HTTP 503 (gh: HTTP 503)" 0 "503 503 503" FAKE_GH_NET=503 FAKE_GH_PROTO=1.1
gh_class "HTTP/1.1 403 rate-limited" ghapi 3 "$C3: HTTP 403, rate limited (gh: API rate limit exceeded" 0 403rl \
  FAKE_GH_NET=403rl FAKE_GH_PROTO=1.1

# 11. T4 (remedy R-B): on the gh path SHA256SUMS is unsigned, and an
#     attestation binds bytes, not a file name. The CLI's verified provenance
#     names every asset its release run attested, so SHA256SUMS must agree
#     with it on whether the validator and the license bundle exist, and each
#     installed file must be attested under the name it is installed as.
#     Every tamper below passes each gh verify call (genuine bytes of the
#     requested tag) and the checksum step: only that comparison can catch
#     it. It reads as a failed verification (class 4) naming the mismatch;
#     with cosign, the edited SHA256SUMS fails its signature.
C4_NOT='authenticat|logged in|credential|GH_TOKEN|network|proxy|unavailable|unreachable|rate.limit|refused|retry|HTTP [0-9]|lacks'
resum() { (cd "$1" && "$REAL_SHA" bpfcompat-* >SHA256SUMS); }
# rb_refused <title> <scenario> <tag> <text after "FAILED for "> <verified assets> [VAR=value...]
rb_refused() {
  local title="$1" scen="$2" tag="$3" want="$4" assets="$5" d="$tmp/i-rb" bad="" cli ghrc
  shift 5
  cli="${assets%% *}"
  run "$scen" "$GH_ONLY" BPFCOMPAT_VERSION="$tag" BPFCOMPAT_BIN_DIR="$d/bin" BPFCOMPAT_LIBEXEC_DIR="$d/libexec" "$@"
  ghrc=$rc
  [[ $rc -ne 0 && ! -e "$d" ]] || bad+=" installed-or-rc0"
  itmp_clean || bad+=" tmpdir-left"
  grep -qxF -- "bpfcompat-install: $C4 $want" "$OUT" || bad+=" reason-not-named"
  ! grep -qiE "$C4_NOT" "$OUT" || bad+=" auth-or-network-wording"
  ! grep -qE "$C2|$C3|attestations verified|checksums verified" "$OUT" || bad+=" other-outcome-named"
  no_ctl || bad+=" control-bytes"
  # shellcheck disable=SC2086 # one asset per word
  verified "$GH_ONLY" "$tag" $assets || bad+=" verify-calls"
  [[ "$(cat "$GH_API_LOG")" == "$(probe_path "$scen" "$tag" "$cli") 200" ]] || bad+=" probe"
  [[ "$(cat "$GH_FMT_LOG")" == "$cli fmt=json jq=$JQ_SUBJECTS" ]] || bad+=" subjects-request"
  [[ -z "$bad" ]] || show
  rm -rf "$d"
  run "$scen" "$WITH_COSIGN" BPFCOMPAT_VERSION="$tag" BPFCOMPAT_BIN_DIR="$d/bin" BPFCOMPAT_LIBEXEC_DIR="$d/libexec" "$@"
  if ! { [[ $rc -ne 0 && ! -e "$d" && ! -s "$GH_LOG" ]] && itmp_clean &&
    grep -q 'cosign signature verification FAILED for SHA256SUMS' "$OUT"; }; then bad+=" cosign-path"; show; fi
  rm -rf "$d"
  if [[ -z "$bad" ]]; then ok "gh: $title: refused as a failed verification (cosign: bad signature)"
  else fail "gh: $title (gh rc=$ghrc, cosign rc=$rc):$bad"; fi
}
# rb_installs <title> <scenario> <tag> <verified assets> [VAR=value...]: an
#   untampered release passes the comparison; the installed bytes are the
#   verified ones.
rb_installs() {
  local title="$1" scen="$2" tag="$3" assets="$4" d="$tmp/i-rbok" bad="" a
  shift 4
  run "$scen" "$GH_ONLY" BPFCOMPAT_VERSION="$tag" BPFCOMPAT_BIN_DIR="$d/bin" BPFCOMPAT_LIBEXEC_DIR="$d/libexec" "$@"
  [[ $rc -eq 0 ]] && itmp_clean && grep -q 'GitHub build attestations verified' "$OUT" || bad+=" not-installed"
  # shellcheck disable=SC2086 # one asset per word
  verified "$GH_ONLY" "$tag" $assets || bad+=" verify-calls"
  [[ "$(cat "$GH_FMT_LOG")" == "${assets%% *} fmt=json jq=$JQ_SUBJECTS" ]] || bad+=" subjects-request"
  for a in $assets; do
    case "$a" in
      bpfcompat-linux-*) cmp -s "$(rel_dir "$scen" "$tag")/$a" "$d/bin/bpfcompat" || bad+=" cli-bytes" ;;
      bpfcompat-validator-*) cmp -s "$(rel_dir "$scen" "$tag")/$a" "$d/libexec/bpfcompat-validator" || bad+=" validator-bytes" ;;
    esac
  done
  [[ "$assets" == *validator* || ! -e "$d/libexec" ]] || bad+=" unexpected-validator"
  if [[ -z "$bad" ]]; then ok "gh: $title: installed"
  else fail "gh: $title (rc=$rc):$bad"; show; fi
  rm -rf "$d"
}
# S1: the validator line deleted from SHA256SUMS (v0.3.7 and rc.5 shapes).
sed -i "/  $VAL_AMD64\$/d" "$(rel_dir rbval037 v0.3.7)/SHA256SUMS" "$(rel_dir rbval5 v0.4.0-rc.5)/SHA256SUMS"
rb_refused "validator line deleted from SHA256SUMS (v0.3.7)" rbval037 v0.3.7 \
  "$VAL_AMD64: SHA256SUMS does not list it, but the v0.3.7 release provenance of $CLI_AMD64 does" "$CLI_AMD64"
rb_refused "validator line deleted from SHA256SUMS (v0.4.0-rc.5, with the license bundle)" rbval5 v0.4.0-rc.5 \
  "$VAL_AMD64: SHA256SUMS does not list it, but the v0.4.0-rc.5 release provenance of $CLI_AMD64 does" \
  "$CLI_AMD64 bpfcompat-third-party-licenses.tar.gz"
# S2: the license bundle line deleted (rc.5).
sed -i '/  bpfcompat-third-party-licenses\.tar\.gz$/d' "$(rel_dir rblic5 v0.4.0-rc.5)/SHA256SUMS"
rb_refused "license bundle line deleted from SHA256SUMS" rblic5 v0.4.0-rc.5 \
  "bpfcompat-third-party-licenses.tar.gz: SHA256SUMS does not list it, but the v0.4.0-rc.5 release provenance of $CLI_AMD64 does" \
  "$CLI_AMD64 $VAL_AMD64"
# S3: the same tag's arm64 CLI served as the amd64 CLI, its line rewritten.
cp "$(rel_dir rbcli v0.3.7)/bpfcompat-linux-arm64" "$(rel_dir rbcli v0.3.7)/$CLI_AMD64"; resum "$(rel_dir rbcli v0.3.7)"
rb_refused "the tag's arm64 CLI served as the amd64 CLI" rbcli v0.3.7 \
  "$CLI_AMD64: the v0.3.7 release provenance of $CLI_AMD64 does not list these bytes under that name (it lists them as bpfcompat-linux-arm64)" \
  "$CLI_AMD64 $VAL_AMD64"
# S4: the CLI's bytes served as the validator.
cp "$(rel_dir rbval v0.3.7)/$CLI_AMD64" "$(rel_dir rbval v0.3.7)/$VAL_AMD64"; resum "$(rel_dir rbval v0.3.7)"
rb_refused "the CLI's bytes served as the validator" rbval v0.3.7 \
  "$VAL_AMD64: the v0.3.7 release provenance of $CLI_AMD64 does not list these bytes under that name (it lists them as $CLI_AMD64)" \
  "$CLI_AMD64 $VAL_AMD64"
# T4-VERIFY's arm64-host variant: no arm64 validator is published, so
# SHA256SUMS gains a line for one, served with the amd64 validator's bytes.
cp "$(rel_dir rbarm v0.3.7)/$VAL_AMD64" "$(rel_dir rbarm v0.3.7)/bpfcompat-validator-static-linux-arm64"
resum "$(rel_dir rbarm v0.3.7)"
rb_refused "aarch64 host, an arm64 validator added to SHA256SUMS (amd64 bytes)" rbarm v0.3.7 \
  "bpfcompat-validator-static-linux-arm64: SHA256SUMS lists it, but the v0.3.7 release provenance of bpfcompat-linux-arm64 does not" \
  "bpfcompat-linux-arm64 bpfcompat-validator-static-linux-arm64" FAKE_ARCH=aarch64
# Bytes the same run attested in another statement (release-candidate
# evidence) served as the validator: not in the CLI's provenance at all.
printf '{"tag": "v0.3.7", "checksums_sha256": "x"}\n' >"$tmp/rbsep-evidence.json"
ev="$("$REAL_SHA" <"$tmp/rbsep-evidence.json" | cut -d' ' -f1)"
printf '%s refs/tags/v0.3.7\n' "$ev" >>"$ATTEST_DB"
printf 'rbsep-v0.3.7-evidence refs/tags/v0.3.7 %s  release-candidate-evidence.json\n' "$ev" >>"$SUBJ_DB"
cp "$tmp/rbsep-evidence.json" "$(rel_dir rbsep v0.3.7)/$VAL_AMD64"; resum "$(rel_dir rbsep v0.3.7)"
rb_refused "bytes from another statement of the same run served as the validator" rbsep v0.3.7 \
  "$VAL_AMD64: the v0.3.7 release provenance of $CLI_AMD64 does not list these bytes under that name" "$CLI_AMD64 $VAL_AMD64"
# The same bytes served as the CLI: the provenance verified for the CLI is
# then that other statement, which names no validator.
cp "$tmp/rbsep-evidence.json" "$(rel_dir rbsepcli v0.3.7)/$CLI_AMD64"; resum "$(rel_dir rbsepcli v0.3.7)"
rb_refused "bytes from another statement of the same run served as the CLI" rbsepcli v0.3.7 \
  "$VAL_AMD64: SHA256SUMS lists it, but the v0.3.7 release provenance of $CLI_AMD64 does not" "$CLI_AMD64 $VAL_AMD64"
# Controls: untampered releases still install on the gh path (the cases in
# 1, 1b, 2 and 8 are controls too).
rb_installs "untampered v0.3.7 with BPFCOMPAT_NO_VALIDATOR=1" ghapi v0.3.7 "$CLI_AMD64" BPFCOMPAT_NO_VALIDATOR=1
rb_installs "aarch64 host, untampered: arm64 CLI only" arm64 v0.3.7 bpfcompat-linux-arm64 FAKE_ARCH=aarch64
# A re-run release job: a second statement for the same tag holds the same
# CLI and a rebuilt validator, which is the one published.
v2="$(rel_dir rbrerun v0.3.7)/$VAL_AMD64"
printf 'validator v0.3.7 amd64, rebuilt by attempt 2\n' >"$v2"
for a in "$CLI_AMD64" bpfcompat-linux-arm64 "$VAL_AMD64"; do
  printf 'rbrerun-v0.3.7-attempt2 refs/tags/v0.3.7 %s  %s\n' "$("$REAL_SHA" <"$(rel_dir rbrerun v0.3.7)/$a" | cut -d' ' -f1)" "$a" >>"$SUBJ_DB"
done
printf '%s refs/tags/v0.3.7\n' "$("$REAL_SHA" <"$v2" | cut -d' ' -f1)" >>"$ATTEST_DB"
resum "$(rel_dir rbrerun v0.3.7)"
rb_installs "re-run release, validator from the second attested statement" rbrerun v0.3.7 "$CLI_AMD64 $VAL_AMD64"
# With pipefail imported, the name comparison still refuses with its reason.
RUN_SH=(bash --posix)
d="$tmp/i-rb-pipefail"
run rbcli "$GH_ONLY" "$PF" BPFCOMPAT_VERSION=v0.3.7 BPFCOMPAT_BIN_DIR="$d/bin" BPFCOMPAT_LIBEXEC_DIR="$d/libexec"
if [[ $rc -ne 0 && ! -e "$d" ]] && itmp_clean &&
  grep -qxF "bpfcompat-install: $C4 $CLI_AMD64: the v0.3.7 release provenance of $CLI_AMD64 does not list these bytes under that name (it lists them as bpfcompat-linux-arm64)" "$OUT"; then
  ok "pipefail imported, arm64 CLI served as amd64: refused with its reason"
else fail "pipefail imported, arm64 CLI served as amd64 (rc=$rc)"; show; fi
RUN_SH=(sh)

if [[ $failures -ne 0 ]]; then
  echo "[install-test] $failures failure(s)" >&2
  exit 1
fi
echo "[install-test] all install.sh cases passed"
