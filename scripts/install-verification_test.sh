#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/mock" "$tmp/assets" "$tmp/no-cosign"
printf '#!/bin/sh\nprintf "fixture version\\n"\n' >"$tmp/assets/bpfcompat-linux-amd64"
printf 'validator\n' >"$tmp/assets/bpfcompat-validator-static-linux-amd64"
printf 'fixture signature\n' >"$tmp/assets/SHA256SUMS.sig"
printf 'fixture certificate\n' >"$tmp/assets/SHA256SUMS.crt"
(cd "$tmp/assets"; sha256sum bpfcompat-linux-amd64 bpfcompat-validator-static-linux-amd64 >SHA256SUMS)
cat >"$tmp/mock/curl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
url="${@: -1}"
[[ "$url" == https://github.com/Kernel-Guard/bpfcompat/releases/download/v0.3.8-rc.1/* ]]
cp "$TEST_ASSETS/${url##*/}" .
SH
cat >"$tmp/mock/cosign" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ "$*" == verify-blob* ]]
[[ "$*" == *'--certificate-identity https://github.com/Kernel-Guard/bpfcompat/.github/workflows/release-artifacts.yml@refs/tags/v0.3.8-rc.1'* ]]
[[ "$*" == *'--certificate-oidc-issuer https://token.actions.githubusercontent.com'* ]]
[[ "${TEST_SIGNATURE_RESULT:-pass}" == pass ]]
SH
chmod +x "$tmp/mock/curl" "$tmp/mock/cosign"
run() {
  mkdir -p "$tmp/$1"
  PATH="$tmp/mock:$PATH" TEST_ASSETS="$tmp/assets" BPFCOMPAT_VERSION=v0.3.8-rc.1 \
    BPFCOMPAT_BIN_DIR="$tmp/$1/bin" BPFCOMPAT_LIBEXEC_DIR="$tmp/$1/libexec" \
    sh "$root/scripts/install.sh" >"$tmp/log" 2>&1
}
run valid
test -x "$tmp/valid/bin/bpfcompat"
if TEST_SIGNATURE_RESULT=fail run invalid-signature; then exit 1; fi
test ! -e "$tmp/invalid-signature/bin/bpfcompat"
duplicate="$(head -1 "$tmp/assets/SHA256SUMS")"
printf '%s\n' "$duplicate" >>"$tmp/assets/SHA256SUMS"
if run duplicate; then exit 1; fi
test ! -e "$tmp/duplicate/bin/bpfcompat"
for program in bash sh curl cp uname grep mktemp dirname rm; do
  if [[ "$program" == curl ]]; then
    ln -s "$tmp/mock/curl" "$tmp/no-cosign/curl"
  else
    ln -s "$(command -v "$program")" "$tmp/no-cosign/$program"
  fi
done
ln -s "$(command -v sha256sum)" "$tmp/no-cosign/sha256sum"
if PATH="$tmp/no-cosign" TEST_ASSETS="$tmp/assets" BPFCOMPAT_VERSION=v0.3.8-rc.1 \
  BPFCOMPAT_BIN_DIR="$tmp/no-signature/bin" BPFCOMPAT_LIBEXEC_DIR="$tmp/no-signature/libexec" \
  sh "$root/scripts/install.sh" >"$tmp/log" 2>&1; then exit 1; fi
grep -q 'cosign is required' "$tmp/log"
test ! -e "$tmp/no-signature/bin/bpfcompat"
echo '[install-verification-test] exact signer, failed signature, duplicate checksums and missing cosign PASS'
