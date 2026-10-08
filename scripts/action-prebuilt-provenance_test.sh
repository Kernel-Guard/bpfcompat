#!/usr/bin/env bash
# Execute the actual composite prebuilt step with only offline fixture services.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/mock" "$tmp/assets" "$tmp/action/scripts"
cp "$root/scripts/verify-release-assets.sh" "$tmp/action/scripts/"
printf 'cli\n' >"$tmp/assets/bpfcompat-linux-amd64"
printf 'validator\n' >"$tmp/assets/bpfcompat-validator-static-linux-amd64"
(cd "$tmp/assets"; sha256sum bpfcompat-linux-amd64 bpfcompat-validator-static-linux-amd64 >SHA256SUMS)
python3 - "$root/action.yml" <<'PY' >"$tmp/prebuilt.sh"
import sys, yaml
with open(sys.argv[1]) as f:
    step = yaml.safe_load(f)['runs']['steps'][0]
    if step['env'].get('GH_TOKEN') != '${{ github.token }}':
        raise ValueError('Action must pass the caller token to gh')
    print(step['run'])
PY
cat >"$tmp/mock/curl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
destination=''
while [[ $# -gt 0 ]]; do
  case "$1" in -o) destination="$2"; shift 2;; *) url="$1"; shift;; esac
done
if [[ "$url" == *'/tags?per_page=100' ]]; then
  printf '[{"name":"v0.3.8-rc.1","commit":{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}]\n'
else
  [[ "$url" == https://github.com/Kernel-Guard/bpfcompat/releases/download/v0.3.8-rc.1/* ]]
  cp "$TEST_ASSETS/${url##*/}" "$destination"
fi
SH
cat >"$tmp/mock/gh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ "$*" == 'attestation --help' ]] && exit 0
[[ "${GH_TOKEN:-}" == offline-fixture ]]
[[ "$*" == attestation\ verify* ]]
[[ "$*" == *'--repo Kernel-Guard/bpfcompat'* ]]
[[ "$*" == *'--signer-workflow Kernel-Guard/bpfcompat/.github/workflows/release-artifacts.yml'* ]]
[[ "$*" == *'--source-digest aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'* ]]
[[ "$*" == *'--source-ref refs/tags/v0.3.8-rc.1'* ]]
[[ "${TEST_ATTESTATION_RESULT:-pass}" == pass ]]
SH
chmod +x "$tmp/mock/curl" "$tmp/mock/gh"
run() {
  PATH="$tmp/mock:$PATH" TEST_ASSETS="$tmp/assets" ACTION_REF=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    GITHUB_API_TOKEN=offline-fixture GH_TOKEN=offline-fixture GITHUB_ACTION_PATH="$tmp/action" GITHUB_OUTPUT="$tmp/output" \
    bash "$tmp/prebuilt.sh" >"$tmp/log" 2>&1
}
run
grep -q '^resolved=true$' "$tmp/output"
cmp "$tmp/assets/bpfcompat-linux-amd64" "$tmp/action/bin/bpfcompat"
mv "$tmp/action/bin" "$tmp/verified-bin"
mv "$tmp/action/validator" "$tmp/verified-validator"
if TEST_ATTESTATION_RESULT=fail run; then
  echo 'Action accepted failed attestation' >&2; exit 1
fi
test ! -e "$tmp/action/bin/bpfcompat"
echo '[action-provenance-test] SHA-to-tag resolution, exact attestation identity and fail-closed install PASS'
