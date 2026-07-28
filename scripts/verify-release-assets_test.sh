#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
verifier="${ROOT_DIR}/scripts/verify-release-assets.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/assets" "$tmp/bin"
printf 'cli\n' >"$tmp/assets/bpfcompat-linux-amd64"
printf 'validator\n' >"$tmp/assets/bpfcompat-validator-static-linux-amd64"
(
  cd "$tmp/assets"
  sha256sum bpfcompat-linux-amd64 bpfcompat-validator-static-linux-amd64 >SHA256SUMS
)

cat >"$tmp/bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "attestation" && "${2:-}" == "--help" ]]; then
  exit 0
fi
if [[ "${1:-}" == "attestation" && "${2:-}" == "verify" ]]; then
  [[ "$*" == *"--repo Kernel-Guard/bpfcompat"* ]]
  [[ "$*" == *"--signer-workflow Kernel-Guard/bpfcompat/.github/workflows/release-artifacts.yml"* ]]
  exit 0
fi
exit 1
EOF
chmod 0700 "$tmp/bin/gh"

PATH="$tmp/bin:$PATH" bash "$verifier" \
  "$tmp/assets" Kernel-Guard/bpfcompat \
  bpfcompat-linux-amd64 bpfcompat-validator-static-linux-amd64 >/dev/null

printf 'tampered\n' >"$tmp/assets/bpfcompat-linux-amd64"
if PATH="$tmp/bin:$PATH" bash "$verifier" \
  "$tmp/assets" Kernel-Guard/bpfcompat \
  bpfcompat-linux-amd64 bpfcompat-validator-static-linux-amd64 >/dev/null 2>&1; then
  echo "tampered asset unexpectedly passed" >&2
  exit 1
fi

echo "[release-assets-test] PASS"
