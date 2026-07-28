#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -lt 3 ]]; then
  echo "usage: $0 <asset-dir> <owner/repo> <asset>..." >&2
  exit 2
fi

asset_dir="$1"
repo="$2"
shift 2
assets=("$@")
checksums="${asset_dir}/SHA256SUMS"

[[ -d "$asset_dir" ]] || {
  echo "[release-assets] missing asset directory: ${asset_dir}" >&2
  exit 1
}
[[ -f "$checksums" ]] || {
  echo "[release-assets] missing SHA256SUMS in ${asset_dir}" >&2
  exit 1
}
command -v gh >/dev/null 2>&1 || {
  echo "[release-assets] GitHub CLI is required for attestation verification" >&2
  exit 1
}
gh attestation --help >/dev/null 2>&1 || {
  echo "[release-assets] installed GitHub CLI lacks attestation support" >&2
  exit 1
}

checklist="$(mktemp "${asset_dir}/.bpfcompat-checksums.XXXXXX")"
trap 'rm -f "$checklist"' EXIT

for asset in "${assets[@]}"; do
  [[ "$asset" != */* && "$asset" != "." && "$asset" != ".." ]] || {
    echo "[release-assets] invalid asset basename: ${asset}" >&2
    exit 1
  }
  [[ -f "${asset_dir}/${asset}" ]] || {
    echo "[release-assets] missing downloaded asset: ${asset}" >&2
    exit 1
  }
  line="$(
    awk -v file="$asset" '
      $2 == file && $1 ~ /^[0-9a-fA-F]{64}$/ {
        count++
        found = $0
      }
      END {
        if (count == 1) {
          print found
        } else {
          exit 1
        }
      }
    ' "$checksums"
  )" || {
    echo "[release-assets] ${asset} must have exactly one valid SHA256SUMS entry" >&2
    exit 1
  }
  printf '%s\n' "$line" >>"$checklist"
done

(
  cd "$asset_dir"
  sha256sum -c "$(basename "$checklist")"
)

for asset in "${assets[@]}"; do
  gh attestation verify "${asset_dir}/${asset}" \
    --repo "$repo" \
    --signer-workflow "${repo}/.github/workflows/release-artifacts.yml"
done

echo "[release-assets] checksums and release-workflow attestations verified"
