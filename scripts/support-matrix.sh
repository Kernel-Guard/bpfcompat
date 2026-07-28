#!/usr/bin/env bash
# Generate docs/support-matrix.md — the single canonical view of which profiles
# are runnable, need a manually-supplied image, are generated at run time, or are
# cataloged-but-not-runnable on the current executor.
#
# The classification is deterministic: it depends only on committed profile YAML
# (runner, image.source_url presence, distro), never on local image cache state.
# That makes the output reproducible in CI, so scripts/check-docs-drift.sh can
# regenerate it and fail if the committed page has fallen behind the profiles.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

OUT_FILE="${BPFCOMPAT_SUPPORT_MATRIX_OUT:-docs/support-matrix.md}"

field() { awk -F': ' -v k="^$2:" '$0 ~ k {gsub(/"/,"",$2); print $2; exit}' "$1"; }
has_source_url() { grep -q "source_url:" "$1"; }

# Rows accumulate per category, tab-separated, then get sorted and rendered.
runnable=""
manual=""
generated=""
notrunnable=""

for path in vm/profiles/*.yaml; do
  id="$(field "$path" id)"
  distro="$(field "$path" distro)"
  version="$(field "$path" version)"
  family="$(field "$path" kernel_family)"
  arch="$(field "$path" arch)"
  runner="$(field "$path" runner)"
  [[ -z "$arch" ]] && arch="x86_64"

  distro_lc="$(echo "$distro" | tr '[:upper:]' '[:lower:]')"
  row="${id}	${distro:--}	${version:--}	${family:--}	${arch}"

  if [[ -n "$runner" ]]; then
    generated+="${row}	${runner}	kernel is built/booted at run time (no vendor image)"$'\n'
  elif [[ "$distro_lc" == "talos" || "$distro_lc" == "bottlerocket" || "$distro_lc" == "flatcar" ]]; then
    notrunnable+="${row}	immutable image	no SSH/cloud-init transport on current executor"$'\n'
  elif [[ "$id" == "amazon-linux-2-4.14" ]]; then
    notrunnable+="${row}	ssh	cataloged; not bootable on current SSH/cloud-init executor"$'\n'
  elif has_source_url "$path"; then
    runnable+="${row}	ssh	auto-downloads vendor cloud image on first run"$'\n'
  else
    manual+="${row}	ssh	no source_url configured — operator supplies the image (see make import-required-images)"$'\n'
  fi
done

count() { printf '%s' "$1" | grep -c . || true; }

render_table() {
  # $1 = tab-separated rows (may be empty)
  echo "| Profile ID | Distro | Version | Kernel family | Arch | Transport / runner | Notes |"
  echo "|---|---|---|---|---|---|---|"
  if [[ -n "$1" ]]; then
    printf '%s' "$1" | LC_ALL=C sort | awk -F'\t' '{printf "| %s | %s | %s | %s | %s | %s | %s |\n", $1,$2,$3,$4,$5,$6,$7}'
  fi
}

{
  echo "# Support Matrix"
  echo
  echo "<!-- GENERATED FILE — do not edit by hand."
  echo "     Regenerate with: make support-matrix (or scripts/support-matrix.sh)."
  echo "     CI fails if this file drifts from vm/profiles/*.yaml. -->"
  echo
  echo "This is the single source of truth for what bpfcompat can actually run."
  echo "It is generated from the committed profile definitions, so it can never"
  echo "claim support the profiles do not describe. \"Runnable\" is a property of"
  echo "the profile and executor, independent of whether an image is cached on any"
  echo "particular machine. For tiering rationale see"
  echo "[profile-catalog.md](profile-catalog.md); for how images are fetched and"
  echo "pinned see [image-pipeline.md](image-pipeline.md)."
  echo
  echo "| Category | Count | Meaning |"
  echo "|---|---|---|"
  echo "| Runnable (auto-download) | $(count "$runnable") | Supported transport and a public vendor image URL — runs anywhere with KVM, no manual setup. |"
  echo "| Manual image required | $(count "$manual") | Supported transport, but the image is licensed or has no public URL; the operator imports it (see \`make import-required-images\`). |"
  echo "| Generated lane | $(count "$generated") | No vendor image at all — the kernel is built/booted at run time (virtme-ng upstream, Firecracker). |"
  echo "| Cataloged, not runnable here | $(count "$notrunnable") | Present in the catalog but not bootable on the current SSH/cloud-init executor (immutable images, executor limits). Marked non-blocking in matrices. |"
  echo
  echo "## Runnable now (auto-download)"
  echo
  echo "These run with nothing more than a KVM-capable host; the vendor cloud"
  echo "image is fetched on first use and its sha256 is recorded."
  echo
  render_table "$runnable"
  echo
  echo "## Manual image required"
  echo
  echo "Supported by the executor, but you must supply the image yourself"
  echo "(licensed distros, or images with no stable public URL)."
  echo
  render_table "$manual"
  echo
  echo "## Generated lanes (no prebuilt image)"
  echo
  echo "The environment is constructed at run time; reproducibility comes from the"
  echo "recorded kernel release, not an image digest."
  echo
  render_table "$generated"
  echo
  echo "## Cataloged, not runnable on the current executor"
  echo
  echo "Tracked for coverage but not bootable via the SSH/cloud-init executor"
  echo "today (immutable/image-based systems, or a known executor limitation)."
  echo "These are marked non-blocking wherever they appear in a matrix."
  echo
  render_table "$notrunnable"
} > "$OUT_FILE"

echo "[support-matrix] wrote ${OUT_FILE}"
