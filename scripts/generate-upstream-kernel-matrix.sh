#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

RELEASES_URL="${BPFCOMPAT_KERNEL_RELEASES_URL:-https://www.kernel.org/releases.json}"
MAINLINE_URL="${BPFCOMPAT_UBUNTU_MAINLINE_URL:-https://kernel.ubuntu.com/mainline/}"
OUT_MATRIX="${BPFCOMPAT_OUT_MATRIX:-matrices/upstream-kernel-runnable.yaml}"
PROFILE_DIR="${BPFCOMPAT_PROFILE_DIR:-vm/profiles}"
PREFLIGHT="${BPFCOMPAT_VIRTME_PREFLIGHT:-1}"
PREFLIGHT_TIMEOUT="${BPFCOMPAT_VIRTME_PREFLIGHT_TIMEOUT:-45s}"
MAX_LATEST_ATTEMPTS="${BPFCOMPAT_MAX_LATEST_ATTEMPTS:-12}"

command -v curl >/dev/null || { echo "[upstream-kernel] missing curl" >&2; exit 1; }
command -v jq >/dev/null || { echo "[upstream-kernel] missing jq" >&2; exit 1; }
command -v sort >/dev/null || { echo "[upstream-kernel] missing sort" >&2; exit 1; }
if [[ "$PREFLIGHT" == "1" ]]; then
  command -v timeout >/dev/null || { echo "[upstream-kernel] missing timeout" >&2; exit 1; }
  command -v vng >/dev/null || { echo "[upstream-kernel] missing virtme-ng executable: vng" >&2; exit 1; }
fi

tmp_releases="$(mktemp)"
tmp_mainline="$(mktemp)"
trap 'rm -f "$tmp_releases" "$tmp_mainline"' EXIT

curl -fsSL "$RELEASES_URL" > "$tmp_releases"
curl -fsSL "$MAINLINE_URL" > "$tmp_mainline"

kernelorg_stable="$(jq -r '.latest_stable.version // empty' "$tmp_releases")"
kernelorg_mainline="$(jq -r '.releases[] | select(.moniker == "mainline") | .version' "$tmp_releases" | head -n1)"
kernelorg_longterm="$(jq -r '.releases[] | select(.moniker == "longterm") | .version' "$tmp_releases" | head -n1)"

available_versions="$(
  sed -nE 's/.*href="(v[0-9][^"/]*)\/".*/\1/p' "$tmp_mainline" |
    grep -E '^v[0-9]+\.[0-9]+($|-rc[0-9]+$)' |
    sort -Vu || true
)"
if [[ -z "$available_versions" ]]; then
  echo "[upstream-kernel] no Ubuntu mainline prebuilt kernel versions found in ${MAINLINE_URL}" >&2
  exit 2
fi

sanitize_id() {
  local value="$1"
  value="${value#v}"
  value="${value//+/-}"
  value="${value//\//-}"
  value="${value//_/-}"
  printf '%s' "$value"
}

major_minor() {
  local value="${1#v}"
  if [[ "$value" =~ ^([0-9]+)\.([0-9]+) ]]; then
    printf 'v%s.%s' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
  fi
}

is_available() {
  local version="$1"
  grep -Fxq "$version" <<<"$available_versions"
}

is_runnable() {
  local version="$1"
  if ! is_available "$version"; then
    echo "[upstream-kernel] skip ${version}: not present in ${MAINLINE_URL}" >&2
    return 1
  fi
  if [[ "$PREFLIGHT" == "1" ]]; then
    if timeout "$PREFLIGHT_TIMEOUT" vng --run "$version" --user root --memory 1024 --cpus 1 --exec /bin/true >/dev/null 2>&1; then
      return 0
    fi
    echo "[upstream-kernel] skip ${version}: virtme-ng preflight boot failed" >&2
    return 1
  fi
  if command -v vng >/dev/null && vng --run "$version" --dry-run >/dev/null 2>&1; then
    return 0
  fi
  return 0
}

select_latest_runnable() {
  local attempts=0
  while IFS= read -r version; do
    [[ -n "$version" ]] || continue
    attempts=$((attempts + 1))
    if is_runnable "$version"; then
      printf '%s' "$version"
      return 0
    fi
    if (( attempts >= MAX_LATEST_ATTEMPTS )); then
      break
    fi
  done
  return 1
}

append_unique() {
  local value="$1"
  local existing
  for existing in "${selected_versions[@]}"; do
    if [[ "$existing" == "$value" ]]; then
      return 0
    fi
  done
  selected_versions+=("$value")
}

write_profile() {
  local role="$1"
  local version="$2"
  local required="$3"
  local id="kernelorg-$(sanitize_id "$role")-$(sanitize_id "$version")"

  mkdir -p "$PROFILE_DIR"
  cat > "${PROFILE_DIR}/${id}.yaml" <<EOF
id: ${id}
distro: upstream-mainline
version: "${role}"
kernel_family: "${version#v}"
arch: x86_64
runner: virtme-ng
virtme_ng:
  run: "${version}"
boot:
  memory_mb: 2048
  cpus: 2
validator:
  path: "/bpfcompat/bin/bpfcompat-validator"
capabilities:
  expected_btf: true
EOF
  printf '%s:%s:%s\n' "$id" "$version" "$required"
}

stable_major_minor="$(major_minor "$kernelorg_stable")"
mainline_rc=""
if [[ -n "$kernelorg_mainline" && "$kernelorg_mainline" == *"-rc"* ]]; then
  mainline_rc="v${kernelorg_mainline#v}"
fi

major_minor_candidates="$(
  grep -E '^v[0-9]+\.[0-9]+$' <<<"$available_versions" |
    sort -Vr || true
)"

selected_versions=()

if [[ -n "$stable_major_minor" ]] && is_runnable "$stable_major_minor"; then
  append_unique "$stable_major_minor"
else
  latest_runnable="$(select_latest_runnable <<<"$major_minor_candidates" || true)"
  if [[ -n "$latest_runnable" ]]; then
    append_unique "$latest_runnable"
  fi
fi

if [[ -n "$mainline_rc" ]] && is_runnable "$mainline_rc"; then
  append_unique "$mainline_rc"
fi

for feature_boundary in v6.8 v6.1 v5.15; do
  if is_runnable "$feature_boundary"; then
    append_unique "$feature_boundary"
  fi
done

if (( ${#selected_versions[@]} == 0 )); then
  echo "[upstream-kernel] no runnable virtme-ng upstream kernels found" >&2
  exit 2
fi

mkdir -p "$PROFILE_DIR"
rm -f "$PROFILE_DIR"/kernelorg-*.yaml

profile_records=()
for index in "${!selected_versions[@]}"; do
  version="${selected_versions[$index]}"
  required="false"
  role="feature"
  if [[ "$index" == "0" ]]; then
    required="true"
    role="latest-runnable"
  elif [[ "$version" == *"-rc"* ]]; then
    role="mainline-rc"
  elif [[ "$version" == "v6.8" ]]; then
    role="feature-ringbuf-era"
  elif [[ "$version" == "v6.1" ]]; then
    role="lts"
  elif [[ "$version" == "v5.15" ]]; then
    role="lts"
  fi
  profile_records+=("$(write_profile "$role" "$version" "$required")")
done

mkdir -p "$(dirname "$OUT_MATRIX")"
{
  echo "name: upstream-kernel-sweep"
  echo "profiles:"
  for record in "${profile_records[@]}"; do
    IFS=: read -r id _version required <<<"$record"
    echo "  - id: ${id}"
    echo "    required: ${required}"
  done
} > "$OUT_MATRIX"

echo "[upstream-kernel] kernel.org releases=$RELEASES_URL"
echo "[upstream-kernel] ubuntu-mainline=${MAINLINE_URL}"
echo "[upstream-kernel] matrix=${OUT_MATRIX}"
echo "[upstream-kernel] kernel.org stable=${kernelorg_stable:-unknown}"
echo "[upstream-kernel] kernel.org mainline=${kernelorg_mainline:-unknown}"
echo "[upstream-kernel] kernel.org longterm=${kernelorg_longterm:-unknown}"
for record in "${profile_records[@]}"; do
  IFS=: read -r id version required <<<"$record"
  echo "[upstream-kernel] selected=${version} profile=${id} required=${required}"
done
