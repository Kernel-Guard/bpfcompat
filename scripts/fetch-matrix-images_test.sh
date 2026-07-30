#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT_DIR/scripts/fetch-matrix-images.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/bin" "$TMP/matrices" "$TMP/scripts" "$TMP/vm/profiles"
cp "$SCRIPT" "$TMP/scripts/fetch-matrix-images.sh"

cat >"$TMP/bin/bpfcompat" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
[[ "$*" == "profile list --matrix matrices/test.yaml" ]]
printf '%s\n' quoted-profile generated-profile
FAKE
chmod +x "$TMP/bin/bpfcompat"

cat >"$TMP/matrices/test.yaml" <<'YAML'
name: test
profiles:
  - id: quoted-profile
    required: true
  - id: generated-profile
    required: true
YAML

cat >"$TMP/vm/profiles/quoted-profile.yaml" <<'YAML'
id: quoted-profile
distro: "amazon-linux"
image:
  source_url: "https://example.invalid/quoted.qcow2"
  local_path: "vm/cache/quoted.qcow2"
YAML

cat >"$TMP/vm/profiles/generated-profile.yaml" <<'YAML'
id: generated-profile
distro: almalinux
image:
    source_url: https://example.invalid/generated.qcow2
    local_path: vm/cache/generated.qcow2
YAML

output="$(
  cd "$TMP"
  BPFCOMPAT_BIN=./bin/bpfcompat \
  BPFCOMPAT_MATRIX=matrices/test.yaml \
  BPFCOMPAT_DRY_RUN=1 \
    bash scripts/fetch-matrix-images.sh
)"

grep -Fq "quoted-profile: would download -> vm/cache/quoted.qcow2" <<<"$output"
grep -Fq "generated-profile: would download -> vm/cache/generated.qcow2" <<<"$output"
grep -Fq "failed:                 0" <<<"$output"

echo "[fetch-matrix-images-test] PASS"
