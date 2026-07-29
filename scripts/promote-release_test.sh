#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script="${ROOT_DIR}/scripts/promote-release.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/bin"
cat >"$tmp/bin/docker" <<'EOF'
#!/usr/bin/env bash
printf 'docker'
printf ' <%s>' "$@"
printf '\n'
EOF
cat >"$tmp/bin/gh" <<'EOF'
#!/usr/bin/env bash
printf 'gh'
printf ' <%s>' "$@"
printf '\n'
EOF
chmod +x "$tmp/bin/docker" "$tmp/bin/gh"

digest="sha256:$(printf 'a%.0s' {1..64})"

PATH="$tmp/bin:$PATH" "$script" \
  ghcr.io/kernel-guard/bpfcompat "$digest" v0.4.0-rc.1 prerelease \
  >"$tmp/prerelease.log"
grep -Fq '<--tag> <ghcr.io/kernel-guard/bpfcompat:0.4.0-rc.1>' "$tmp/prerelease.log"
grep -Fq 'gh <release> <edit> <v0.4.0-rc.1> <--draft=false> <--prerelease>' "$tmp/prerelease.log"
if grep -Eq ':(latest|0\.4)>' "$tmp/prerelease.log"; then
  echo "[promote-release-test] prerelease attempted to mutate a stable alias" >&2
  exit 1
fi

PATH="$tmp/bin:$PATH" "$script" \
  ghcr.io/kernel-guard/bpfcompat "$digest" v0.4.0 stable \
  >"$tmp/stable.log"
for tag in 0.4.0 0.4 latest; do
  grep -Fq "<--tag> <ghcr.io/kernel-guard/bpfcompat:${tag}>" "$tmp/stable.log"
done
grep -Fq 'gh <release> <edit> <v0.4.0> <--draft=false> <--latest>' "$tmp/stable.log"

for bad_case in \
  "v0.4.0-rc.1 stable" \
  "v0.4.0 prerelease" \
  "v0.4.0-rc.0 prerelease" \
  "v0.4.0 preview"; do
  read -r tag channel <<<"$bad_case"
  if PATH="$tmp/bin:$PATH" "$script" \
    ghcr.io/kernel-guard/bpfcompat "$digest" "$tag" "$channel" \
    >"$tmp/bad.log" 2>&1; then
    echo "[promote-release-test] accepted invalid ${tag}/${channel}" >&2
    exit 1
  fi
done

echo "[promote-release-test] PASS"
