#!/usr/bin/env bash
# Build the shipped static validator from declared, pinned inputs.
#
#   build-validator-pinned.sh <out-binary> <out-build-inputs.json>
#
# The validator statically links distro libbpf/libelf/zlib/zstd/glibc, so the
# runner image used to decide its bytes. This builds it inside the lock's
# digest-pinned builder_image with exactly the lock's package versions,
# resolved from the lock's fixed snapshot.ubuntu.com timestamp (apt_snapshot)
# rather than the moving archive, so an Ubuntu SRU cannot remove a pinned
# version or change an unpinned transitive one (apt fails closed if the
# snapshot cannot provide them), checks the installed versions, builds
# `make validator-static`'s recipe, proves the binary's libbpf/compiler with
# check-validator-build-inputs.sh, and writes a JSON record of every input.
#
# If validator/c-libbpf is the tree named on the lock's `reproduces=` line, the
# result must be byte-identical to the recorded sha256 (a reproducibility gate:
# same sources + same inputs = same bytes). Otherwise it reports the new
# sha256 so the lock line can be updated together with a new release candidate.
#
# Env: BPFCOMPAT_VALIDATOR_LOCK overrides the lock path (tests).
# Exit 0: built and verified. Exit 1: drift or build failure. Exit 2: usage.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK="${BPFCOMPAT_VALIDATOR_LOCK:-$ROOT/validator/build-inputs.lock}"

lock_value() {
  awk -v key="$1" 'index($0, key "=") == 1 { v = substr($0, length(key) + 2); n++ }
    END { if (n == 1) print v; exit n == 1 ? 0 : 1 }' "$LOCK"
}
lock_pkgs() {
  awk 'index($0, "pkg=") == 1 { print substr($0, 5) }' "$LOCK"
}

validate_lock() {
  [[ -f "$LOCK" ]] || { echo "build-validator-pinned: lock $LOCK not found" >&2; return 2; }
  local image pkgs line
  image="$(lock_value builder_image)" ||
    { echo "build-validator-pinned: lock needs exactly one builder_image" >&2; return 2; }
  [[ "$image" =~ @sha256:[0-9a-f]{64}$ ]] ||
    { echo "build-validator-pinned: builder_image must be pinned by @sha256 digest, got '$image'" >&2; return 2; }
  local snapshot
  snapshot="$(lock_value apt_snapshot)" ||
    { echo "build-validator-pinned: lock needs exactly one apt_snapshot" >&2; return 2; }
  [[ "$snapshot" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] ||
    { echo "build-validator-pinned: apt_snapshot must be a snapshot.ubuntu.com id like 20261014T154800Z, got '$snapshot'" >&2; return 2; }
  local snap_epoch
  if ! snap_epoch="$(date -u -d "${snapshot:0:4}-${snapshot:4:2}-${snapshot:6:2} ${snapshot:9:2}:${snapshot:11:2}:${snapshot:13:2} UTC" +%s 2>/dev/null)" ||
    [[ "$(date -u -d "@$snap_epoch" +%Y%m%dT%H%M%SZ)" != "$snapshot" ]]; then
    echo "build-validator-pinned: apt_snapshot '$snapshot' is not a valid UTC timestamp" >&2
    return 2
  fi
  # snapshot.ubuntu.com answers a future id with the newest state so far, i.e.
  # the moving archive until that date: refuse it.
  if ((snap_epoch > $(date -u +%s))); then
    echo "::error::apt_snapshot $snapshot is in the future ($(date -u +%Y%m%dT%H%M%SZ) now); it would follow the moving archive, not a fixed state" >&2
    return 1
  fi
  pkgs="$(lock_pkgs)"
  [[ -n "$pkgs" ]] || { echo "build-validator-pinned: lock declares no pkg= lines" >&2; return 2; }
  while IFS= read -r line; do
    [[ "$line" =~ ^[a-z0-9][a-z0-9.+-]*=[A-Za-z0-9.+:~-]+$ ]] ||
      { echo "build-validator-pinned: pkg line must be name=exact-version, got '$line'" >&2; return 2; }
  done <<<"$pkgs"
  # Everything that ends up inside the static binary, plus the compiler.
  local required
  for required in libbpf-dev libelf-dev zlib1g-dev libzstd-dev libc6-dev binutils 'gcc-[0-9]+'; do
    grep -Eq "^${required}=" <<<"$pkgs" ||
      { echo "build-validator-pinned: lock must pin ${required}" >&2; return 2; }
  done
}

# Write the apt configuration that resolves every package from the lock's
# snapshot into <apt-dir> (/etc/apt in the builder). The builder image has no
# ca-certificates, and installing them would need the moving archive. With
# [<ca-bundle>] (the runner's bundle, mounted read-only) TLS to
# snapshot.ubuntu.com is verified against it. Without one, TLS peer
# verification is off for snapshot.ubuntu.com only. Integrity does not rest on
# TLS either way: apt still requires the InRelease signature against the
# image's ubuntu-archive-keyring (Signed-By) and the per-file hashes, and
# unsigned or insecure repositories stay refused. Without TLS an attacker could
# at most replay another genuine Ubuntu-signed index; a different package set
# then fails the exact-version check or the recorded byte-identity check, and
# it is no weaker than the image's default plain-http archive sources.
render_apt_config() {
  local dir="$1" ca="${2:-}" snapshot
  snapshot="$(lock_value apt_snapshot)"
  mkdir -p "$dir/sources.list.d" "$dir/apt.conf.d"
  cat >"$dir/sources.list.d/bpfcompat-snapshot.sources" <<EOF
Types: deb
URIs: https://snapshot.ubuntu.com/ubuntu/${snapshot}/
Suites: noble noble-updates noble-security
Components: main universe
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
EOF
  if [[ -n "$ca" ]]; then
    printf 'Acquire::https::snapshot.ubuntu.com::CaInfo "%s";\n' "$ca"
  else
    printf 'Acquire::https::snapshot.ubuntu.com::Verify-Peer "false";\n'
  fi >"$dir/apt.conf.d/90bpfcompat-snapshot"
  cat >>"$dir/apt.conf.d/90bpfcompat-snapshot" <<'EOF'
Acquire::AllowInsecureRepositories "false";
Acquire::AllowDowngradeToInsecureRepositories "false";
APT::Get::AllowUnauthenticated "false";
Acquire::Retries "5";
Acquire::http::Timeout "60";
Acquire::https::Timeout "60";
Acquire::Languages "none";
EOF
}

# --render-apt-config <dir>: write the snapshot apt configuration (tests).
if [[ "${1:-}" == "--render-apt-config" ]]; then
  [[ $# -eq 2 || $# -eq 3 ]] || { echo "Usage: $0 --render-apt-config <dir> [<ca-bundle>]" >&2; exit 2; }
  validate_lock
  render_apt_config "$2" "${3:-}"
  exit 0
fi

# --check-lock: validate the lock's shape only (CI regression test).
if [[ "${1:-}" == "--check-lock" ]]; then
  validate_lock
  reproduces="$(lock_value reproduces)" ||
    { echo "build-validator-pinned: lock needs exactly one reproduces= line" >&2; exit 2; }
  [[ "$reproduces" =~ ^[0-9a-f]{40}\ [0-9a-f]{64}$ ]] ||
    { echo "build-validator-pinned: reproduces= must be '<40-hex tree> <64-hex sha256>'" >&2; exit 2; }
  echo "build-validator-pinned: lock $LOCK is well-formed"
  exit 0
fi

# --inside: runs in the builder container. /src is the read-only repo, /out the
# output directory. Installs the exact packages, verifies them, builds.
if [[ "${1:-}" == "--inside" ]]; then
  validate_lock
  export DEBIAN_FRONTEND=noninteractive
  mapfile -t pkgs < <(lock_pkgs)
  snapshot="$(lock_value apt_snapshot)"
  # Only the snapshot: drop the image's moving-archive sources.
  rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources
  rm -rf /var/lib/apt/lists/*
  if [[ -s /etc/bpfcompat-snapshot-ca.crt ]]; then
    render_apt_config /etc/apt /etc/bpfcompat-snapshot-ca.crt
    echo "tls-verified-host-ca" >/out/apt-tls.txt
  else
    render_apt_config /etc/apt
    echo "signature-only" >/out/apt-tls.txt
  fi
  updated=0
  for attempt in 1 2 3; do
    # A failed index fetch is only a warning (exit 0) without --error-on=any,
    # which would skip the retry and fail later as "Unable to locate package".
    if timeout 600 apt-get update -qq --error-on=any; then
      updated=1
      break
    fi
    echo "::warning::apt-get update from snapshot $snapshot failed (attempt $attempt of 3)" >&2
    sleep $((attempt * 10))
  done
  if [[ "$updated" -ne 1 ]]; then
    echo "::error::cannot read the noble indexes of snapshot.ubuntu.com snapshot $snapshot" >&2
    exit 1
  fi
  if ! timeout 1200 apt-get install -y -qq --no-install-recommends make "${pkgs[@]}" >/dev/null; then
    echo "::error::snapshot $snapshot cannot provide the locked package versions; fix validator/build-inputs.lock (and cut a new release candidate)" >&2
    exit 1
  fi
  : >/out/installed.txt
  for spec in "${pkgs[@]}"; do
    name="${spec%%=*}"
    want="${spec#*=}"
    have="$(dpkg-query -W -f '${Version}' "$name" 2>/dev/null || true)"
    if [[ "$have" != "$want" ]]; then
      echo "::error::builder has $name=${have:-<none>}, the lock declares $want" >&2
      exit 1
    fi
    echo "$name=$have" >>/out/installed.txt
  done
  mkdir -p /build/validator
  cp -r /src/validator/c-libbpf /build/validator/c-libbpf
  # Same recipe as `make validator-static` in the top-level Makefile.
  make -C /build/validator/c-libbpf clean all LIBBPF_LINK_MODE=static
  cp /build/validator/c-libbpf/bin/bpfcompat-validator /out/bpfcompat-validator
  exit 0
fi

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <out-binary> <out-build-inputs.json>" >&2
  exit 2
fi
out_bin="$1"
out_json="$2"
validate_lock
for tool in docker jq git sha256sum; do
  command -v "$tool" >/dev/null || { echo "build-validator-pinned: $tool is required" >&2; exit 2; }
done

image="$(lock_value builder_image)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The runner's CA bundle (read-only) lets apt verify TLS to snapshot.ubuntu.com.
# BPFCOMPAT_SNAPSHOT_CA_BUNDLE overrides the path; empty or missing falls back
# to signature-only verification (see render_apt_config), recorded as apt_tls.
ca_bundle="${BPFCOMPAT_SNAPSHOT_CA_BUNDLE-/etc/ssl/certs/ca-certificates.crt}"
ca_mount=()
if [[ -n "$ca_bundle" && -s "$ca_bundle" && -r "$ca_bundle" ]]; then
  ca_mount=(-v "$(readlink -f "$ca_bundle"):/etc/bpfcompat-snapshot-ca.crt:ro")
else
  echo "::notice::no CA bundle at '${ca_bundle}'; snapshot TLS is unverified, integrity rests on apt's signature check"
fi

docker run --rm --pull=missing "${ca_mount[@]}" \
  -v "$ROOT:/src:ro" -v "$work:/out" -v "$(cd "$(dirname "$LOCK")" && pwd)/$(basename "$LOCK"):/build-inputs.lock:ro" \
  -e BPFCOMPAT_VALIDATOR_LOCK=/build-inputs.lock \
  "$image" bash /src/scripts/build-validator-pinned.sh --inside

bash "$ROOT/scripts/check-validator-build-inputs.sh" "$work/bpfcompat-validator" "$LOCK"

sha="$(sha256sum "$work/bpfcompat-validator" | awk '{print $1}')"
tree="$(git -C "$ROOT" rev-parse HEAD:validator/c-libbpf)"
dirty="$(git -C "$ROOT" status --porcelain -- validator/c-libbpf)"
reproduces="$(lock_value reproduces || true)"
known_tree="${reproduces%% *}"
known_sha="${reproduces##* }"
reproduction="unrecorded"
if [[ -n "$reproduces" && -z "$dirty" && "$tree" == "$known_tree" ]]; then
  if [[ "$sha" == "$known_sha" ]]; then
    reproduction="byte-identical"
    echo "validator: byte-identical to the recorded build of tree $tree ($sha)"
  else
    echo "::error::validator tree $tree is the recorded one but built $sha, not the recorded $known_sha; a build input drifted" >&2
    exit 1
  fi
else
  echo "::notice::validator tree $tree${dirty:+ (modified)} has no recorded reproduction; built $sha. Record it on the lock's reproduces= line with the next release candidate."
fi

mkdir -p "$(dirname "$out_bin")" "$(dirname "$out_json")"
cp "$work/bpfcompat-validator" "$out_bin"
jq -n \
  --arg image "$image" \
  --arg snapshot "$(lock_value apt_snapshot)" \
  --arg tree "$tree" \
  --arg sha "$sha" \
  --arg reproduction "$reproduction" \
  --arg apt_tls "$(tr -d '\n' <"$work/apt-tls.txt")" \
  --arg lock_sha "$(sha256sum "$LOCK" | awk '{print $1}')" \
  --rawfile installed "$work/installed.txt" '
  {
    schema_version: "v0.1",
    artifact: "bpfcompat-validator-static-linux-amd64",
    sha256: $sha,
    validator_tree: $tree,
    builder_image: $image,
    apt_snapshot: $snapshot,
    build_inputs_lock_sha256: $lock_sha,
    packages: ($installed | split("\n") | map(select(length > 0))),
    reproduction: $reproduction,
    apt_tls: $apt_tls
  }' >"$out_json"
echo "validator: $out_bin ($sha), inputs recorded in $out_json"
