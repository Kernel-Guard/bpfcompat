#!/bin/sh
# bpfcompat one-command installer.
#
#   curl -fsSL https://raw.githubusercontent.com/Kernel-Guard/bpfcompat/main/scripts/install.sh | sh
#
# Downloads the prebuilt bpfcompat CLI and its static guest validator from the
# GitHub release, verifies both against the release SHA256SUMS and either its
# Sigstore signature or GitHub build attestation, and installs them. The
# validator goes to a location the CLI discovers automatically, so
# `bpfcompat test` works from any directory.
#
# Environment overrides:
#   BPFCOMPAT_VERSION      release tag to install (default: latest)
#   BPFCOMPAT_BIN_DIR      CLI install dir       (default: /usr/local/bin)
#   BPFCOMPAT_LIBEXEC_DIR  validator install dir (default: /usr/local/libexec/bpfcompat)
#   BPFCOMPAT_NO_VALIDATOR set to 1 to install the CLI only
#
# Linux CLI assets are published for x86_64 and arm64. The static validator is
# currently published for x86_64 only.
set -eu

REPO="Kernel-Guard/bpfcompat"
BIN_DIR="${BPFCOMPAT_BIN_DIR:-/usr/local/bin}"
LIBEXEC_DIR="${BPFCOMPAT_LIBEXEC_DIR:-/usr/local/libexec/bpfcompat}"

err() { printf 'bpfcompat-install: %s\n' "$*" >&2; }
die() { err "$*"; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

have curl || die "curl is required"
if have sha256sum; then SHACHK="sha256sum -c"; elif have shasum; then SHACHK="shasum -a 256 -c"; else
  die "need sha256sum or shasum to verify downloads"
fi

os="$(uname -s)"; arch="$(uname -m)"
[ "$os" = "Linux" ] || die "unsupported OS '$os' (only Linux is published today)"
case "$arch" in
  x86_64|amd64) GOARCH=amd64; QEMU_ARCH=x86_64 ;;
  aarch64|arm64) GOARCH=arm64; QEMU_ARCH=aarch64 ;;
  *) die "unsupported arch '$arch' (published: x86_64, arm64; build from source: https://github.com/$REPO)";;
esac
CLI_ASSET="bpfcompat-linux-$GOARCH"
VALIDATOR_ASSET="bpfcompat-validator-static-linux-$GOARCH"

VERSION="${BPFCOMPAT_VERSION:-latest}"
if [ "$VERSION" = "latest" ]; then
  VERSION="$(curl -fsSL --retry 2 --connect-timeout 10 --max-time 60 \
    "https://api.github.com/repos/$REPO/releases/latest" \
    | grep '"tag_name"' | head -1 | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"
  [ -n "$VERSION" ] || die "could not resolve the latest release tag"
fi
base="https://github.com/$REPO/releases/download/$VERSION"
err "installing bpfcompat $VERSION (linux/$GOARCH)"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"

DL_FILES="$CLI_ASSET"
curl -fsSLO --retry 2 --connect-timeout 10 --max-time 300 \
  "$base/$CLI_ASSET" || die "download failed: $CLI_ASSET ($VERSION)"
curl -fsSLO --retry 2 --connect-timeout 10 --max-time 300 \
  "$base/SHA256SUMS" || die "download failed: SHA256SUMS ($VERSION)"
install_validator=1
[ "${BPFCOMPAT_NO_VALIDATOR:-0}" = "1" ] && install_validator=0
# The static C validator is published for amd64 only today. If this release has
# no validator for the current arch, install the CLI without it rather than
# failing - VM artifact validation then needs `make validator-static` locally or
# command mode. (SHA256SUMS is integrity-checked below regardless.)
if [ "$install_validator" = "1" ]; then
  if grep -qE "^[0-9a-fA-F]{64}  ${VALIDATOR_ASSET}\$" SHA256SUMS; then
    curl -fsSLO --retry 2 --connect-timeout 10 --max-time 300 \
      "$base/$VALIDATOR_ASSET" || die "download failed: $VALIDATOR_ASSET ($VERSION)"
    DL_FILES="$DL_FILES $VALIDATOR_ASSET"
  else
    install_validator=0
    err "note: no prebuilt validator for $GOARCH in $VERSION - installing the CLI only."
    err "      artifact-mode VM validation needs the validator: build it with"
    err "      'make validator-static' on an $GOARCH host, or use command mode."
  fi
fi

# 1. Cryptographic verification first. Checksums come from the same origin as
#    the binaries, so they catch corruption but not a malicious mirror; the
#    Sigstore signature over SHA256SUMS or GitHub's build attestation is what
#    makes tampering detectable. Verification is mandatory.
if have cosign; then
  curl -fsSLO --retry 2 --connect-timeout 10 --max-time 300 \
    "$base/SHA256SUMS.sig" || die "cannot fetch SHA256SUMS.sig for signature verification"
  curl -fsSLO --retry 2 --connect-timeout 10 --max-time 300 \
    "$base/SHA256SUMS.crt" || die "cannot fetch SHA256SUMS.crt for signature verification"
  if cosign verify-blob --certificate SHA256SUMS.crt --signature SHA256SUMS.sig \
      --certificate-identity-regexp "^https://github.com/$REPO/.github/workflows/release-artifacts.yml@refs/tags/v" \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      SHA256SUMS >/dev/null 2>&1; then
    err "cosign signature over SHA256SUMS verified"
  else
    die "cosign signature verification FAILED for SHA256SUMS - refusing to install"
  fi
elif have gh && gh attestation --help >/dev/null 2>&1; then
  err "cosign not found; verifying GitHub build attestations"
  GH_REPO="$REPO" gh attestation verify "$CLI_ASSET" --repo "$REPO" \
    --signer-workflow "$REPO/.github/workflows/release-artifacts.yml" >/dev/null 2>&1 ||
    die "GitHub attestation verification FAILED for $CLI_ASSET"
  if [ "$install_validator" = "1" ]; then
    GH_REPO="$REPO" gh attestation verify "$VALIDATOR_ASSET" --repo "$REPO" \
      --signer-workflow "$REPO/.github/workflows/release-artifacts.yml" >/dev/null 2>&1 ||
      die "GitHub attestation verification FAILED for $VALIDATOR_ASSET"
  fi
  err "GitHub build attestations verified"
else
  die "cryptographic verification requires cosign or GitHub CLI (gh); refusing checksum-only installation"
fi

# 2. Strict checksum check, scoped to exactly the files being installed. Every
#    required file must have a matching entry in SHA256SUMS or we abort - no
#    --ignore-missing, no error suppression, no silent pass.
err "verifying checksums"
: > .install-checklist
for f in $DL_FILES; do
  line="$(grep -E "^[0-9a-fA-F]{64}  ${f}\$" SHA256SUMS || true)"
  [ -n "$line" ] || die "no SHA256SUMS entry for '$f' - refusing to install"
  printf '%s\n' "$line" >> .install-checklist
done
$SHACHK .install-checklist >/dev/null || die "checksum verification failed for: $DL_FILES"
err "checksums verified: $DL_FILES"

# Install, using sudo only when the target dirs are not writable.
SUDO=""
if [ ! -w "$(dirname "$BIN_DIR")" ] || { [ -d "$BIN_DIR" ] && [ ! -w "$BIN_DIR" ]; }; then
  if have sudo; then
    SUDO="sudo"
  else
    die "no write access to $BIN_DIR and sudo not available (set BPFCOMPAT_BIN_DIR to a writable path)"
  fi
fi

$SUDO install -d "$BIN_DIR"
$SUDO install -m 0755 "$CLI_ASSET" "$BIN_DIR/bpfcompat"
err "installed $BIN_DIR/bpfcompat"

if [ "$install_validator" = "1" ]; then
  $SUDO install -d "$LIBEXEC_DIR"
  $SUDO install -m 0755 "$VALIDATOR_ASSET" "$LIBEXEC_DIR/bpfcompat-validator"
  err "installed $LIBEXEC_DIR/bpfcompat-validator (auto-discovered by 'bpfcompat test')"
fi

printf '\n'
"$BIN_DIR/bpfcompat" version || true
printf '\nNext:\n'
printf '  bpfcompat test --artifact <your.bpf.o> --quick        # needs a KVM-capable Linux host (qemu-system-%s)\n' "$QEMU_ARCH"
printf '  bpfcompat test --artifact ghcr.io/org/gadget:tag --quick   # validate a published OCI gadget\n'
printf 'Docs: https://github.com/%s\n' "$REPO"
