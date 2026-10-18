#!/bin/sh
# bpfcompat one-command installer.
#
#   curl -fsSL https://raw.githubusercontent.com/Kernel-Guard/bpfcompat/main/scripts/install.sh | sh
#
# Downloads the prebuilt bpfcompat CLI and its static guest validator from the
# GitHub release, verifies both against the release SHA256SUMS and either its
# Sigstore signature or GitHub build attestation, and installs them. The
# validator goes to a location the CLI discovers automatically, so
# `bpfcompat test` works from any directory. When the release publishes a
# third-party license bundle (listed in its SHA256SUMS), it is verified the
# same way and its texts are installed under the documentation directory.
#
# Environment overrides:
#   BPFCOMPAT_VERSION      release tag to install (default: latest)
#   BPFCOMPAT_BIN_DIR      CLI install dir       (default: /usr/local/bin)
#   BPFCOMPAT_LIBEXEC_DIR  validator install dir (default: /usr/local/libexec/bpfcompat;
#                          any other dir needs BPFCOMPAT_VALIDATOR_BIN at run time)
#   BPFCOMPAT_NO_VALIDATOR set to 1 to install the CLI only
#   BPFCOMPAT_DOC_DIR      license texts dir     (default: <BIN_DIR>/../share/doc/bpfcompat;
#                          the bundle goes to <DOC_DIR>/<tag>/)
#
# Linux CLI assets are published for x86_64 and arm64. The static validator is
# currently published for x86_64 only.
#
# The whole installer is the body of main(), called on the last line, so a
# download cut short by `curl | sh` runs nothing instead of half an install.
set -eu

REPO="Kernel-Guard/bpfcompat"
# The locations resolveValidatorBinary() (internal/runner) searches by itself.
DEFAULT_LIBEXEC_DIR="/usr/local/libexec/bpfcompat"
ALT_LIBEXEC_DIR="/usr/libexec/bpfcompat"

err() { printf 'bpfcompat-install: %s\n' "$*" >&2; }
die() { err "$*"; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# needs_root DIR: true when DIR (or, if it does not exist yet, its nearest
# existing ancestor, which `install -d` would create it under) is not writable.
needs_root() {
  d="$1"
  while [ ! -d "$d" ]; do
    parent="$(dirname "$d")"
    [ "$parent" != "$d" ] || break
    d="$parent"
  done
  [ ! -w "$d" ]
}

main() {
BIN_DIR="${BPFCOMPAT_BIN_DIR:-/usr/local/bin}"
LIBEXEC_DIR="${BPFCOMPAT_LIBEXEC_DIR:-$DEFAULT_LIBEXEC_DIR}"
DOC_DIR="${BPFCOMPAT_DOC_DIR:-$(dirname "$BIN_DIR")/share/doc/bpfcompat}"
LICENSE_ASSET="bpfcompat-third-party-licenses.tar.gz"

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
# The tag is spliced into download URLs and into the exact signing identity
# below, so it must be a plain release tag (no path segments, no regex). grep
# matches line by line, so first reject any character a tag cannot hold (a
# newline included): the whole value is checked, not just one of its lines.
case "$VERSION" in
  *[!0123456789.crv-]*) die "invalid release tag '$VERSION' (expected vX.Y.Z or vX.Y.Z-rc.N)" ;;
esac
printf '%s\n' "$VERSION" | grep -Eqx 'v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?' ||
  die "invalid release tag '$VERSION' (expected vX.Y.Z or vX.Y.Z-rc.N)"
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
#    makes tampering detectable. Verification is mandatory, and it is bound to
#    the requested tag: a signature or attestation produced by the release run
#    of a different tag (say, a prerelease) does not vouch for $VERSION.
# Releases built with the distribution bundle list it in SHA256SUMS; older ones do not.
# A bundle listed in SHA256SUMS is required and verified like the binaries.
install_licenses=0
if grep -qE "^[0-9a-fA-F]{64}  ${LICENSE_ASSET}\$" SHA256SUMS; then
  curl -fsSLO --retry 2 --connect-timeout 10 --max-time 300 \
    "$base/$LICENSE_ASSET" || die "download failed: $LICENSE_ASSET ($VERSION)"
  DL_FILES="$DL_FILES $LICENSE_ASSET"
  install_licenses=1
else
  err "note: $VERSION publishes no third-party license bundle; see LICENSE, NOTICE and"
  err "      THIRD_PARTY_NOTICES.md at https://github.com/$REPO/tree/$VERSION"
fi

if have cosign; then
  curl -fsSLO --retry 2 --connect-timeout 10 --max-time 300 \
    "$base/SHA256SUMS.sig" || die "cannot fetch SHA256SUMS.sig for signature verification"
  curl -fsSLO --retry 2 --connect-timeout 10 --max-time 300 \
    "$base/SHA256SUMS.crt" || die "cannot fetch SHA256SUMS.crt for signature verification"
  if cosign verify-blob --certificate SHA256SUMS.crt --signature SHA256SUMS.sig \
      --certificate-identity "https://github.com/$REPO/.github/workflows/release-artifacts.yml@refs/tags/$VERSION" \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      SHA256SUMS >/dev/null 2>&1; then
    err "cosign signature over SHA256SUMS verified"
  else
    die "cosign signature verification FAILED for SHA256SUMS - refusing to install"
  fi
elif have gh; then
  # The tag-bound check below needs `gh attestation` (gh 2.49.0),
  # --signer-workflow (2.51.0) and --source-ref (2.68.0). An older gh would
  # fail it like a forged release would, so ask gh's own help what it offers
  # (not its version: distro builds vary) and name what is missing instead.
  gh_lacks=""
  if ! gh attestation --help >/dev/null 2>&1; then
    gh_lacks="the 'gh attestation' command"
  else
    gh_help="$(gh attestation verify --help 2>&1 || true)"
    for flag in --signer-workflow --source-ref; do
      printf '%s\n' "$gh_help" | grep -Eq -- "(^|[^[:alnum:]-])$flag([^[:alnum:]-]|\$)" ||
        gh_lacks="${gh_lacks:+$gh_lacks and }$flag"
    done
    [ -z "$gh_lacks" ] || gh_lacks="$gh_lacks in 'gh attestation verify'"
  fi
  if [ -n "$gh_lacks" ]; then
    gh_ver="$(gh --version 2>/dev/null | sed -n '1s/^gh version \([0-9][0-9.]*\).*/\1/p')"
    die "installed gh${gh_ver:+ $gh_ver} lacks $gh_lacks, needed for tag-bound attestation verification; upgrade to gh >= 2.68.0 or install cosign - refusing checksum-only installation"
  fi
  err "cosign not found; verifying GitHub build attestations"
  GH_REPO="$REPO" gh attestation verify "$CLI_ASSET" --repo "$REPO" \
    --signer-workflow "$REPO/.github/workflows/release-artifacts.yml" \
    --source-ref "refs/tags/$VERSION" >/dev/null 2>&1 ||
    die "GitHub attestation verification FAILED for $CLI_ASSET"
  if [ "$install_validator" = "1" ]; then
    GH_REPO="$REPO" gh attestation verify "$VALIDATOR_ASSET" --repo "$REPO" \
      --signer-workflow "$REPO/.github/workflows/release-artifacts.yml" \
      --source-ref "refs/tags/$VERSION" >/dev/null 2>&1 ||
      die "GitHub attestation verification FAILED for $VALIDATOR_ASSET"
  fi
  if [ "$install_licenses" = "1" ]; then
    GH_REPO="$REPO" gh attestation verify "$LICENSE_ASSET" --repo "$REPO" \
      --signer-workflow "$REPO/.github/workflows/release-artifacts.yml" \
      --source-ref "refs/tags/$VERSION" >/dev/null 2>&1 ||
      die "GitHub attestation verification FAILED for $LICENSE_ASSET"
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

# Install, using sudo only for the target dirs that are not writable. Both
# dirs are checked before anything is installed, so a missing permission
# cannot leave the CLI installed without its validator.
BIN_SUDO=""
if needs_root "$BIN_DIR"; then
  have sudo || die "no write access to $BIN_DIR and sudo not available (set BPFCOMPAT_BIN_DIR to a writable path)"
  BIN_SUDO="sudo"
fi
DOC_SUDO=""
if [ "$install_licenses" = "1" ] && needs_root "$DOC_DIR"; then
  have sudo || die "no write access to $DOC_DIR and sudo not available (set BPFCOMPAT_DOC_DIR to a writable path)"
  DOC_SUDO="sudo"
fi
LIBEXEC_SUDO=""
if [ "$install_validator" = "1" ] && needs_root "$LIBEXEC_DIR"; then
  have sudo || die "no write access to $LIBEXEC_DIR and sudo not available (set BPFCOMPAT_LIBEXEC_DIR to a writable path, or BPFCOMPAT_NO_VALIDATOR=1)"
  LIBEXEC_SUDO="sudo"
fi

$BIN_SUDO install -d "$BIN_DIR"
if [ "$install_validator" = "1" ]; then
  $LIBEXEC_SUDO install -d "$LIBEXEC_DIR"
fi
$BIN_SUDO install -m 0755 "$CLI_ASSET" "$BIN_DIR/bpfcompat"
err "installed $BIN_DIR/bpfcompat"

if [ "$install_validator" = "1" ]; then
  $LIBEXEC_SUDO install -m 0755 "$VALIDATOR_ASSET" "$LIBEXEC_DIR/bpfcompat-validator"
  case "$LIBEXEC_DIR" in
    "$DEFAULT_LIBEXEC_DIR"|"$ALT_LIBEXEC_DIR")
      err "installed $LIBEXEC_DIR/bpfcompat-validator (auto-discovered by 'bpfcompat test')" ;;
    *)
      err "installed $LIBEXEC_DIR/bpfcompat-validator"
      err "note: 'bpfcompat test' does not search $LIBEXEC_DIR; set"
      err "      export BPFCOMPAT_VALIDATOR_BIN=$LIBEXEC_DIR/bpfcompat-validator" ;;
  esac
fi

if [ "$install_licenses" = "1" ]; then
  lic_dir="$DOC_DIR/$VERSION"
  $DOC_SUDO install -d "$lic_dir"
  if have tar && have gzip; then
    mkdir licenses
    tar -xzf "$LICENSE_ASSET" -C licenses || die "cannot unpack $LICENSE_ASSET"
    [ -f licenses/bpfcompat-third-party-licenses/INVENTORY.json ] ||
      die "$LICENSE_ASSET does not have the expected layout"
    $DOC_SUDO cp -R licenses/bpfcompat-third-party-licenses/. "$lic_dir/"
  else
    $DOC_SUDO install -m 0644 "$LICENSE_ASSET" "$lic_dir/$LICENSE_ASSET"
    err "note: tar/gzip not found; installed the license bundle as its unextracted archive"
  fi
  err "installed third-party license texts in $lic_dir"
fi

printf '\n'
"$BIN_DIR/bpfcompat" version || true
printf '\nNext:\n'
printf '  bpfcompat test --artifact <your.bpf.o> --quick        # needs a KVM-capable Linux host (qemu-system-%s)\n' "$QEMU_ARCH"
printf '  bpfcompat test --artifact ghcr.io/org/gadget:tag --quick   # validate a published OCI gadget\n'
printf 'Docs: https://github.com/%s\n' "$REPO"
}

main "$@"
