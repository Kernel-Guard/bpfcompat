#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

OUT_DIR="${1:-dist/research-corpus-v1}"
BPF_SOURCE_REV="b8ef57f4e02ebecee4649f7657ea8eea6af46ca9"
FALCO_SOURCE_REV="1800b330ce92b532456178abfcbfba3dd157f974"
CILIUM_SOURCE_REV="f035193453c32429bc2f6b6d623c4dfa200ad48f"
BPFCOMPAT_RELEASE="v0.3.7"
BPFCOMPAT_EXEC_REV="179ff612ed2b5d1afb16dd9c282752028d47c415"
BPFCOMPAT_CLI_SHA="1365337098474dc0a42484271ee6383d46cb1cd20da09d248f9a0063c5147f0e"
BPFCOMPAT_VALIDATOR_SHA="4ae1d5b838be07e6e7c304d753389a239c19eb92f6ba3bd77657e5c9583b9d04"
EXPECTED_GO="go1.25.14"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[research-materialize] missing required tool: $1" >&2
    exit 1
  }
}

for tool in git clang go cmake make curl tar jq sha256sum file; do
  need "$tool"
done

actual_go="$(go env GOVERSION)"
if [[ "$actual_go" != "$EXPECTED_GO" ]]; then
  echo "[research-materialize] expected $EXPECTED_GO, got $actual_go" >&2
  echo "Use the pinned workflow or install the exact Go toolchain." >&2
  exit 1
fi

if [[ "$(uname -m)" != "x86_64" ]]; then
  echo "[research-materialize] v1 is frozen to x86_64; got $(uname -m)" >&2
  exit 1
fi

for invariant in   "$BPF_SOURCE_REV"   "$FALCO_SOURCE_REV"   "$CILIUM_SOURCE_REV"   "$BPFCOMPAT_EXEC_REV"   "$BPFCOMPAT_CLI_SHA"   "$BPFCOMPAT_VALIDATOR_SHA"; do
  grep -R -Fq "$invariant" research/corpus/v1 || {
    echo "[research-materialize] frozen selection no longer contains invariant $invariant" >&2
    exit 1
  }
done

rm -rf "$OUT_DIR"
mkdir -p   "$OUT_DIR/artifacts"   "$OUT_DIR/loaders"   "$OUT_DIR/bin"   "$OUT_DIR/contracts"   "$OUT_DIR/inputs/manifests"   "$OUT_DIR/licenses"   "$OUT_DIR/toolchain"

TMP_DIR="$ROOT_DIR/.bpfcompat/research-materialize-v1"
BPF_WORKTREE="$TMP_DIR/bpfcompat-source"
FALCO_DIR="$TMP_DIR/falco-libs"

# Stable build paths remove one source of debug/build-id drift. Clean up an
# interrupted prior worktree before reusing the canonical scratch location.
git worktree prune
if git worktree list --porcelain | grep -Fq "worktree $BPF_WORKTREE"; then
  git worktree remove --force "$BPF_WORKTREE" >/dev/null 2>&1 || true
fi
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"

cleanup() {
  if git worktree list --porcelain | grep -Fq "worktree $BPF_WORKTREE"; then
    git worktree remove --force "$BPF_WORKTREE" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

if ! git cat-file -e "$BPF_SOURCE_REV^{commit}" 2>/dev/null; then
  git fetch --no-tags origin "$BPF_SOURCE_REV"
fi
git worktree add --detach "$BPF_WORKTREE" "$BPF_SOURCE_REV" >/dev/null

echo "[research-materialize] building frozen BPFCompat-derived objects"
COMMON_CLANG=(
  -O2 -g -target bpf -D__TARGET_ARCH_x86
  -I/usr/include/x86_64-linux-gnu
  -fdebug-compilation-dir=/src/bpfcompat
  "-fdebug-prefix-map=$BPF_WORKTREE=/src/bpfcompat"
  "-ffile-prefix-map=$BPF_WORKTREE=/src/bpfcompat"
  "-fmacro-prefix-map=$BPF_WORKTREE=/src/bpfcompat"
)

clang "${COMMON_CLANG[@]}"   -c "$BPF_WORKTREE/examples/simple-pass/simple_pass.bpf.c"   -o "$OUT_DIR/artifacts/simple_pass.bpf.o"

clang "${COMMON_CLANG[@]}"   -c "$BPF_WORKTREE/examples/ringbuf-modern/ringbuf_modern.bpf.c"   -o "$OUT_DIR/artifacts/ringbuf_modern.bpf.o"

clang "${COMMON_CLANG[@]}"   -c "$BPF_WORKTREE/examples/perfbuf-fallback/perfbuf_fallback.bpf.c"   -o "$OUT_DIR/artifacts/perfbuf_fallback.bpf.o"

clang "${COMMON_CLANG[@]}"   -c "$BPF_WORKTREE/examples/core-relocation-fail/core_relocation_fail.bpf.c"   -o "$OUT_DIR/artifacts/core_relocation_fail.bpf.o"

clang "${COMMON_CLANG[@]}"   -c "$BPF_WORKTREE/examples/oss/cilium-tracepoint-in-c/tracepoint.bpf.c"   -o "$OUT_DIR/artifacts/cilium_tracepoint_in_c.bpf.o"

cp "$BPF_WORKTREE/examples/simple-pass/manifest.yaml"   "$OUT_DIR/inputs/manifests/simple-pass.yaml"
cp "$BPF_WORKTREE/examples/ringbuf-modern/manifest.yaml"   "$OUT_DIR/inputs/manifests/ringbuf-modern.yaml"
cp "$BPF_WORKTREE/examples/perfbuf-fallback/manifest.yaml"   "$OUT_DIR/inputs/manifests/perfbuf-fallback.yaml"
cp "$BPF_WORKTREE/examples/core-relocation-fail/manifest.yaml"   "$OUT_DIR/inputs/manifests/core-relocation-fail.yaml"
cp "$BPF_WORKTREE/examples/oss/cilium-tracepoint-in-c/manifest.yaml"   "$OUT_DIR/inputs/manifests/cilium-tracepoint-in-c.yaml"
cp "$BPF_WORKTREE/LICENSE" "$OUT_DIR/licenses/BPFCompat-LICENSE"

echo "[research-materialize] building pinned cilium/ebpf loader"
(
  cd "$BPF_WORKTREE/examples/ebpf-go-loader"
  CGO_ENABLED=0 go build -trimpath -buildvcs=false \
    -o "$ROOT_DIR/$OUT_DIR/loaders/ebpf-go-loader" .
)

echo "[research-materialize] downloading pinned BPFCompat execution binaries"
curl -fsSL   "https://github.com/Kernel-Guard/bpfcompat/releases/download/$BPFCOMPAT_RELEASE/bpfcompat-linux-amd64"   -o "$OUT_DIR/bin/bpfcompat-linux-amd64"
curl -fsSL   "https://github.com/Kernel-Guard/bpfcompat/releases/download/$BPFCOMPAT_RELEASE/bpfcompat-validator-static-linux-amd64"   -o "$OUT_DIR/bin/bpfcompat-validator-static-linux-amd64"
chmod +x   "$OUT_DIR/bin/bpfcompat-linux-amd64"   "$OUT_DIR/bin/bpfcompat-validator-static-linux-amd64"

actual_cli_sha="$(sha256sum "$OUT_DIR/bin/bpfcompat-linux-amd64" | awk '{print $1}')"
actual_validator_sha="$(sha256sum "$OUT_DIR/bin/bpfcompat-validator-static-linux-amd64" | awk '{print $1}')"
[[ "$actual_cli_sha" == "$BPFCOMPAT_CLI_SHA" ]] || {
  echo "[research-materialize] BPFCompat CLI checksum mismatch" >&2
  exit 1
}
[[ "$actual_validator_sha" == "$BPFCOMPAT_VALIDATOR_SHA" ]] || {
  echo "[research-materialize] validator checksum mismatch" >&2
  exit 1
}

echo "[research-materialize] fetching pinned Falco source"
git init -q "$FALCO_DIR"
git -C "$FALCO_DIR" remote add origin https://github.com/falcosecurity/libs.git
git -C "$FALCO_DIR" fetch -q --depth=1 origin "$FALCO_SOURCE_REV"
git -C "$FALCO_DIR" checkout -q --detach FETCH_HEAD
[[ "$(git -C "$FALCO_DIR" rev-parse HEAD)" == "$FALCO_SOURCE_REV" ]] || {
  echo "[research-materialize] Falco revision mismatch" >&2
  exit 1
}

need bpftool

echo "[research-materialize] building pinned Falco scap-open"
mkdir -p "$FALCO_DIR/build"
(
  cd "$FALCO_DIR/build"
  export SOURCE_DATE_EPOCH
  SOURCE_DATE_EPOCH="$(git -C "$FALCO_DIR" show -s --format=%ct HEAD)"
  prefix_flags="-ffile-prefix-map=$ROOT_DIR=/workspace/bpfcompat -fdebug-prefix-map=$ROOT_DIR=/workspace/bpfcompat"
  export CFLAGS="${CFLAGS:-} $prefix_flags"
  export CXXFLAGS="${CXXFLAGS:-} $prefix_flags"
  cmake     -DUSE_BUNDLED_DEPS=ON     -DBUILD_LIBSCAP_MODERN_BPF=ON     -DMUSL_OPTIMIZED_BUILD=ON     -DMODERN_BPFTOOL_EXE="$(command -v bpftool)"     -DCREATE_TEST_TARGETS=OFF     -DBUILD_BPF=OFF     -DBUILD_DRIVER=OFF     ..
  make scap-open -j"$(nproc)"
)
cp "$FALCO_DIR/build/libscap/examples/01-open/scap-open"   "$OUT_DIR/loaders/scap-open"
chmod +x "$OUT_DIR/loaders/scap-open"
cp "$FALCO_DIR/LICENSE" "$OUT_DIR/licenses/Falco-libs-LICENSE"
cp "$FALCO_DIR/NOTICES" "$OUT_DIR/licenses/Falco-libs-NOTICES"

curl -fsSL   "https://raw.githubusercontent.com/cilium/ebpf/$CILIUM_SOURCE_REV/LICENSE"   -o "$OUT_DIR/licenses/Cilium-ebpf-LICENSE"

echo "[research-materialize] recording toolchain"
{
  echo "uname:"
  uname -a
  echo
  echo "go:"
  go version
  echo
  echo "clang:"
  clang --version
  echo
  echo "cmake:"
  cmake --version
  echo
  echo "bpftool:"
  bpftool version
  echo
  echo "git:"
  git --version
  echo
  echo "file outputs:"
  file     "$OUT_DIR/artifacts/"*.bpf.o     "$OUT_DIR/loaders/ebpf-go-loader"     "$OUT_DIR/loaders/scap-open"     "$OUT_DIR/bin/bpfcompat-linux-amd64"     "$OUT_DIR/bin/bpfcompat-validator-static-linux-amd64"
} > "$OUT_DIR/toolchain/versions.txt"

if command -v dpkg-query >/dev/null 2>&1; then
  dpkg-query -W     clang llvm libbpf-dev libelf-dev zlib1g-dev cmake build-essential     pkg-config autoconf automake libtool     > "$OUT_DIR/toolchain/dpkg-packages.txt" 2>/dev/null || true
fi

bpftool_path="$(command -v bpftool)"
bpftool_sha="$(sha256sum "$bpftool_path" | awk '{print $1}')"
clang_version="$(clang --version | head -1)"
cmake_version="$(cmake --version | head -1)"
go_version="$(go version)"
materializer_commit="$(git rev-parse HEAD)"
generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

sha_of() {
  sha256sum "$1" | awk '{print $1}'
}

simple_sha="$(sha_of "$OUT_DIR/artifacts/simple_pass.bpf.o")"
ringbuf_sha="$(sha_of "$OUT_DIR/artifacts/ringbuf_modern.bpf.o")"
perfbuf_sha="$(sha_of "$OUT_DIR/artifacts/perfbuf_fallback.bpf.o")"
core_sha="$(sha_of "$OUT_DIR/artifacts/core_relocation_fail.bpf.o")"
cilium_obj_sha="$(sha_of "$OUT_DIR/artifacts/cilium_tracepoint_in_c.bpf.o")"
ebpf_go_loader_sha="$(sha_of "$OUT_DIR/loaders/ebpf-go-loader")"
scap_open_sha="$(sha_of "$OUT_DIR/loaders/scap-open")"

contract_id() {
  local key="$1"
  local payload="$2"
  local canonical hash
  canonical="$(jq -cS . <<<"$payload")"
  printf '%s' "$canonical" > "$OUT_DIR/contracts/${key}.canonical.json"
  hash="$(printf '%s' "$canonical" | sha256sum | awk '{print $1}')"
  jq -S --arg id "sha256:$hash" '. + {id: $id}' <<<"$canonical"     > "$OUT_DIR/contracts/${key}.json"
  printf 'sha256:%s' "$hash"
}

libbpf_attach_id="$(contract_id "libbpf-v037-load-attach-v1" "$(
  jq -nc     --arg commit "$BPFCOMPAT_EXEC_REV"     --arg validator "sha256:$BPFCOMPAT_VALIDATOR_SHA"     '{
      kind:"builtin_validator",
      mode:"load_attach",
      implementation:{
        bpfcompat_commit:$commit,
        validator_sha256:$validator
      },
      success_criteria:{
        required_load:"pass",
        required_attach:"pass",
        infrastructure_errors_are_compatibility_failures:false
      }
    }'
)")"

libbpf_load_id="$(contract_id "libbpf-v037-load-only-v1" "$(
  jq -nc     --arg commit "$BPFCOMPAT_EXEC_REV"     --arg validator "sha256:$BPFCOMPAT_VALIDATOR_SHA"     '{
      kind:"builtin_validator",
      mode:"load_only",
      implementation:{
        bpfcompat_commit:$commit,
        validator_sha256:$validator
      },
      success_criteria:{
        required_load:"pass",
        infrastructure_errors_are_compatibility_failures:false
      }
    }'
)")"

cilium_loader_id="$(contract_id "cilium-ebpf-v022-load-only-v1" "$(
  jq -nc     --arg source_revision "$BPF_SOURCE_REV"     --arg loader "sha256:$ebpf_go_loader_sha"     '{
      kind:"project_loader",
      mode:"command",
      loader:{
        source_revision:$source_revision,
        dependency:"github.com/cilium/ebpf@v0.22.0",
        binary_sha256:$loader
      },
      command:"$BPFCOMPAT_BIN $BPFCOMPAT_ARTIFACT",
      expected_exit_codes:[0],
      semantics:"load every map and program through cilium/ebpf; no attach claim"
    }'
)")"

falco_loader_id="$(contract_id "falco-modern-bpf-scap-open-v1" "$(
  jq -nc     --arg source_revision "$FALCO_SOURCE_REV"     --arg loader "sha256:$scap_open_sha"     '{
      kind:"project_loader",
      mode:"command",
      loader:{
        source_revision:$source_revision,
        binary_sha256:$loader
      },
      command:"$BPFCOMPAT_BIN --modern_bpf --num_events 10",
      expected_exit_codes:[0],
      semantics:"real Falco modern_bpf loader path plus bounded event capture"
    }'
)")"

jq -n   --arg generated_at "$generated_at"   --arg materializer_commit "$materializer_commit"   --arg bpf_source_revision "$BPF_SOURCE_REV"   --arg falco_source_revision "$FALCO_SOURCE_REV"   --arg cilium_source_revision "$CILIUM_SOURCE_REV"   --arg bpfcompat_execution_revision "$BPFCOMPAT_EXEC_REV"   --arg go_version "$go_version"   --arg clang_version "$clang_version"   --arg cmake_version "$cmake_version"   --arg bpftool_path "$bpftool_path"   --arg bpftool_sha256 "sha256:$bpftool_sha"   --arg simple_sha "sha256:$simple_sha"   --arg ringbuf_sha "sha256:$ringbuf_sha"   --arg perfbuf_sha "sha256:$perfbuf_sha"   --arg core_sha "sha256:$core_sha"   --arg cilium_obj_sha "sha256:$cilium_obj_sha"   --arg ebpf_go_loader_sha "sha256:$ebpf_go_loader_sha"   --arg scap_open_sha "sha256:$scap_open_sha"   --arg cli_sha "sha256:$actual_cli_sha"   --arg validator_sha "sha256:$actual_validator_sha"   --arg libbpf_attach_id "$libbpf_attach_id"   --arg libbpf_load_id "$libbpf_load_id"   --arg cilium_loader_id "$cilium_loader_id"   --arg falco_loader_id "$falco_loader_id"   '{
    schema_version:"bpfcompat.research.materialization.v1",
    corpus_version:"v1",
    generated_at_utc:$generated_at,
    materializer_commit:$materializer_commit,
    source_revisions:{
      bpfcompat_selection_source:$bpf_source_revision,
      falco:$falco_source_revision,
      cilium_tracepoint_upstream:$cilium_source_revision,
      bpfcompat_execution:$bpfcompat_execution_revision
    },
    toolchain:{
      go:$go_version,
      clang:$clang_version,
      cmake:$cmake_version,
      bpftool:{
        path:$bpftool_path,
        sha256:$bpftool_sha256
      }
    },
    artifacts:[
      {id:"bpfcompat-simple-pass", path:"artifacts/simple_pass.bpf.o", sha256:$simple_sha},
      {id:"bpfcompat-ringbuf-modern", path:"artifacts/ringbuf_modern.bpf.o", sha256:$ringbuf_sha},
      {id:"bpfcompat-perfbuf-fallback", path:"artifacts/perfbuf_fallback.bpf.o", sha256:$perfbuf_sha},
      {id:"bpfcompat-core-relocation-fail", path:"artifacts/core_relocation_fail.bpf.o", sha256:$core_sha},
      {id:"cilium-tracepoint-in-c", path:"artifacts/cilium_tracepoint_in_c.bpf.o", sha256:$cilium_obj_sha},
      {id:"cilium-ebpf-v022-loader", path:"loaders/ebpf-go-loader", sha256:$ebpf_go_loader_sha},
      {id:"falco-modern-bpf-scap-open", path:"loaders/scap-open", sha256:$scap_open_sha},
      {id:"bpfcompat-v037-cli", path:"bin/bpfcompat-linux-amd64", sha256:$cli_sha},
      {id:"bpfcompat-v037-validator", path:"bin/bpfcompat-validator-static-linux-amd64", sha256:$validator_sha}
    ],
    validation_contracts:{
      "libbpf-v037-load-attach-v1":$libbpf_attach_id,
      "libbpf-v037-load-only-v1":$libbpf_load_id,
      "cilium-ebpf-v022-load-only-v1":$cilium_loader_id,
      "falco-modern-bpf-scap-open-v1":$falco_loader_id
    }
  }' > "$OUT_DIR/materialization.json"

(
  cd "$OUT_DIR"
  LC_ALL=C find . -type f ! -name SHA256SUMS -print0 |
    LC_ALL=C sort -z |
    xargs -0 sha256sum > SHA256SUMS
)

echo "[research-materialize] bundle created at $OUT_DIR"
cat "$OUT_DIR/materialization.json"
