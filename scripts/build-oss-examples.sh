#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

CLANG="${CLANG:-clang}"
BUILD_TMP=".bpfcompat/tmp/oss-build"
VMLINUX_HEADER="${BUILD_TMP}/vmlinux.h"

mkdir -p "$BUILD_TMP"

if ! command -v bpftool >/dev/null 2>&1; then
  echo "[oss-build] missing bpftool in PATH" >&2
  exit 1
fi

if [[ ! -r /sys/kernel/btf/vmlinux ]]; then
  echo "[oss-build] missing /sys/kernel/btf/vmlinux (host BTF unavailable)" >&2
  exit 1
fi

echo "[oss-build] generating vmlinux.h"
bpftool btf dump file /sys/kernel/btf/vmlinux format c >"$VMLINUX_HEADER"

echo "[oss-build] compiling cilium-tracepoint-in-c"
"$CLANG" -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu \
  -c examples/oss/cilium-tracepoint-in-c/tracepoint.bpf.c \
  -o examples/oss/cilium-tracepoint-in-c/tracepoint.bpf.o

echo "[oss-build] compiling bcc-execsnoop"
"$CLANG" -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu \
  -I"$BUILD_TMP" \
  -Iexamples/oss/bcc-execsnoop \
  -c examples/oss/bcc-execsnoop/execsnoop.bpf.c \
  -o examples/oss/bcc-execsnoop/execsnoop.bpf.o

echo "[oss-build] complete"
