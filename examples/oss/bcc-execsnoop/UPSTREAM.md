# Upstream Reference

- Project: `iovisor/bcc`
- Source files:
  - `libbpf-tools/execsnoop.bpf.c`
  - `libbpf-tools/execsnoop.h`
- URLs:
  - <https://github.com/iovisor/bcc/blob/master/libbpf-tools/execsnoop.bpf.c>
  - <https://github.com/iovisor/bcc/blob/master/libbpf-tools/execsnoop.h>
- Retrieved: 2026-05-15

## Local Adaptations

No behavior changes were made.

Build-time note:

- This source expects `vmlinux.h` to be present in the include path.
- `scripts/build-oss-examples.sh` generates `vmlinux.h` from host BTF via:
  `bpftool btf dump file /sys/kernel/btf/vmlinux format c`.

## License

Source files retain upstream SPDX declaration:

- `(LGPL-2.1 OR BSD-2-Clause)`
