# Upstream Reference

- Project: `cilium/ebpf`
- Source file: `examples/tracepoint_in_c/tracepoint.c`
- URL: <https://github.com/cilium/ebpf/blob/main/examples/tracepoint_in_c/tracepoint.c>
- Retrieved: 2026-05-15

## Local Adaptations

To compile with this repository's existing toolchain, this copy makes two minimal changes:

1. Replaced `#include "common.h"` with system libbpf headers.
2. Replaced `u32`/`u64` aliases with `__u32`/`__u64`.

No runtime logic was changed.

## License

The source retains upstream license declaration:

- `Dual MIT/GPL`
