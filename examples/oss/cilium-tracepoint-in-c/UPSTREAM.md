# Upstream Reference

- Project: `cilium/ebpf`
- Source file: `examples/tracepoint_in_c/tracepoint.c`
- Upstream revision: `f035193453c32429bc2f6b6d623c4dfa200ad48f`
- Permalink: <https://github.com/cilium/ebpf/blob/f035193453c32429bc2f6b6d623c4dfa200ad48f/examples/tracepoint_in_c/tracepoint.c>
- Retrieved: 2026-05-15

The pinned revision is the latest commit that touched this source file before
the recorded retrieval date. Pinning the file revision makes the provenance
reproducible instead of depending on the moving `main` branch.

## Local Adaptations

To compile with this repository's existing toolchain, this copy makes two minimal changes:

1. Replaced `#include "common.h"` with system libbpf headers.
2. Replaced `u32`/`u64` aliases with `__u32`/`__u64`.

No runtime logic was changed.

## License

The source retains upstream license declaration:

- `Dual MIT/GPL`
