# Third-Party Notices

bpfcompat is licensed under the Apache License 2.0 (`LICENSE`, `NOTICE`). Its
release binaries contain third-party code:

- **The CLI** (`bpfcompat-linux-*`, the container image) links Go modules
  vendored under `vendor/` (see `vendor/modules.txt`) and the Go standard
  library. Each module's license, notice and patent files are in its
  `vendor/<module>/` tree.
- **The static validator** (`bpfcompat-validator-static-linux-amd64`) is linked
  statically against Ubuntu's libbpf, libelf (elfutils), zstd, zlib, glibc and
  libgcc, at the exact versions in `validator/build-inputs.lock`. Their source
  packages are listed, with hashes, in `distribution/native-sources.lock`.

For each release that includes it, the authoritative, version-exact record is
the release asset `bpfcompat-third-party-licenses.tar.gz`: it carries the
verbatim texts and an `INVENTORY.json` generated from the shipped binaries
(see `docs/verifying-releases.md`). The validator's object file, link commands
and build record are in `bpfcompat-validator-relink-kit-linux-amd64.tar.gz`.
The container image carries the CLI's texts in `/usr/share/doc/bpfcompat/`.

Open distribution decisions (for example which option of a dual-licensed
library is relied on, and which source or object materials accompany a
release) are recorded in `distribution/policy.json`. Nothing in this file or in
the bundle elects a license or states that a license condition is met.
