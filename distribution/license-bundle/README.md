# bpfcompat third-party license material

This bundle collects, verbatim, the license, notice and patent texts of the
third-party code in the binaries of this bpfcompat release, together with a
machine-readable inventory of where each one came from.

It contains three different kinds of information. Keep them apart:

1. **Observed facts** (`INVENTORY.json` → `observed`, and every text file):
   produced by the release build from the shipped binaries themselves. The Go
   module list comes from each CLI binary's build information; the native list
   comes from the validator's link trace in the pinned builder. Texts are copied
   unmodified from the vendored module trees, the Go toolchain and the owning
   Ubuntu packages.
2. **Recorded decisions** (`INVENTORY.json` → `recorded_decisions`, and
   `distribution-policy.json`): choices such as which option of a dual-licensed
   library is relied on. A decision with status `undecided` has not been made,
   and nothing in this bundle should be read as making it.
3. **Not established** (`INVENTORY.json` → `not_established`): what this bundle
   does not show.

This bundle does not elect a license, does not create notices that upstream
projects did not write, and is not a statement that any license condition is
met. Each owning package's copyright file is included whole, with every
`/usr/share/common-licenses` text it refers to, whichever options it lists.

## Layout

| Path | Contents |
|---|---|
| `INVENTORY.json` | Components, versions, provenance and sha256 of every included text |
| `bpfcompat/` | bpfcompat's own `LICENSE` and `NOTICE` |
| `go/toolchain/` | The Go toolchain's `LICENSE` and `PATENTS`, and its version |
| `go/modules/<module>/` | License-like files (LICENSE, NOTICE, PATENTS, AUTHORS, ...) of every linked Go module, at their path inside the module |
| `go/modules.tsv` | Linked Go modules, versions, the binaries that link them, and their files |
| `native/packages.tsv` | Ubuntu packages that provided the validator's link inputs and headers |
| `native/inputs.tsv` | Every link input and header with sha256 and owning package |
| `native/members.tsv` | Every archive member the linker included |
| `native/copyright/<package>/copyright` | Each owning package's Debian copyright file, verbatim |
| `native/common-licenses/` | Full texts that those copyright files refer to |
| `distribution-policy.json` | The recorded distribution decisions at release time |
| `SHA256SUMS` | Checksums of every file in the bundle |

The validator's object file, link commands and build record are in the separate
relink kit asset, `bpfcompat-validator-relink-kit-linux-amd64.tar.gz`.
