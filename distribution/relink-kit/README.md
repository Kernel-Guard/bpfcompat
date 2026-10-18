# bpfcompat validator relink kit

This kit describes how the shipped static validator
(`bpfcompat-validator-static-linux-amd64`) was built and lets you link it again,
including against modified versions of the static libraries it contains.

It is technical material produced by the release build. It is not a license
statement: which licenses apply to the validator's components, and what their
terms require, are recorded (or still open) in the third-party license bundle
(`bpfcompat-third-party-licenses.tar.gz`, `INVENTORY.json`).

## Contents

| Path | What it is |
|---|---|
| `main.o` | The validator's own object file, compiled in the release builder with the flags in `build/commands.txt` |
| `validator-source/` | The validator's C sources (`validator/c-libbpf` at the release commit) |
| `build/commands.txt` | The Makefile recipe, and the same recipe split into the compile and link commands |
| `build/link-trace.txt` | The linker's own trace: every input file and every archive member it took |
| `build/link.map` | The linker map: why each archive member was pulled in, and where it was placed |
| `build/inputs.tsv` | Every link input and every header the compile read, with sha256 and owning Ubuntu package |
| `build/members.tsv` | Archive and member name of each linked archive member |
| `build/packages.tsv` | Owning packages with exact versions and source packages |
| `build/validator-build-inputs.json` | The release's build record: builder image digest, snapshot, package versions, validator sha256 |
| `build/build-inputs.lock` | The locked builder image, snapshot and package versions |
| `build/native-sources.lock` | The exact Ubuntu source packages of the linked native code, with sha256 and download URLs |
| `tools/build-validator-pinned.sh` | The release's builder script (used here only to configure the snapshot) |
| `relink.sh` | Links `main.o` again (see below) |
| `SHA256SUMS` | Checksums of every file in the kit |

The release build refuses to publish this kit unless linking `main.o` with the
recorded command reproduces the shipped validator byte for byte.

## Relinking

```sh
./relink.sh                       # pinned builder (docker); must reproduce the shipped validator
./relink.sh --lib-dir ./mylibs    # link against modified archives in ./mylibs first
./relink.sh --here                # use this machine's compiler and libraries
```

The pinned path needs docker and network access to `snapshot.ubuntu.com`. The
static libraries themselves are not in this kit; `relink.sh` installs them from
the locked packages. If the release carries
`bpfcompat-validator-link-inputs-linux-amd64.tar.gz`, its archives can be
passed explicitly with `--lib-dir`.

## Limits

- The member list is exact (from the linker); mapping a member back to the
  library source file it was compiled from is by name and is not exact.
- The snapshot and the Ubuntu archives are third-party services; their
  retention is outside this project's control.
- `--here` reproduces the shipped bytes only with the exact locked toolchain and
  library versions.
