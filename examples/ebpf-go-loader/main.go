// Command ebpf-go-loader loads a compiled .bpf.o with ebpf-go (cilium/ebpf)
// and exits 0 iff every map and program in the object loads into the kernel.
//
// Why this exists: ebpf-go is libbpf-compatible for the features it supports,
// but it is a separate loader implementation — so a libbpf load-pass does not
// guarantee an ebpf-go load-pass on the same kernel. If your project ships
// with ebpf-go, validate through ebpf-go. Ship this binary into each matrix
// kernel with bpfcompat command mode:
//
//	CGO_ENABLED=0 go build -o ebpf-go-loader .
//	bpfcompat test-command \
//	  --cmd '$BPFCOMPAT_BIN $BPFCOMPAT_ARTIFACT' \
//	  --bin ./ebpf-go-loader \
//	  --artifact ./your_object.bpf.o \
//	  --matrix matrices/quirk-library.yaml --out report.json
//
// This is a standalone Go module so the example's cilium/ebpf dependency does
// not enter the main bpfcompat module. See docs/ebpf-go-validation.md.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	// os.Exit only in main, with no pending defers.
	os.Exit(run())
}

func run() int {
	path := os.Getenv("BPFCOMPAT_ARTIFACT")
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	if path == "" {
		fmt.Fprintln(os.Stderr, "usage: ebpf-go-loader <object.bpf.o>  (or set $BPFCOMPAT_ARTIFACT)")
		return 2
	}

	// Kernels < 5.11 account BPF map memory against RLIMIT_MEMLOCK.
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Fprintf(os.Stderr, "ebpf-go-loader: remove memlock: %v\n", err)
		return 1
	}

	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ebpf-go-loader: parse %s: %v\n", path, err)
		return 1
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			// %+v prints the full verifier log, which lands in the bounded
			// stderr tail of the bpfcompat report.
			fmt.Fprintf(os.Stderr, "ebpf-go-loader: verifier rejected %s:\n%+v\n", path, verr)
		} else {
			fmt.Fprintf(os.Stderr, "ebpf-go-loader: load %s: %v\n", path, err)
		}
		return 1
	}
	defer coll.Close()

	fmt.Printf("ebpf-go-loader: loaded %d program(s) and %d map(s) from %s\n",
		len(coll.Programs), len(coll.Maps), path)
	return 0
}
