// Command preload-gate is a minimal, real example of using bpfcompat as a
// library: validate a compiled eBPF object against the node's own running
// kernel before loading it. This is the bpfman-style pre-load path — a real
// bpf() load, no VM, no network.
//
// Build with the hostload tag (host-kernel loading is gated off by default):
//
//	go build -tags hostload -o preload-gate ./examples/preload-gate
//	sudo ./preload-gate probe.bpf.o
//
// Exit code: 0 if it would load, 1 if the gate blocks it (or on error).
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/kernel-guard/bpfcompat/pkg/bpfcompat"
)

// preloadGate refuses to load a BPF object that won't verify on THIS kernel.
func preloadGate(ctx context.Context, path string) error {
	res, err := bpfcompat.ValidateBeforeLoad(ctx, path)
	if err != nil {
		return err
	}
	if !res.OK() {
		return fmt.Errorf("refusing to load on %s: [%s] %s",
			res.Kernel.Release, res.Classification.Code, res.Classification.Reason)
	}
	fmt.Printf("ok: loads on %s (%s)\n", res.Kernel.Release, res.Load.Status)
	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: preload-gate <artifact.bpf.o>")
		os.Exit(2)
	}
	if err := preloadGate(context.Background(), os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "blocked:", err)
		os.Exit(1)
	}
}
