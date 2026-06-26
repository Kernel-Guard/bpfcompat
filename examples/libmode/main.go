// Command libmode is a tiny driver that exercises the pkg/bpfcompat library
// entry point (ValidateBeforeLoad) end-to-end. Build with -tags hostload and
// run with privilege:
//
//	go build -tags hostload -o /tmp/libmode ./examples/libmode
//	sudo /tmp/libmode <artifact.bpf.o>
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/kernel-guard/bpfcompat/pkg/bpfcompat"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: libmode <artifact.bpf.o>")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	start := time.Now()
	res, err := bpfcompat.ValidateBeforeLoad(ctx, os.Args[1])
	elapsed := time.Since(start)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("ValidateBeforeLoad -> OK=%v  (%.0fms)\n", res.OK(), float64(elapsed.Microseconds())/1000)
	fmt.Printf("  kernel : %s %s  btf=%v\n", res.Kernel.Release, res.Kernel.Arch, res.Kernel.BTF)
	fmt.Printf("  load   : %s  errno=%d\n", res.Load.Status, res.Load.Errno)
	if !res.OK() {
		fmt.Printf("  reason : [%s/%s] %s\n", res.Classification.Code, res.Classification.Confidence, res.Classification.Reason)
		if res.Load.LogTail != "" {
			fmt.Printf("  verifier-log-tail: %s\n", res.Load.LogTail)
		}
	}

	// Exit code mirrors what a gate would do: 0 loadable, 1 not.
	if !res.OK() {
		os.Exit(1)
	}
}
