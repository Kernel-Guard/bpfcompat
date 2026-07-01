// Standalone module: keeps the example's cilium/ebpf dependency out of the
// main bpfcompat module (and its vulnerability/license scanning surface).
module github.com/kernel-guard/bpfcompat/examples/ebpf-go-loader

go 1.25.0

require (
	github.com/cilium/ebpf v0.22.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
)
