# Generic eBPF Project Adapter

This adapter is a copy/paste starting point for projects that ship multiple
compiled `.bpf.o` artifacts and want a Falco-style compatibility gate:

1. choose a VM/kernel matrix,
2. list the BPF artifacts,
3. provide manifests with attach and optional functional test steps,
4. run `bpfcompat` in GitHub Actions on a self-hosted KVM runner,
5. keep JSON/Markdown/log artifacts for release evidence.

## Files

- `bpfcompat-suite.yaml`: multi-artifact suite template.
- `manifests/tracepoint-exec.yaml`: manifest with a real functional assertion.
- `workflows/bpfcompat-suite.yml`: GitHub Actions workflow template.

## Expected Project Layout

```text
build/
  exec_tracepoint.bpf.o
  network_xdp.bpf.o
manifests/
  exec_tracepoint.yaml
  network_xdp.yaml
matrices/
  customer-kernels.yaml
```

Update the paths in `bpfcompat-suite.yaml` to match your repository. Keep
functional commands small and deterministic; long behavioral tests should live
in scripts that the manifest calls.
