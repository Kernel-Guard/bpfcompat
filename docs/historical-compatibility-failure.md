# Historical Compatibility Failure Reproduction

This evidence captures a real compatibility boundary: ring-buffer maps depend on kernel support introduced in Linux 5.8.

## External Technical References

- eBPF docs map reference: `BPF_MAP_TYPE_RINGBUF` (introduced in Linux 5.8):  
  https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_RINGBUF/
- eBPF feature timeline (`v5.8` includes ring-buffer map type):  
  https://docs.ebpf.io/linux/timeline/

## Reproduction in This Project

- Modern ring-buffer artifact:
  - `examples/ringbuf-modern/ringbuf_modern.bpf.o`
  - `examples/ringbuf-modern/manifest.yaml`
- Cross-profile report:
  - `reports/ringbuf-modern-mvp.json`

Observed outcome in report:

- `ubuntu-20.04-5.4` fails with `UNSUPPORTED_MAP_TYPE` and `-22` load error.
- newer profiles such as `ubuntu-22.04-5.15` and `ubuntu-24.04-6.8` pass for the same artifact.
- fallback artifact `reports/perfbuf-fallback-mvp.json` passes required profiles, matching expected compatibility strategy.

This demonstrates a documented historical kernel capability boundary and the runtime/fallback value proposition.

