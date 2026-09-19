# Table 1 — Frozen corpus and validation contracts

| Case | Analysis role | Artifact | Frozen source revision | Execution mode | Loader / validator | Immutable base contract ID |
| --- | --- | --- | --- | --- | --- | --- |
| simple-pass-libbpf | controlled_probe | bpfcompat-simple-pass | b8ef57f4e02ebecee4649f7657ea8eea6af46ca9 | load_attach | BPFCompat v0.3.7 static libbpf validator | sha256:3e0e015d1fdd127c02f727f7ddda378200e4fe88c3f38f55316d75ec76d36d50 |
| perfbuf-fallback-libbpf | controlled_probe | bpfcompat-perfbuf-fallback | b8ef57f4e02ebecee4649f7657ea8eea6af46ca9 | load_attach | BPFCompat v0.3.7 static libbpf validator | sha256:3e0e015d1fdd127c02f727f7ddda378200e4fe88c3f38f55316d75ec76d36d50 |
| ringbuf-modern-libbpf | controlled_probe | bpfcompat-ringbuf-modern | b8ef57f4e02ebecee4649f7657ea8eea6af46ca9 | load_attach | BPFCompat v0.3.7 static libbpf validator | sha256:3e0e015d1fdd127c02f727f7ddda378200e4fe88c3f38f55316d75ec76d36d50 |
| cilium-tracepoint-libbpf | primary_oss_derived | cilium-tracepoint-in-c | f035193453c32429bc2f6b6d623c4dfa200ad48f | load_attach | BPFCompat v0.3.7 static libbpf validator | sha256:3e0e015d1fdd127c02f727f7ddda378200e4fe88c3f38f55316d75ec76d36d50 |
| cilium-tracepoint-ebpf-go | primary_oss_derived | cilium-tracepoint-in-c | f035193453c32429bc2f6b6d623c4dfa200ad48f (artifact); b8ef57f4e02ebecee4649f7657ea8eea6af46ca9 (loader) | command | cilium/ebpf v0.22.0 custom loader | sha256:2bcd1be1d9180b1ef790a3fd6e8bd635168d43dd7b16956535a1d464fd76c853 |
| falco-modern-bpf-scap-open | primary_real_world | falco-modern-bpf-scap-open | 1800b330ce92b532456178abfcbfba3dd157f974 | command | Falco scap-open modern_bpf path | sha256:7fe31f06529db32acfc5a6fe5b109700e59cfd7deb79c176f601af5e5090bf66 |
| core-relocation-fail-libbpf | calibration | bpfcompat-core-relocation-fail | b8ef57f4e02ebecee4649f7657ea8eea6af46ca9 | load_only | BPFCompat v0.3.7 static libbpf validator | sha256:2b193bd305a6fe63c466a30fd31fde0ead09c7d8b8026c3379113d28dfd529f5 |
