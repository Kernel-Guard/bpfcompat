// SPDX-License-Identifier: GPL-2.0
/* Fixture for trial_probe_maps_test.sh. One runtime-sized hash map
 * (max_entries left 0 for the loader to fill in, like Inspektor Gadget's
 * ig_build_id), two two-variant program groups and one extra program.
 * Never loaded into a kernel: the test links the validator against a fake
 * bpf_object__load (fake_load.c). */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
} runtime_sized SEC(".maps");

static __always_inline int touch(void) {
    __u32 key = 0;
    __u64 *v = bpf_map_lookup_elem(&runtime_sized, &key);
    return v ? 1 : 0;
}

SEC("socket")
int variant_preferred(void *ctx) { return touch(); }

SEC("socket")
int variant_fallback(void *ctx) { return touch(); }

SEC("socket")
int other_prog(void *ctx) { return touch(); }

/* Second group: fake_load.c rejects probe_rejected when trial-loaded alone,
 * for a reason unrelated to maps, so its probe output must stay out of
 * logs.libbpf even when the probe genuinely fails. */
SEC("socket")
int probe_rejected(void *ctx) { return touch(); }

SEC("socket")
int probe_rejected_fallback(void *ctx) { return touch(); }

char LICENSE[] SEC("license") = "GPL";
