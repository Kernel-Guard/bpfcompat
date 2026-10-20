// SPDX-License-Identifier: Apache-2.0
/* Fixture for input_handling_test.sh (never loaded into a kernel).
 *
 * - runtime_sized: a hash map with no max_entries, the target of the
 *   --set-map-max-entries leading-zero checks.
 * - The program/section/map names carry JSON metacharacters, control bytes,
 *   invalid UTF-8 (lone 0xff/0xfe, a broken 2-byte sequence, an encoded
 *   UTF-16 surrogate, an overlong '/', a truncated 3-byte sequence) and valid
 *   multi-byte UTF-8 (U+00E9, U+20AC, U+1F600) that must survive unchanged. */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
} runtime_sized SEC(".maps");

/* No max_entries either, so its name reaches result.json via
 * auto_sized_maps. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
} evil_map __asm__("m\"},{\"name\":\"INJ\\\x01\xff\xfe\n") SEC(".maps");

static __always_inline int touch(void) {
    __u32 key = 0;
    __u64 *v = bpf_map_lookup_elem(&evil_map, &key);
    __u64 *w = bpf_map_lookup_elem(&runtime_sized, &key);
    return (v ? 1 : 0) + (w ? 1 : 0);
}

int p1(void *ctx) __asm__("p\"\\\n\x01\x1f\x7f\xc3\x28\xed\xa0\x80\xc0\xaf"
                          "-\xc3\xa9\xe2\x82\xac\xf0\x9f\x98\x80-\xe2\x82");
SEC("socket\",\"status\":\"pass\",\"x\":\"\\\n\tQQ")
int p1(void *ctx) { return touch(); }

SEC("kprobe/\"}],\"load\":{\"status\":\"fail\"},\"z\":[{\"a\":\"")
int p2(void *ctx) { return touch(); }

char LICENSE[] SEC("license") = "GPL";
