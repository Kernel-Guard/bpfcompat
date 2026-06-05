//go:build ignore
//
// Upstream source:
// https://github.com/cilium/ebpf/blob/main/examples/tracepoint_in_c/tracepoint.c
// Adaptation in this repo:
// - use system libbpf headers (<linux/bpf.h>, <bpf/bpf_helpers.h>)
// - replace u32/u64 aliases with __u32/__u64 for standalone compilation

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1);
} counting_map SEC(".maps");

// This struct is defined according to the following format file:
// /sys/kernel/tracing/events/kmem/mm_page_alloc/format
struct alloc_info {
	/* The first 8 bytes is not allowed to read */
	unsigned long pad;

	unsigned long pfn;
	unsigned int order;
	unsigned int gfp_flags;
	int migratetype;
};

// This tracepoint is defined in mm/page_alloc.c:__alloc_pages_nodemask()
// Userspace pathname: /sys/kernel/tracing/events/kmem/mm_page_alloc
SEC("tracepoint/kmem/mm_page_alloc")
int mm_page_alloc(struct alloc_info *info)
{
	__u32 key = 0;
	__u64 initval = 1, *valp;

	(void)info;
	valp = bpf_map_lookup_elem(&counting_map, &key);
	if (!valp) {
		bpf_map_update_elem(&counting_map, &key, &initval, BPF_ANY);
		return 0;
	}
	__sync_fetch_and_add(valp, 1);
	return 0;
}
