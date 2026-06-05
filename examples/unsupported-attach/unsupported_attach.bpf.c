#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("kprobe/bpfcompat_symbol_should_not_exist_987654")
int handle_missing_symbol(void *ctx)
{
	(void)ctx;
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
