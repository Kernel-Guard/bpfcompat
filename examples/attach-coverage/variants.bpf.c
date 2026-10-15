// Attach-coverage fixture: a program_variants group selects one of two
// tracepoint programs; the other is not loaded and must not be attached.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_getpid")
int getpid_new(void *ctx)
{
	(void)ctx;
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getpid")
int getpid_old(void *ctx)
{
	(void)ctx;
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
