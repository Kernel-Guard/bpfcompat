// Attach-coverage fixture: one program the validator attaches and one it
// cannot, so a passing attach covers only part of the object.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_getpid")
int tp_getpid(void *ctx)
{
	(void)ctx;
	return 0;
}

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
	(void)ctx;
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
