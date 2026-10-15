// Attach-coverage fixture: loads everywhere, but the validator has no attach
// mechanism for XDP (it needs an interface), so nothing is exercised.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
	(void)ctx;
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
