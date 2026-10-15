// Attach-coverage fixture: every program is one the validator auto-attaches.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_getpid")
int tp_getpid(void *ctx)
{
	(void)ctx;
	return 0;
}

SEC("raw_tracepoint/sys_enter")
int raw_sys_enter(void *ctx)
{
	(void)ctx;
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
