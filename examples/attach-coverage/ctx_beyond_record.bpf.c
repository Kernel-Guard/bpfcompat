// Attach-regression fixture, candidate half. Paired with ctx_in_record.bpf.c:
// the two objects differ ONLY in the context offset read below (8 vs 512).
//
// The verifier bounds a tracepoint program's context reads by the perf trace
// buffer size, so both objects LOAD. At attach time the kernel also requires
// the program's highest context offset to fit the tracepoint's own record
// (perf_event_set_bpf_prog: max_ctx_offset > trace_event_get_offsets() ->
// -EACCES). sys_enter_getpid's record ends after __syscall_nr (offset 8, 4
// bytes), so this object fails to attach and the paired one attaches.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define CTX_OFF 512

SEC("tracepoint/syscalls/sys_enter_getpid")
int tp_getpid_ctx(void *ctx)
{
	(void)*(volatile __u32 *)((char *)ctx + CTX_OFF);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
