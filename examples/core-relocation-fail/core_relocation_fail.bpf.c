#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct bpfcompat_nonexistent_kernel_type {
	__u64 field_should_not_resolve;
} __attribute__((preserve_access_index));

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_exec_core_fail(void *ctx)
{
	struct bpfcompat_nonexistent_kernel_type *p = (void *)ctx;

	return (int)p->field_should_not_resolve;
}

char LICENSE[] SEC("license") = "GPL";
