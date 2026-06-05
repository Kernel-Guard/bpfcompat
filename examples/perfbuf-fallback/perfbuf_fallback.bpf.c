#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct exec_event {
	__u32 pid;
	char comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 256);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_exec(void *ctx)
{
	struct exec_event event = {};

	event.pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	bpf_get_current_comm(event.comm, sizeof(event.comm));
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
