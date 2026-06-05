#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct exec_event {
	__u32 pid;
	char comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 12);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_exec(void *ctx)
{
	struct exec_event *event;

	(void)ctx;
	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		return 0;
	}

	event->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	bpf_get_current_comm(event->comm, sizeof(event->comm));
	bpf_ringbuf_submit(event, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
