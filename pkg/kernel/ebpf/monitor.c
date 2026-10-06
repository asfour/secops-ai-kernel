#include <linux/bpf.h>
#include <linux/sched.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

struct token_metadata {
    __u64 agent_id;
    __u32 permission_mask;
    __u64 execution_window_expiry_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64); // Token ID Key (PID mapped)
    __type(value, struct token_metadata);
} active_tokens_map SEC(".maps");

struct trace_event_raw_sys_enter {
    __u64 unused;
    __s64 id;
    __u64 args;
};

SEC("tp/syscalls/sys_enter_execve")
int handle_execve_entry(struct trace_event_raw_sys_enter *ctx) {
    __u64 current_time = bpf_ktime_get_ns();
    __u64 current_pid_tgid = bpf_get_current_pid_tgid();
    __u32 current_pid = current_pid_tgid >> 32;

    __u64 mock_token_key = (__u64)current_pid;
    struct token_metadata *meta = bpf_map_lookup_elem(&active_tokens_map, &mock_token_key);

    if (!meta) {
        bpf_send_signal(9); 
        return 0;
    }

    if (current_time > meta->execution_window_expiry_ns) {
        bpf_map_delete_elem(&active_tokens_map, &mock_token_key);
        bpf_send_signal(9); 
        return 0;
    }

    return 0;
}
