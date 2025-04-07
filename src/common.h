#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define SIGKILL 9
#define TASK_COMM_LEN 16

/* --- Important Structure Definitions --- */
// Define rule to filter system calls with respective cgroup id
struct syscall_filter_key
{
	u32 syscall_nr;
	u64 cgroup_id;
};

// Empty placeholder value
struct filter_rule
{
	u8 pad;
};

struct process_info
{
	u32 pid;
	u32 uid;
	u32 syscall_nr;
	u64 cgroup_id;
	u8 comm[TASK_COMM_LEN];
};

/* --- BPF Map Definitions --- */
// Map for filtering system calls
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct syscall_filter_key);
	__type(value, struct filter_rule);
} filter_map SEC(".maps");

// Map for logging events
struct
{
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(value, struct process_info);
} events SEC(".maps");
