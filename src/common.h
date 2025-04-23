//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define SIGKILL 9
#define TASK_COMM_LEN 16
#define MAX_COMBINED_LEN 256


struct process_info
{
	u32 pid;
	u32 uid;
	u32 syscall_nr;
	u64 cgroup_id;
	u8 comm[TASK_COMM_LEN];
	u8 file_path[MAX_COMBINED_LEN];
};
