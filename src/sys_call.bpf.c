//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <asm/errno.h>
#include <string.h>

#define SIGKILL 9
#define TASK_COMM_LEN 16
// #define WILDCARD 4294967295

// Define filter rule struct
struct filter_rule
{
	// uid_t uid;
	// u32 mnt_ns_id;
	u64 cgroup_id;
};

struct process_info
{
	u32 pid;
	u32 uid;
	u32 mnt_ns_id;
	u32 syscall_nr;
	u64 cgroup_id;
	u8 comm[TASK_COMM_LEN];
};

// Define BPF map for filter rules
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u32); // Syscall number
	__type(value, struct filter_rule);
} filter_map SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, 1);

} kprobe_map SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(value, struct process_info);
} events SEC(".maps");

SEC("kprobe/x64_sys_call")
int sys_call_block(struct pt_regs *ctx)
{
	// Variables
	struct task_struct *task;
	pid_t pid;
	uid_t uid;
	u32 mnt_ns_id;
	u64 cgroup_id;
	unsigned int syscall_nr;
	struct filter_rule *rule;

	// System call number
	syscall_nr = PT_REGS_PARM2(ctx);

	// Getting PID, UID and CGroupID
	pid = bpf_get_current_pid_tgid() >> 32;
	uid = (uid_t)bpf_get_current_uid_gid();
	cgroup_id = bpf_get_current_cgroup_id();

	// Extracting Mount Namespace ID
	// stat -L -c %i /proc/<pid>/ns/mnt
	task = bpf_get_current_task_btf();
	mnt_ns_id = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);

	// Command being executed
	char comm[TASK_COMM_LEN];
	bpf_get_current_comm(&comm, sizeof(comm));

	rule = bpf_map_lookup_elem(&filter_map, &syscall_nr);
	if (rule)
	{
		// Check if the rule matches UID, Mount NS or Cgroup ID and kill process if match found
		// if ((rule->uid == uid || rule->uid == WILDCARD) &&
		// 	(rule->mnt_ns_id == mnt_ns_id || rule->mnt_ns_id == WILDCARD) &&
		if (rule->cgroup_id == cgroup_id || rule->cgroup_id == 0)
		{

			long ret;
			// Send SIGKILL to the offending process
			ret = bpf_send_signal(SIGKILL);
			if (ret == 0)
			{
				bpf_printk("Blocking syscall %u for PID %d with UID %u, MntNS %u and CgroupID %llu\n", syscall_nr, pid, uid, mnt_ns_id, cgroup_id);

				struct process_info info = {};
				info.pid = pid;
				info.uid = uid;
				info.mnt_ns_id = mnt_ns_id;
				info.syscall_nr = syscall_nr;
				info.cgroup_id = cgroup_id;
				bpf_get_current_comm(&info.comm, sizeof(info.comm));

				// Send event to userspace for logging
				bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &info, sizeof(info));
			}
		}
	}

	return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";