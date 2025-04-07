//go:build ignore

#include "common.h"

SEC("kprobe/x64_sys_call")
int sys_call_block(struct pt_regs *ctx)
{
	// Variables
	struct task_struct *task;
	pid_t pid;
	uid_t uid;
	u64 cgroup_id;
	unsigned int syscall_nr;
	struct filter_rule *rule;

	// System call number
	syscall_nr = PT_REGS_PARM2(ctx);

	// Getting PID, UID and CGroupID
	pid = bpf_get_current_pid_tgid() >> 32;
	uid = (uid_t)bpf_get_current_uid_gid();
	cgroup_id = bpf_get_current_cgroup_id();

	task = bpf_get_current_task_btf();

	// Command being executed
	char comm[TASK_COMM_LEN];
	bpf_get_current_comm(&comm, sizeof(comm));

	struct syscall_filter_key key = {
		.syscall_nr = syscall_nr,
		.cgroup_id = cgroup_id,
	};

	// Check if the system call matches cgroup id and kill process
	rule = bpf_map_lookup_elem(&filter_map, &key);
	if (rule)
	{
		long ret;
		ret = bpf_send_signal(SIGKILL);
		if (ret == 0)
		{
			bpf_printk("Blocking syscall %u for PID %d with UID %u and CgroupID %llu\n", syscall_nr, pid, uid, cgroup_id);

			struct process_info info = {};
			info.pid = pid;
			info.uid = uid;
			info.syscall_nr = syscall_nr;
			info.cgroup_id = cgroup_id;
			bpf_get_current_comm(&info.comm, sizeof(info.comm));

			// Send event to userspace for logging
			bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &info, sizeof(info));
		}
	}

	return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";