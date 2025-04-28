//go:build ignore

#include "common.h"
#include <linux/errno.h>

#define X86_64_UNSHARE_SYSCALL 272
#define UNSHARE_SYSCALL X86_64_UNSHARE_SYSCALL
#define CLONE_NEWUSER		0x10000000


/* --- Important Structure Definitions --- */
typedef unsigned int gfp_t;

struct privilege_key
{
    unsigned long long cgroup_id;
};

// Empty placeholder value
struct filter_pad
{
    unsigned char pad;
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
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct privilege_key);
	__type(value, struct filter_pad);
} privilege_map SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(value, struct process_info);
} privilege_escalation_events SEC(".maps");

// Map to store process info struct
struct
{
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct process_info);
	__uint(max_entries, 1);
} process_info_map SEC(".maps");

SEC("lsm/cred_prepare")
int BPF_PROG(handle_cred_prepare, struct cred *new, const struct cred *old, gfp_t gfp, int ret)
{
    struct pt_regs *regs;
    struct task_struct *task;
    int syscall;
    unsigned long flags;
    unsigned long long cgroup_id;
    
    if (ret) {
        return ret;
    }

    task = bpf_get_current_task_btf();
    regs = (struct pt_regs *) bpf_task_pt_regs(task);
    cgroup_id = bpf_get_current_cgroup_id();

    syscall = regs -> orig_ax;

    if (syscall != UNSHARE_SYSCALL) {
        return 0;
    }

    flags = PT_REGS_PARM1_CORE(regs);

    if (!(flags & CLONE_NEWUSER)) {
        return 0;
    }

    struct privilege_key key = {
		.cgroup_id = cgroup_id,
	};

    struct filter_pad *rule = bpf_map_lookup_elem(&privilege_map, &key);
    if(rule) {
        const u32 key_zero = 0;
        struct process_info *info = bpf_map_lookup_elem(&process_info_map, &key_zero);
        if (info == NULL) return ret;

        info->pid = bpf_get_current_pid_tgid() >> 32;
        info->uid = (uid_t)bpf_get_current_uid_gid();
        info->syscall_nr = syscall;
        info->cgroup_id = cgroup_id;
        bpf_get_current_comm(&info->comm, sizeof(info->comm));

        // Send event to userspace for logging
        bpf_perf_event_output(ctx, &privilege_escalation_events, BPF_F_CURRENT_CPU, info, sizeof(*info));

        return -EPERM;
    }

    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
