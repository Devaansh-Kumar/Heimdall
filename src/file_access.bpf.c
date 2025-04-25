// go:build ignore

#include "common.h"
#include <linux/errno.h>

#define BUF_SIZE 32768
#define MAX_BLOCKED_FILES 64

/* --- Important Structure Definitions --- */
struct buffer
{
	char data[BUF_SIZE];
};

struct filePath
{
	char path[MAX_COMBINED_LEN];
	u64 cgroup_id;
};

struct file_path_context {
	long ret;
	const char *cur_file;
	u64 cgroup_id;
};

/* --- BPF Map Definitions --- */
struct
{
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct buffer);
	__uint(max_entries, 1);
} buffers SEC(".maps");

// Map to hold all block files
struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct filePath);
	__uint(max_entries, MAX_BLOCKED_FILES);
} blocked_files SEC(".maps");

// Map for logging events
struct
{
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(value, struct process_info);
} file_access_events SEC(".maps");

// Map to store process info struct
struct
{
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct process_info);
	__uint(max_entries, 1);
} process_info_map SEC(".maps");


static __always_inline struct mount *real_mount(struct vfsmount *mnt)
{
	return container_of(mnt, struct mount, mnt);
}

/* Lifted from KubeArmor/KubeArmor/BPF/shared.h
 * Fills a buffer starting from the end of the string
 * Returns start of string inside `buf`
 */
static __always_inline char *prepend_path(const struct path *path, struct buffer *buf)
{
	char slash = '/';
	char null = '\0';
	char *string_p = buf->data;

	u32 offset = MAX_COMBINED_LEN;
	string_p[offset] = null;
	/* return &string_p[offset]; */

	struct dentry *dentry = BPF_CORE_READ(path, dentry);
	struct vfsmount *vfsmnt = BPF_CORE_READ(path, mnt);

	struct mount *mnt = real_mount(vfsmnt);

	struct dentry *parent;
	struct dentry *mnt_root;
	struct mount *m;
	struct qstr d_name;
	
#pragma unroll
	for (int i = 0; i < 20; i++)
	{
		parent = BPF_CORE_READ(dentry, d_parent);
		mnt_root = BPF_CORE_READ(vfsmnt, mnt_root);

		if (dentry == mnt_root)
		{
			m = BPF_CORE_READ(mnt, mnt_parent);
			if (mnt != m)
			{
				dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
				mnt = BPF_CORE_READ(mnt, mnt_parent);
				vfsmnt = &mnt->mnt;
				continue;
			}
			break;
		}

		if (dentry == parent)
		{
			break;
		}

		// get d_name
		d_name = BPF_CORE_READ(dentry, d_name);

		offset -= (d_name.len + 1); // 1 for slash
		if (offset < 0)
			break;
		if (offset < BUF_SIZE - 1)
		{
			bpf_probe_read(&string_p[offset & (MAX_COMBINED_LEN - 1)], 1, &slash);
			bpf_probe_read(&string_p[(offset + 1) & (MAX_COMBINED_LEN - 1)], d_name.len & (MAX_COMBINED_LEN - 1), d_name.name);
		}

		dentry = parent;
	}

	if (offset < 0)
	{
		offset = 0;
	}
	else if (offset > MAX_COMBINED_LEN)
	{
		offset = MAX_COMBINED_LEN;
	}
	return &string_p[offset];
}

static __always_inline bool my_substr(const char *path, const char *prefix)
{
// #pragma unroll
	for (int i = 0; i < MAX_COMBINED_LEN; i++)
	{ 
		// Cap at 256 to stay within BPF limits
		char p = path[i];
		char b = prefix[i];

		if (b == '\0')
		{
			// Match complete — check boundary
			if (p == '/' || p == '\0')
			{
				return true; // Match
			}
			else
			{
				return false; // False positive (e.g., "/tmpfolder")
			}
		}

		if (p != b)
		{
			return false; // Mismatch
		}
	}

	return false; // Safety: if we reach here, no match
}

static __always_inline bool compare_file_names(const char *s1, const char *s2)
{
	if ((s1 == NULL) ^ (s2 == NULL))
		return false;
	else if (s1 == NULL && s2 == NULL)
		return true;
	
	return my_substr(s1, s2);
}

static long callback_fn(struct bpf_map *_map, const void *_key,
	const struct filePath* blocked_file, struct file_path_context* ctx)
{
	const char *blocked_file_path = blocked_file->path;
	// Empty filename means end of list
	if (blocked_file_path[0] == '\0')
		return 1;
	
	u64 cgroup_id_recv = blocked_file->cgroup_id;
	u64 cgroupid_curr = ctx->cgroup_id;
	
	if(cgroup_id_recv == cgroupid_curr
		&& compare_file_names(ctx->cur_file, blocked_file_path)) {
		bpf_printk("BLOCKED");
		ctx->ret = -EPERM;
		return 1;
	}
	return 0;
}

SEC("lsm/file_open")
int BPF_PROG(restrict_file_open, struct file *file)
{
	int ret = 0;
	const u32 key_zero = 0;
	
	struct buffer *buf = bpf_map_lookup_elem(&buffers, &key_zero);
	if (buf == NULL)
	{
		bpf_printk("Not found");
		return 0;
	}

	// Construct the full path
	struct path path = BPF_CORE_READ(file, f_path);
	const char *cur_file = prepend_path(&path, buf);

	// Skip if file_open was detected on the host and not a container
	u64 cgroup_id = bpf_get_current_cgroup_id();
	if (cgroup_id == 0) {
		return 0;
	}

	struct file_path_context file_ctx = {
		.cur_file = cur_file,
		.cgroup_id = cgroup_id,
	};

	// Iterate over the blocked_files map to match current path
	bpf_for_each_map_elem(&blocked_files, callback_fn, &file_ctx, 0);
	
	// Block access if return value is not 0
	if (file_ctx.ret != 0){ 
		ret = file_ctx.ret;
		struct process_info *info = bpf_map_lookup_elem(&process_info_map, &key_zero);
		if (info == NULL) return ret;

		info->pid = bpf_get_current_pid_tgid() >> 32;
		info->uid = (uid_t)bpf_get_current_uid_gid();
		bpf_probe_read_str(info->file_path, sizeof(info->file_path), cur_file);
		info->cgroup_id = cgroup_id;
		bpf_get_current_comm(&info->comm, sizeof(info->comm));

		// Send event to userspace for logging
		bpf_perf_event_output(ctx, &file_access_events, BPF_F_CURRENT_CPU, info, sizeof(*info));
	}

	return ret;
}

char __license[] SEC("license") = "Dual MIT/GPL";
