// go:build ignore

#include "common.h"
#include <linux/errno.h>

#define BUF_SIZE 32768
// #define MAX_COMBINED_LEN 512
#define MAX_BUFS 2
#define MAX_BLOCKED_FILES 10

// #define DEBUG
// #define HASH_COMP

/* --- Important Structure Definitions --- */
struct buffer
{
	char data[BUF_SIZE];
};

struct filePath
{
	char path[MAX_COMBINED_LEN];
	unsigned long long cgroup_id;
};

struct
{
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct buffer);
	__uint(max_entries, MAX_BUFS);
} buffers SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct filePath);
	__uint(max_entries, MAX_BLOCKED_FILES);
} blocked_files SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(value, struct process_info);
} file_access_events SEC(".maps");

static inline struct mount *real_mount(struct vfsmount *mnt)
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
	;

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

	// int i = 0;
	
#pragma unroll
	for (int i = 0; i < 20; i++)
	// bpf_for(i, 0, 20)
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
	else if (offset >= MAX_COMBINED_LEN)
	{
		offset = MAX_COMBINED_LEN;
	}
	return &string_p[offset];
}

static __inline bool my_substr(const char *path, const char *prefix)
{
	int i = 0;

#pragma unroll
	for (i = 0; i < MAX_COMBINED_LEN; i++)
	{ // Cap at 256 to stay within BPF limits
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
	if ((s1 == 0) ^ (s2 == 0))
		return false;
	else if (s1 == 0 && s2 == 0)
		return true;
	
	return my_substr(s1, s2);
}

struct cont {
	long ret;
	const char *cur_file;
};

static long callback_fn(struct bpf_map *map, const void *key, struct filePath* blocked_file, struct cont* ctx) {
	
	if (!blocked_file){
		bpf_printk("Not found");
		// ctx->ret = 0;
		return 0;
	}
	
	unsigned long long cgroup_id_recv = blocked_file->cgroup_id;
	if(cgroup_id_recv == 0){
		// ctx->ret = 0;
		return 0;
	}
	
	unsigned long long cgroupid_curr = bpf_get_current_cgroup_id();
	
	if(cgroup_id_recv == cgroupid_curr){
		bpf_printk("cgroup: %lu\n", blocked_file->cgroup_id);
		bpf_printk("path: %s\n", blocked_file->path);
		bpf_printk("current path: %s\n", ctx->cur_file);
		const char *blocked_file_path = blocked_file->path;

		if (blocked_file_path == NULL){
			bpf_printk("Blocked file path is NULL");
			// ctx->ret = 0;
			return 0;
		}
		if (compare_file_names(ctx->cur_file, blocked_file_path)){
			bpf_printk("BLOCKED");
			ctx->ret = -EPERM;
		}
	}
	return 0;
}

SEC("lsm/file_open")
int BPF_PROG(restrict_file_open, struct file *file)
{

	struct path path = BPF_CORE_READ(file, f_path);
	int ret = 0;

	u32 key = 0;
	struct buffer *buf = bpf_map_lookup_elem(&buffers, &key);
	if (buf == NULL)
	{
		bpf_printk("Not found");
		return 0;
	}

	const char *cur_file = prepend_path(&path, buf);

	u32 index = 0;

	struct filePath *blocked_file;

	struct cont c = {
		.cur_file = cur_file,
	};
	bpf_for_each_map_elem(&blocked_files, callback_fn, &c, 0);

	unsigned long long cgroup_id = bpf_get_current_cgroup_id();
	
	if (c.ret != 0){ 
		ret = c.ret;

		struct process_info info = {};
		info.pid = bpf_get_current_pid_tgid() >> 32;
		info.uid = (uid_t)bpf_get_current_uid_gid();
		bpf_probe_read_str(&info.file_path, sizeof(info.file_path), cur_file);
		info.cgroup_id = cgroup_id;
		bpf_get_current_comm(&info.comm, sizeof(info.comm));

		// Send event to userspace for logging
		bpf_perf_event_output(ctx, &file_access_events, BPF_F_CURRENT_CPU, &info, sizeof(info));
	
	}

	return ret;
}

char __license[] SEC("license") = "Dual MIT/GPL";
