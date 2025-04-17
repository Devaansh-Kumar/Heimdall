//go:build ignore

#include "common.h"

#define EPERM 1

#define BUF_SIZE 32768
#define MAX_COMBINED_LEN 2048
#define MAX_BUFS 2

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
	__uint(max_entries, 1);
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

static inline u32 hash(const char *str)
{
	unsigned long hash = 5381;
	int c;

	for (int i = 0; i < MAX_COMBINED_LEN && str[i]; i++)
	{
		c = str[i];
		hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
	}

	return hash;
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
	else if (offset >= MAX_COMBINED_LEN)
	{
		offset = MAX_COMBINED_LEN;
	}
	return &string_p[offset];
}

static __always_inline bool my_strncmp(const char *s1, const char *s2) {
	bpf_printk("Comparing %s and %s", s1, s2);
    #pragma unroll
    for (int i = 0; i < MAX_COMBINED_LEN; i++) {
        char c1 = s1[i];
        char c2 = s2[i];

        if (c1 != c2)
            return false;

        if (c1 == '\0') // both strings ended
            return true;
    }
    return true; // both strings are equal up to MAX_COMBINED_LEN
}

static __inline bool my_substr(const char *path, const char *prefix) {
    int i = 0;

    #pragma unroll
    for (i = 0; i < MAX_COMBINED_LEN; i++) { // Cap at 256 to stay within BPF limits
        char p = path[i];
        char b = prefix[i];

        if (b == '\0') {
            // Match complete — check boundary
            if (p == '/' || p == '\0') {
                return true; // Match
            } else {
                return false; // False positive (e.g., "/tmpfolder")
            }
        }

        if (p != b) {
            return false; // Mismatch
        }
    }

    return false; // Safety: if we reach here, no match
}



static __always_inline bool compare_file_names(const char *s1, const char *s2)
{
#ifdef HASH_COMP
	u32 h1 = hash(s1);
	// u32 h1 = 0;
	u32 h2 = hash(s2);
	return h1 == h2;
#else
	if ((s1 == 0) ^ (s2 == 0))
		return false;
	else if (s1 == 0 && s2 == 0)
		return true;
	// return bpf_strncmp(s1, MAX_COMBINED_LEN, s2) == 0;
	// return my_strncmp(s1, s2);
	return my_substr(s1, s2);
#endif
}

static __always_inline int check_file(const struct file *file)
{
	struct path path = BPF_CORE_READ(file, f_path);

	u32 key = 0;
	struct buffer *buf = bpf_map_lookup_elem(&buffers, &key);
	if (buf == NULL)
	{
		bpf_printk("Not found");
		return 0;
	}

	const char *cur_file = prepend_path(&path, buf);

#ifdef DEBUG
	bpf_printk("Checking file: %s", cur_file);
#endif // DEBUG
	struct filePath *blocked_file = bpf_map_lookup_elem(&blocked_files, &key);
	
	if (blocked_file == NULL)
	{
		bpf_printk("Not found");
		return 0;
	}

	unsigned long long cgroup_id_recv = blocked_file->cgroup_id;
	// bpf_printk("Cgroup ID: %llu", cgroup_id_recv);
	unsigned long long cgroup_id = bpf_get_current_cgroup_id();
#ifdef DEBUG
		bpf_printk("File to be blocked: %s", blocked_file->path);
#endif // DEBUG
	const char *blocked_file_path = blocked_file->path;
	if(blocked_file_path == NULL)
	{
		bpf_printk("Blocked file path is NULL");
		return 0;
	}

	if (cgroup_id_recv == cgroup_id)
	{
		// bpf_printk("Cgroup ID match");
		// bpf_printk("Blocked file path: %s", blocked_file_path);
		// bpf_printk("Current file path: %s", cur_file);

	if (compare_file_names(cur_file, blocked_file_path))
	{
		bpf_printk("BLOCKED");
		return -EPERM;
	}
	}

	return 0;
}

SEC("lsm/file_open")
int BPF_PROG(restrict_file_open, struct file *file)
{
	int ret = check_file(file);
	
	struct process_info info = {};
        info.pid = bpf_get_current_pid_tgid() >> 32;
        info.uid = (uid_t)bpf_get_current_uid_gid();
        // info.file_path = file_path;
        // info.cgroup_id = cgroup_id;
        bpf_get_current_comm(&info.comm, sizeof(info.comm));

		// Send event to userspace for logging
        bpf_perf_event_output(ctx, &file_access_events, BPF_F_CURRENT_CPU, &info, sizeof(info));

	return ret;
}

char __license[] SEC("license") = "Dual MIT/GPL";
