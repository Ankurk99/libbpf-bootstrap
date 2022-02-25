// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */

/* CREDITS: code heavily based on Tracee's implementation */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/*
 * Limitations of the code:
 * 1. Can only be used for the file path matching
 * 2. Limit on first pass:12chars second pass:64chars third pass:12chars
 *
 */

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#if 0
SEC("kprobe/do_execve")
int BPF_KPROBE(do_execve, const char *name,
		const char *const *__argv,
		const char *const *__envp)
{
	pid_t pid;
	char comm[64];
	char filename[256];

	pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&comm, sizeof(comm));
	bpf_probe_read_kernel_str(filename, sizeof(filename), (void *)name);
	//bpf_probe_read_user_str(filename, sizeof(filename), (const char*)ctx->args[0]);
	bpf_printk("=------KPROBE ENTRY pid=%d, comm=%s\n", pid, filename);
	return 0;
}
#endif

#define STR_T         10UL
#define MAX_BUFFER_SIZE   32768
#define MAX_PERCPU_BUFSIZE 256
#define MAX_STRING_SIZE 128
#define MAX_PATH_SZ 32
#define MAX_PATH_COMPONENTS 10

struct bpf_map_def SEC("maps") path_buffer = {
      .type = BPF_MAP_TYPE_ARRAY,
      .key_size = sizeof(u32),
      .value_size = 32,
      .max_entries = 256,
};



SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter* ctx)
{
	char filename[128];

	bpf_probe_read_user_str(filename, sizeof(filename), (const char*)ctx->args[0]);
	bpf_printk("=------process=%s\n", filename);
	return 0;
}

#define READ_KERN(ptr)                                                  \
    ({                                                                  \
        typeof(ptr) _val;                                               \
        __builtin_memset((void *)&_val, 0, sizeof(_val));               \
        bpf_core_read((void *)&_val, sizeof(_val), &ptr);               \
        _val;                                                           \
    })

static __always_inline dev_t get_dev_from_file(struct file *file)
{   
    struct inode *f_inode = READ_KERN(file->f_inode);
    struct super_block *i_sb = READ_KERN(f_inode->i_sb);
    return READ_KERN(i_sb->s_dev);
}   

static __always_inline unsigned long get_inode_nr_from_file(struct file *file)
{
    struct inode *f_inode = READ_KERN(file->f_inode);
    return READ_KERN(f_inode->i_ino);
}

static __always_inline struct qstr get_d_name_from_dentry(struct dentry *dentry)
{
    return READ_KERN(dentry->d_name);
}

static __always_inline struct file* get_file_ptr_from_bprm(struct linux_binprm *bprm)
{
    return READ_KERN(bprm->file);
}

#define GET_FIELD_ADDR(field) __builtin_preserve_access_index(&field)

static __always_inline struct dentry* get_mnt_root_ptr_from_vfsmnt(struct vfsmount *vfsmnt)
{
	return READ_KERN(vfsmnt->mnt_root);
}

static __always_inline struct dentry* get_d_parent_ptr_from_dentry(struct dentry *dentry)
{
	return READ_KERN(dentry->d_parent);
}

static inline struct mount *real_mount(struct vfsmount *mnt)
{
    return container_of(mnt, struct mount, mnt);
}

static inline int copystr(char *dst, char *src, int len) {
	int c = 0;
#pragma unroll
	for (;;c++) {
		if(c>=len) break;
		if(!src[c]) break;
		dst[c] = src[c];
	}
	return c;
}

static __always_inline void get_path_str(struct path *path)//, char *filename, int max_len)
{
    struct path f_path;
    bpf_probe_read(&f_path, sizeof(struct path), path);
    char slash = '/';
    int zero = 0;
    struct dentry *dentry = f_path.dentry;
    struct vfsmount *vfsmnt = f_path.mnt;
    struct mount *mnt_parent_p;

    struct mount *mnt_p = real_mount(vfsmnt);
    bpf_probe_read(&mnt_parent_p, sizeof(struct mount*), &mnt_p->mnt_parent);

    struct dentry *mnt_root;
    struct dentry *d_parent;
    struct qstr d_name;
    unsigned int len;
    int sz;
	char pc[MAX_PATH_COMPONENTS][MAX_PATH_SZ];
	char filename[128];
	int off = 0;
	int pcidx = MAX_PATH_COMPONENTS - 1;
    int last;

    #pragma unroll
    for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {
        mnt_root = get_mnt_root_ptr_from_vfsmnt(vfsmnt);
        d_parent = get_d_parent_ptr_from_dentry(dentry);
        if (dentry == mnt_root || dentry == d_parent) {
            if (dentry != mnt_root) {
                // We reached root, but not mount root - escaped?
                break;
            }
            if (mnt_p != mnt_parent_p) {
                // We reached root, but not global root - continue with mount point path
                bpf_probe_read(&dentry, sizeof(struct dentry*), &mnt_p->mnt_mountpoint);
                bpf_probe_read(&mnt_p, sizeof(struct mount*), &mnt_p->mnt_parent);
                bpf_probe_read(&mnt_parent_p, sizeof(struct mount*), &mnt_p->mnt_parent);
                vfsmnt = &mnt_p->mnt;
                continue;
            }
            // Global root - path fully parsed
            break;
        }
        // Add this dentry name to path
        d_name = get_d_name_from_dentry(dentry);
        len = (d_name.len+1) & (MAX_PATH_SZ-1);

		if (pcidx < 0) {
			break;
		}

        // Is string buffer big enough for dentry name?
        sz = 0;
		if (len < sizeof(pc[pcidx])) {
            bpf_probe_read(pc[pcidx], 1, &slash);
			sz = bpf_probe_read_str(&pc[pcidx][1], sizeof(pc[pcidx]), (void *)d_name.name);
			if(sz > 1)
				pcidx--;
			else
				break;
		}
        dentry = d_parent;
    }

    int index = 0;
    void* value = 0;
    int s = pcidx;
    int position = 0;
    void* path_str = 0;
    char filepathname[32] = {0};
    char fullname[32] = {0};
    int l = -1;
    int psize = 0;
    #define KEY_SIZE (sizeof(filepathname) - 1)
    int k = 0;
    int path_sz = MAX_STRING_SIZE;
    #pragma unroll
        for (pcidx++;pcidx<MAX_PATH_COMPONENTS;pcidx++, index++) {
            //bpf_printk("part=%s", pc[pcidx]);
            bpf_map_update_elem(&path_buffer, &index, &pc[pcidx], BPF_ANY);
            // value = bpf_map_lookup_elem(&path_buffer, &index);
            // bpf_printk("value= %s\n", value);
        }

    for (s++; s < MAX_PATH_COMPONENTS; s++, position++) {
        path_str = bpf_map_lookup_elem(&path_buffer, &position);
       // bpf_printk("path_str: %s", path_str);
        psize = bpf_probe_read_str(filepathname, KEY_SIZE, path_str);
        bpf_printk("filepathname: %s", filepathname);
        path_sz -= (psize + 1);
        if (path_sz < 0)
            break;
        
        //bpf_printk("psize: %d", psize-1);
        int pathsz = bpf_probe_read_str(&(fullname[(path_sz) & (MAX_STRING_SIZE - 1)]), (psize + 1) & (MAX_STRING_SIZE - 1), filepathname);

        if (pathsz > 1) {
			bpf_probe_read(&(fullname[(path_sz + psize) &(MAX_STRING_SIZE - 1)]), 1, &slash);
		} else {
            path_sz += (psize + 1);
		}


        // for (l = 0; l < 20; l++) {
        //     fullname[l + path_sz] = filepathname[l];
        // }
        bpf_printk("fullname: %s", fullname);
        //path_sz = path_sz + psize + 1;
        bpf_printk("path_sz: %d", path_sz);
    }
            bpf_printk("fullname1: %s", fullname[0]);
        // for (; l < 12; l++) {
        //     bpf_printk("fullname: %s", fullname);
        // }
    //    bpf_printk("filepathname: %s\n", filepathname);

}

SEC("kprobe/security_bprm_check")
int BPF_KPROBE(trace_security_bprm_check)
{
    struct linux_binprm *bprm = (struct linux_binprm *)PT_REGS_PARM1(ctx);
    struct file* file = get_file_ptr_from_bprm(bprm);
    get_path_str(GET_FIELD_ADDR(file->f_path));
    return 0;
}

