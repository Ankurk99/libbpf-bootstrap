// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

//#define KA_BLOCK "./goodbworld"
#define KA_BLOCK "BLOCKED_BY_KUBEARMOR"

/* TODO
 * 1. full path of the process in execve
 * 2. try file open example
 * 3. connect with ip based filter
 * 4. control process execution based on user ID
 */

static inline int streq(const char *a, const char *b)
{
#pragma unroll
	for (int i=0; i < 64; i++) {
		if (a[i] != b[i]) {
			return 0;
		}
		if (!*a && !*b) return 1;
		if (!*b) return 0;
		if (!*a) return 0;
	}
	return 1;
}

#if 1
SEC("kprobe/__x64_sys_execve")
int BPF_KPROBE(execve, struct pt_regs *regs)
{
	pid_t pid;
	char *name = (char *)PT_REGS_PARM1_CORE(regs);
	char oldname[32];
	char newname[32]=KA_BLOCK;
	long ret;

	pid = bpf_get_current_pid_tgid() >> 32;
	ret = bpf_probe_read_user_str(oldname, sizeof(oldname), name);
	if (ret < 0) {
		bpf_printk("bpf_probe_read_user failed");
		return 0;
	}

#if 1
	if (oldname[0] != '.' || oldname[1] != '/') {
		return 0;
	}
	ret = bpf_probe_write_user(name, newname, sizeof(KA_BLOCK));
#else
	ret = 0;
#endif
	if (ret) {
		bpf_printk("bpf_probe_write_user failed");
	} else {
		bpf_printk("=------KPROBE ENTRY pid=%d, comm=%s", pid, name);
	}
	return 0;
}
#endif

#if 0
#define MYFILE "myopenfile.txt"
#define MYBLOCK "./XXX"
//#define MYFILE "/home/rahul/myspecialfile.txt"
SEC("kprobe/__x64_sys_openat")
int BPF_KPROBE(openat, struct pt_regs *regs)
{
	pid_t pid;
	char *name = (char *)PT_REGS_PARM2_CORE(regs);
	int flags = PT_REGS_PARM3_CORE(regs);
	char myfile[64] = MYFILE;
	char oldname[64] = {0};
	char newname[64] = MYBLOCK;
	long ret;

	pid = bpf_get_current_pid_tgid() >> 32;
	ret = bpf_probe_read_user_str(oldname, sizeof(oldname), name);
	if (ret < 0) {
		// bpf_printk("bpf_probe_read_user openat failed ret=%d name=[%s]", ret, name);
		return 0;
	}

	ret = 0;
#if 1
	if(!streq(oldname, myfile)) {
		// bpf_printk("NOMATCH OPENAT oldname=[%s], name=[%s]", oldname, name);
		return 0;
	}
	ret = bpf_probe_write_user(name, newname, sizeof(MYBLOCK));
#endif
	if (ret) {
		bpf_printk("bpf_probe_write_user failed ret=%d name:%s flags=%x", ret, oldname, flags);
	} else {
		bpf_printk("=------KPROBE OPENAT oldname=%s, comm=%s, flags=%x", myfile, oldname, flags);
	}
	return 0;
}
#endif


#if 0
#define NTOHS(VAL) ((((VAL) & 0xff) << 8) | ((VAL) >> 8))

/*
 * Change the connect port at runtime!
 */
SEC("kprobe/__x64_sys_connect")
int BPF_KPROBE(connect, struct pt_regs *regs)
{
	pid_t pid;
	int fd = PT_REGS_PARM1_CORE(regs);
	struct sockaddr *addr = (struct sockaddr *)PT_REGS_PARM2_CORE(regs);
	unsigned short family=0x1234;
	long ret;

	ret = bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);
	if (ret) {
		bpf_printk("bpf_probe_read_user failed");
	}

	pid = bpf_get_current_pid_tgid() >> 32;
	if (2 == family) {	// AF_INET
		struct sockaddr_in inaddr;
		int socklen = PT_REGS_PARM3_CORE(regs);

		ret = bpf_probe_read_user(&inaddr, sizeof(inaddr), addr);
		if (ret) {
			bpf_printk("bpf_probe_read_user 2 failed");
		} else {
			unsigned short port = NTOHS(inaddr.sin_port);
			bpf_printk("=------KPROBE CONNECT fd=%d socklen=%d port=%d", fd, socklen, port);
			if (8912 == port) {
				inaddr.sin_port = 0xfff0;
				bpf_printk("=------Setting port=%d", NTOHS(inaddr.sin_port));
				ret = bpf_probe_write_user(addr, &inaddr, sizeof(inaddr));
				if (ret) {
					bpf_printk("bpf_probe_write_user failed");
				}
			}
		}
//		bpf_override_return(regs, -ENOMEM);  //EACESS
	}
	return 0;
}
#endif

#if 0
	SEC("kretprobe/do_execve")
int BPF_KRETPROBE(do_execve_exit)
{
	pid_t pid;
	char comm[64];

	pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&comm, sizeof(comm));
	if (wildcardMatch(comm, wc)) {
		bpf_printk("KRETPROBE ENTRY pid = %d, filename = %s\n", pid, comm);
	}
	return 0;
}
#endif

#if 0
//SEC("tracepoint/syscalls/sys_enter_execve")
	SEC("tp/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter* ctx)
{
	char filename[128];

	bpf_probe_read_user_str(filename, sizeof(filename), (const char*)ctx->args[0]);
	bpf_printk("TRACEPOINT ENTRY filename=%s\n", filename);
	return 0;
}
#endif
