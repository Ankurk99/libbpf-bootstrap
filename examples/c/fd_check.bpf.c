#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define SRV_PID 220070
// #define SRV_PID 3670987

// accept4 syscall
// int accept4(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen);
SEC("kretprobe/__x64_sys_accept")
int BPF_KRETPROBE(accept, int ret) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    // filter specific pid for simplicity
    if (pid != SRV_PID || ret < 0) {
        return 0;
    }

    // debug returned file descriptor
    bpf_printk("opened pid=%d fd=%d", pid, ret);
    return 0;
}

SEC("kretprobe/__x64_sys_openat")
int BPF_KRETPROBE(open, int ret) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    // filter specific pid for simplicity
    if (pid != SRV_PID || ret < 0) {
        return 0;
    }

    // debug returned file descriptor
    bpf_printk("opened pid=%d fd=%d", pid, ret);
    return 0;
}
// close syscall
// int close(int fd);
SEC("kprobe/__x64_sys_close")
int BPF_KPROBE(close, struct pt_regs *regs) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // filter specific pid for simplicity
	
	int fd = PT_REGS_PARM1_CORE(regs);
    if (pid != SRV_PID) {
        return 0;
    }

    // debug fd arg (expected to be equal to fd returned on accept4)
    bpf_printk("closed pid=%d fd=%d", pid, fd);
    return 0;
}

