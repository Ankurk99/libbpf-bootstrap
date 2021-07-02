// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";
//const char wc[] = "*p";
const char wc[] = "/home/*/*/????/*p";

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

#define MAX_PATH_SZ 256

#define CHK_TWO  \
    if (!wild[w] || !str[i])     \
        goto CHK_TWO_OUT;                                    \
	two++;\
                                                             \
    if (wild[w] == '*') {                                    \
        if (!wild[++w]) return 1;                            \
        mp = w;                                              \
        cp = i+1;                                            \
    } else if ((wild[w] == str[i]) || (wild[w] == '?')) {    \
        w++;                                                 \
        i++;                                                 \
    } else {                                                 \
        w = mp;                                              \
        i = cp++;                                            \
    }

/*
 * This function has to be eBPF compliant which means no unbound loops. Infact,
 * no loops!
 */
static int wildcardMatch(const char* str, const char* wild)
{
    int i = 0, w = 0, mp = 0, cp = 0, one = 0, two = 0, three = 0;

#define CHK_ONE \
    if (!str[i] || wild[i] == '*') goto CHK_ONE_OUT;\
    if ((wild[i] != str[i]) && (wild[i] != '?')) return 0;\
	one++;\
    i++;

    CHK_ONE    CHK_ONE     CHK_ONE    CHK_ONE
    CHK_ONE    CHK_ONE     CHK_ONE    CHK_ONE
    CHK_ONE    CHK_ONE     CHK_ONE    CHK_ONE
    CHK_ONE    CHK_ONE     CHK_ONE    CHK_ONE
    CHK_ONE    CHK_ONE     CHK_ONE    CHK_ONE
    CHK_ONE    CHK_ONE     CHK_ONE    CHK_ONE
    CHK_ONE    CHK_ONE     CHK_ONE    CHK_ONE
    CHK_ONE    CHK_ONE     CHK_ONE    CHK_ONE
    CHK_ONE    CHK_ONE     CHK_ONE    CHK_ONE
    CHK_ONE    CHK_ONE     CHK_ONE    CHK_ONE
    CHK_ONE    CHK_ONE     CHK_ONE    CHK_ONE
    CHK_ONE    CHK_ONE     CHK_ONE    CHK_ONE
    CHK_ONE    CHK_ONE     CHK_ONE    CHK_ONE
    CHK_ONE    CHK_ONE     CHK_ONE    CHK_ONE
    CHK_ONE    CHK_ONE     CHK_ONE    CHK_ONE
    CHK_ONE    CHK_ONE     CHK_ONE    CHK_ONE
    CHK_ONE_OUT:
    w = i;

    CHK_TWO    CHK_TWO    CHK_TWO    CHK_TWO
    CHK_TWO    CHK_TWO    CHK_TWO    CHK_TWO
    CHK_TWO    CHK_TWO    CHK_TWO    CHK_TWO
    CHK_TWO    CHK_TWO    CHK_TWO    CHK_TWO
    CHK_TWO    CHK_TWO    CHK_TWO    CHK_TWO
    CHK_TWO    CHK_TWO    CHK_TWO    CHK_TWO
    CHK_TWO    CHK_TWO    CHK_TWO    CHK_TWO
    CHK_TWO    CHK_TWO    CHK_TWO    CHK_TWO
    CHK_TWO    CHK_TWO    CHK_TWO    CHK_TWO
    CHK_TWO    CHK_TWO    CHK_TWO    CHK_TWO
    CHK_TWO    CHK_TWO    CHK_TWO    CHK_TWO
    CHK_TWO    CHK_TWO    CHK_TWO    CHK_TWO
    CHK_TWO    CHK_TWO    CHK_TWO    CHK_TWO
    CHK_TWO    CHK_TWO    CHK_TWO    CHK_TWO
    CHK_TWO    CHK_TWO    CHK_TWO    CHK_TWO
    CHK_TWO    CHK_TWO    CHK_TWO    CHK_TWO
    CHK_TWO_OUT:

#define CHK_THREE    \
    if (wild[w] != '*') goto CHK_THREE_OUT;\
	three++;\
	w++;

    CHK_THREE    CHK_THREE    CHK_THREE    CHK_THREE
    CHK_THREE    CHK_THREE    CHK_THREE    CHK_THREE
    CHK_THREE    CHK_THREE    CHK_THREE    CHK_THREE
    CHK_THREE    CHK_THREE    CHK_THREE    CHK_THREE
    CHK_THREE    CHK_THREE    CHK_THREE    CHK_THREE
    CHK_THREE    CHK_THREE    CHK_THREE    CHK_THREE
    CHK_THREE    CHK_THREE    CHK_THREE    CHK_THREE
    CHK_THREE    CHK_THREE    CHK_THREE    CHK_THREE
    CHK_THREE    CHK_THREE    CHK_THREE    CHK_THREE
    CHK_THREE    CHK_THREE    CHK_THREE    CHK_THREE
    CHK_THREE    CHK_THREE    CHK_THREE    CHK_THREE
    CHK_THREE    CHK_THREE    CHK_THREE    CHK_THREE
    CHK_THREE    CHK_THREE    CHK_THREE    CHK_THREE
    CHK_THREE    CHK_THREE    CHK_THREE    CHK_THREE
    CHK_THREE    CHK_THREE    CHK_THREE    CHK_THREE
    CHK_THREE    CHK_THREE    CHK_THREE    CHK_THREE
    CHK_THREE_OUT:

	if (!wild[w]) {
		bpf_printk("one=%d, two=%d, three=%d\n", one, two, three);
	}

    return !wild[w];
}

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

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter* ctx)
{
	char filename[256];

	bpf_probe_read_user_str(filename, sizeof(filename), (const char*)ctx->args[0]);
	if (wildcardMatch(filename, wc)) {
		bpf_printk("TRACEPOINT ENTRY filename=%s\n", filename);
	}
	return 0;
}

