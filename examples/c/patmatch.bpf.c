// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#if 0
SEC("kprobe/do_execve")
int BPF_KPROBE(do_execve, const char *name,
		const char *const *__argv,
		const char *const *__envp)
{
	pid_t pid;
	char comm[64];

	pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&comm, sizeof(comm));
	bpf_printk("KPROBE ENTRY pid = %d, filename = %s\n", pid, comm);
	return 0;
}
#endif

#define MAX_PATH_SZ 256

#define CHK_TWO  \
    if (!wild[w] || !str[i])     \
        goto CHK_TWO_OUT;                                    \
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
    int i = 0, w = 0, mp = 0, cp = 0;

#define CHK_ONE \
    if (!str[i] || wild[i] == '*') goto CHK_ONE_OUT;\
    if ((wild[i] != str[i]) && (wild[i] != '?')) return 0;\
    i++;

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
    CHK_TWO_OUT:

#define CHK_THREE    \
    if (wild[w] != '*') goto CHK_THREE_OUT;\
        w++;

    CHK_THREE    CHK_THREE    CHK_THREE    CHK_THREE
    CHK_THREE    CHK_THREE    CHK_THREE    CHK_THREE
    CHK_THREE    CHK_THREE    CHK_THREE    CHK_THREE
    CHK_THREE    CHK_THREE    CHK_THREE    CHK_THREE
    CHK_THREE    CHK_THREE    CHK_THREE    CHK_THREE
    CHK_THREE    CHK_THREE    CHK_THREE    CHK_THREE
    CHK_THREE    CHK_THREE    CHK_THREE    CHK_THREE
    CHK_THREE    CHK_THREE    CHK_THREE    CHK_THREE
    CHK_THREE_OUT:

    return !wild[w];
}

const char wc[] = "sle*ep";
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

