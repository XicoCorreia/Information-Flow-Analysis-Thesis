/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef unsigned int u32;
typedef int pid_t;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tracepoint/syscalls/sys_enter_write")
int fol(void *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // We will multiply pid by 10 a few times, but only if it's below a threshold
    #pragma unroll
    for (int i = 0; i < 3; i++) {
        if (pid > 1000000) {
            i += 7;
            i = i * (u32)pid;
            return i;
        }
        pid *= 10;
    }
    return pid;
}
