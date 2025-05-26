/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef unsigned int u32;
typedef int pid_t;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tracepoint/syscalls/sys_enter_write")
int nestedLoops(void *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 acc = 1;

    #pragma unroll
    for (int i = 0; i < 5; i++) {
        #pragma unroll
        for (int j = 0; j < 2; j++) {
            acc *= pid % (j + i + 2);
        }
        if (acc == 13){
            return 0;
        }
    }

    if (acc > 100) {
        return acc % 100 + 1;
    }
    else 
        return acc;
}
