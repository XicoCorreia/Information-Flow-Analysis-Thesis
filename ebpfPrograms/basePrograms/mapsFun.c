#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef unsigned int u32;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// ✅ Global map declaration
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 256);
    __type(key, u32);
    __type(value, u32);
} my_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_write")
int ex(void *ctx)
{
    u32 key = 1;
    u32 value = 42;
    u32 *val;

    val = bpf_map_lookup_elem(&my_map, &key);
    if (val) {
        *val = *val + value;
    }

    return 0;
}
