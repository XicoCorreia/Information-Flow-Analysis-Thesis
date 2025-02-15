# Delete ebpf program if already loaded
sudo rm -rf /sys/fs/bpf/$1
# Compile ebpf file
clang -O2 -target bpf -c ebpfPrograms/$1.c -o ebpfPrograms/$1.o
# Load ebpf file without attach
sudo bpftool prog load ebpfPrograms/$1.o /sys/fs/bpf/$1 autoattach
# Check if it is correctly loaded
sudo bpftool prog show name $2
# Verify if it is printing
#sudo cat /sys/kernel/debug/tracing/trace_pipe 