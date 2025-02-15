# Delete ebpf program if already loaded
sudo rm -rf /sys/fs/bpf/$1
# Compile ebpf file
clang -O2 -target bpf -c ebpfPrograms/$1.c -o ebpfPrograms/$1.o
# Load ebpf file without attach
sudo bpftool prog load ebpfPrograms/$1.o /sys/fs/bpf/$1
# Get opcodes + hex
sudo bpftool prog dump xlated name $2 opcodes > ebpfPrograms/opcodes.txt
# Remove opcodes leaving only hex
awk 'NR % 2 == 0' ebpfPrograms/opcodes.txt > ebpfPrograms/opcodesFiltered.txt
# Turn hex into binary to be decoded
xxd -p -r ebpfPrograms/opcodesFiltered.txt > ebpfPrograms/$1\_opcodes.bin
# Call ebpf-tools decoder
cabal exec -- ebpf-tools -d ebpfPrograms/$1\_opcodes.bin > ebpfPrograms/$1.asm
# Cleanup extra files
rm ebpfPrograms/opcodesFiltered.txt