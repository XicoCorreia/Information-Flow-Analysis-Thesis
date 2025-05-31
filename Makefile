CABAL_CMD = cabal run ebpf-cfg --

TESTS = doWhile \
		whileLoop \
		whileLoopLow \
		ifStatement \
		nestedIfLoop \
		nestedWhiles \
		seqWhiles \
		doWhileIfNested \
		ifStatementNested \
		loadFromImm \
		loadFromReg \
		memoryOpLoop \
		largeMemoryIndex \

TEST_NAME = doWhile
SECRET_RS = r1

EBPF_PROG = ifProgram
EBPF_FUN = ite

# Default target
all: cabalTest

# Build using cabal
build:
	cabal build

# Test using cabal
cabalTest: 
	cabal test

# Run the program for each example
run-synthetic-tests: build
	@for file in $(TESTS); do \
		$(CABAL_CMD) examples/$$file.asm examples/graphs/$$file.dot $(SECRET_RS); \
		dot -Tpdf examples/graphs/$$file.dot -o examples/graphs/$$file.pdf; \
	done

# Run one synthetic program
run-one-synthetic-test: build
	$(CABAL_CMD) examples/$(TEST_NAME).asm examples/graphs/$(TEST_NAME).dot $(SECRET_RS); \
	dot -Tpdf examples/graphs/$(TEST_NAME).dot -o examples/graphs/$(TEST_NAME).pdf; \

# Run one ebpf program
run-one-ebpf-test: build
	$(CABAL_CMD) ebpfPrograms/bytecodePrograms/$(EBPF_PROG).asm ebpfPrograms/graphs/$(EBPF_PROG).dot $(SECRET_RS); \
	dot -Tpdf ebpfPrograms/graphs/$(EBPF_PROG).dot -o ebpfPrograms/graphs/$(EBPF_PROG).pdf; \

# Load and attach an ebpf file
load-and-attach-ebpf-program:
### Delete ebpf program if already loaded
	sudo rm -rf /sys/fs/bpf/$(EBPF_PROG)
### Compile ebpf file
	clang -O2 -target bpf -c ebpfPrograms/basePrograms/$(EBPF_PROG).c -o ebpfPrograms/basePrograms/$(EBPF_PROG).o
### Load ebpf file without attach
	sudo bpftool prog load ebpfPrograms/basePrograms/$(EBPF_PROG).o /sys/fs/bpf/$(EBPF_PROG) autoattach
### Check if it is correctly loaded
	sudo bpftool prog show name $(EBPF_FUN)
### Verify if it is printing
	#sudo cat /sys/kernel/debug/tracing/trace_pipe 
### Cleanup extra files
	rm -r ebpfPrograms/basePrograms/*.o

# Use ebpf-tools to decode a .c ebpf program into assembly
run-ebpf-decoder:
### Delete ebpf program if already loaded
	sudo rm -rf /sys/fs/bpf/$(EBPF_PROG)
### Compile ebpf file
	clang -O2 -target bpf -c ebpfPrograms/basePrograms/$(EBPF_PROG).c -o ebpfPrograms/basePrograms/$(EBPF_PROG).o
### Load ebpf file without attach
	sudo bpftool prog load ebpfPrograms/basePrograms/$(EBPF_PROG).o /sys/fs/bpf/$(EBPF_PROG)
### Get opcodes + hex
	sudo bpftool prog dump xlated name $(EBPF_FUN) opcodes > ebpfPrograms/$(EBPF_PROG)\_opcodes.txt
### Remove opcodes leaving only hex
	awk 'NR % 2 == 0' ebpfPrograms/$(EBPF_PROG)\_opcodes.txt > ebpfPrograms/opcodesFiltered.txt
### Turn hex into binary to be decoded
	xxd -p -r ebpfPrograms/opcodesFiltered.txt > ebpfPrograms/$(EBPF_PROG)\_opcodes.bin
### Call ebpf-tools decoder
	cabal exec -- ebpf-tools -d ebpfPrograms/$(EBPF_PROG)\_opcodes.bin > ebpfPrograms/bytecodePrograms/$(EBPF_PROG).asm
### Cleanup extra files
	rm ebpfPrograms/opcodesFiltered.txt
	rm -r ebpfPrograms/*.bin
	rm -r ebpfPrograms/basePrograms/*.o


# Remove a loaded ebpf program from the bpf environment
remove-loaded-ebpf-program:
	sudo rm -rf /sys/fs/bpf/$(EBPF_PROG)

# Clean up generated graphs
clean-graphs:
	rm -r examples/graphs/*
	rm -r ebpfPrograms/graphs/*

# Clean up build artifacts
clean:
	cabal clean
	rm -r examples/graphs/*
	rm -r ebpfPrograms/graphs/*
	rm -r ebpfPrograms/*.txt
