CABAL_CMD = cabal run ebpf-cfg --

TESTS = doWhile \
		whileLoop \
		ifStatement \
		nestedIfLoop \
		nestedWhiles \
		seqWhiles \
		doWhileIfNested \
		loadFromImm \
		loadFromReg \
		whileLoopLow \

TEST_NAME = test
SECRET_RS = r1

EBPF_PROG = firstProg
EBPF_FUN = handle_tp

# Default target
all: run-synthetic-tests

# Build using cabal
build:
	cabal build

# Run the program for each example
run-synthetic-tests: build
	@for file in $(TESTS); do \
		$(CABAL_CMD) examples/$$file.asm examples/graphs/$$file.dot $(SECRET_RS); \
		dot -Tpdf examples/graphs/$$file.dot -o examples/graphs/$$file.pdf; \
	done

# Run the program for each example
run-interval-analysis-tests: build
	@for file in $(TESTS); do \
		$(CABAL_CMD) examples/$$file.asm; \
	done

# Run one examples of a program
run-one-synthetic-test: build
	$(CABAL_CMD) examples/$(TEST_NAME).asm examples/graphs/$(TEST_NAME).dot $(SECRET_RS); \
	dot -Tpdf examples/graphs/$(TEST_NAME).dot -o examples/graphs/$(TEST_NAME).pdf; \

# Load and attach an ebpf file
load-and-attach-ebpf-program:
### Delete ebpf program if already loaded
	sudo rm -rf /sys/fs/bpf/$(EBPF_PROG)
### Compile ebpf file
	clang -O2 -target bpf -c ebpfPrograms/$(EBPF_PROG).c -o ebpfPrograms/$(EBPF_PROG).o
### Load ebpf file without attach
	sudo bpftool prog load ebpfPrograms/$(EBPF_PROG).o /sys/fs/bpf/$(EBPF_PROG) autoattach
### Check if it is correctly loaded
	sudo bpftool prog show name $(EBPF_FUN)
### Verify if it is printing
	#sudo cat /sys/kernel/debug/tracing/trace_pipe 

# Use ebpf-tools to decode a .c ebpf program into assembly
run-ebpf-decoder:
### Delete ebpf program if already loaded
	sudo rm -rf /sys/fs/bpf/$(EBPF_PROG)
### Compile ebpf file
	clang -O2 -target bpf -c ebpfPrograms/$(EBPF_PROG).c -o ebpfPrograms/$(EBPF_PROG).o
### Load ebpf file without attach
	sudo bpftool prog load ebpfPrograms/$(EBPF_PROG).o /sys/fs/bpf/$(EBPF_PROG)
### Get opcodes + hex
	sudo bpftool prog dump xlated name $(EBPF_FUN) opcodes > ebpfPrograms/opcodes.txt
### Remove opcodes leaving only hex
	awk 'NR % 2 == 0' ebpfPrograms/opcodes.txt > ebpfPrograms/opcodesFiltered.txt
### Turn hex into binary to be decoded
	xxd -p -r ebpfPrograms/opcodesFiltered.txt > ebpfPrograms/$(EBPF_PROG)\_opcodes.bin
### Call ebpf-tools decoder
	cabal exec -- ebpf-tools -d ebpfPrograms/$(EBPF_PROG)\_opcodes.bin > ebpfPrograms/$(EBPF_PROG).asm
### Cleanup extra files
	rm ebpfPrograms/opcodesFiltered.txt

# Remove a loaded ebpf program from the bpf environment
remove-loaded-ebpf-program:
	# Delete ebpf program if already loaded
	sudo rm -rf /sys/fs/bpf/$(EBPF_PROG)

# Clean up build artifacts in ebpfPrograms
clean-ebpfPrograms:
	rm -r ebpfPrograms/*.bin
	rm -r ebpfPrograms/*.o
	rm -r ebpfPrograms/*.txt

# Clean up generated graphs
clean-graphs:
	rm -r examples/graphs/*

# Clean up build artifacts
clean:
	cabal clean
	rm -r examples/graphs/*
	rm -r ebpfPrograms/*.bin
	rm -r ebpfPrograms/*.o
	rm -r ebpfPrograms/*.txt
