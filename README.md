eBPF Information Flow Analysis
=======================

Cabal test
-------------
Run ``` cabal test ``` to verify the analysis correctness using the synthetic programs 
against the expected results.

Synthetic Tests
-------------
To run all the synthetic tests with the information flow analysis, run the command:

```
make run-synthetic-tests SECRET_RS=[registers]
```

To run a specific test with the information flow analysis, run the command:

```
make run-one-synthetic-test TEST_NAME=<testname> SECRET_RS=[registers]
```
Note: Important to note that <testname> should be without the .asm extenstion.
Note: The list [registers] should be written in the form: "r0 r1 r2".

### Example
Run the test ifStatement.asm with r1 and r2 as the secret registers:

```
make run-one-synthetic-test TEST_NAME=ifStatement SECRET_RS="r1 r2"
```

eBPF Tests
-------------
To run a specific eBPF tests with the information flow analysis, run the command:

```
make run-one-ebpf-test EBPF_PROG=<testname> SECRET_RS=[registers]
```

CFG
-------------
The CFG graphs will be created in the directory examples/graphs/ with the same name as the test. 

Clean Project
-------------
To run cabal clean, remove all the created graphs and dot files run:

```
make clean
```

To only remove the graphs, run the command:

```
make clean-graphs
```

Run the program using cabal
-----------------
To make a `dot` file of the CFG for an eBPF assembler file and execute
the analysis, run the command:

```
cabal run ebpf-cfg -- examples/<testname>.asm <dotfilename>.dot
```

To make a PDF out of the `dot` file run the command (requires
[graphviz](https://graphviz.org/)):

```
dot -Tpdf <dotfilename>.dot -o <pdfname>.pdf
```
