eBPF Information Flow Analysis
=======================
To run all the tests with the information flow analysis, run the make file:

```
make run-tests SECRET_REGISTERS=[registers]
```
To run a specific test with the information flow analysis, run the command:

```
make run-test EXAMPLE_NAME=<testname> SECRET_REGISTERS=[registers]
```
Important to note that <testname> should be without the .asm extenstion.

The CFG graphs will be created in the directory graphs/ with the same name as the test. 
To run cabal clean and remove all the created graphs and dot files run:

```
make clean
```

Visualise the CFG using cabal
-----------------
To make a `dot` file of the CFG for an eBPF assembler file, say
`examples/add.asm`, run the command:

```
cabal run ebpf-cfg -- examples/<testname>.asm <dotfilename>.dot
```

To make a PDF out of the `dot` file run the command (requires
[graphviz](https://graphviz.org/)):

```
dot -Tpdf <dotfilename>.dot -o <pdfname>.pdf
```

Example
-------------
Run the test ifStatement.asm with r1 and r2 as the secret registers:

```
make run-test EXAMPLE_NAME=ifStatement SECRET_REGISTERS=r1 r2
```
