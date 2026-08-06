# HQC Reference Code in SPARK/Ada

This library implements HQC, soon to be FIPS-207.

This implementation is written in SPARK - a subset of Ada that is designed
for static verification - and has been subject to verification
with the SPARK toolset.

If the reader is not familiar with SPARK, then [start here](https://learn.adacore.com/).

## IMPORTANT WARNING

This implementation is absolutely NOT intended for production or any use
in a "high assurance" setting. In particular:

* While the code is written in a "constant time" style, this property is not formally verified at
the level of the generated code and micro-architecture, and is not guranteed to be preserved by all compilers.

* Secondly, intermediate values are not sanitized at present.

* Finally, performance is unlikely to be competetive with other, more optimized, implementations.

## Goals

### From-scratch implementation

This code is basically a re-write of the HQC reference C code as it as
in February 2026. Updates for the draft of FIPS-207 will following in due course.

### Readability and correspondence with the reference code

The code is designed to be trivially traceable to the HQC C code
reference implementation. In particular, each C translation
unit of the original becomes a (nested) package in the SPARK Code.

### Hybrid static and dynamic verification

This implementation takes a hybrid verification approach that combines
static verification with dynamic testing. Specifically:

* Static verification of the absence of undefined behaviour, plus
memory-safety and type-safety with respect to the stated types,
pre-conditions, post-conditions, and assertions. The proof
is "auto-active" in that it is completely automated
using the standard provers that ship with the SPARK toolset,
and based on the types and assertions in the code alone.

* Static verification of worst-case memory consumption.

* Dynamic testing of functional behaviour with respect to the KATs.

### Minimal dependencies and SBOM

In line with SPARK's design as a "bare metal" programming language,
this implementation has only two dependencies:

* LibKeccak - a SPARK implementation of SHA3 from Daniel King. This is imported
as a sub-module of this repository.

* GNU libc. The compiler generates calls to memset() (for initialization of array objects)
and memcpy() (for assignment and concatenation of arrays) and nothing else.

No other components of the Ada runtime library are used.

### Portability

Given that SPARK is unambiguous, the code should exhibit identical behaviour
on all target platforms, operating systems, and CPU ISAs. Potential targets
are only limited by the availability of a reasonably recent build of GCC or
LLVM that enable the Ada compiler, covering most contemporary 32- and 64-bit
ISAs.

## Not Goals

### Performance

Performance is not a design goal of the current implementation.
Benchmarks and potential performance improvements may be added in the future.

At this stage, there has been no attempt at all to optimize performance of this code.
The code follows the intent and letter of the specification, even where this might
involve some overhead.

## Tools

This library has been developed and compiled with GNAT 15.3.0 and GPRBuild 26.0.0 on macOS,
both available from [here](https://github.com/alire-project/GNAT-FSF-builds/releases)

To reproduce the proofs, you'll need GNATProve 15.1.0 or higher, available
from the same site.

## Cloning, building and running the tests

### Clone this repo and initialize submodules

```
git clone https://github.com/awslabs/LibFormalPQC.git
cd LibFormalPQC
git submodule init
git submodule update
```

### Initial configuration and build of LibKeccak

```
cd libkeccak
alr build
```

### Run KATs

```
cd HQC/spark_ada
make
```

should result in:

```
gprbuild -Phqc -XHQC_PARAM=1 -XHQC_BUILD_MODE=debug -XHQC_RUNTIME_CHECKS=enabled -XHQC_CONTRACTS_CHECKS=enabled
Compile
   [Ada]          test_intermediates.adb
   [Ada]          test_kat.adb
   [Ada]          hqc.adb
Bind
   [gprbind]      test_intermediates.bexch
   [Ada]          test_intermediates.ali
   [gprbind]      test_kat.bexch
   [Ada]          test_kat.ali
Link
   [link]         test_intermediates.adb
   [link]         test_kat.adb
gprbuild -Phqc -XHQC_PARAM=3 -XHQC_BUILD_MODE=debug -XHQC_RUNTIME_CHECKS=enabled -XHQC_CONTRACTS_CHECKS=enabled
Compile
   [Ada]          test_intermediates.adb
   [Ada]          test_kat.adb
   [Ada]          hqc.adb
Bind
   [gprbind]      test_intermediates.bexch
   [Ada]          test_intermediates.ali
   [gprbind]      test_kat.bexch
   [Ada]          test_kat.ali
Link
   [link]         test_intermediates.adb
   [link]         test_kat.adb
gprbuild -Phqc -XHQC_PARAM=5 -XHQC_BUILD_MODE=debug -XHQC_RUNTIME_CHECKS=enabled -XHQC_CONTRACTS_CHECKS=enabled
Compile
   [Ada]          test_intermediates.adb
   [Ada]          test_kat.adb
   [Ada]          hqc.adb
Bind
   [gprbind]      test_intermediates.bexch
   [Ada]          test_intermediates.ali
   [gprbind]      test_kat.bexch
   [Ada]          test_kat.ali
Link
   [link]         test_intermediates.adb
   [link]         test_kat.adb
obj1/test_intermediates >kats/hqc-1/tinew.txt
obj1/test_kat >kats/hqc-1/katsnew.txt
obj3/test_intermediates >kats/hqc-3/tinew.txt
obj3/test_kat >kats/hqc-3/katsnew.txt
obj5/test_intermediates >kats/hqc-5/tinew.txt
obj5/test_kat >kats/hqc-5/katsnew.txt
diff -b kats/hqc-1/tiref.txt kats/hqc-1/tinew.txt
diff -b kats/hqc-3/tiref.txt kats/hqc-3/tinew.txt
diff -b kats/hqc-5/tiref.txt kats/hqc-5/tinew.txt
diff -b kats/hqc-1/katsref.txt kats/hqc-1/katsnew.txt
diff -b kats/hqc-3/katsref.txt kats/hqc-3/katsnew.txt
diff -b kats/hqc-5/katsref.txt kats/hqc-5/katsnew.txt
```

showing no differences between the computed results and the reference results.

## Reproducing the proofs

The configuration and options for the proof tools are stored in
the `mlkem.gpr` file.  Reproducing the proof of just the
HQC package for the HQC-1 parameter set:

```
cd HQC/spark_ada
make proof1
```

That should show lots and lots of proofs marked with "Info" indicating success, and
zero "Warning" or "Error" lines.

A more details summary of the proof can be inspected in `obj1/gnatprove/gnatprove.out`
In short:

```
=========================
Summary of SPARK analysis
=========================

----------------------------------------------------------------------------------------------------------------------------
SPARK Analysis results        Total         Flow                                              Provers   Justified   Unproved
----------------------------------------------------------------------------------------------------------------------------
Data Dependencies                70           70                                                    .           .          .
Flow Dependencies                 .            .                                                    .           .          .
Initialization                  245          234                                              11 (Z3)           .          .
Non-Aliasing                      1            1                                                    .           .          .
Run-time Checks                 547            .     547 (CVC5DEF 5%, Trivial 5%, Z3 87%, altergo 2%)           .          .
Assertions                      117            .    117 (CVC5DEF 5%, Trivial 19%, Z3 74%, altergo 2%)           .          .
Functional Contracts             96            .      96 (CVC5DEF 8%, Trivial 6%, Z3 83%, altergo 2%)           .          .
LSP Verification                  .            .                                                    .           .          .
Termination                      51           42                                               4 (Z3)           5          .
Concurrency                       .            .                                                    .           .          .
----------------------------------------------------------------------------------------------------------------------------
Total                          1127    347 (31%)                                            775 (69%)      5 (0%)          .
```

Similarly, proofs for the HQC-3 and HQC-5 parameter sets can be run with the `proof3` and `proof5` Makefile targets
respectively.
