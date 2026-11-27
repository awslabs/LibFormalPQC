# Cycle counter

`hal.c` and `hal.h` are copied unchanged from
[mlkem-native](https://github.com/pq-code-package/mlkem-native/tree/main/test/hal)
(commit c5be9efec72363997dbef3b14662411fe178b73c), under the MIT licence
(see `../../THIRD-PARTY`). They are shared by the benchmarks of all the
implementations of SLH-DSA in this repository.

Select the counter with a C preprocessor symbol:

* `-DMAC_CYCLES`: Apple Silicon macOS, using the private `kperf`
  framework. The program must run as root.
* `-DPERF_CYCLES`: Linux, using `perf_event_open`. Needs
  `/proc/sys/kernel/perf_event_paranoid` to allow user-space counting
  (2 or less).
* `-DPMU_CYCLES`: read the CPU's cycle counter register directly
  (x86_64 `rdtsc`, AArch64 `pmccntr_el0`, RISC-V `rdcycle`). On AArch64
  Linux this needs a kernel module that enables user access.

With none of these, `get_cyclecounter` always returns 0.
