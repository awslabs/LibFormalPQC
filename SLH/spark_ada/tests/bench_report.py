#!/usr/bin/env python3
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: Apache-2.0

"""Summarize the output of the tbench programs built by 'make bench'.

    bench_report.py FILE...

Each FILE is the output of one tbench run, with lines of the form

    BENCH LABEL OPERATION MEDIAN MIN ITER

where LABEL is MODE-rtc_RUNTIME_CHECKS-contracts_CONTRACTS. Prints a
table with one row per build variant, giving the median cycles for each
operation, and how many times slower each variant is than the fastest.

Exits with status 1 if any file has no results.
"""

import sys

OPERATIONS = ["Keygen", "Sign", "Verify"]
MODES = ["debug", "Og", "O1", "O2", "O3", "Os"]


def parse(path):
    results = {}
    label = None
    with open(path, encoding="ascii", errors="replace") as fd:
        for line in fd:
            fields = line.split()
            if len(fields) == 6 and fields[0] == "BENCH":
                label = fields[1]
                results[fields[2]] = (int(fields[3]), int(fields[4]), int(fields[5]))
    return label, results


def sort_key(label):
    mode, rtc, contracts = label.split("-")
    return (MODES.index(mode) if mode in MODES else len(MODES), rtc, contracts)


def main():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} FILE...", file=sys.stderr)
        return 1

    rows = {}
    missing = []
    for path in sys.argv[1:]:
        label, results = parse(path)
        if label is None or any(op not in results for op in OPERATIONS):
            missing.append(path)
        else:
            rows[label] = results
    if not rows:
        print("No benchmark results found")
        return 1

    best = {op: min(r[op][0] for r in rows.values()) for op in OPERATIONS}
    iters = next(iter(rows.values()))

    print("SLH-DSA-SHAKE-256s, median CPU cycles")
    print("Iterations: " + ", ".join(f"{op} {iters[op][2]}" for op in OPERATIONS))
    print("(x N.NN is the slowdown relative to the fastest variant)")
    print()
    header = f"{'Mode':6} {'Runtime':8} {'Contracts':9}"
    for op in OPERATIONS:
        header += f" {op:>22}"
    print(header)
    print("-" * len(header))
    for label in sorted(rows, key=sort_key):
        mode, rtc, contracts = label.split("-")
        line = f"{mode:6} {rtc[4:]:8} {contracts[10:]:9}"
        for op in OPERATIONS:
            median = rows[label][op][0]
            line += f" {median:>14,} x{median / best[op]:5.2f}"
        print(line)

    if missing:
        print()
        for path in missing:
            print(f"FAIL {path}: no results")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
