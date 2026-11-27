#!/usr/bin/env python3
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: Apache-2.0

"""Summarize the output of the tbench programs built by 'make bench'.

    bench_report.py FILE...

Each FILE is the output of one tbench run, with lines of the form

    BENCH LABEL OPERATION MEDIAN MIN ITER

where LABEL is MODE-KEY_VALUE-KEY_VALUE..., for example
O2-rtc_disabled-contracts_disabled for the SPARK benchmark or
O3-overflow_enabled for the Rust one. Prints a table with one row per
build variant, giving the median cycles for each operation, and how many
times slower each variant is than the fastest.

Exits with status 1 if any file has no results.
"""

import sys

OPERATIONS = ["Keygen", "Sign", "Verify"]
MODES = ["debug", "Og", "O0", "O1", "O2", "O3", "Os", "Oz"]

#  Column headings for the KEY parts of labels
HEADINGS = {"rtc": "Runtime", "contracts": "Contracts", "overflow": "Overflow"}


def split_label(label):
    """Return (mode, [(key, value), ...]) for a label"""
    parts = label.split("-")
    return parts[0], [tuple(p.split("_", 1)) if "_" in p else (p, "") for p in parts[1:]]


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
    mode, rest = split_label(label)
    return (MODES.index(mode) if mode in MODES else len(MODES), mode, rest)


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
    keys = [k for k, _ in split_label(next(iter(rows)))[1]]
    header = f"{'Mode':6}" + "".join(f" {HEADINGS.get(k, k):9}" for k in keys)
    for op in OPERATIONS:
        header += f" {op:>22}"
    print(header)
    print("-" * len(header))
    for label in sorted(rows, key=sort_key):
        mode, rest = split_label(label)
        line = f"{mode:6}" + "".join(f" {v:9}" for _, v in rest)
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
