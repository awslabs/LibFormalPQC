#!/usr/bin/env python3
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: Apache-2.0

"""Check the output of tkats against FIPS 205 section 11.1.

Reads the output of tkats (from a file named on the command line, or
stdin), recomputes each result independently using Python's
hashlib.shake_256, and reports any mismatch.

Exits with status 0 if every record matches and every function was
tested at least once, and status 1 otherwise.
"""

import hashlib
import sys

# SLH-DSA-SHAKE-256s parameters (FIPS 205 Table 2)
N = 32
M = 47
ADRS_BYTES = 32

# For each function: the inputs in the order that FIPS 205 section 11.1
# concatenates them (which is not always parameter order: see PRF),
# the expected length of each input (None for a variable-length message),
# and the output length in bytes.
SPECS = {
    "PRF_Msg": ([("SK_Prf", N), ("Opt_Rand", N), ("M", None)], N),
    "H_Msg":   ([("R", N), ("PK_Seed", N), ("PK_Root", N), ("M", None)], M),
    "PRF":     ([("PK_Seed", N), ("ADRS", ADRS_BYTES), ("SK_Seed", N)], N),
    "T_L":     ([("PK_Seed", N), ("ADRS", ADRS_BYTES), ("M_L", None)], N),
    "H":       ([("PK_Seed", N), ("ADRS", ADRS_BYTES), ("M2", 2 * N)], N),
    "F":       ([("PK_Seed", N), ("ADRS", ADRS_BYTES), ("M1", N)], N),
}


def parse_records(lines):
    """Yield one dict per blank-line-separated record of 'Key = Value' lines."""
    record = {}
    for line_no, line in enumerate(lines, start=1):
        line = line.strip()
        if not line:
            if record:
                yield record
                record = {}
            continue
        key, sep, value = line.partition("=")
        if not sep:
            raise ValueError(f"line {line_no}: expected 'Key = Value', got {line!r}")
        record[key.strip()] = value.strip()
    if record:
        yield record


def check_record(record):
    """Return None if the record is correct, or a description of the problem."""
    name = record.get("Function")
    if name not in SPECS:
        return f"unknown function {name!r}"
    inputs, out_len = SPECS[name]

    data = b""
    for field, length in inputs:
        if field not in record:
            return f"missing input {field}"
        value = bytes.fromhex(record[field])
        if length is not None and len(value) != length:
            return f"{field} is {len(value)} bytes, expected {length}"
        if name == "T_L" and field == "M_L" and (len(value) == 0 or len(value) % N != 0):
            return f"M_L is {len(value)} bytes, not a positive multiple of {N}"
        data += value

    if "Result" not in record:
        return "missing Result"
    result = bytes.fromhex(record["Result"])
    expected = hashlib.shake_256(data).digest(out_len)
    if result != expected:
        return f"Result {result.hex()} /= expected {expected.hex()}"
    return None


def main():
    if len(sys.argv) > 2:
        print(f"usage: {sys.argv[0]} [tkats_output_file]", file=sys.stderr)
        return 1

    if len(sys.argv) == 2:
        with open(sys.argv[1], encoding="ascii") as f:
            lines = f.readlines()
    else:
        lines = sys.stdin.readlines()

    passed = {name: 0 for name in SPECS}
    failures = 0
    for record in parse_records(lines):
        problem = check_record(record)
        label = f"{record.get('Function')} Count {record.get('Count')}"
        if problem is None:
            passed[record["Function"]] += 1
        else:
            failures += 1
            print(f"FAIL {label}: {problem}")

    for name, count in passed.items():
        print(f"{name:8} {count:3} passed")
        if count == 0:
            failures += 1
            print(f"FAIL {name}: no test cases found")

    if failures:
        print(f"{failures} failure(s)")
        return 1
    print("All hash function KATs passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
