#!/usr/bin/env python3
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: Apache-2.0

"""Check the output of 'tkats xmss' against a reference model of FIPS 205 section 6.

Reads the output of 'tkats xmss' (from a file named on the command line,
or stdin), recomputes each result with the reference model below, and
reports any mismatch. For XMSS_Round_Trip records, it also checks that
the root computed from the signature equals the root of the XMSS tree.

The model follows the pseudocode of FIPS 205 Algorithms 9 to 11 closely,
including its by-reference updates to ADRS (which the recursive calls
in Algorithm 9 share), so that it is independent of the SPARK code,
which uses pure functions.

Exits with status 0 if every record matches and every function was
tested at least once, and status 1 otherwise.
"""

import hashlib
import sys

from check_hash_kats import parse_records
from check_wots_kats import ADRS, LEN, N, WOTS_HASH, wots_pk_from_sig, wots_pk_gen, wots_sign

# SLH-DSA-SHAKE-256s parameters (FIPS 205 Table 2)
H_TICK = 8

# Address types (FIPS 205 section 4.2)
TREE = 2

XMSS_SIG_BYTES = (LEN + H_TICK) * N


def h(pk_seed, adrs, m2):
    """H from FIPS 205 section 11.1"""
    return hashlib.shake_256(pk_seed + adrs.bytes() + m2).digest(N)


def xmss_node(sk_seed, i, z, pk_seed, adrs):
    """Algorithm 9"""
    if z == 0:
        adrs.set_type_and_clear(WOTS_HASH)
        adrs.set_key_pair_address(i)
        node = wots_pk_gen(sk_seed, pk_seed, adrs)
    else:
        lnode = xmss_node(sk_seed, 2 * i, z - 1, pk_seed, adrs)
        rnode = xmss_node(sk_seed, 2 * i + 1, z - 1, pk_seed, adrs)
        adrs.set_type_and_clear(TREE)
        adrs.set_tree_height(z)
        adrs.set_tree_index(i)
        node = h(pk_seed, adrs, lnode + rnode)
    return node


def xmss_sign(m, sk_seed, idx, pk_seed, adrs):
    """Algorithm 10. Returns SIG_XMSS = sig || AUTH as one byte string"""
    auth = b""
    for j in range(H_TICK):
        k = (idx >> j) ^ 1
        auth += xmss_node(sk_seed, k, j, pk_seed, adrs)
    adrs.set_type_and_clear(WOTS_HASH)
    adrs.set_key_pair_address(idx)
    sig = wots_sign(m, sk_seed, pk_seed, adrs)
    return sig + auth


def xmss_pk_from_sig(idx, sig_xmss, m, pk_seed, adrs):
    """Algorithm 11"""
    adrs.set_type_and_clear(WOTS_HASH)
    adrs.set_key_pair_address(idx)
    sig = sig_xmss[0:LEN * N]
    auth = sig_xmss[LEN * N:(LEN + H_TICK) * N]
    node0 = wots_pk_from_sig(sig, m, pk_seed, adrs)
    adrs.set_type_and_clear(TREE)
    adrs.set_tree_index(idx)
    for k in range(H_TICK):
        adrs.set_tree_height(k + 1)
        auth_k = auth[k * N:(k + 1) * N]
        if (idx >> k) % 2 == 0:
            adrs.set_tree_index(adrs.get_tree_index() // 2)
            node1 = h(pk_seed, adrs, node0 + auth_k)
        else:
            adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
            node1 = h(pk_seed, adrs, auth_k + node0)
        node0 = node1
    return node0


# ---------------------------------------------------------------------
# Checking tkats output
# ---------------------------------------------------------------------

# For each function: the input fields and their lengths in bytes
# (None for a decimal integer)
SPECS = {
    "XMSS_Node":        [("SK_Seed", N), ("I", None), ("Z", None), ("PK_Seed", N), ("ADRS", 32)],
    "XMSS_Sign":        [("M", N), ("SK_Seed", N), ("Idx", None), ("PK_Seed", N), ("ADRS", 32)],
    "XMSS_PK_From_Sig": [("Idx", None), ("Sig_XMSS", XMSS_SIG_BYTES), ("M", N), ("PK_Seed", N),
                         ("ADRS", 32)],
    "XMSS_Round_Trip":  [("M", N), ("SK_Seed", N), ("Idx", None), ("PK_Seed", N), ("ADRS", 32)],
}


def get_inputs(name, record):
    """Return a dict of decoded inputs, or raise ValueError"""
    values = {}
    for field, length in SPECS[name]:
        if field not in record:
            raise ValueError(f"missing input {field}")
        if length is None:
            values[field] = int(record[field])
        else:
            value = bytes.fromhex(record[field])
            if len(value) != length:
                raise ValueError(f"{field} is {len(value)} bytes, expected {length}")
            values[field] = value
    return values


def get_output(record, field):
    if field not in record:
        raise ValueError(f"missing {field}")
    return bytes.fromhex(record[field])


def check_record(record):
    """Return None if the record is correct, or a description of the problem."""
    name = record.get("Function")
    if name not in SPECS:
        return f"unknown function {name!r}"
    try:
        v = get_inputs(name, record)
        adrs = ADRS(v["ADRS"])
        if "Idx" in v and not 0 <= v["Idx"] < 2**H_TICK:
            return f"Idx = {v['Idx']} out of range"
        if name == "XMSS_Node":
            if not (0 <= v["Z"] <= H_TICK and 0 <= v["I"] < 2**(H_TICK - v["Z"])):
                return f"I = {v['I']}, Z = {v['Z']} out of range"
            checks = [("Result", xmss_node(v["SK_Seed"], v["I"], v["Z"], v["PK_Seed"], adrs))]
        elif name == "XMSS_Sign":
            checks = [("Result", xmss_sign(v["M"], v["SK_Seed"], v["Idx"], v["PK_Seed"], adrs))]
        elif name == "XMSS_PK_From_Sig":
            checks = [("Result",
                       xmss_pk_from_sig(v["Idx"], v["Sig_XMSS"], v["M"], v["PK_Seed"], adrs))]
        else:  # XMSS_Round_Trip
            root = xmss_node(v["SK_Seed"], 0, H_TICK, v["PK_Seed"], adrs.copy())
            sig = xmss_sign(v["M"], v["SK_Seed"], v["Idx"], v["PK_Seed"], adrs.copy())
            root_sig = xmss_pk_from_sig(v["Idx"], sig, v["M"], v["PK_Seed"], adrs.copy())
            if root_sig != root:
                return "reference model round trip failed"
            if get_output(record, "PK_From_Sig") != get_output(record, "Root"):
                return "PK_From_Sig /= Root"
            checks = [("Root", root), ("PK_From_Sig", root_sig)]
        for field, expected in checks:
            result = get_output(record, field)
            if result != expected:
                return f"{field} {result.hex()} /= expected {expected.hex()}"
    except ValueError as e:
        return str(e)
    return None


def main():
    if len(sys.argv) > 2:
        print(f"usage: {sys.argv[0]} [tkats_output_file]", file=sys.stderr)
        return 1

    if len(sys.argv) == 2:
        with open(sys.argv[1], encoding="ascii") as fd:
            lines = fd.readlines()
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
        print(f"{name:16} {count:3} passed")
        if count == 0:
            failures += 1
            print(f"FAIL {name}: no test cases found")

    if failures:
        print(f"{failures} failure(s)")
        return 1
    print("All XMSS KATs passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
