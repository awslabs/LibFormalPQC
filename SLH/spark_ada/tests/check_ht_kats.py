#!/usr/bin/env python3
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: Apache-2.0

"""Check the output of 'tkats ht' against a reference model of FIPS 205 section 7.

Reads the output of 'tkats ht' (from a file named on the command line,
or stdin), recomputes each result with the reference model below, and
reports any mismatch. For HT_Round_Trip records, it also checks that the
valid signature verifies, and that the changed signature, PK.root and
idx_leaf do not.

The model follows the pseudocode of FIPS 205 Algorithms 12 and 13
closely, including its reuse of one ADRS for every layer, so that it is
independent of the SPARK code, which builds a new ADRS for each layer.

Exits with status 0 if every record matches and every function was
tested at least once, and status 1 otherwise.
"""

import sys

from check_hash_kats import parse_records
from check_wots_kats import ADRS, LEN, N
from check_xmss_kats import H_TICK, XMSS_SIG_BYTES, xmss_node, xmss_pk_from_sig, xmss_sign

# SLH-DSA-SHAKE-256s parameters (FIPS 205 Table 2)
H = 64
D = 8

HT_SIG_BYTES = D * XMSS_SIG_BYTES
assert HT_SIG_BYTES == (H + D * LEN) * N


def ht_sign(m, sk_seed, pk_seed, idx_tree, idx_leaf):
    """Algorithm 12"""
    adrs = ADRS(bytes(32))
    adrs.set_tree_address(idx_tree)
    sig_tmp = xmss_sign(m, sk_seed, idx_leaf, pk_seed, adrs)
    sig_ht = sig_tmp
    root = xmss_pk_from_sig(idx_leaf, sig_tmp, m, pk_seed, adrs)
    for j in range(1, D):
        idx_leaf = idx_tree % 2**H_TICK
        idx_tree = idx_tree >> H_TICK
        adrs.set_layer_address(j)
        adrs.set_tree_address(idx_tree)
        sig_tmp = xmss_sign(root, sk_seed, idx_leaf, pk_seed, adrs)
        sig_ht = sig_ht + sig_tmp
        if j < D - 1:
            root = xmss_pk_from_sig(idx_leaf, sig_tmp, root, pk_seed, adrs)
    return sig_ht


def ht_verify(m, sig_ht, pk_seed, idx_tree, idx_leaf, pk_root):
    """Algorithm 13"""
    adrs = ADRS(bytes(32))
    adrs.set_tree_address(idx_tree)
    sig_tmp = sig_ht[0:XMSS_SIG_BYTES]
    node = xmss_pk_from_sig(idx_leaf, sig_tmp, m, pk_seed, adrs)
    for j in range(1, D):
        idx_leaf = idx_tree % 2**H_TICK
        idx_tree = idx_tree >> H_TICK
        adrs.set_layer_address(j)
        adrs.set_tree_address(idx_tree)
        sig_tmp = sig_ht[j * XMSS_SIG_BYTES:(j + 1) * XMSS_SIG_BYTES]
        node = xmss_pk_from_sig(idx_leaf, sig_tmp, node, pk_seed, adrs)
    return node == pk_root


def ht_root(sk_seed, pk_seed):
    """PK.root, as in Algorithm 18 (slh_keygen_internal) lines 1 to 3"""
    adrs = ADRS(bytes(32))
    adrs.set_layer_address(D - 1)
    return xmss_node(sk_seed, 0, H_TICK, pk_seed, adrs)


# ---------------------------------------------------------------------
# Checking tkats output
# ---------------------------------------------------------------------

# For each function: the input fields and their lengths in bytes
# (None for a decimal integer)
SPECS = {
    "HT_Verify":     [("M", N), ("Sig_HT", HT_SIG_BYTES), ("PK_Seed", N), ("Idx_Tree", None),
                      ("Idx_Leaf", None), ("PK_Root", N)],
    "HT_Round_Trip": [("M", N), ("SK_Seed", N), ("PK_Seed", N), ("Idx_Tree", None),
                      ("Idx_Leaf", None)],
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
    if not 0 <= values["Idx_Tree"] < 2**(H - H_TICK):
        raise ValueError(f"Idx_Tree = {values['Idx_Tree']} out of range")
    if not 0 <= values["Idx_Leaf"] < 2**H_TICK:
        raise ValueError(f"Idx_Leaf = {values['Idx_Leaf']} out of range")
    return values


def get_bytes(record, field, length):
    if field not in record:
        raise ValueError(f"missing {field}")
    value = bytes.fromhex(record[field])
    if len(value) != length:
        raise ValueError(f"{field} is {len(value)} bytes, expected {length}")
    return value


def get_bool(record, field):
    if field not in record:
        raise ValueError(f"missing {field}")
    if record[field] not in ("TRUE", "FALSE"):
        raise ValueError(f"{field} = {record[field]!r}, expected TRUE or FALSE")
    return record[field] == "TRUE"


def check_record(record):
    """Return None if the record is correct, or a description of the problem."""
    name = record.get("Function")
    if name not in SPECS:
        return f"unknown function {name!r}"
    try:
        v = get_inputs(name, record)
        if name == "HT_Verify":
            expected = ht_verify(v["M"], v["Sig_HT"], v["PK_Seed"], v["Idx_Tree"],
                                 v["Idx_Leaf"], v["PK_Root"])
            if get_bool(record, "Result") != expected:
                return f"Result {record['Result']} /= expected {expected}"
            return None

        # HT_Round_Trip
        m, sk_seed, pk_seed = v["M"], v["SK_Seed"], v["PK_Seed"]
        idx_tree, idx_leaf = v["Idx_Tree"], v["Idx_Leaf"]
        sig = ht_sign(m, sk_seed, pk_seed, idx_tree, idx_leaf)
        root = ht_root(sk_seed, pk_seed)
        for field, expected in [("Sig_HT", sig), ("PK_Root", root)]:
            result = get_bytes(record, field, len(expected))
            if result != expected:
                return f"{field} differs from the reference model"

        # The same changes as in SLH.KAT.HT_Round_Trip_KATs
        tampered = bytearray(sig)
        tampered[3 * XMSS_SIG_BYTES + LEN * N + 5 * N + 7] ^= 1
        wrong_root = bytes([root[0] ^ 1]) + root[1:]
        cases = [
            ("Verify", ht_verify(m, sig, pk_seed, idx_tree, idx_leaf, root), True),
            ("Verify_Tampered_Sig",
             ht_verify(m, bytes(tampered), pk_seed, idx_tree, idx_leaf, root), False),
            ("Verify_Wrong_Root",
             ht_verify(m, sig, pk_seed, idx_tree, idx_leaf, wrong_root), False),
            ("Verify_Wrong_Leaf",
             ht_verify(m, sig, pk_seed, idx_tree, idx_leaf ^ 1, root), False),
        ]
        for field, model, intended in cases:
            if model != intended:
                return f"reference model gives {field} = {model}, expected {intended}"
            if get_bool(record, field) != model:
                return f"{field} {record[field]} /= expected {model}"
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
    print("All hypertree KATs passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
