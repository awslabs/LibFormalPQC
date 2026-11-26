#!/usr/bin/env python3
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: Apache-2.0

"""Check the output of 'tkats fors' against a reference model of FIPS 205 section 8.

Reads the output of 'tkats fors' (from a file named on the command line,
or stdin), recomputes each result with the reference model below, and
reports any mismatch. For FORS_Round_Trip records, it also checks that
the public key computed from the signature equals the FORS public key,
T_k of the roots of the k trees.

The model follows the pseudocode of FIPS 205 Algorithms 14 to 17
closely, including its by-reference updates to ADRS (which the
recursive calls in Algorithm 15 share), so that it is independent of
the SPARK code, which uses pure functions.

Exits with status 0 if every record matches and every function was
tested at least once, and status 1 otherwise.
"""

import sys

from check_hash_kats import parse_records
from check_wots_kats import ADRS, N, base_2b, f, prf, t_l
from check_xmss_kats import h

# SLH-DSA-SHAKE-256s parameters (FIPS 205 Table 2)
A = 14
K = 22

# Address types (FIPS 205 section 4.2)
FORS_ROOTS = 4
FORS_PRF = 6

MD_BYTES = (K * A + 7) // 8
FORS_SIG_BYTES = K * (A + 1) * N


def fors_sk_gen(sk_seed, pk_seed, adrs, idx):
    """Algorithm 14"""
    sk_adrs = adrs.copy()
    sk_adrs.set_type_and_clear(FORS_PRF)
    sk_adrs.set_key_pair_address(adrs.get_key_pair_address())
    sk_adrs.set_tree_index(idx)
    return prf(pk_seed, sk_seed, sk_adrs)


def fors_node(sk_seed, i, z, pk_seed, adrs):
    """Algorithm 15"""
    if z == 0:
        sk = fors_sk_gen(sk_seed, pk_seed, adrs, i)
        adrs.set_tree_height(0)
        adrs.set_tree_index(i)
        node = f(pk_seed, adrs, sk)
    else:
        lnode = fors_node(sk_seed, 2 * i, z - 1, pk_seed, adrs)
        rnode = fors_node(sk_seed, 2 * i + 1, z - 1, pk_seed, adrs)
        adrs.set_tree_height(z)
        adrs.set_tree_index(i)
        node = h(pk_seed, adrs, lnode + rnode)
    return node


def fors_sign(md, sk_seed, pk_seed, adrs):
    """Algorithm 16. Returns SIG_FORS as one byte string"""
    sig_fors = b""
    indices = base_2b(md, A, K)
    for i in range(K):
        sig_fors += fors_sk_gen(sk_seed, pk_seed, adrs, i * 2**A + indices[i])
        auth = b""
        for j in range(A):
            s = (indices[i] >> j) ^ 1
            auth += fors_node(sk_seed, i * 2**(A - j) + s, j, pk_seed, adrs)
        sig_fors += auth
    return sig_fors


def fors_pk_from_sig(sig_fors, md, pk_seed, adrs):
    """Algorithm 17"""
    indices = base_2b(md, A, K)
    root = b""
    for i in range(K):
        sk = sig_fors[i * (A + 1) * N:(i * (A + 1) + 1) * N]
        adrs.set_tree_height(0)
        adrs.set_tree_index(i * 2**A + indices[i])
        node0 = f(pk_seed, adrs, sk)
        auth = sig_fors[(i * (A + 1) + 1) * N:(i + 1) * (A + 1) * N]
        for j in range(A):
            adrs.set_tree_height(j + 1)
            auth_j = auth[j * N:(j + 1) * N]
            if (indices[i] >> j) % 2 == 0:
                adrs.set_tree_index(adrs.get_tree_index() // 2)
                node1 = h(pk_seed, adrs, node0 + auth_j)
            else:
                adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
                node1 = h(pk_seed, adrs, auth_j + node0)
            node0 = node1
        root += node0
    fors_pk_adrs = adrs.copy()
    fors_pk_adrs.set_type_and_clear(FORS_ROOTS)
    fors_pk_adrs.set_key_pair_address(adrs.get_key_pair_address())
    return t_l(pk_seed, fors_pk_adrs, root)


def fors_pk(sk_seed, pk_seed, adrs):
    """The FORS public key: T_k of the roots of the k trees"""
    root = b"".join(fors_node(sk_seed, i, A, pk_seed, adrs.copy()) for i in range(K))
    fors_pk_adrs = adrs.copy()
    fors_pk_adrs.set_type_and_clear(FORS_ROOTS)
    fors_pk_adrs.set_key_pair_address(adrs.get_key_pair_address())
    return t_l(pk_seed, fors_pk_adrs, root)


# ---------------------------------------------------------------------
# Checking tkats output
# ---------------------------------------------------------------------

# For each function: the input fields and their lengths in bytes
# (None for a decimal integer)
SPECS = {
    "FORS_SK_Gen":      [("SK_Seed", N), ("PK_Seed", N), ("ADRS", 32), ("Idx", None)],
    "FORS_Node":        [("SK_Seed", N), ("I", None), ("Z", None), ("PK_Seed", N), ("ADRS", 32)],
    "FORS_Sign":        [("MD", MD_BYTES), ("SK_Seed", N), ("PK_Seed", N), ("ADRS", 32)],
    "FORS_PK_From_Sig": [("Sig_FORS", FORS_SIG_BYTES), ("MD", MD_BYTES), ("PK_Seed", N),
                         ("ADRS", 32)],
    "FORS_Round_Trip":  [("MD", MD_BYTES), ("SK_Seed", N), ("PK_Seed", N), ("ADRS", 32)],
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
        if name == "FORS_SK_Gen":
            if not 0 <= v["Idx"] < K * 2**A:
                return f"Idx = {v['Idx']} out of range"
            checks = [("Result", fors_sk_gen(v["SK_Seed"], v["PK_Seed"], adrs, v["Idx"]))]
        elif name == "FORS_Node":
            if not (0 <= v["Z"] <= A and 0 <= v["I"] < K * 2**(A - v["Z"])):
                return f"I = {v['I']}, Z = {v['Z']} out of range"
            checks = [("Result", fors_node(v["SK_Seed"], v["I"], v["Z"], v["PK_Seed"], adrs))]
        elif name == "FORS_Sign":
            checks = [("Result", fors_sign(v["MD"], v["SK_Seed"], v["PK_Seed"], adrs))]
        elif name == "FORS_PK_From_Sig":
            checks = [("Result", fors_pk_from_sig(v["Sig_FORS"], v["MD"], v["PK_Seed"], adrs))]
        else:  # FORS_Round_Trip
            pk = fors_pk(v["SK_Seed"], v["PK_Seed"], adrs.copy())
            sig = fors_sign(v["MD"], v["SK_Seed"], v["PK_Seed"], adrs.copy())
            pk_sig = fors_pk_from_sig(sig, v["MD"], v["PK_Seed"], adrs.copy())
            if pk_sig != pk:
                return "reference model round trip failed"
            if get_output(record, "PK_From_Sig") != get_output(record, "PK"):
                return "PK_From_Sig /= PK"
            checks = [("PK", pk), ("PK_From_Sig", pk_sig)]
        for field, expected in checks:
            result = get_output(record, field)
            if result != expected:
                return f"{field} {result.hex()[:64]}... /= expected {expected.hex()[:64]}..."
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
    print("All FORS KATs passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
