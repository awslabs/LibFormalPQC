#!/usr/bin/env python3
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: Apache-2.0

"""Check the output of 'tkats slh' against a reference model of FIPS 205 section 9.

Reads the output of 'tkats slh' (from a file named on the command line,
or stdin), recomputes each result with the reference model below, and
reports any mismatch. Each SLH_Round_Trip record has a key pair, a
signature, and the results of verifying it and five changed versions of
it. The checker also checks that only the first of these is TRUE.

The model follows the pseudocode of FIPS 205 Algorithms 18 to 20
closely, and uses the models of sections 4 to 8 in the other checkers.
It is also used by check_acvp.py.

Exits with status 0 if every record matches and every function was
tested at least once, and status 1 otherwise.
"""

import hashlib
import sys

from check_hash_kats import parse_records
from check_wots_kats import ADRS, LEN, N, to_int
from check_xmss_kats import H_TICK, xmss_node
from check_ht_kats import D, H, HT_SIG_BYTES, ht_sign, ht_verify
from check_fors_kats import A, FORS_SIG_BYTES, K, fors_pk_from_sig, fors_sign

# Address types (FIPS 205 section 4.2)
FORS_TREE = 3

# m, and the parts of the digest (FIPS 205 section 9)
MD_BYTES = (K * A + 7) // 8
TREE_BYTES = (H - H_TICK + 7) // 8
LEAF_BYTES = (H_TICK + 7) // 8
M = MD_BYTES + TREE_BYTES + LEAF_BYTES

SIG_BYTES = (1 + K * (1 + A) + H + D * LEN) * N
assert SIG_BYTES == N + FORS_SIG_BYTES + HT_SIG_BYTES == 29792


def prf_msg(sk_prf, opt_rand, msg):
    """PRF_msg from FIPS 205 section 11.1"""
    return hashlib.shake_256(sk_prf + opt_rand + msg).digest(N)


def h_msg(r, pk_seed, pk_root, msg):
    """H_msg from FIPS 205 section 11.1"""
    return hashlib.shake_256(r + pk_seed + pk_root + msg).digest(M)


def slh_keygen_internal(sk_seed, sk_prf, pk_seed):
    """Algorithm 18. Returns (SK, PK) as byte strings"""
    adrs = ADRS(bytes(32))
    adrs.set_layer_address(D - 1)
    pk_root = xmss_node(sk_seed, 0, H_TICK, pk_seed, adrs)
    return sk_seed + sk_prf + pk_seed + pk_root, pk_seed + pk_root


def split_digest(digest):
    """Algorithm 19 lines 6 to 10, and Algorithm 20 lines 9 to 13"""
    md = digest[0:MD_BYTES]
    tmp_idx_tree = digest[MD_BYTES:MD_BYTES + TREE_BYTES]
    tmp_idx_leaf = digest[MD_BYTES + TREE_BYTES:MD_BYTES + TREE_BYTES + LEAF_BYTES]
    idx_tree = to_int(tmp_idx_tree, TREE_BYTES) % 2**(H - H_TICK)
    idx_leaf = to_int(tmp_idx_leaf, LEAF_BYTES) % 2**H_TICK
    return md, idx_tree, idx_leaf


def slh_sign_internal(msg, sk, addrnd):
    """Algorithm 19. addrnd is None for the deterministic variant"""
    sk_seed, sk_prf, pk_seed, pk_root = (sk[i * N:(i + 1) * N] for i in range(4))
    adrs = ADRS(bytes(32))
    opt_rand = pk_seed if addrnd is None else addrnd
    r = prf_msg(sk_prf, opt_rand, msg)
    sig = r
    digest = h_msg(r, pk_seed, pk_root, msg)
    md, idx_tree, idx_leaf = split_digest(digest)
    adrs.set_tree_address(idx_tree)
    adrs.set_type_and_clear(FORS_TREE)
    adrs.set_key_pair_address(idx_leaf)
    sig_fors = fors_sign(md, sk_seed, pk_seed, adrs)
    sig = sig + sig_fors
    pk_fors = fors_pk_from_sig(sig_fors, md, pk_seed, adrs)
    sig_ht = ht_sign(pk_fors, sk_seed, pk_seed, idx_tree, idx_leaf)
    return sig + sig_ht


def slh_verify_internal(msg, sig, pk):
    """Algorithm 20"""
    if len(sig) != SIG_BYTES:
        return False
    pk_seed, pk_root = pk[0:N], pk[N:2 * N]
    adrs = ADRS(bytes(32))
    r = sig[0:N]
    sig_fors = sig[N:N + FORS_SIG_BYTES]
    sig_ht = sig[N + FORS_SIG_BYTES:SIG_BYTES]
    digest = h_msg(r, pk_seed, pk_root, msg)
    md, idx_tree, idx_leaf = split_digest(digest)
    adrs.set_tree_address(idx_tree)
    adrs.set_type_and_clear(FORS_TREE)
    adrs.set_key_pair_address(idx_leaf)
    pk_fors = fors_pk_from_sig(sig_fors, md, pk_seed, adrs)
    return ht_verify(pk_fors, sig_ht, pk_seed, idx_tree, idx_leaf, pk_root)


# ---------------------------------------------------------------------
# Checking tkats output
# ---------------------------------------------------------------------

def get_bytes(record, field, length=None):
    if field not in record:
        raise ValueError(f"missing {field}")
    value = bytes.fromhex(record[field])
    if length is not None and len(value) != length:
        raise ValueError(f"{field} is {len(value)} bytes, expected {length}")
    return value


def get_bool(record, field):
    if field not in record:
        raise ValueError(f"missing {field}")
    if record[field] not in ("TRUE", "FALSE"):
        raise ValueError(f"{field} = {record[field]!r}, expected TRUE or FALSE")
    return record[field] == "TRUE"


def flip(data, i):
    return data[:i] + bytes([data[i] ^ 1]) + data[i + 1:]


def check_record(record):
    """Return None if the record is correct, or a description of the problem."""
    name = record.get("Function")
    if name != "SLH_Round_Trip":
        return f"unknown function {name!r}"
    try:
        sk_seed = get_bytes(record, "SK_Seed", N)
        sk_prf = get_bytes(record, "SK_Prf", N)
        pk_seed = get_bytes(record, "PK_Seed", N)
        msg = get_bytes(record, "Msg")
        addrnd = get_bytes(record, "Addrnd", N) if "Addrnd" in record else None

        sk, pk = slh_keygen_internal(sk_seed, sk_prf, pk_seed)
        sig = slh_sign_internal(msg, sk, addrnd)
        for field, expected in [("SK", sk), ("PK", pk), ("Sig", sig)]:
            if get_bytes(record, field, len(expected)) != expected:
                return f"{field} differs from the reference model"

        # The same changes as in SLH.KAT.SLH_Round_Trip_KATs
        wrong_root = pk[:N] + flip(pk[N:], 0)
        cases = [
            ("Verify", slh_verify_internal(msg, sig, pk), True),
            ("Verify_Tampered_R", slh_verify_internal(msg, flip(sig, 5), pk), False),
            ("Verify_Tampered_FORS",
             slh_verify_internal(msg, flip(sig, N + 1000), pk), False),
            ("Verify_Tampered_HT",
             slh_verify_internal(msg, flip(sig, N + FORS_SIG_BYTES + 10000), pk), False),
            ("Verify_Wrong_Msg", slh_verify_internal(msg + b"\x00", sig, pk), False),
            ("Verify_Wrong_Root", slh_verify_internal(msg, sig, wrong_root), False),
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

    passed = {"deterministic": 0, "hedged": 0}
    failures = 0
    for record in parse_records(lines):
        problem = check_record(record)
        label = f"{record.get('Function')} Count {record.get('Count')}"
        if problem is None:
            passed["hedged" if "Addrnd" in record else "deterministic"] += 1
        else:
            failures += 1
            print(f"FAIL {label}: {problem}")

    for name, count in passed.items():
        print(f"SLH_Round_Trip ({name}) {count:3} passed")
        if count == 0:
            failures += 1
            print(f"FAIL {name}: no test cases found")

    if failures:
        print(f"{failures} failure(s)")
        return 1
    print("All SLH-DSA KATs passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
