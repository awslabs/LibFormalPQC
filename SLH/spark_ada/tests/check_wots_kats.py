#!/usr/bin/env python3
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: Apache-2.0

"""Check the output of 'tkats wots' against a reference model of FIPS 205 section 5.

Reads the output of 'tkats wots' (from a file named on the command line,
or stdin), recomputes each result with the reference model below, and
reports any mismatch. For WOTS_Round_Trip records, it also checks that
the public key computed from the signature equals the generated one.

The model follows the pseudocode of FIPS 205 Algorithms 1 to 8 closely,
including its by-reference updates to ADRS, so that it is independent
of the SPARK code, which uses pure functions.

Exits with status 0 if every record matches and every function was
tested at least once, and status 1 otherwise.
"""

import hashlib
import sys

from check_hash_kats import parse_records

# SLH-DSA-SHAKE-256s parameters (FIPS 205 Table 2)
N = 32
LG_W = 4
W = 2**LG_W                        # (5.1)
LEN1 = (8 * N + LG_W - 1) // LG_W  # (5.2)
LEN2 = 3                           # (5.3)
LEN = LEN1 + LEN2                  # (5.4)

# Address types (FIPS 205 section 4.2)
WOTS_HASH = 0
WOTS_PK = 1
WOTS_PRF = 5


# ---------------------------------------------------------------------
# Section 4.4: Algorithms 2 to 4
# ---------------------------------------------------------------------

def to_int(x, n):
    """Algorithm 2"""
    total = 0
    for i in range(n):
        total = 256 * total + x[i]
    return total


def to_byte(x, n):
    """Algorithm 3"""
    total = x
    s = bytearray(n)
    for i in range(n):
        s[n - 1 - i] = total % 256
        total >>= 8
    return bytes(s)


def base_2b(x, b, out_len):
    """Algorithm 4"""
    i = 0
    bits = 0
    total = 0
    baseb = []
    for _ in range(out_len):
        while bits < b:
            total = (total << 8) + x[i]
            i += 1
            bits += 8
        bits -= b
        baseb.append((total >> bits) % 2**b)
    return baseb


# ---------------------------------------------------------------------
# Section 4.3: ADRS member functions (Table 1)
# ---------------------------------------------------------------------

class ADRS:
    """A 32-byte address, updated in place like ADRS in FIPS 205"""

    def __init__(self, data):
        assert len(data) == 32
        self.a = bytearray(data)

    def copy(self):
        return ADRS(self.a)

    def bytes(self):
        return bytes(self.a)

    def set_layer_address(self, l):
        self.a[0:4] = to_byte(l, 4)

    def set_tree_address(self, t):
        self.a[4:16] = to_byte(t, 12)

    def set_type_and_clear(self, y):
        self.a[16:32] = to_byte(y, 4) + to_byte(0, 12)

    def set_key_pair_address(self, i):
        self.a[20:24] = to_byte(i, 4)

    def set_chain_address(self, i):
        self.a[24:28] = to_byte(i, 4)

    def set_hash_address(self, i):
        self.a[28:32] = to_byte(i, 4)

    def set_tree_height(self, i):
        self.a[24:28] = to_byte(i, 4)

    def set_tree_index(self, i):
        self.a[28:32] = to_byte(i, 4)

    def get_tree_index(self):
        return to_int(self.a[28:32], 4)

    def get_key_pair_address(self):
        return to_int(self.a[20:24], 4)


# ---------------------------------------------------------------------
# Section 11.1: hash functions for SLH-DSA-SHAKE
# ---------------------------------------------------------------------

def shake(data, n):
    return hashlib.shake_256(data).digest(n)


def prf(pk_seed, sk_seed, adrs):
    return shake(pk_seed + adrs.bytes() + sk_seed, N)


def t_l(pk_seed, adrs, m_l):
    return shake(pk_seed + adrs.bytes() + m_l, N)


def f(pk_seed, adrs, m1):
    return shake(pk_seed + adrs.bytes() + m1, N)


# ---------------------------------------------------------------------
# Section 5: Algorithms 5 to 8
# ---------------------------------------------------------------------

def chain(x, i, s, pk_seed, adrs):
    """Algorithm 5"""
    tmp = x
    for j in range(i, i + s):
        adrs.set_hash_address(j)
        tmp = f(pk_seed, adrs, tmp)
    return tmp


def wots_pk_gen(sk_seed, pk_seed, adrs):
    """Algorithm 6"""
    sk_adrs = adrs.copy()
    sk_adrs.set_type_and_clear(WOTS_PRF)
    sk_adrs.set_key_pair_address(adrs.get_key_pair_address())
    tmp = b""
    for i in range(LEN):
        sk_adrs.set_chain_address(i)
        sk = prf(pk_seed, sk_seed, sk_adrs)
        adrs.set_chain_address(i)
        tmp += chain(sk, 0, W - 1, pk_seed, adrs)
    wotspk_adrs = adrs.copy()
    wotspk_adrs.set_type_and_clear(WOTS_PK)
    wotspk_adrs.set_key_pair_address(adrs.get_key_pair_address())
    return t_l(pk_seed, wotspk_adrs, tmp)


def msg_with_checksum(m):
    """Lines 1 to 7 of Algorithms 7 and 8"""
    csum = 0
    msg = base_2b(m, LG_W, LEN1)
    for i in range(LEN1):
        csum = csum + W - 1 - msg[i]
    csum <<= (8 - ((LEN2 * LG_W) % 8)) % 8
    msg += base_2b(to_byte(csum, (LEN2 * LG_W + 7) // 8), LG_W, LEN2)
    return msg


def wots_sign(m, sk_seed, pk_seed, adrs):
    """Algorithm 7. Returns the signature as one byte string"""
    msg = msg_with_checksum(m)
    sk_adrs = adrs.copy()
    sk_adrs.set_type_and_clear(WOTS_PRF)
    sk_adrs.set_key_pair_address(adrs.get_key_pair_address())
    sig = b""
    for i in range(LEN):
        sk_adrs.set_chain_address(i)
        sk = prf(pk_seed, sk_seed, sk_adrs)
        adrs.set_chain_address(i)
        sig += chain(sk, 0, msg[i], pk_seed, adrs)
    return sig


def wots_pk_from_sig(sig, m, pk_seed, adrs):
    """Algorithm 8. sig is one byte string of LEN * N bytes"""
    msg = msg_with_checksum(m)
    tmp = b""
    for i in range(LEN):
        adrs.set_chain_address(i)
        tmp += chain(sig[i * N:(i + 1) * N], msg[i], W - 1 - msg[i], pk_seed, adrs)
    wotspk_adrs = adrs.copy()
    wotspk_adrs.set_type_and_clear(WOTS_PK)
    wotspk_adrs.set_key_pair_address(adrs.get_key_pair_address())
    return t_l(pk_seed, wotspk_adrs, tmp)


# ---------------------------------------------------------------------
# Checking tkats output
# ---------------------------------------------------------------------

# For each function: the input fields and their lengths in bytes
# (None for a decimal integer)
SPECS = {
    "Chain":            [("X", N), ("I", None), ("S", None), ("PK_Seed", N), ("ADRS", 32)],
    "WOTS_PK_Gen":      [("SK_Seed", N), ("PK_Seed", N), ("ADRS", 32)],
    "WOTS_Sign":        [("M", N), ("SK_Seed", N), ("PK_Seed", N), ("ADRS", 32)],
    "WOTS_PK_From_Sig": [("Sig", LEN * N), ("M", N), ("PK_Seed", N), ("ADRS", 32)],
    "WOTS_Round_Trip":  [("M", N), ("SK_Seed", N), ("PK_Seed", N), ("ADRS", 32)],
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
        if name == "Chain":
            if not (0 <= v["I"] and 0 <= v["S"] and v["I"] + v["S"] < W):
                return f"I = {v['I']}, S = {v['S']} out of range"
            checks = [("Result", chain(v["X"], v["I"], v["S"], v["PK_Seed"], adrs))]
        elif name == "WOTS_PK_Gen":
            checks = [("Result", wots_pk_gen(v["SK_Seed"], v["PK_Seed"], adrs))]
        elif name == "WOTS_Sign":
            checks = [("Result", wots_sign(v["M"], v["SK_Seed"], v["PK_Seed"], adrs))]
        elif name == "WOTS_PK_From_Sig":
            checks = [("Result", wots_pk_from_sig(v["Sig"], v["M"], v["PK_Seed"], adrs))]
        else:  # WOTS_Round_Trip
            pk = wots_pk_gen(v["SK_Seed"], v["PK_Seed"], adrs.copy())
            sig = wots_sign(v["M"], v["SK_Seed"], v["PK_Seed"], adrs.copy())
            pk_sig = wots_pk_from_sig(sig, v["M"], v["PK_Seed"], adrs.copy())
            if pk_sig != pk:
                return "reference model round trip failed"
            if get_output(record, "PK_From_Sig") != get_output(record, "PK_Gen"):
                return "PK_From_Sig /= PK_Gen"
            checks = [("PK_Gen", pk), ("PK_From_Sig", pk_sig)]
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
    print("All WOTS+ KATs passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
