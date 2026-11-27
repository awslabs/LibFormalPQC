#!/usr/bin/env python3
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: Apache-2.0

"""Run the NIST ACVP test vectors for SLH-DSA-SHAKE-256s through 'tkats acvp'.

The vectors in SLH/acvp/ (shared by all the implementations of
SLH-DSA in this repository) are from the NIST ACVP server
(https://github.com/usnistgov/ACVP-Server, gen-val/json-files/
SLH-DSA-{keyGen,sigGen,sigVer}-FIPS205/internalProjection.json),
filtered to the SLH-DSA-SHAKE-256s parameter set and, for the pre-hash
tests, to the pre-hash functions provided (SHA3-512 and SHAKE-256).
The internal interface tests use Algorithms 18 to 20, and the external
interface tests use Algorithms 21 to 25.

  check_acvp.py input FILE    writes the test inputs to FILE, in the
                              'Key = Value' format read by 'tkats acvp'
  check_acvp.py check FILE    checks the output of 'tkats acvp' in FILE
                              against the expected results

Exits with status 0 if every test passes, and every test was run,
and status 1 otherwise.
"""

import json
import os
import sys

from check_hash_kats import parse_records

HERE = os.path.dirname(os.path.abspath(__file__))
ACVP_DIR = os.path.join(HERE, "..", "..", "acvp")
FILES = {
    "KeyGen": "SLH-DSA-keyGen-SHAKE-256s.json",
    "SigGen": "SLH-DSA-sigGen-SHAKE-256s.json",
    "SigVer": "SLH-DSA-sigVer-SHAKE-256s.json",
}


def function_name(mode, group):
    """The name of the function in 'tkats acvp' that runs a test"""
    if mode == "KeyGen" or group["signatureInterface"] == "internal":
        return mode
    return mode + ("Pure" if group["preHash"] == "pure" else "PreHash")


def load_tests():
    """Yield (function, test group, test) for every test case"""
    for mode, name in FILES.items():
        with open(os.path.join(ACVP_DIR, name), encoding="ascii") as fd:
            data = json.load(fd)
        for group in data["testGroups"]:
            assert group["parameterSet"] == "SLH-DSA-SHAKE-256s"
            for test in group["tests"]:
                yield function_name(mode, group), group, test


def write_input(path):
    with open(path, "w", encoding="ascii") as fd:
        for func, group, test in load_tests():
            fd.write(f"Function = {func}\n")
            fd.write(f"tcId = {test['tcId']}\n")
            if func == "KeyGen":
                fd.write(f"SK_Seed = {test['skSeed']}\n")
                fd.write(f"SK_Prf = {test['skPrf']}\n")
                fd.write(f"PK_Seed = {test['pkSeed']}\n")
            elif func.startswith("SigGen"):
                fd.write(f"SK = {test['sk']}\n")
                fd.write(f"Message = {test['message']}\n")
                if not group["deterministic"]:
                    fd.write(f"Addrnd = {test['additionalRandomness']}\n")
            else:
                fd.write(f"PK = {test['pk']}\n")
                fd.write(f"Message = {test['message']}\n")
                fd.write(f"Signature = {test['signature']}\n")
            if func.endswith("Pure") or func.endswith("PreHash"):
                fd.write(f"Context = {test['context']}\n")
            if func.endswith("PreHash"):
                fd.write(f"HashAlg = {test['hashAlg']}\n")
            fd.write("\n")
    return 0


def check_output(path):
    with open(path, encoding="ascii") as fd:
        results = {(r.get("Function"), r.get("tcId")): r for r in parse_records(fd.readlines())}

    passed = {func: 0 for func in ("KeyGen", "SigGen", "SigGenPure", "SigGenPreHash",
                                   "SigVer", "SigVerPure", "SigVerPreHash")}
    failures = 0
    for func, group, test in load_tests():
        label = f"{func} tcId {test['tcId']}"
        result = results.get((func, str(test["tcId"])))
        if result is None:
            failures += 1
            print(f"FAIL {label}: no result")
            continue
        if func == "KeyGen":
            expected = [("SK", test["sk"]), ("PK", test["pk"])]
        elif func.startswith("SigGen"):
            expected = [("Signature", test["signature"])]
        else:
            expected = [("Result", "TRUE" if test["testPassed"] else "FALSE")]
        problems = [field for field, value in expected
                    if result.get(field, "").upper() != value.upper()]
        if problems:
            failures += 1
            reason = f" ({test['reason']})" if "reason" in test else ""
            print(f"FAIL {label}{reason}: wrong {', '.join(problems)}")
        else:
            passed[func] += 1

    for func, count in passed.items():
        print(f"ACVP {func:13} {count:3} passed")
        if count == 0:
            failures += 1
            print(f"FAIL {func}: no test cases found")

    if failures:
        print(f"{failures} failure(s)")
        return 1
    print("All ACVP tests passed")
    return 0


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ("input", "check"):
        print(f"usage: {sys.argv[0]} input|check FILE", file=sys.stderr)
        return 1
    if sys.argv[1] == "input":
        return write_input(sys.argv[2])
    return check_output(sys.argv[2])


if __name__ == "__main__":
    sys.exit(main())
