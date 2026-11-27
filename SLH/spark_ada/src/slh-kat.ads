--  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
--  SPDX-License-Identifier: Apache-2.0

--  Known Answer Test (KAT) drivers for SLH internal subprograms.
--
--  As a child of SLH, the body of this package can see the private
--  part of SLH, which declares the internal packages under test.
package SLH.KAT
  with SPARK_Mode => Off
is
   --  Calls each of the hash functions and PRFs from FIPS 205 section 4.1
   --  on pseudo-random inputs of various lengths. Writes the inputs
   --  and results to stdout, in a format checked by
   --  SLH/checkers/check_hash_kats.py
   procedure Hash_KATs;

   --  Calls chain, wots_pkGen, wots_sign and wots_pkFromSig from
   --  FIPS 205 section 5, and checks the round trip
   --  wots_pkFromSig (wots_sign (M)) = wots_pkGen. Writes the inputs
   --  and results to stdout, in a format checked by
   --  SLH/checkers/check_wots_kats.py
   procedure WOTS_KATs;

   --  Calls xmss_node, xmss_sign and xmss_pkFromSig from FIPS 205
   --  section 6, and checks the round trip
   --  xmss_pkFromSig (xmss_sign (M)) = xmss_node (0, h').
   --  Writes the inputs and results to stdout, in a format checked
   --  by SLH/checkers/check_xmss_kats.py
   procedure XMSS_KATs;

   --  Calls ht_sign and ht_verify from FIPS 205 section 7, on random
   --  signatures, on valid signatures, and on signatures with a
   --  changed byte, PK.root or idx_leaf. Writes the inputs and
   --  results to stdout, in a format checked by SLH/checkers/check_ht_kats.py
   procedure HT_KATs;

   --  Calls fors_skGen, fors_node, fors_sign and fors_pkFromSig from
   --  FIPS 205 section 8, and checks the round trip: the public key
   --  computed from fors_sign (md) is T_k of the K tree roots.
   --  Writes the inputs and results to stdout, in a format checked
   --  by SLH/checkers/check_fors_kats.py
   procedure FORS_KATs;

   --  Calls slh_keygen_internal, slh_sign_internal (hedged and
   --  deterministic) and slh_verify_internal from FIPS 205 section 9.
   --  Writes the inputs and results to stdout, in a format checked
   --  by SLH/checkers/check_slh_kats.py
   procedure SLH_KATs;

   --  Reads NIST ACVP test cases for SLH-DSA-SHAKE-256s (keyGen, and
   --  sigGen and sigVer with the internal interface) from stdin, in
   --  the format written by SLH/checkers/check_acvp.py, runs each one, and
   --  writes the results to stdout, in a format checked by
   --  SLH/checkers/check_acvp.py
   procedure ACVP_Tests;

end SLH.KAT;
