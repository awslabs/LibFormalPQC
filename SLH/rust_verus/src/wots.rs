//  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

//! Winternitz One-Time Signature Plus (WOTS+), FIPS 205 section 5,
//! Algorithms 5 to 8.
//!
//! All functions here are pure: the address is passed by value, and
//! each address used is built from it, where FIPS 205 updates ADRS in
//! place. Each use of ADRS in FIPS 205 is preceded by the setters that
//! give it the words that the hash functions read, so the two agree.

use crate::adrs::*;
use crate::hash::*;
#[cfg(verus_keep_ghost)]  // Only used in specifications
use crate::params::*;
#[cfg(verus_keep_ghost)]  // Only used in specifications
use crate::util::*;
use vstd::prelude::*;

verus! {

/// The chain function, Algorithm 5: s iterations of F, starting from
/// x at index i. Iteration j (from i to i + s - 1) uses hash address j
pub open spec fn spec_chain(x: Seq<u8>, i: int, s: int, pk_seed: Seq<u8>, adrs: Seq<u8>) -> Seq<u8>
    decreases s,
{
    if s <= 0 {
        x
    } else {
        spec_f(pk_seed, spec_set_hash_address(adrs, (i + s - 1) as u32),
               spec_chain(x, i, s - 1, pk_seed, adrs))
    }
}

/// Algorithm 5. chain (X, i, s, PK.seed, ADRS)
pub fn chain(x: &[u8; 32], i: u32, s: u32, pk_seed: &[u8; 32], adrs: &Adrs) -> (r: [u8; 32])
    requires i + s <= 15,
    ensures r@ == spec_chain(x@, i as int, s as int, pk_seed@, adrs@),
{
    let mut tmp = *x;                                               // Line 1
    let mut j = i;
    while j < i + s                                                 // Line 2
        invariant
            i <= j <= i + s <= 15,
            tmp@ == spec_chain(x@, i as int, (j - i) as int, pk_seed@, adrs@),
        decreases i + s - j,
    {
        let a = set_hash_address(*adrs, j);                         // Line 3
        tmp = f(pk_seed, &a, &tmp);                                 // Line 4
        j += 1;
    }
    tmp                                                             // Line 6
}

//  The message and checksum in base w, lines 1 to 7 of Algorithms 7
//  and 8. base_2b (X, lg_w, out_len) gives the 4-bit nibbles of X, most
//  significant first, so digit j of M is a nibble of byte j / 2.

/// Nibble j of m
pub open spec fn spec_nibble(m: Seq<u8>, j: int) -> int {
    if j % 2 == 0 { (m[j / 2] / 16) as int } else { (m[j / 2] % 16) as int }
}

/// csum after lines 3 to 5 have added the first k digits
pub open spec fn spec_csum(m: Seq<u8>, k: int) -> int
    decreases k,
{
    if k <= 0 { 0 } else { spec_csum(m, k - 1) + (15 - spec_nibble(m, k - 1)) }
}

/// The two bytes of toByte (csum << 4, 2), line 7. ((len2 lg_w) mod 8 = 4,
/// so line 6 shifts csum left by 4 bits)
pub open spec fn spec_csum_bytes(m: Seq<u8>) -> Seq<u8> {
    let c = spec_csum(m, LEN1 as int) * 16;
    seq![(c / 256 % 256) as u8, (c % 256) as u8]
}

/// Digit j of msg after line 7: base_2b (M, lg_w, len1) followed by
/// base_2b (toByte (csum, 2), lg_w, len2)
pub open spec fn spec_digit(m: Seq<u8>, j: int) -> int {
    if j < LEN1 { spec_nibble(m, j) } else { spec_nibble(spec_csum_bytes(m), j - LEN1) }
}

proof fn lemma_csum_bound(m: Seq<u8>, k: int)
    requires 0 <= k <= 64, m.len() == 32,
    ensures 0 <= spec_csum(m, k) <= 15 * k,
    decreases k,
{
    if k > 0 {
        lemma_csum_bound(m, k - 1);
    }
}

/// Lines 1 to 7 of Algorithms 7 and 8: M and its checksum in base w
pub fn msg_digits(m: &[u8; 32]) -> (r: [u32; 67])
    ensures forall|j: int| 0 <= j < 67 ==> #[trigger] r@[j] as int == spec_digit(m@, j) && r@[j] <= 15,
{
    let mut r = [0u32; 67];
    let mut csum: u32 = 0;                                          // Line 1
    let mut j: usize = 0;
    while j < 64                                                    // Lines 2 to 5
        invariant
            j <= 64,
            csum as int == spec_csum(m@, j as int),
            csum <= 15 * j,
            forall|k: int| 0 <= k < j ==> #[trigger] r@[k] as int == spec_digit(m@, k) && r@[k] <= 15,
        decreases 64 - j,
    {
        let b = m[j / 2];
        let d: u32 = if j % 2 == 0 { (b / 16) as u32 } else { (b % 16) as u32 };
        r[j] = d;
        csum = csum + (15 - d);
        j += 1;
    }
    proof { lemma_csum_bound(m@, 64); }
    let c = csum * 16;                                              // Line 6
    let c0 = (c / 256 % 256) as u8;                                 // Line 7
    let c1 = (c % 256) as u8;
    let ghost cb = spec_csum_bytes(m@);
    assert(cb[0] == c0 && cb[1] == c1);
    r[64] = (c0 / 16) as u32;
    r[65] = (c0 % 16) as u32;
    r[66] = (c1 / 16) as u32;
    r
}

/// skADRS for chain i: Algorithm 6 lines 1 to 3 and 5 (Algorithm 7
/// lines 8 to 10 and 12)
pub open spec fn spec_sk_adrs(a: Seq<u8>, i: int) -> Seq<u8> {
    spec_set_chain_address(
        spec_set_key_pair_address(spec_set_type_and_clear(a, WOTS_PRF), spec_get_key_pair_address(a)),
        i as u32)
}

/// ADRS for chain i: ADRS.setChainAddress (i)
pub open spec fn spec_chain_adrs(a: Seq<u8>, i: int) -> Seq<u8> {
    spec_set_chain_address(a, i as u32)
}

/// wotspkADRS: Algorithm 6 lines 10 to 12 (Algorithm 8 lines 12 to 14)
pub open spec fn spec_wots_pk_adrs(a: Seq<u8>) -> Seq<u8> {
    spec_set_key_pair_address(spec_set_type_and_clear(a, WOTS_PK), spec_get_key_pair_address(a))
}

/// The private key value for chain i, Algorithm 6 line 6
pub open spec fn spec_sk(sk_seed: Seq<u8>, pk_seed: Seq<u8>, a: Seq<u8>, i: int) -> Seq<u8> {
    spec_prf(pk_seed, sk_seed, spec_sk_adrs(a, i))
}

/// Algorithm 6. wots_pkGen (SK.seed, PK.seed, ADRS)
pub open spec fn spec_wots_pk_gen(sk_seed: Seq<u8>, pk_seed: Seq<u8>, a: Seq<u8>) -> Seq<u8> {
    spec_t(pk_seed, spec_wots_pk_adrs(a), flat(Seq::new(67, |i: int|
        spec_chain(spec_sk(sk_seed, pk_seed, a, i), 0, 15, pk_seed, spec_chain_adrs(a, i)))))
}

/// Algorithm 7. wots_sign (M, SK.seed, PK.seed, ADRS)
pub open spec fn spec_wots_sign(m: Seq<u8>, sk_seed: Seq<u8>, pk_seed: Seq<u8>, a: Seq<u8>) -> Seq<Seq<u8>> {
    Seq::new(67, |i: int|
        spec_chain(spec_sk(sk_seed, pk_seed, a, i), 0, spec_digit(m, i), pk_seed, spec_chain_adrs(a, i)))
}

/// tmp[i] in Algorithm 8
pub open spec fn spec_pk_from_sig_value(sig: Seq<Seq<u8>>, m: Seq<u8>, pk_seed: Seq<u8>, a: Seq<u8>, i: int) -> Seq<u8> {
    spec_chain(sig[i], spec_digit(m, i), 15 - spec_digit(m, i), pk_seed, spec_chain_adrs(a, i))
}

/// Algorithm 8. wots_pkFromSig (sig, M, PK.seed, ADRS)
pub open spec fn spec_wots_pk_from_sig(sig: Seq<Seq<u8>>, m: Seq<u8>, pk_seed: Seq<u8>, a: Seq<u8>) -> Seq<u8> {
    spec_t(pk_seed, spec_wots_pk_adrs(a),
           flat(Seq::new(67, |i: int| spec_pk_from_sig_value(sig, m, pk_seed, a, i))))
}

/// The private key value for chain i, Algorithm 6 lines 5 and 6
fn sk_value(sk_seed: &[u8; 32], pk_seed: &[u8; 32], adrs: &Adrs, i: u32) -> (r: [u8; 32])
    requires i < 67,
    ensures r@ == spec_sk(sk_seed@, pk_seed@, adrs@, i as int),
{
    let kp = get_key_pair_address(adrs);
    let sk_adrs = set_chain_address(set_key_pair_address(set_type_and_clear(*adrs, WOTS_PRF), kp), i);
    prf(pk_seed, sk_seed, &sk_adrs)
}

fn wots_pk_adrs(adrs: &Adrs) -> (r: Adrs)
    ensures r@ == spec_wots_pk_adrs(adrs@),
{
    let kp = get_key_pair_address(adrs);
    set_key_pair_address(set_type_and_clear(*adrs, WOTS_PK), kp)
}

/// Algorithm 6. wots_pkGen (SK.seed, PK.seed, ADRS)
pub fn wots_pk_gen(sk_seed: &[u8; 32], pk_seed: &[u8; 32], adrs: &Adrs) -> (r: [u8; 32])
    ensures r@ == spec_wots_pk_gen(sk_seed@, pk_seed@, adrs@),
{
    let ghost vals = Seq::new(67, |i: int|
        spec_chain(spec_sk(sk_seed@, pk_seed@, adrs@, i), 0, 15, pk_seed@, spec_chain_adrs(adrs@, i)));
    let mut tmp = [[0u8; 32]; 67];
    let mut i: u32 = 0;
    while i < 67                                                    // Line 4
        invariant
            i <= 67,
            vals == Seq::new(67, |i: int|
                spec_chain(spec_sk(sk_seed@, pk_seed@, adrs@, i), 0, 15, pk_seed@, spec_chain_adrs(adrs@, i))),
            forall|k: int| 0 <= k < i ==> (#[trigger] tmp@[k])@ == vals[k],
        decreases 67 - i,
    {
        let sk = sk_value(sk_seed, pk_seed, adrs, i);               // Lines 5 and 6
        let a = set_chain_address(*adrs, i);                        // Line 7
        tmp[i as usize] = chain(&sk, 0, 15, pk_seed, &a);           // Line 8
        i += 1;
    }
    assert(views32(tmp@) =~= vals);
    let pk_adrs = wots_pk_adrs(adrs);                               // Lines 10 to 12
    t_l(pk_seed, &pk_adrs, tmp.as_slice())                          // Lines 13 and 14
}

/// Algorithm 7. wots_sign (M, SK.seed, PK.seed, ADRS)
pub fn wots_sign(m: &[u8; 32], sk_seed: &[u8; 32], pk_seed: &[u8; 32], adrs: &Adrs) -> (r: [[u8; 32]; 67])
    ensures views32(r@) == spec_wots_sign(m@, sk_seed@, pk_seed@, adrs@),
{
    let msg = msg_digits(m);                                        // Lines 1 to 7
    let mut sig = [[0u8; 32]; 67];
    let mut i: u32 = 0;
    while i < 67                                                    // Line 11
        invariant
            i <= 67,
            forall|j: int| 0 <= j < 67 ==> #[trigger] msg@[j] as int == spec_digit(m@, j) && msg@[j] <= 15,
            forall|k: int| 0 <= k < i ==> (#[trigger] sig@[k])@ == spec_wots_sign(m@, sk_seed@, pk_seed@, adrs@)[k],
        decreases 67 - i,
    {
        let sk = sk_value(sk_seed, pk_seed, adrs, i);               // Lines 12 and 13
        let a = set_chain_address(*adrs, i);                        // Line 14
        sig[i as usize] = chain(&sk, 0, msg[i as usize], pk_seed, &a);  // Line 15
        i += 1;
    }
    assert(views32(sig@) =~= spec_wots_sign(m@, sk_seed@, pk_seed@, adrs@));
    sig
}

/// Algorithm 8. wots_pkFromSig (sig, M, PK.seed, ADRS)
pub fn wots_pk_from_sig(sig: &[[u8; 32]; 67], m: &[u8; 32], pk_seed: &[u8; 32], adrs: &Adrs) -> (r: [u8; 32])
    ensures r@ == spec_wots_pk_from_sig(views32(sig@), m@, pk_seed@, adrs@),
{
    let ghost s = views32(sig@);
    let msg = msg_digits(m);                                        // Lines 1 to 7
    let mut tmp = [[0u8; 32]; 67];
    let mut i: u32 = 0;
    while i < 67                                                    // Line 8
        invariant
            i <= 67,
            s == views32(sig@),
            forall|j: int| 0 <= j < 67 ==> #[trigger] msg@[j] as int == spec_digit(m@, j) && msg@[j] <= 15,
            forall|k: int| 0 <= k < i ==> (#[trigger] tmp@[k])@ == spec_pk_from_sig_value(s, m@, pk_seed@, adrs@, k),
        decreases 67 - i,
    {
        let a = set_chain_address(*adrs, i);                        // Line 9
        let d = msg[i as usize];
        tmp[i as usize] = chain(&sig[i as usize], d, 15 - d, pk_seed, &a);  // Line 10
        i += 1;
    }
    assert(views32(tmp@) =~= Seq::new(67, |i: int| spec_pk_from_sig_value(s, m@, pk_seed@, adrs@, i)));
    let pk_adrs = wots_pk_adrs(adrs);                               // Lines 12 to 14
    t_l(pk_seed, &pk_adrs, tmp.as_slice())                          // Lines 15 and 16
}

} // verus!
