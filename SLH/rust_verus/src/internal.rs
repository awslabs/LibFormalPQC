//  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

//! The SLH-DSA internal functions, FIPS 205 section 9, Algorithms 18
//! to 20.
//!
//! FIPS 205 says that, other than for testing, these functions should
//! not be made available to applications, so this module is only
//! public with the `kat` feature.
//!
//! The message M is given as three byte strings m1 || m2 || m3, so
//! that the external functions of section 10 can pass M' without
//! copying it.

use crate::adrs::*;
use crate::formats::*;
use crate::fors::*;
use crate::hash::*;
use crate::ht::*;
use crate::util::*;
use crate::xmss::*;
use vstd::prelude::*;

verus! {

/// Algorithm 2. toInt (X, n), for n = X.len()
pub open spec fn spec_to_int(x: Seq<u8>) -> nat
    decreases x.len(),
{
    if x.len() == 0 { 0 } else { spec_to_int(x.drop_last()) * 256 + x.last() as nat }
}

pub open spec fn spec_pow256(n: nat) -> nat
    decreases n,
{
    if n == 0 { 1 } else { 256 * spec_pow256((n - 1) as nat) }
}

proof fn lemma_pow256_bound(n: nat)
    requires n <= 7,
    ensures spec_pow256(n) <= 0x100_0000_0000_0000,
    decreases 7 - n,
{
    if n < 7 {
        lemma_pow256_bound(n + 1);
    } else {
        assert(spec_pow256(7) == 0x100_0000_0000_0000) by (compute);
    }
}

/// Algorithm 2. toInt (b[off : off + n], n), for n <= 7
fn to_int(b: &[u8], off: usize, n: usize) -> (r: u64)
    requires off + n <= b.len(), n <= 7,
    ensures r as nat == spec_to_int(b@.subrange(off as int, off + n)), (r as nat) < spec_pow256(n as nat),
{
    let mut total: u64 = 0;                                         // Line 1
    let mut i: usize = 0;
    while i < n                                                     // Line 2
        invariant
            off + n <= b.len(), n <= 7, i <= n,
            total as nat == spec_to_int(b@.subrange(off as int, off + i)),
            (total as nat) < spec_pow256(i as nat),
        decreases n - i,
    {
        proof {
            lemma_pow256_bound((i + 1) as nat);
            assert(b@.subrange(off as int, off + i + 1).drop_last() =~= b@.subrange(off as int, off + i));
        }
        total = 256 * total + b[off + i] as u64;                    // Line 3
        i += 1;
    }
    total                                                           // Line 5
}

/// The parts of the digest (Algorithm 19 lines 6 to 10, Algorithm 20
/// lines 9 to 13)
pub open spec fn spec_md(digest: Seq<u8>) -> Seq<u8> {
    digest.subrange(0, 39)
}

pub open spec fn spec_idx_tree(digest: Seq<u8>) -> u64 {
    (spec_to_int(digest.subrange(39, 46)) % 0x100_0000_0000_0000) as u64
}

pub open spec fn spec_idx_leaf(digest: Seq<u8>) -> u32 {
    (spec_to_int(digest.subrange(46, 47)) % 256) as u32
}

/// ADRS for the FORS key (Algorithm 19 lines 1 and 11 to 13, and
/// Algorithm 20 lines 4 and 14 to 16)
pub open spec fn spec_fors_adrs(idx_tree: u64, idx_leaf: u32) -> Seq<u8> {
    spec_set_key_pair_address(spec_set_type_and_clear(spec_set_tree_address(zeros32(), idx_tree), FORS_TREE),
                              idx_leaf)
}

/// The parts of SK (FIPS 205 Figure 15) and PK (Figure 16)
pub open spec fn spec_sk_seed(sk: Seq<u8>) -> Seq<u8> { sk.subrange(0, 32) }
pub open spec fn spec_sk_prf(sk: Seq<u8>) -> Seq<u8> { sk.subrange(32, 64) }
pub open spec fn spec_sk_pk_seed(sk: Seq<u8>) -> Seq<u8> { sk.subrange(64, 96) }
pub open spec fn spec_sk_pk_root(sk: Seq<u8>) -> Seq<u8> { sk.subrange(96, 128) }
pub open spec fn spec_pk_seed(pk: Seq<u8>) -> Seq<u8> { pk.subrange(0, 32) }
pub open spec fn spec_pk_root(pk: Seq<u8>) -> Seq<u8> { pk.subrange(32, 64) }

/// PK.root (Algorithm 18 lines 1 to 3)
pub open spec fn spec_pk_root_of(sk_seed: Seq<u8>, pk_seed: Seq<u8>) -> Seq<u8> {
    spec_xmss_node(sk_seed, 0, 8, pk_seed, spec_set_layer_address(zeros32(), 7))
}

/// Algorithm 18. slh_keygen_internal (SK.seed, SK.prf, PK.seed): (SK, PK)
pub open spec fn spec_slh_keygen_internal(sk_seed: Seq<u8>, sk_prf: Seq<u8>, pk_seed: Seq<u8>)
    -> (Seq<u8>, Seq<u8>)
{
    let root = spec_pk_root_of(sk_seed, pk_seed);
    (sk_seed + sk_prf + pk_seed + root, pk_seed + root)
}

/// Algorithm 19. slh_sign_internal (M, SK, addrnd), where opt_rand is
/// addrnd for the hedged variant and PK.seed for the deterministic one
pub open spec fn spec_slh_sign_internal(m: Seq<u8>, sk: Seq<u8>, opt_rand: Seq<u8>) -> Seq<u8> {
    let sk_seed = spec_sk_seed(sk);
    let pk_seed = spec_sk_pk_seed(sk);
    let r = spec_prf_msg(spec_sk_prf(sk), opt_rand, m);                     // Line 3
    let digest = spec_h_msg(r, pk_seed, spec_sk_pk_root(sk), m);            // Line 5
    let md = spec_md(digest);                                               // Lines 6 to 10
    let idx_tree = spec_idx_tree(digest);
    let idx_leaf = spec_idx_leaf(digest);
    let adrs = spec_fors_adrs(idx_tree, idx_leaf);                          // Lines 11 to 13
    let sig_fors = spec_fors_sign(md, sk_seed, pk_seed, adrs);              // Line 14
    let pk_fors = spec_fors_pk_from_sig(sig_fors, md, pk_seed, adrs);       // Line 16
    let sig_ht = spec_ht_sign(pk_fors, sk_seed, pk_seed, idx_tree, idx_leaf);  // Line 17
    r + spec_fors_bytes(sig_fors) + spec_ht_bytes(sig_ht)                   // Lines 4, 15 and 18
}

/// Algorithm 20. slh_verify_internal (M, SIG, PK), for a SIG of the right length
pub open spec fn spec_slh_verify_internal(m: Seq<u8>, sig: Seq<u8>, pk: Seq<u8>) -> bool {
    let pk_seed = spec_pk_seed(pk);
    let pk_root = spec_pk_root(pk);
    let r = sig.subrange(0, 32);                                            // Line 5
    let sig_fors = spec_parse_fors(sig.subrange(32, 10592));                // Line 6
    let sig_ht = spec_parse_ht(sig.subrange(10592, 29792));                 // Line 7
    let digest = spec_h_msg(r, pk_seed, pk_root, m);                        // Line 8
    let md = spec_md(digest);                                               // Lines 9 to 13
    let idx_tree = spec_idx_tree(digest);
    let idx_leaf = spec_idx_leaf(digest);
    let adrs = spec_fors_adrs(idx_tree, idx_leaf);                          // Lines 14 to 16
    let pk_fors = spec_fors_pk_from_sig(sig_fors, md, pk_seed, adrs);       // Line 17
    spec_ht_verify(pk_fors, sig_ht, pk_seed, idx_tree, idx_leaf, pk_root)  // Line 18
}

/// Splits the digest (Algorithm 19 lines 6 to 10, Algorithm 20 lines 9 to 13)
fn split_digest(digest: &[u8; 47]) -> (r: ([u8; 39], u64, u32))
    ensures
        r.0@ == spec_md(digest@),
        r.1 == spec_idx_tree(digest@),
        r.2 == spec_idx_leaf(digest@),
        r.2 < 256,
{
    let mut md = [0u8; 39];                                         // Line 6
    let mut i: usize = 0;
    while i < 39
        invariant
            i <= 39,
            forall|j: int| 0 <= j < i ==> #[trigger] md@[j] == digest@[j],
        decreases 39 - i,
    {
        md[i] = digest[i];
        i += 1;
    }
    assert(md@ =~= spec_md(digest@));
    let tree = to_int(digest.as_slice(), 39, 7);                    // Lines 7 and 9
    let leaf = to_int(digest.as_slice(), 46, 1);                    // Lines 8 and 10
    (md, tree % 0x100_0000_0000_0000, (leaf % 256) as u32)
}

fn fors_adrs(idx_tree: u64, idx_leaf: u32) -> (r: Adrs)
    ensures r@ == spec_fors_adrs(idx_tree, idx_leaf),
{
    let z = [0u8; 32];
    assert(z@ =~= zeros32());
    set_key_pair_address(set_type_and_clear(set_tree_address(z, idx_tree), FORS_TREE), idx_leaf)
}

fn get_part<const T: usize>(b: &[u8; T], off: usize) -> (r: [u8; 32])
    requires off + 32 <= T,
    ensures r@ == b@.subrange(off as int, off + 32),
{
    get32(b.as_slice(), off)
}

/// Algorithm 18. slh_keygen_internal (SK.seed, SK.prf, PK.seed)
pub fn slh_keygen_internal(sk_seed: &[u8; 32], sk_prf: &[u8; 32], pk_seed: &[u8; 32])
    -> (r: ([u8; 128], [u8; 64]))
    ensures (r.0@, r.1@) == spec_slh_keygen_internal(sk_seed@, sk_prf@, pk_seed@),
{
    let z = [0u8; 32];                                              // Line 1
    assert(z@ =~= zeros32());
    let a = set_layer_address(z, 7);                                // Line 2
    assert(spec_valid_node(0, 8)) by (bit_vector);
    let pk_root = xmss_node(sk_seed, 0, 8, pk_seed, &a);            // Line 3
    let mut sk = [0u8; 128];                                        // Line 4
    copy_at(&mut sk, 0, sk_seed.as_slice());
    copy_at(&mut sk, 32, sk_prf.as_slice());
    copy_at(&mut sk, 64, pk_seed.as_slice());
    copy_at(&mut sk, 96, pk_root.as_slice());
    let mut pk = [0u8; 64];
    copy_at(&mut pk, 0, pk_seed.as_slice());
    copy_at(&mut pk, 32, pk_root.as_slice());
    let ghost root = spec_pk_root_of(sk_seed@, pk_seed@);
    assert(sk@ =~= sk_seed@ + sk_prf@ + pk_seed@ + root);
    assert(pk@ =~= pk_seed@ + root);
    (sk, pk)
}

/// Algorithm 19. slh_sign_internal (M, SK, addrnd), for M = m1 || m2 || m3.
/// opt_rand is addrnd for the hedged variant, and PK.seed for the
/// deterministic variant (line 2)
pub fn slh_sign_internal_parts(m1: &[u8], m2: &[u8], m3: &[u8], sk: &[u8; 128], opt_rand: &[u8; 32])
    -> (r: [u8; 29792])
    ensures r@ == spec_slh_sign_internal(m1@ + m2@ + m3@, sk@, opt_rand@),
{
    let sk_seed = get_part(sk, 0);
    let sk_prf = get_part(sk, 32);
    let pk_seed = get_part(sk, 64);
    let pk_root = get_part(sk, 96);
    let r = prf_msg(&sk_prf, opt_rand, m1, m2, m3);                 // Line 3
    let digest = h_msg(&r, &pk_seed, &pk_root, m1, m2, m3);         // Line 5
    let (md, idx_tree, idx_leaf) = split_digest(&digest);           // Lines 6 to 10
    let adrs = fors_adrs(idx_tree, idx_leaf);                       // Lines 1 and 11 to 13
    let sig_fors = fors_sign(&md, &sk_seed, &pk_seed, &adrs);       // Line 14
    let pk_fors = fors_pk_from_sig(&sig_fors, &md, &pk_seed, &adrs);  // Line 16
    let sig_ht = ht_sign(&pk_fors, &sk_seed, &pk_seed, idx_tree, idx_leaf);  // Line 17
    let fb = fors_to_bytes(&sig_fors);
    let hb = ht_to_bytes(&sig_ht);
    let mut sig = [0u8; 29792];
    copy_at(&mut sig, 0, r.as_slice());                             // Line 4
    copy_at(&mut sig, 32, fb.as_slice());                           // Line 15
    copy_at(&mut sig, 10592, hb.as_slice());                        // Line 18
    assert(sig@ =~= r@ + fb@ + hb@);
    sig                                                             // Line 19
}

/// Algorithm 20. slh_verify_internal (M, SIG, PK), for M = m1 || m2 || m3.
/// SIG has the length required by lines 1 to 3
pub fn slh_verify_internal_parts(m1: &[u8], m2: &[u8], m3: &[u8], sig: &[u8; 29792], pk: &[u8; 64]) -> (r: bool)
    ensures r == spec_slh_verify_internal(m1@ + m2@ + m3@, sig@, pk@),
{
    let pk_seed = get_part(pk, 0);
    let pk_root = get_part(pk, 32);
    let r = get_part(sig, 0);                                       // Line 5
    let sig_fors = fors_from_bytes(sig.as_slice(), 32);             // Line 6
    let sig_ht = ht_from_bytes(sig.as_slice(), 10592);              // Line 7
    let digest = h_msg(&r, &pk_seed, &pk_root, m1, m2, m3);         // Line 8
    let (md, idx_tree, idx_leaf) = split_digest(&digest);           // Lines 9 to 13
    let adrs = fors_adrs(idx_tree, idx_leaf);                       // Lines 4 and 14 to 16
    let pk_fors = fors_pk_from_sig(&sig_fors, &md, &pk_seed, &adrs);  // Line 17
    ht_verify(&pk_fors, &sig_ht, &pk_seed, idx_tree, idx_leaf, &pk_root)  // Line 18
}

/// Algorithm 19. slh_sign_internal (M, SK, addrnd), hedged
#[allow(dead_code)]  // Used by the test programs, with the kat feature
pub fn slh_sign_internal(m: &[u8], sk: &[u8; 128], addrnd: &[u8; 32]) -> (r: [u8; 29792])
    ensures r@ == spec_slh_sign_internal(m@, sk@, addrnd@),
{
    let e: [u8; 0] = [];
    assert(m@ + e@ + e@ =~= m@);
    slh_sign_internal_parts(m, e.as_slice(), e.as_slice(), sk, addrnd)
}

/// Algorithm 19. slh_sign_internal (M, SK), deterministic: opt_rand is PK.seed
#[allow(dead_code)]  // Used by the test programs, with the kat feature
pub fn slh_sign_internal_deterministic(m: &[u8], sk: &[u8; 128]) -> (r: [u8; 29792])
    ensures r@ == spec_slh_sign_internal(m@, sk@, spec_sk_pk_seed(sk@)),
{
    let pk_seed = get_part(sk, 64);
    slh_sign_internal(m, sk, &pk_seed)
}

/// Algorithm 20. slh_verify_internal (M, SIG, PK)
#[allow(dead_code)]  // Used by the test programs, with the kat feature
pub fn slh_verify_internal(m: &[u8], sig: &[u8; 29792], pk: &[u8; 64]) -> (r: bool)
    ensures r == spec_slh_verify_internal(m@, sig@, pk@),
{
    let e: [u8; 0] = [];
    assert(m@ + e@ + e@ =~= m@);
    slh_verify_internal_parts(m, e.as_slice(), e.as_slice(), sig, pk)
}

} // verus!
