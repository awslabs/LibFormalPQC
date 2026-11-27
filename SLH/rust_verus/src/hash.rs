//  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

//! The hash functions and pseudorandom functions for SLH-DSA-SHAKE
//! (FIPS 205 sections 4.1 and 11.1), and the pre-hash functions of
//! section 10.2.2.
//!
//! SHAKE256 and SHA3-512 are modelled by the uninterpreted spec
//! functions `shake256` and `sha3_512`. The `#[verifier::external_body]`
//! functions in this module call the `sha3` crate, and are trusted to
//! compute them. They are the only trusted code in the library.

#[cfg(verus_keep_ghost)]  // Only used in specifications
use crate::util::*;
use sha3::digest::{Digest, ExtendableOutput, Update, XofReader};
use vstd::prelude::*;

verus! {

/// SHAKE256 (input, 8 out_len)
pub uninterp spec fn shake256(input: Seq<u8>, out_len: nat) -> Seq<u8>;

/// SHA3-512 (input)
pub uninterp spec fn sha3_512(input: Seq<u8>) -> Seq<u8>;

/// PRF (PK.seed, SK.seed, ADRS) = SHAKE256 (PK.seed || ADRS || SK.seed, 8n)
pub open spec fn spec_prf(pk_seed: Seq<u8>, sk_seed: Seq<u8>, adrs: Seq<u8>) -> Seq<u8> {
    shake256(pk_seed + adrs + sk_seed, 32)
}

/// F (PK.seed, ADRS, M1) = SHAKE256 (PK.seed || ADRS || M1, 8n)
pub open spec fn spec_f(pk_seed: Seq<u8>, adrs: Seq<u8>, m1: Seq<u8>) -> Seq<u8> {
    shake256(pk_seed + adrs + m1, 32)
}

/// H (PK.seed, ADRS, M2) = SHAKE256 (PK.seed || ADRS || M2, 8n)
pub open spec fn spec_h(pk_seed: Seq<u8>, adrs: Seq<u8>, m2: Seq<u8>) -> Seq<u8> {
    shake256(pk_seed + adrs + m2, 32)
}

/// T_l (PK.seed, ADRS, M_l) = SHAKE256 (PK.seed || ADRS || M_l, 8n)
pub open spec fn spec_t(pk_seed: Seq<u8>, adrs: Seq<u8>, m_l: Seq<u8>) -> Seq<u8> {
    shake256(pk_seed + adrs + m_l, 32)
}

/// PRF_msg (SK.prf, opt_rand, M) = SHAKE256 (SK.prf || opt_rand || M, 8n)
pub open spec fn spec_prf_msg(sk_prf: Seq<u8>, opt_rand: Seq<u8>, m: Seq<u8>) -> Seq<u8> {
    shake256(sk_prf + opt_rand + m, 32)
}

/// H_msg (R, PK.seed, PK.root, M) = SHAKE256 (R || PK.seed || PK.root || M, 8m)
pub open spec fn spec_h_msg(r: Seq<u8>, pk_seed: Seq<u8>, pk_root: Seq<u8>, m: Seq<u8>) -> Seq<u8> {
    shake256(r + pk_seed + pk_root + m, 47)
}

#[verifier::external_body]
fn shake256_32_3(a: &[u8], b: &[u8], c: &[u8]) -> (r: [u8; 32])
    ensures r@ == shake256(a@ + b@ + c@, 32),
{
    let mut h = sha3::Shake256::default();
    h.update(a);
    h.update(b);
    h.update(c);
    let mut r = [0u8; 32];
    h.finalize_xof().read(&mut r);
    r
}

pub fn prf(pk_seed: &[u8; 32], sk_seed: &[u8; 32], adrs: &[u8; 32]) -> (r: [u8; 32])
    ensures r@ == spec_prf(pk_seed@, sk_seed@, adrs@),
{
    shake256_32_3(pk_seed.as_slice(), adrs.as_slice(), sk_seed.as_slice())
}

pub fn f(pk_seed: &[u8; 32], adrs: &[u8; 32], m1: &[u8; 32]) -> (r: [u8; 32])
    ensures r@ == spec_f(pk_seed@, adrs@, m1@),
{
    shake256_32_3(pk_seed.as_slice(), adrs.as_slice(), m1.as_slice())
}

pub fn h(pk_seed: &[u8; 32], adrs: &[u8; 32], m2: &[u8; 64]) -> (r: [u8; 32])
    ensures r@ == spec_h(pk_seed@, adrs@, m2@),
{
    shake256_32_3(pk_seed.as_slice(), adrs.as_slice(), m2.as_slice())
}

/// T_l, where M_l is the concatenation of the n-byte strings in m
#[verifier::external_body]
pub fn t_l(pk_seed: &[u8; 32], adrs: &[u8; 32], m: &[[u8; 32]]) -> (r: [u8; 32])
    ensures r@ == spec_t(pk_seed@, adrs@, flat(views32(m@))),
{
    let mut h = sha3::Shake256::default();
    h.update(pk_seed);
    h.update(adrs);
    for x in m {
        h.update(x);
    }
    let mut r = [0u8; 32];
    h.finalize_xof().read(&mut r);
    r
}

/// PRF_msg, where M is m1 || m2 || m3
#[verifier::external_body]
pub fn prf_msg(sk_prf: &[u8; 32], opt_rand: &[u8; 32], m1: &[u8], m2: &[u8], m3: &[u8]) -> (r: [u8; 32])
    ensures r@ == spec_prf_msg(sk_prf@, opt_rand@, m1@ + m2@ + m3@),
{
    let mut h = sha3::Shake256::default();
    h.update(sk_prf);
    h.update(opt_rand);
    h.update(m1);
    h.update(m2);
    h.update(m3);
    let mut r = [0u8; 32];
    h.finalize_xof().read(&mut r);
    r
}

/// H_msg, where M is m1 || m2 || m3
#[verifier::external_body]
pub fn h_msg(r: &[u8; 32], pk_seed: &[u8; 32], pk_root: &[u8; 32], m1: &[u8], m2: &[u8], m3: &[u8])
    -> (res: [u8; 47])
    ensures res@ == spec_h_msg(r@, pk_seed@, pk_root@, m1@ + m2@ + m3@),
{
    let mut h = sha3::Shake256::default();
    h.update(r);
    h.update(pk_seed);
    h.update(pk_root);
    h.update(m1);
    h.update(m2);
    h.update(m3);
    let mut res = [0u8; 47];
    h.finalize_xof().read(&mut res);
    res
}

/// SHAKE256 (M, 512), a pre-hash
#[verifier::external_body]
pub fn shake256_512(m: &[u8]) -> (r: [u8; 64])
    ensures r@ == shake256(m@, 64),
{
    let mut h = sha3::Shake256::default();
    h.update(m);
    let mut r = [0u8; 64];
    h.finalize_xof().read(&mut r);
    r
}

/// SHA3-512 (M), a pre-hash
#[verifier::external_body]
pub fn sha3_512_hash(m: &[u8]) -> (r: [u8; 64])
    ensures r@ == sha3_512(m@),
{
    let d = sha3::Sha3_512::digest(m);
    let mut r = [0u8; 64];
    r.copy_from_slice(&d);
    r
}

} // verus!
