//  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

//! Known Answer Test (KAT) drivers for the slh_dsa crate.
//!
//!   tkats hash   the hash functions (FIPS 205 section 4.1)
//!   tkats wots   WOTS+ (section 5)
//!   tkats xmss   XMSS (section 6)
//!   tkats ht     the hypertree (section 7)
//!   tkats fors   FORS (section 8)
//!   tkats slh    the internal functions (section 9)
//!   tkats acvp   the NIST ACVP tests read from stdin
//!
//! Each writes its inputs and results to stdout, in the format read by
//! the Python checkers in SLH/checkers. This is a port of the SPARK test
//! package SLH.KAT (SLH/spark_ada/src/slh-kat.adb), so both
//! implementations are checked by the same scripts.
//!
//! This is a test program: it uses std, and is not verified by Verus.
//! It needs the `kat` feature, which makes the internal functions public.

use std::io::{self, BufRead, Write};

use slh_dsa::adrs;
use slh_dsa::formats;
use slh_dsa::fors::{self, ForsElem, ForsSig};
use slh_dsa::hash;
use slh_dsa::ht::{self, HtSig};
use slh_dsa::internal;
use slh_dsa::wots;
use slh_dsa::xmss::{self, XmssSig};
use slh_dsa::{PreHash, MAX_CONTEXT_LENGTH};

type B32 = [u8; 32];

/// Simple xorshift32 generator for reproducible test inputs, as in the
/// SPARK tests. The quality of the randomness does not matter here.
struct Rng(u32);

impl Rng {
    fn byte(&mut self) -> u8 {
        let mut s = self.0;
        s ^= s << 13;
        s ^= s >> 17;
        s ^= s << 5;
        self.0 = s;
        (s & 0xff) as u8
    }

    fn fill(&mut self, d: &mut [u8]) {
        for b in d.iter_mut() {
            *b = self.byte();
        }
    }

    fn b32(&mut self) -> B32 {
        let mut r = [0u8; 32];
        self.fill(&mut r);
        r
    }

    fn vec(&mut self, n: usize) -> Vec<u8> {
        let mut v = vec![0u8; n];
        self.fill(&mut v);
        v
    }

    /// Message M for case count. Cases 0 and 1 give the largest and
    /// smallest WOTS+ checksums. Other cases are random
    fn msg(&mut self, count: usize) -> B32 {
        match count {
            0 => [0x00; 32],
            1 => [0xff; 32],
            _ => self.b32(),
        }
    }

    /// A WOTS+ address. Odd cases are fully random. Even cases are as
    /// set up by Algorithms 10, 11 and 12: a random layer, tree and key
    /// pair address, with type WOTS_HASH, and chain and hash addresses 0
    fn wots_adrs(&mut self, count: usize) -> B32 {
        let a = self.b32();
        if count % 2 == 0 {
            let k = self.b32();
            let kp = u32::from_be_bytes([k[0], k[1], k[2], k[3]]);
            adrs::set_key_pair_address(adrs::set_type_and_clear(a, adrs::WOTS_HASH), kp)
        } else {
            a
        }
    }
}

struct Out(io::BufWriter<io::Stdout>);

impl Out {
    fn header(&mut self, name: &str, count: usize) {
        writeln!(self.0, "Function = {}", name).unwrap();
        writeln!(self.0, "Count = {}", count).unwrap();
    }

    fn hex(&mut self, name: &str, d: &[u8]) {
        let mut s = String::with_capacity(2 * d.len());
        for b in d {
            s.push_str(&format!("{:02x}", b));
        }
        writeln!(self.0, "{} = {}", name, s).unwrap();
    }

    fn int(&mut self, name: &str, v: u64) {
        writeln!(self.0, "{} = {}", name, v).unwrap();
    }

    fn bool(&mut self, name: &str, v: bool) {
        writeln!(self.0, "{} = {}", name, if v { "TRUE" } else { "FALSE" }).unwrap();
    }

    fn end(&mut self) {
        writeln!(self.0).unwrap();
    }
}

fn flat(v: &[B32]) -> Vec<u8> {
    v.iter().flat_map(|x| x.iter().copied()).collect()
}

fn chunks(v: &[u8]) -> Vec<B32> {
    v.chunks(32).map(|c| c.try_into().unwrap()).collect()
}

//---------------------------------------------------------------------
//  Hash functions (section 4.1)
//---------------------------------------------------------------------

/// Message lengths around one and two multiples of the SHAKE256 rate
/// (136 bytes), for PRF_msg (64 bytes before M) and H_msg (96 bytes)
const MSG_LENGTHS: [usize; 15] = [0, 1, 39, 40, 41, 71, 72, 73, 135, 136, 137, 175, 176, 177, 1000];

/// Values of l for T_l. 3 crosses the rate boundary, k is used for
/// FORS roots, and len for WOTS+ public keys
const L_VALUES: [usize; 5] = [1, 2, 3, 22, 67];

const FIXED_CASES: usize = 8;

fn hash_kats(rng: &mut Rng, out: &mut Out) {
    for (count, &len) in MSG_LENGTHS.iter().enumerate() {
        let (sk_prf, opt_rand, m) = (rng.b32(), rng.b32(), rng.vec(len));
        out.header("PRF_Msg", count);
        out.hex("SK_Prf", &sk_prf);
        out.hex("Opt_Rand", &opt_rand);
        out.hex("M", &m);
        out.hex("Result", &hash::prf_msg(&sk_prf, &opt_rand, &m, &[], &[]));
        out.end();
    }
    for (count, &len) in MSG_LENGTHS.iter().enumerate() {
        let (r, pk_seed, pk_root, m) = (rng.b32(), rng.b32(), rng.b32(), rng.vec(len));
        out.header("H_Msg", count);
        out.hex("R", &r);
        out.hex("PK_Seed", &pk_seed);
        out.hex("PK_Root", &pk_root);
        out.hex("M", &m);
        out.hex("Result", &hash::h_msg(&r, &pk_seed, &pk_root, &m, &[], &[]));
        out.end();
    }
    for count in 0..FIXED_CASES {
        let (pk_seed, sk_seed, a) = (rng.b32(), rng.b32(), rng.b32());
        out.header("PRF", count);
        out.hex("PK_Seed", &pk_seed);
        out.hex("SK_Seed", &sk_seed);
        out.hex("ADRS", &a);
        out.hex("Result", &hash::prf(&pk_seed, &sk_seed, &a));
        out.end();
    }
    for (count, &l) in L_VALUES.iter().enumerate() {
        let (pk_seed, a, m) = (rng.b32(), rng.b32(), rng.vec(32 * l));
        out.header("T_L", count);
        out.hex("PK_Seed", &pk_seed);
        out.hex("ADRS", &a);
        out.hex("M_L", &m);
        out.hex("Result", &hash::t_l(&pk_seed, &a, &chunks(&m)));
        out.end();
    }
    for count in 0..FIXED_CASES {
        let (pk_seed, a) = (rng.b32(), rng.b32());
        let m2: [u8; 64] = rng.vec(64).try_into().unwrap();
        out.header("H", count);
        out.hex("PK_Seed", &pk_seed);
        out.hex("ADRS", &a);
        out.hex("M2", &m2);
        out.hex("Result", &hash::h(&pk_seed, &a, &m2));
        out.end();
    }
    for count in 0..FIXED_CASES {
        let (pk_seed, a, m1) = (rng.b32(), rng.b32(), rng.b32());
        out.header("F", count);
        out.hex("PK_Seed", &pk_seed);
        out.hex("ADRS", &a);
        out.hex("M1", &m1);
        out.hex("Result", &hash::f(&pk_seed, &a, &m1));
        out.end();
    }
}

//---------------------------------------------------------------------
//  WOTS+ (section 5)
//---------------------------------------------------------------------

const CHAIN_CASES: [(u32, u32); 10] = [(0, 0), (0, 1), (0, 15), (15, 0), (14, 1), (1, 14), (3, 7), (7, 8), (5, 0), (8, 3)];

fn wots_kats(rng: &mut Rng, out: &mut Out) {
    for (count, &(i, s)) in CHAIN_CASES.iter().enumerate() {
        let (x, pk_seed) = (rng.b32(), rng.b32());
        let a = rng.wots_adrs(count);
        out.header("Chain", count);
        out.hex("X", &x);
        out.int("I", i as u64);
        out.int("S", s as u64);
        out.hex("PK_Seed", &pk_seed);
        out.hex("ADRS", &a);
        out.hex("Result", &wots::chain(&x, i, s, &pk_seed, &a));
        out.end();
    }
    for count in 0..FIXED_CASES {
        let (sk_seed, pk_seed) = (rng.b32(), rng.b32());
        let a = rng.wots_adrs(count);
        out.header("WOTS_PK_Gen", count);
        out.hex("SK_Seed", &sk_seed);
        out.hex("PK_Seed", &pk_seed);
        out.hex("ADRS", &a);
        out.hex("Result", &wots::wots_pk_gen(&sk_seed, &pk_seed, &a));
        out.end();
    }
    for count in 0..FIXED_CASES {
        let m = rng.msg(count);
        let (sk_seed, pk_seed) = (rng.b32(), rng.b32());
        let a = rng.wots_adrs(count);
        out.header("WOTS_Sign", count);
        out.hex("M", &m);
        out.hex("SK_Seed", &sk_seed);
        out.hex("PK_Seed", &pk_seed);
        out.hex("ADRS", &a);
        out.hex("Result", &flat(&wots::wots_sign(&m, &sk_seed, &pk_seed, &a)));
        out.end();
    }
    //  wots_pkFromSig on random signatures, which need not be valid
    for count in 0..FIXED_CASES {
        let sig: [B32; 67] = core::array::from_fn(|_| rng.b32());
        let m = rng.msg(count);
        let pk_seed = rng.b32();
        let a = rng.wots_adrs(count);
        out.header("WOTS_PK_From_Sig", count);
        out.hex("Sig", &flat(&sig));
        out.hex("M", &m);
        out.hex("PK_Seed", &pk_seed);
        out.hex("ADRS", &a);
        out.hex("Result", &wots::wots_pk_from_sig(&sig, &m, &pk_seed, &a));
        out.end();
    }
    //  Signs M, then computes the public key from the signature, and
    //  generates the public key. The checker confirms that they agree
    for count in 0..FIXED_CASES {
        let m = rng.msg(count);
        let (sk_seed, pk_seed) = (rng.b32(), rng.b32());
        let a = rng.wots_adrs(count);
        out.header("WOTS_Round_Trip", count);
        out.hex("M", &m);
        out.hex("SK_Seed", &sk_seed);
        out.hex("PK_Seed", &pk_seed);
        out.hex("ADRS", &a);
        out.hex("PK_Gen", &wots::wots_pk_gen(&sk_seed, &pk_seed, &a));
        let sig = wots::wots_sign(&m, &sk_seed, &pk_seed, &a);
        out.hex("PK_From_Sig", &wots::wots_pk_from_sig(&sig, &m, &pk_seed, &a));
        out.end();
    }
}

//---------------------------------------------------------------------
//  XMSS (section 6)
//---------------------------------------------------------------------

/// Leaf indices for the signing tests: the first and last, and others
const SIGN_IDX: [u32; 6] = [0, 255, 1, 128, 77, 170];

const NODE_CASES: [(u32, u32); 10] = [(0, 0), (255, 0), (0, 1), (127, 1), (5, 2), (31, 3), (3, 4), (15, 4), (1, 7), (0, 8)];

fn xmss_bytes(s: &XmssSig) -> [u8; 2400] {
    formats::xmss_to_bytes(s)
}

fn xmss_kats(rng: &mut Rng, out: &mut Out) {
    for (count, &(i, z)) in NODE_CASES.iter().enumerate() {
        let (sk_seed, pk_seed, a) = (rng.b32(), rng.b32(), rng.b32());
        out.header("XMSS_Node", count);
        out.hex("SK_Seed", &sk_seed);
        out.int("I", i as u64);
        out.int("Z", z as u64);
        out.hex("PK_Seed", &pk_seed);
        out.hex("ADRS", &a);
        out.hex("Result", &xmss::xmss_node(&sk_seed, i, z, &pk_seed, &a));
        out.end();
    }
    for (count, &idx) in SIGN_IDX[0..3].iter().enumerate() {
        let m = rng.msg(count);
        let (sk_seed, pk_seed, a) = (rng.b32(), rng.b32(), rng.b32());
        out.header("XMSS_Sign", count);
        out.hex("M", &m);
        out.hex("SK_Seed", &sk_seed);
        out.int("Idx", idx as u64);
        out.hex("PK_Seed", &pk_seed);
        out.hex("ADRS", &a);
        out.hex("Result", &xmss_bytes(&xmss::xmss_sign(&m, &sk_seed, idx, &pk_seed, &a)));
        out.end();
    }
    //  xmss_pkFromSig on random signatures, which need not be valid
    for (count, &idx) in SIGN_IDX.iter().enumerate() {
        let s = XmssSig { sig: core::array::from_fn(|_| rng.b32()), auth: core::array::from_fn(|_| rng.b32()) };
        let m = rng.msg(count);
        let (pk_seed, a) = (rng.b32(), rng.b32());
        out.header("XMSS_PK_From_Sig", count);
        out.int("Idx", idx as u64);
        out.hex("Sig_XMSS", &xmss_bytes(&s));
        out.hex("M", &m);
        out.hex("PK_Seed", &pk_seed);
        out.hex("ADRS", &a);
        out.hex("Result", &xmss::xmss_pk_from_sig(idx, &s, &m, &pk_seed, &a));
        out.end();
    }
    //  The root computed from a signature, and the root of the tree
    for (count, &idx) in SIGN_IDX[3..6].iter().enumerate() {
        let m = rng.msg(count);
        let (sk_seed, pk_seed, a) = (rng.b32(), rng.b32(), rng.b32());
        out.header("XMSS_Round_Trip", count);
        out.hex("M", &m);
        out.hex("SK_Seed", &sk_seed);
        out.int("Idx", idx as u64);
        out.hex("PK_Seed", &pk_seed);
        out.hex("ADRS", &a);
        out.hex("Root", &xmss::xmss_node(&sk_seed, 0, 8, &pk_seed, &a));
        let s = xmss::xmss_sign(&m, &sk_seed, idx, &pk_seed, &a);
        out.hex("PK_From_Sig", &xmss::xmss_pk_from_sig(idx, &s, &m, &pk_seed, &a));
        out.end();
    }
}

//---------------------------------------------------------------------
//  The hypertree (section 7)
//---------------------------------------------------------------------

/// The first and last trees and leaves, and some others
const HT_CASES: [(u64, u32); 3] = [(0, 0), ((1u64 << 56) - 1, 255), (0x00A5_5A3C_C3F0_0F96, 77)];

/// toByte (0, 32), setLayerAddress (d - 1): the ADRS of the top tree
fn top_adrs() -> B32 {
    adrs::set_layer_address([0u8; 32], 7)
}

fn ht_kats(rng: &mut Rng, out: &mut Out) {
    //  ht_verify on random signatures, which need not be valid
    for (count, &(idx_tree, idx_leaf)) in HT_CASES.iter().enumerate() {
        let s: HtSig = core::array::from_fn(|_| XmssSig {
            sig: core::array::from_fn(|_| rng.b32()),
            auth: core::array::from_fn(|_| rng.b32()),
        });
        let m = rng.msg(count);
        let (pk_seed, pk_root) = (rng.b32(), rng.b32());
        out.header("HT_Verify", count);
        out.hex("M", &m);
        out.hex("Sig_HT", &formats::ht_to_bytes(&s));
        out.hex("PK_Seed", &pk_seed);
        out.int("Idx_Tree", idx_tree);
        out.int("Idx_Leaf", idx_leaf as u64);
        out.hex("PK_Root", &pk_root);
        out.bool("Result", ht::ht_verify(&m, &s, &pk_seed, idx_tree, idx_leaf, &pk_root));
        out.end();
    }
    //  Signs M, then verifies the signature, and the signature with a
    //  changed byte, a different PK.root, and a different idx_leaf
    for (count, &(idx_tree, idx_leaf)) in HT_CASES[0..2].iter().enumerate() {
        let m = rng.msg(count);
        let (sk_seed, pk_seed) = (rng.b32(), rng.b32());
        out.header("HT_Round_Trip", count);
        out.hex("M", &m);
        out.hex("SK_Seed", &sk_seed);
        out.hex("PK_Seed", &pk_seed);
        out.int("Idx_Tree", idx_tree);
        out.int("Idx_Leaf", idx_leaf as u64);
        let s = ht::ht_sign(&m, &sk_seed, &pk_seed, idx_tree, idx_leaf);
        let pk_root = xmss::xmss_node(&sk_seed, 0, 8, &pk_seed, &top_adrs());
        out.hex("Sig_HT", &formats::ht_to_bytes(&s));
        out.hex("PK_Root", &pk_root);
        out.bool("Verify", ht::ht_verify(&m, &s, &pk_seed, idx_tree, idx_leaf, &pk_root));
        let mut t = s;
        t[3].auth[5][7] ^= 1;
        out.bool("Verify_Tampered_Sig", ht::ht_verify(&m, &t, &pk_seed, idx_tree, idx_leaf, &pk_root));
        let mut bad = pk_root;
        bad[0] ^= 1;
        out.bool("Verify_Wrong_Root", ht::ht_verify(&m, &s, &pk_seed, idx_tree, idx_leaf, &bad));
        out.bool("Verify_Wrong_Leaf", ht::ht_verify(&m, &s, &pk_seed, idx_tree, idx_leaf ^ 1, &pk_root));
        out.end();
    }
}

//---------------------------------------------------------------------
//  FORS (section 8)
//---------------------------------------------------------------------

/// md with every index 0, every index 2^a - 1, then random
fn fill_md(rng: &mut Rng, count: usize) -> [u8; 39] {
    match count {
        0 => [0x00; 39],
        1 => [0xff; 39],
        _ => rng.vec(39).try_into().unwrap(),
    }
}

const FORS_NODE_CASES: [(u32, u32); 9] = [
    (0, 0), (22 * (1 << 14) - 1, 0), (12_345, 0), (5, 1), (22 * (1 << 13) - 1, 1),
    (1_000, 6), (22 * (1 << 3) - 1, 11), (0, 14), (21, 14),
];

const FORS_SK_IDX: [u32; 5] = [0, 1, 16_384, 22 * (1 << 14) - 1, 200_000];

/// The FORS public key, T_k of the k tree roots
fn fors_pk(sk_seed: &B32, pk_seed: &B32, a: &B32) -> B32 {
    let roots: Vec<B32> = (0..22).map(|i| fors::fors_node(sk_seed, i, 14, pk_seed, a)).collect();
    let kp = adrs::get_key_pair_address(a);
    let pk_adrs = adrs::set_key_pair_address(adrs::set_type_and_clear(*a, adrs::FORS_ROOTS), kp);
    hash::t_l(pk_seed, &pk_adrs, &roots)
}

fn fors_kats(rng: &mut Rng, out: &mut Out) {
    for (count, &idx) in FORS_SK_IDX.iter().enumerate() {
        let (sk_seed, pk_seed, a) = (rng.b32(), rng.b32(), rng.b32());
        out.header("FORS_SK_Gen", count);
        out.hex("SK_Seed", &sk_seed);
        out.hex("PK_Seed", &pk_seed);
        out.hex("ADRS", &a);
        out.int("Idx", idx as u64);
        out.hex("Result", &fors::fors_sk_gen(&sk_seed, &pk_seed, &a, idx));
        out.end();
    }
    for (count, &(i, z)) in FORS_NODE_CASES.iter().enumerate() {
        let (sk_seed, pk_seed, a) = (rng.b32(), rng.b32(), rng.b32());
        out.header("FORS_Node", count);
        out.hex("SK_Seed", &sk_seed);
        out.int("I", i as u64);
        out.int("Z", z as u64);
        out.hex("PK_Seed", &pk_seed);
        out.hex("ADRS", &a);
        out.hex("Result", &fors::fors_node(&sk_seed, i, z, &pk_seed, &a));
        out.end();
    }
    for count in 0..3 {
        let md = fill_md(rng, count);
        let (sk_seed, pk_seed, a) = (rng.b32(), rng.b32(), rng.b32());
        out.header("FORS_Sign", count);
        out.hex("MD", &md);
        out.hex("SK_Seed", &sk_seed);
        out.hex("PK_Seed", &pk_seed);
        out.hex("ADRS", &a);
        out.hex("Result", &formats::fors_to_bytes(&fors::fors_sign(&md, &sk_seed, &pk_seed, &a)));
        out.end();
    }
    //  fors_pkFromSig on random signatures, which need not be valid
    for count in 0..4 {
        let s: ForsSig = core::array::from_fn(|_| ForsElem { sk: rng.b32(), auth: core::array::from_fn(|_| rng.b32()) });
        let md = fill_md(rng, count);
        let (pk_seed, a) = (rng.b32(), rng.b32());
        out.header("FORS_PK_From_Sig", count);
        out.hex("Sig_FORS", &formats::fors_to_bytes(&s));
        out.hex("MD", &md);
        out.hex("PK_Seed", &pk_seed);
        out.hex("ADRS", &a);
        out.hex("Result", &fors::fors_pk_from_sig(&s, &md, &pk_seed, &a));
        out.end();
    }
    //  The public key computed from a signature, and from the tree roots
    for count in 0..3 {
        let md = fill_md(rng, count);
        let (sk_seed, pk_seed, a) = (rng.b32(), rng.b32(), rng.b32());
        out.header("FORS_Round_Trip", count);
        out.hex("MD", &md);
        out.hex("SK_Seed", &sk_seed);
        out.hex("PK_Seed", &pk_seed);
        out.hex("ADRS", &a);
        out.hex("PK", &fors_pk(&sk_seed, &pk_seed, &a));
        let s = fors::fors_sign(&md, &sk_seed, &pk_seed, &a);
        out.hex("PK_From_Sig", &fors::fors_pk_from_sig(&s, &md, &pk_seed, &a));
        out.end();
    }
}

//---------------------------------------------------------------------
//  Internal functions (section 9)
//---------------------------------------------------------------------

/// Signs a message with a new key pair, then verifies the signature,
/// and the signature with one byte changed in each of R, SIG_FORS and
/// SIG_HT, a different message, and a different PK.root
fn slh_kats(rng: &mut Rng, out: &mut Out) {
    for count in 0..2 {
        let (sk_seed, sk_prf, pk_seed, addrnd) = (rng.b32(), rng.b32(), rng.b32(), rng.b32());
        let msg = rng.vec(100 * count);
        let mut bad_msg = msg.clone();
        bad_msg.push(0);
        let (sk, pk) = internal::slh_keygen_internal(&sk_seed, &sk_prf, &pk_seed);
        out.header("SLH_Round_Trip", count);
        out.hex("SK_Seed", &sk_seed);
        out.hex("SK_Prf", &sk_prf);
        out.hex("PK_Seed", &pk_seed);
        out.hex("Msg", &msg);
        //  Count 0 is deterministic, count 1 is hedged
        let s = if count == 0 {
            internal::slh_sign_internal_deterministic(&msg, &sk)
        } else {
            out.hex("Addrnd", &addrnd);
            internal::slh_sign_internal(&msg, &sk, &addrnd)
        };
        out.hex("SK", &sk);
        out.hex("PK", &pk);
        out.hex("Sig", &s);
        out.bool("Verify", internal::slh_verify_internal(&msg, &s, &pk));
        let mut t = s;
        t[5] ^= 1;
        out.bool("Verify_Tampered_R", internal::slh_verify_internal(&msg, &t, &pk));
        let mut t = s;
        t[32 + 1000] ^= 1;
        out.bool("Verify_Tampered_FORS", internal::slh_verify_internal(&msg, &t, &pk));
        let mut t = s;
        t[10592 + 10000] ^= 1;
        out.bool("Verify_Tampered_HT", internal::slh_verify_internal(&msg, &t, &pk));
        out.bool("Verify_Wrong_Msg", internal::slh_verify_internal(&bad_msg, &s, &pk));
        let mut bad_pk = pk;
        bad_pk[32] ^= 1;
        out.bool("Verify_Wrong_Root", internal::slh_verify_internal(&msg, &s, &bad_pk));
        out.end();
    }
}

//---------------------------------------------------------------------
//  NIST ACVP tests, read from stdin in the format written by
//  SLH/checkers/check_acvp.py
//---------------------------------------------------------------------

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "bad hex string");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("bad hex digit")).collect()
}

fn pre_hash(name: &str) -> PreHash {
    match name {
        "SHA3-512" => PreHash::Sha3_512,
        "SHAKE-256" => PreHash::Shake256,
        _ => panic!("unsupported pre-hash {}", name),
    }
}

fn run_acvp_test(r: &std::collections::HashMap<String, String>, out: &mut Out) {
    let func = r["Function"].as_str();
    let get = |k: &str| unhex(r.get(k).unwrap_or_else(|| panic!("missing {}", k)));
    let get32 = |k: &str| -> B32 { get(k).try_into().expect("wrong length") };
    out.header(func, 0);
    writeln!(out.0, "tcId = {}", r["tcId"]).unwrap();
    match func {
        "KeyGen" => {
            //  Algorithm 21 (which calls Algorithm 18)
            let kp = slh_dsa::slh_keygen(&get32("SK_Seed"), &get32("SK_Prf"), &get32("PK_Seed"));
            out.hex("SK", &kp.sk);
            out.hex("PK", &kp.pk);
        }
        "SigGen" | "SigGenPure" | "SigGenPreHash" => {
            let sk: [u8; 128] = get("SK").try_into().expect("wrong length");
            let msg = get("Message");
            let addrnd = r.get("Addrnd").map(|_| get32("Addrnd"));
            let ctx = if func == "SigGen" { vec![] } else { get("Context") };
            assert!(ctx.len() <= MAX_CONTEXT_LENGTH, "context too long");
            let s = match (func, addrnd) {
                ("SigGen", Some(a)) => internal::slh_sign_internal(&msg, &sk, &a),            // Algorithm 19
                ("SigGen", None) => internal::slh_sign_internal_deterministic(&msg, &sk),
                ("SigGenPure", Some(a)) => slh_dsa::slh_sign(&msg, &ctx, &sk, &a),             // Algorithm 22
                ("SigGenPure", None) => slh_dsa::slh_sign_deterministic(&msg, &ctx, &sk),
                (_, Some(a)) => slh_dsa::hash_slh_sign(&msg, &ctx, &pre_hash(&r["HashAlg"]), &sk, &a),  // Algorithm 23
                (_, None) => slh_dsa::hash_slh_sign_deterministic(&msg, &ctx, &pre_hash(&r["HashAlg"]), &sk),
            };
            out.hex("Signature", &s);
        }
        "SigVer" | "SigVerPure" | "SigVerPreHash" => {
            let pk: [u8; 64] = get("PK").try_into().expect("wrong length");
            let msg = get("Message");
            let sig = get("Signature");
            let ctx = if func == "SigVer" { vec![] } else { get("Context") };
            //  Algorithm 20 lines 1 to 3. A signature of the wrong length
            //  can't be a Signature, so it is rejected here
            let result = match <[u8; 29792]>::try_from(sig.as_slice()) {
                Err(_) => false,
                Ok(s) => match func {
                    "SigVer" => internal::slh_verify_internal(&msg, &s, &pk),                  // Algorithm 20
                    "SigVerPure" => slh_dsa::slh_verify(&msg, &s, &ctx, &pk),                  // Algorithm 24
                    _ => slh_dsa::hash_slh_verify(&msg, &s, &ctx, &pre_hash(&r["HashAlg"]), &pk),  // Algorithm 25
                },
            };
            out.bool("Result", result);
        }
        _ => panic!("unknown function {}", func),
    }
    out.end();
}

fn acvp_tests(out: &mut Out) {
    let mut record = std::collections::HashMap::new();
    for line in io::stdin().lock().lines() {
        let line = line.expect("read error");
        if line.is_empty() {
            if record.contains_key("Function") {
                run_acvp_test(&record, out);
            }
            record.clear();
        } else {
            let (k, v) = line.split_once(" = ").expect("expected 'Key = Value'");
            record.insert(k.to_string(), v.to_string());
        }
    }
    if record.contains_key("Function") {
        run_acvp_test(&record, out);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut rng = Rng(0x5EED_1205);
    let mut out = Out(io::BufWriter::new(io::stdout()));
    match args.get(1).map(String::as_str) {
        Some("hash") if args.len() == 2 => hash_kats(&mut rng, &mut out),
        Some("wots") if args.len() == 2 => wots_kats(&mut rng, &mut out),
        Some("xmss") if args.len() == 2 => xmss_kats(&mut rng, &mut out),
        Some("ht") if args.len() == 2 => ht_kats(&mut rng, &mut out),
        Some("fors") if args.len() == 2 => fors_kats(&mut rng, &mut out),
        Some("slh") if args.len() == 2 => slh_kats(&mut rng, &mut out),
        Some("acvp") if args.len() == 2 => acvp_tests(&mut out),
        _ => {
            eprintln!("usage: tkats hash|wots|xmss|ht|fors|slh|acvp");
            std::process::exit(1);
        }
    }
    out.0.flush().unwrap();
}
