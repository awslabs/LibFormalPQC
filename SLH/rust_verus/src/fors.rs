//  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

//! Forest of Random Subsets (FORS), FIPS 205 section 8, Algorithms 14
//! to 17.
//!
//! The functions are pure. FIPS 205 Algorithms 15 and 17 only change
//! the tree height and tree index of the caller's ADRS, and set both
//! before each use, so their earlier values are never observed.
//! Algorithms 14 and 17 copy ADRS before calling setTypeAndClear.

use crate::adrs::*;
use crate::hash::*;
#[cfg(verus_keep_ghost)]  // Only used in specifications
use crate::params::*;
use crate::util::*;
use vstd::prelude::*;

verus! {

/// One private key value and its AUTH (FIPS 205 Figure 14)
#[derive(Clone, Copy)]
pub struct ForsElem {
    pub sk: [u8; 32],
    pub auth: [[u8; 32]; 14],
}

/// SIG_FORS, the elements for trees 0 to k - 1 (Figure 14)
pub type ForsSig = [ForsElem; 22];

pub open spec fn fors_elem_view(e: ForsElem) -> (Seq<u8>, Seq<Seq<u8>>) {
    (e.sk@, views32(e.auth@))
}

pub open spec fn fors_view(s: Seq<ForsElem>) -> Seq<(Seq<u8>, Seq<Seq<u8>>)> {
    s.map_values(|e: ForsElem| fors_elem_view(e))
}

/// indices[i] = base_2b (md, a, k)[i] (Algorithm 16 line 2 and
/// Algorithm 17 line 1): the a-bit integer formed by bits a i to
/// a i + a - 1 of md, most significant bit first. These bits are in the
/// three bytes from byte floor (a i / 8), as bits (a i) mod 8 to
/// (a i) mod 8 + 13 of the 24-bit integer formed by those bytes
pub open spec fn spec_fors_index(md: Seq<u8>, i: int) -> u32 {
    let s = 14 * i;
    let b = s / 8;
    let v: u32 = ((md[b] as u32) << 16u32) | ((md[b + 1] as u32) << 8u32) | (md[b + 2] as u32);
    (v >> ((10 - s % 8) as u32)) & 0x3fffu32
}

/// i 2^a + indices[i], the index of the leaf of tree i that is signed
/// (Algorithm 16 line 4 and Algorithm 17 line 5)
pub open spec fn spec_leaf_index(i: int, ind: u32) -> u32 {
    (((i as u32) << 14u32) + ind) as u32
}

/// i 2^(a - j) + s, where s = floor (indices[i] / 2^j) xor 1: the
/// sibling of the node of height j on the path from the leaf
/// (Algorithm 16 lines 6 and 7)
pub open spec fn spec_auth_index(i: int, ind: u32, j: int) -> u32 {
    (((i as u32) << ((14 - j) as u32)) + ((ind >> (j as u32)) ^ 1u32)) as u32
}

/// True if i is the index of a node of height z, i < k 2^(a - z)
pub open spec fn spec_fors_valid_node(i: u32, z: u32) -> bool {
    z <= 14 && (i >> ((14 - z) as u32)) < 22
}

/// skADRS in Algorithm 14 lines 1 to 4
pub open spec fn spec_fors_sk_adrs(a: Seq<u8>, idx: u32) -> Seq<u8> {
    spec_set_tree_index(
        spec_set_key_pair_address(spec_set_type_and_clear(a, FORS_PRF), spec_get_key_pair_address(a)), idx)
}

/// ADRS after setTreeHeight (z) and setTreeIndex (i) (Algorithm 15
/// lines 3 and 4 or 9 and 10, and Algorithm 17 lines 4 and 5 or 9 to 14)
pub open spec fn spec_fors_node_adrs(a: Seq<u8>, z: u32, i: u32) -> Seq<u8> {
    spec_set_tree_index(spec_set_tree_height(a, z), i)
}

/// forspkADRS in Algorithm 17 lines 21 to 23
pub open spec fn spec_fors_roots_adrs(a: Seq<u8>) -> Seq<u8> {
    spec_set_key_pair_address(spec_set_type_and_clear(a, FORS_ROOTS), spec_get_key_pair_address(a))
}

/// Algorithm 14. fors_skGen (SK.seed, PK.seed, ADRS, idx)
pub open spec fn spec_fors_sk_gen(sk_seed: Seq<u8>, pk_seed: Seq<u8>, a: Seq<u8>, idx: u32) -> Seq<u8> {
    spec_prf(pk_seed, sk_seed, spec_fors_sk_adrs(a, idx))
}

/// Algorithm 15. fors_node (SK.seed, i, z, PK.seed, ADRS)
pub open spec fn spec_fors_node(sk_seed: Seq<u8>, i: u32, z: u32, pk_seed: Seq<u8>, a: Seq<u8>) -> Seq<u8>
    decreases z,
{
    if z == 0 {
        spec_f(pk_seed, spec_fors_node_adrs(a, 0, i), spec_fors_sk_gen(sk_seed, pk_seed, a, i))
    } else {
        spec_h(pk_seed, spec_fors_node_adrs(a, z, i),
               spec_fors_node(sk_seed, (2 * i) as u32, (z - 1) as u32, pk_seed, a)
               + spec_fors_node(sk_seed, (2 * i + 1) as u32, (z - 1) as u32, pk_seed, a))
    }
}

/// Element i of SIG_FORS (Algorithm 16 lines 4 to 9)
pub open spec fn spec_fors_sign_elem(md: Seq<u8>, sk_seed: Seq<u8>, pk_seed: Seq<u8>, a: Seq<u8>, i: int)
    -> (Seq<u8>, Seq<Seq<u8>>)
{
    let ind = spec_fors_index(md, i);
    (spec_fors_sk_gen(sk_seed, pk_seed, a, spec_leaf_index(i, ind)),
     Seq::new(14, |j: int| spec_fors_node(sk_seed, spec_auth_index(i, ind, j), j as u32, pk_seed, a)))
}

/// Algorithm 16. fors_sign (md, SK.seed, PK.seed, ADRS)
pub open spec fn spec_fors_sign(md: Seq<u8>, sk_seed: Seq<u8>, pk_seed: Seq<u8>, a: Seq<u8>)
    -> Seq<(Seq<u8>, Seq<Seq<u8>>)>
{
    Seq::new(22, |i: int| spec_fors_sign_elem(md, sk_seed, pk_seed, a, i))
}

/// node[0] after k iterations of Algorithm 17 lines 8 to 18, for the
/// leaf with index g = i 2^a + ind. The tree index in ADRS after
/// iteration k is floor (g / 2^k)
pub open spec fn spec_fors_path(leaf: Seq<u8>, g: u32, ind: u32, auth: Seq<Seq<u8>>, k: u32, pk_seed: Seq<u8>,
                                a: Seq<u8>) -> Seq<u8>
    decreases k,
{
    if k == 0 {
        leaf
    } else {
        let n = spec_fors_path(leaf, g, ind, auth, (k - 1) as u32, pk_seed, a);
        let adrs = spec_fors_node_adrs(a, k, g >> k);
        if (ind >> ((k - 1) as u32)) % 2 == 0 {
            spec_h(pk_seed, adrs, n + auth[k - 1])
        } else {
            spec_h(pk_seed, adrs, auth[k - 1] + n)
        }
    }
}

/// root[i] in Algorithm 17 (lines 3 to 19)
pub open spec fn spec_fors_root(s: Seq<(Seq<u8>, Seq<Seq<u8>>)>, md: Seq<u8>, pk_seed: Seq<u8>, a: Seq<u8>, i: int)
    -> Seq<u8>
{
    let ind = spec_fors_index(md, i);
    let g = spec_leaf_index(i, ind);
    spec_fors_path(spec_f(pk_seed, spec_fors_node_adrs(a, 0, g), s[i].0), g, ind, s[i].1, 14, pk_seed, a)
}

/// Algorithm 17. fors_pkFromSig (SIG_FORS, md, PK.seed, ADRS)
pub open spec fn spec_fors_pk_from_sig(s: Seq<(Seq<u8>, Seq<Seq<u8>>)>, md: Seq<u8>, pk_seed: Seq<u8>, a: Seq<u8>)
    -> Seq<u8>
{
    spec_t(pk_seed, spec_fors_roots_adrs(a), flat(Seq::new(22, |i: int| spec_fors_root(s, md, pk_seed, a, i))))
}

/// indices <- base_2b (md, a, k) (Algorithm 16 line 2, Algorithm 17 line 1)
pub fn fors_indices(md: &[u8; 39]) -> (r: [u32; 22])
    ensures forall|i: int| 0 <= i < 22 ==> #[trigger] r@[i] == spec_fors_index(md@, i) && r@[i] < 16384,
{
    let mut r = [0u32; 22];
    let mut i: usize = 0;
    while i < 22
        invariant
            i <= 22,
            forall|l: int| 0 <= l < i ==> #[trigger] r@[l] == spec_fors_index(md@, l) && r@[l] < 16384,
        decreases 22 - i,
    {
        let s = 14 * i;
        let b = s / 8;
        let v: u32 = ((md[b] as u32) << 16u32) | ((md[b + 1] as u32) << 8u32) | (md[b + 2] as u32);
        let x = (v >> ((10 - s % 8) as u32)) & 0x3fffu32;
        assert(x < 16384) by (bit_vector)
            requires x == (v >> ((10 - s % 8) as u32)) & 0x3fffu32;
        r[i] = x;
        i += 1;
    }
    r
}

fn fors_node_adrs(a: &Adrs, z: u32, i: u32) -> (r: Adrs)
    ensures r@ == spec_fors_node_adrs(a@, z, i),
{
    set_tree_index(set_tree_height(*a, z), i)
}

/// Algorithm 14. fors_skGen (SK.seed, PK.seed, ADRS, idx)
pub fn fors_sk_gen(sk_seed: &[u8; 32], pk_seed: &[u8; 32], adrs: &Adrs, idx: u32) -> (r: [u8; 32])
    ensures r@ == spec_fors_sk_gen(sk_seed@, pk_seed@, adrs@, idx),
{
    let kp = get_key_pair_address(adrs);                            // Line 1
    let sk_adrs = set_tree_index(set_key_pair_address(set_type_and_clear(*adrs, FORS_PRF), kp), idx);  // Lines 2 to 4
    prf(pk_seed, sk_seed, &sk_adrs)                                 // Line 5
}

/// Algorithm 15. fors_node (SK.seed, i, z, PK.seed, ADRS)
pub fn fors_node(sk_seed: &[u8; 32], i: u32, z: u32, pk_seed: &[u8; 32], adrs: &Adrs) -> (r: [u8; 32])
    requires spec_fors_valid_node(i, z),
    ensures r@ == spec_fors_node(sk_seed@, i, z, pk_seed@, adrs@),
    decreases z,
{
    if z == 0 {                                                     // Line 1
        let sk = fors_sk_gen(sk_seed, pk_seed, adrs, i);            // Line 2
        let a = fors_node_adrs(adrs, 0, i);                         // Lines 3 and 4
        f(pk_seed, &a, &sk)                                         // Line 5
    } else {
        assert(spec_fors_valid_node((2 * i) as u32, (z - 1) as u32)
            && spec_fors_valid_node((2 * i + 1) as u32, (z - 1) as u32)
            && 2 * i + 1 < 0x1_0000_0000) by (bit_vector)
            requires z <= 14, z >= 1, (i >> ((14 - z) as u32)) < 22;
        let lnode = fors_node(sk_seed, 2 * i, z - 1, pk_seed, adrs);      // Line 7
        let rnode = fors_node(sk_seed, 2 * i + 1, z - 1, pk_seed, adrs);  // Line 8
        let a = fors_node_adrs(adrs, z, i);                         // Lines 9 and 10
        h(pk_seed, &a, &concat(&lnode, &rnode))                     // Line 11
    }
}

/// Algorithm 16. fors_sign (md, SK.seed, PK.seed, ADRS)
pub fn fors_sign(md: &[u8; 39], sk_seed: &[u8; 32], pk_seed: &[u8; 32], adrs: &Adrs) -> (r: ForsSig)
    ensures fors_view(r@) == spec_fors_sign(md@, sk_seed@, pk_seed@, adrs@),
{
    let ghost sig_spec = spec_fors_sign(md@, sk_seed@, pk_seed@, adrs@);
    let indices = fors_indices(md);                                 // Line 2
    let mut sig = [ForsElem { sk: [0u8; 32], auth: [[0u8; 32]; 14] }; 22];  // Line 1
    let mut i: u32 = 0;
    while i < 22                                                    // Line 3
        invariant
            i <= 22,
            sig_spec == spec_fors_sign(md@, sk_seed@, pk_seed@, adrs@),
            forall|l: int| 0 <= l < 22 ==> #[trigger] indices@[l] == spec_fors_index(md@, l) && indices@[l] < 16384,
            forall|l: int| 0 <= l < i ==> fors_elem_view(#[trigger] sig@[l]) == sig_spec[l],
        decreases 22 - i,
    {
        let ind = indices[i as usize];
        let ghost e = spec_fors_sign_elem(md@, sk_seed@, pk_seed@, adrs@, i as int);
        assert(((i << 14u32) + ind) < 0x1_0000_0000) by (bit_vector)
            requires i < 22, ind < 16384;
        let sk = fors_sk_gen(sk_seed, pk_seed, adrs, (i << 14u32) + ind);  // Line 4
        let mut auth = [[0u8; 32]; 14];
        let mut j: u32 = 0;
        while j < 14                                                // Line 5
            invariant
                i < 22,
                j <= 14,
                ind < 16384,
                ind == spec_fors_index(md@, i as int),
                e == spec_fors_sign_elem(md@, sk_seed@, pk_seed@, adrs@, i as int),
                forall|l: int| 0 <= l < j ==> (#[trigger] auth@[l])@ == e.1[l],
            decreases 14 - j,
        {
            let s = (ind >> j) ^ 1u32;                              // Line 6
            assert(spec_fors_valid_node(((i << ((14 - j) as u32)) + s) as u32, j)
                && (i << ((14 - j) as u32)) + s < 0x1_0000_0000) by (bit_vector)
                requires i < 22, j < 14, ind < 16384, s == (ind >> j) ^ 1u32;
            auth[j as usize] = fors_node(sk_seed, (i << (14 - j)) + s, j, pk_seed, adrs);  // Line 7
            j += 1;
        }
        assert(views32(auth@) =~= e.1);
        sig[i as usize] = ForsElem { sk, auth };                    // Line 9
        i += 1;
    }
    assert(fors_view(sig@) =~= sig_spec);
    sig                                                             // Line 11
}

/// Algorithm 17. fors_pkFromSig (SIG_FORS, md, PK.seed, ADRS)
pub fn fors_pk_from_sig(sig: &ForsSig, md: &[u8; 39], pk_seed: &[u8; 32], adrs: &Adrs) -> (r: [u8; 32])
    ensures r@ == spec_fors_pk_from_sig(fors_view(sig@), md@, pk_seed@, adrs@),
{
    let ghost s = fors_view(sig@);
    let indices = fors_indices(md);                                 // Line 1
    let mut root = [[0u8; 32]; 22];
    let mut i: u32 = 0;
    while i < 22                                                    // Line 2
        invariant
            i <= 22,
            s == fors_view(sig@),
            forall|l: int| 0 <= l < 22 ==> #[trigger] indices@[l] == spec_fors_index(md@, l) && indices@[l] < 16384,
            forall|l: int| 0 <= l < i ==> (#[trigger] root@[l])@ == spec_fors_root(s, md@, pk_seed@, adrs@, l),
        decreases 22 - i,
    {
        let ind = indices[i as usize];
        assert(((i << 14u32) + ind) < 0x1_0000_0000) by (bit_vector)
            requires i < 22, ind < 16384;
        let g = (i << 14u32) + ind;
        let elem = &sig[i as usize];                                // Lines 3 and 7
        let ghost auth = views32(elem.auth@);
        let mut t = g;
        let a = fors_node_adrs(adrs, 0, t);                         // Lines 4 and 5
        let leaf = f(pk_seed, &a, &elem.sk);                        // Line 6
        let mut node = leaf;
        let mut j: u32 = 0;
        assert(g >> 0u32 == g) by (bit_vector);
        while j < 14                                                // Line 8
            invariant
                i < 22,
                j <= 14,
                ind < 16384,
                g == ((i << 14u32) + ind) as u32,
                t == g >> j,
                elem == &sig@[i as int],
                auth == views32(elem.auth@),
                node@ == spec_fors_path(leaf@, g, ind, auth, j, pk_seed@, adrs@),
            decreases 14 - j,
        {
            let auth_j = &elem.auth[j as usize];
            if (ind >> j) % 2 == 0 {                                // Line 10
                assert(t / 2 == g >> (j + 1)) by (bit_vector)
                    requires i < 22, j < 14, ind < 16384, g == ((i << 14u32) + ind) as u32, t == g >> j,
                        (ind >> j) % 2 == 0;
                t = t / 2;                                          // Line 11
                let a = fors_node_adrs(adrs, j + 1, t);             // Line 9
                node = h(pk_seed, &a, &concat(&node, auth_j));      // Line 12
            } else {
                assert(t >= 1 && (t - 1) / 2 == g >> (j + 1)) by (bit_vector)
                    requires i < 22, j < 14, ind < 16384, g == ((i << 14u32) + ind) as u32, t == g >> j,
                        (ind >> j) % 2 == 1;
                t = (t - 1) / 2;                                    // Line 14
                let a = fors_node_adrs(adrs, j + 1, t);             // Line 9
                node = h(pk_seed, &a, &concat(auth_j, &node));      // Line 15
            }
            j += 1;                                                 // Line 17
        }
        root[i as usize] = node;                                    // Line 19
        i += 1;
    }
    assert(views32(root@) =~= Seq::new(22, |i: int| spec_fors_root(s, md@, pk_seed@, adrs@, i)));
    let kp = get_key_pair_address(adrs);                            // Line 21
    let pk_adrs = set_key_pair_address(set_type_and_clear(*adrs, FORS_ROOTS), kp);  // Lines 22 and 23
    t_l(pk_seed, &pk_adrs, root.as_slice())                         // Lines 24 and 25
}

} // verus!
