//  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

//! The eXtended Merkle Signature Scheme (XMSS), FIPS 205 section 6,
//! Algorithms 9 to 11.
//!
//! As for WOTS+, the functions are pure. Each use of ADRS in FIPS 205
//! Algorithms 9 to 11 is preceded by setTypeAndClear, and the layer and
//! tree addresses are never changed, so the two agree.

use crate::adrs::*;
use crate::hash::*;
#[cfg(verus_keep_ghost)]  // Only used in specifications
use crate::params::*;
use crate::util::*;
use crate::wots::*;
use vstd::prelude::*;

verus! {

/// An XMSS signature, SIG_XMSS = sig || AUTH (FIPS 205 Figure 11)
#[derive(Clone, Copy)]
pub struct XmssSig {
    pub sig: [[u8; 32]; 67],
    pub auth: [[u8; 32]; 8],
}

/// The view of an XMSS signature: (sig, AUTH)
pub open spec fn xmss_view(s: XmssSig) -> (Seq<Seq<u8>>, Seq<Seq<u8>>) {
    (views32(s.sig@), views32(s.auth@))
}

/// True if i is the index of a node of height z, i < 2^(h' - z)
pub open spec fn spec_valid_node(i: u32, z: u32) -> bool {
    z <= 8 && (i >> ((8 - z) as u32)) == 0
}

/// ADRS for leaf i: setTypeAndClear (WOTS_HASH), setKeyPairAddress (i)
/// (Algorithm 9 lines 2 and 3, Algorithm 10 lines 5 and 6, and
/// Algorithm 11 lines 1 and 2)
pub open spec fn spec_leaf_adrs(a: Seq<u8>, i: u32) -> Seq<u8> {
    spec_set_key_pair_address(spec_set_type_and_clear(a, WOTS_HASH), i)
}

/// ADRS for node i of height z: setTypeAndClear (TREE),
/// setTreeHeight (z), setTreeIndex (i) (Algorithm 9 lines 8 to 10)
pub open spec fn spec_tree_adrs(a: Seq<u8>, z: u32, i: u32) -> Seq<u8> {
    spec_set_tree_index(spec_set_tree_height(spec_set_type_and_clear(a, TREE), z), i)
}

/// Algorithm 9. xmss_node (SK.seed, i, z, PK.seed, ADRS)
pub open spec fn spec_xmss_node(sk_seed: Seq<u8>, i: u32, z: u32, pk_seed: Seq<u8>, a: Seq<u8>) -> Seq<u8>
    decreases z,
{
    if z == 0 {
        spec_wots_pk_gen(sk_seed, pk_seed, spec_leaf_adrs(a, i))
    } else {
        spec_h(pk_seed, spec_tree_adrs(a, z, i),
               spec_xmss_node(sk_seed, (2 * i) as u32, (z - 1) as u32, pk_seed, a)
               + spec_xmss_node(sk_seed, (2 * i + 1) as u32, (z - 1) as u32, pk_seed, a))
    }
}

/// k in Algorithm 10 line 2: the sibling of the node of height j on
/// the path from leaf idx to the root
pub open spec fn spec_sibling(idx: u32, j: u32) -> u32 {
    (idx >> j) ^ 1u32
}

/// Algorithm 10. xmss_sign (M, SK.seed, idx, PK.seed, ADRS)
pub open spec fn spec_xmss_sign(m: Seq<u8>, sk_seed: Seq<u8>, idx: u32, pk_seed: Seq<u8>, a: Seq<u8>)
    -> (Seq<Seq<u8>>, Seq<Seq<u8>>)
{
    (spec_wots_sign(m, sk_seed, pk_seed, spec_leaf_adrs(a, idx)),
     Seq::new(8, |j: int| spec_xmss_node(sk_seed, spec_sibling(idx, j as u32), j as u32, pk_seed, a)))
}

/// node[0] after k iterations of Algorithm 11 lines 8 to 18, computed
/// from the leaf value and AUTH. The tree index in ADRS after
/// iteration k is floor (idx / 2^k)
pub open spec fn spec_path_node(leaf: Seq<u8>, idx: u32, auth: Seq<Seq<u8>>, k: u32, pk_seed: Seq<u8>, a: Seq<u8>)
    -> Seq<u8>
    decreases k,
{
    if k == 0 {
        leaf
    } else {
        let n = spec_path_node(leaf, idx, auth, (k - 1) as u32, pk_seed, a);
        let adrs = spec_tree_adrs(a, k, idx >> k);
        if (idx >> ((k - 1) as u32)) % 2 == 0 {
            spec_h(pk_seed, adrs, n + auth[k - 1])
        } else {
            spec_h(pk_seed, adrs, auth[k - 1] + n)
        }
    }
}

/// Algorithm 11. xmss_pkFromSig (idx, SIG_XMSS, M, PK.seed, ADRS)
pub open spec fn spec_xmss_pk_from_sig(idx: u32, s: (Seq<Seq<u8>>, Seq<Seq<u8>>), m: Seq<u8>, pk_seed: Seq<u8>,
                                       a: Seq<u8>) -> Seq<u8> {
    spec_path_node(spec_wots_pk_from_sig(s.0, m, pk_seed, spec_leaf_adrs(a, idx)), idx, s.1, 8, pk_seed, a)
}

fn leaf_adrs(a: &Adrs, i: u32) -> (r: Adrs)
    ensures r@ == spec_leaf_adrs(a@, i),
{
    set_key_pair_address(set_type_and_clear(*a, WOTS_HASH), i)
}

fn tree_adrs(a: &Adrs, z: u32, i: u32) -> (r: Adrs)
    ensures r@ == spec_tree_adrs(a@, z, i),
{
    set_tree_index(set_tree_height(set_type_and_clear(*a, TREE), z), i)
}

/// Algorithm 9. xmss_node (SK.seed, i, z, PK.seed, ADRS)
pub fn xmss_node(sk_seed: &[u8; 32], i: u32, z: u32, pk_seed: &[u8; 32], adrs: &Adrs) -> (r: [u8; 32])
    requires spec_valid_node(i, z),
    ensures r@ == spec_xmss_node(sk_seed@, i, z, pk_seed@, adrs@),
    decreases z,
{
    if z == 0 {                                                     // Line 1
        let a = leaf_adrs(adrs, i);                                 // Lines 2 and 3
        wots_pk_gen(sk_seed, pk_seed, &a)                           // Line 4
    } else {
        assert(spec_valid_node((2 * i) as u32, (z - 1) as u32)
            && spec_valid_node((2 * i + 1) as u32, (z - 1) as u32)
            && 2 * i + 1 < 0x1_0000_0000) by (bit_vector)
            requires z <= 8, z >= 1, (i >> ((8 - z) as u32)) == 0;
        let lnode = xmss_node(sk_seed, 2 * i, z - 1, pk_seed, adrs);      // Line 6
        let rnode = xmss_node(sk_seed, 2 * i + 1, z - 1, pk_seed, adrs);  // Line 7
        let a = tree_adrs(adrs, z, i);                              // Lines 8 to 10
        h(pk_seed, &a, &concat(&lnode, &rnode))                     // Line 11
    }
}

/// Algorithm 10. xmss_sign (M, SK.seed, idx, PK.seed, ADRS)
pub fn xmss_sign(m: &[u8; 32], sk_seed: &[u8; 32], idx: u32, pk_seed: &[u8; 32], adrs: &Adrs) -> (r: XmssSig)
    requires idx < 256,
    ensures xmss_view(r) == spec_xmss_sign(m@, sk_seed@, idx, pk_seed@, adrs@),
{
    let ghost spec_auth = spec_xmss_sign(m@, sk_seed@, idx, pk_seed@, adrs@).1;
    let mut auth = [[0u8; 32]; 8];
    let mut j: u32 = 0;
    while j < 8                                                     // Line 1
        invariant
            j <= 8,
            idx < 256,
            spec_auth == spec_xmss_sign(m@, sk_seed@, idx, pk_seed@, adrs@).1,
            forall|l: int| 0 <= l < j ==> (#[trigger] auth@[l])@ == spec_auth[l],
        decreases 8 - j,
    {
        let k = (idx >> j) ^ 1;                                     // Line 2
        assert(spec_valid_node(k, j)) by (bit_vector)
            requires idx < 256, j < 8, k == (idx >> j) ^ 1u32;
        auth[j as usize] = xmss_node(sk_seed, k, j, pk_seed, adrs);  // Line 3
        j += 1;
    }
    assert(views32(auth@) =~= spec_auth);
    let a = leaf_adrs(adrs, idx);                                   // Lines 5 and 6
    let sig = wots_sign(m, sk_seed, pk_seed, &a);                   // Line 7
    XmssSig { sig, auth }                                           // Line 8
}

/// Algorithm 11. xmss_pkFromSig (idx, SIG_XMSS, M, PK.seed, ADRS)
pub fn xmss_pk_from_sig(idx: u32, s: &XmssSig, m: &[u8; 32], pk_seed: &[u8; 32], adrs: &Adrs) -> (r: [u8; 32])
    requires idx < 256,
    ensures r@ == spec_xmss_pk_from_sig(idx, xmss_view(*s), m@, pk_seed@, adrs@),
{
    let ghost auth = views32(s.auth@);
    let a = leaf_adrs(adrs, idx);                                   // Lines 1 and 2
    let leaf = wots_pk_from_sig(&s.sig, m, pk_seed, &a);            // Lines 3 to 5
    let mut node = leaf;
    let mut t = idx;                                                // Lines 6 and 7
    let mut k: u32 = 0;
    assert(idx >> 0u32 == idx) by (bit_vector);
    while k < 8                                                     // Line 8
        invariant
            k <= 8,
            idx < 256,
            t == idx >> k,
            auth == views32(s.auth@),
            node@ == spec_path_node(leaf@, idx, auth, k, pk_seed@, adrs@),
        decreases 8 - k,
    {
        //  Line 9 sets the tree height to k + 1, and lines 11 and 14
        //  set the tree index to floor (idx / 2^(k + 1))
        let auth_k = &s.auth[k as usize];
        if (idx >> k) % 2 == 0 {                                    // Line 10
            assert(t / 2 == idx >> (k + 1)) by (bit_vector)
                requires k < 8, idx < 256, t == idx >> k, (idx >> k) % 2 == 0;
            t = t / 2;                                              // Line 11
            let a = tree_adrs(adrs, k + 1, t);
            node = h(pk_seed, &a, &concat(&node, auth_k));          // Line 12
        } else {
            assert(t >= 1 && (t - 1) / 2 == idx >> (k + 1)) by (bit_vector)
                requires k < 8, idx < 256, t == idx >> k, (idx >> k) % 2 == 1;
            t = (t - 1) / 2;                                        // Line 14
            let a = tree_adrs(adrs, k + 1, t);
            node = h(pk_seed, &a, &concat(auth_k, &node));          // Line 15
        }
        k += 1;                                                     // Line 17
    }
    node                                                            // Line 19
}

} // verus!
