//  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

//! The SLH-DSA hypertree, FIPS 205 section 7, Algorithms 12 and 13.
//!
//! In FIPS 205, one ADRS is used for every layer, and only its layer
//! and tree addresses are set between layers. Here each layer gets a
//! new ADRS with only those words set. The XMSS functions only read
//! the other words after setTypeAndClear, so the two agree.

use crate::adrs::*;
use crate::util::*;
use crate::xmss::*;
use vstd::prelude::*;

verus! {

/// SIG_HT, the XMSS signatures of layers 0 to d - 1 (FIPS 205 Figure 13)
pub type HtSig = [XmssSig; 8];

pub open spec fn ht_view(s: Seq<XmssSig>) -> Seq<(Seq<Seq<u8>>, Seq<Seq<u8>>)> {
    s.map_values(|x: XmssSig| xmss_view(x))
}

/// idx_tree at layer j: Algorithm 12 line 8 and Algorithm 13 line 7
/// remove h' bits of idx_tree for each layer
pub open spec fn spec_tree_at(idx_tree: u64, j: u32) -> u64 {
    idx_tree >> ((8 * j) as u64)
}

/// idx_leaf at layer j: Algorithm 12 line 7 and Algorithm 13 line 6
/// take it from the h' least significant bits of idx_tree at layer j - 1
pub open spec fn spec_leaf_at(idx_tree: u64, idx_leaf: u32, j: u32) -> u32 {
    if j == 0 { idx_leaf } else { (spec_tree_at(idx_tree, (j - 1) as u32) % 256) as u32 }
}

/// ADRS at layer j: toByte (0, 32), setLayerAddress (j), setTreeAddress (t)
/// (Algorithm 12 lines 1, 2, 9 and 10, and Algorithm 13 lines 1, 2, 8 and 9).
/// At layer 0, setLayerAddress (0) leaves toByte (0, 32) unchanged.
pub open spec fn spec_layer_adrs(j: u32, t: u64) -> Seq<u8> {
    spec_set_tree_address(spec_set_layer_address(zeros32(), j), t)
}

/// The message signed at layer j: M at layer 0, and root, the XMSS
/// public key computed from the signature at layer j - 1, otherwise
/// (Algorithm 12 lines 5 and 14)
pub open spec fn spec_ht_msg(m: Seq<u8>, sk_seed: Seq<u8>, pk_seed: Seq<u8>, idx_tree: u64, idx_leaf: u32, j: u32)
    -> Seq<u8>
    decreases j,
{
    if j == 0 {
        m
    } else {
        let p = (j - 1) as u32;
        let a = spec_layer_adrs(p, spec_tree_at(idx_tree, p));
        let leaf = spec_leaf_at(idx_tree, idx_leaf, p);
        let msg = spec_ht_msg(m, sk_seed, pk_seed, idx_tree, idx_leaf, p);
        spec_xmss_pk_from_sig(leaf, spec_xmss_sign(msg, sk_seed, leaf, pk_seed, a), msg, pk_seed, a)
    }
}

/// SIG_tmp at layer j (Algorithm 12 lines 3 and 11)
pub open spec fn spec_ht_layer_sig(m: Seq<u8>, sk_seed: Seq<u8>, pk_seed: Seq<u8>, idx_tree: u64, idx_leaf: u32,
                                   j: u32) -> (Seq<Seq<u8>>, Seq<Seq<u8>>) {
    spec_xmss_sign(spec_ht_msg(m, sk_seed, pk_seed, idx_tree, idx_leaf, j), sk_seed,
                   spec_leaf_at(idx_tree, idx_leaf, j), pk_seed, spec_layer_adrs(j, spec_tree_at(idx_tree, j)))
}

/// Algorithm 12. ht_sign (M, SK.seed, PK.seed, idx_tree, idx_leaf)
pub open spec fn spec_ht_sign(m: Seq<u8>, sk_seed: Seq<u8>, pk_seed: Seq<u8>, idx_tree: u64, idx_leaf: u32)
    -> Seq<(Seq<Seq<u8>>, Seq<Seq<u8>>)>
{
    Seq::new(8, |j: int| spec_ht_layer_sig(m, sk_seed, pk_seed, idx_tree, idx_leaf, j as u32))
}

/// node after layer j of Algorithm 13 (lines 4 and 11)
pub open spec fn spec_verify_node(m: Seq<u8>, s: Seq<(Seq<Seq<u8>>, Seq<Seq<u8>>)>, pk_seed: Seq<u8>,
                                  idx_tree: u64, idx_leaf: u32, j: u32) -> Seq<u8>
    decreases j,
{
    let msg = if j == 0 { m } else { spec_verify_node(m, s, pk_seed, idx_tree, idx_leaf, (j - 1) as u32) };
    spec_xmss_pk_from_sig(spec_leaf_at(idx_tree, idx_leaf, j), s[j as int], msg, pk_seed,
                          spec_layer_adrs(j, spec_tree_at(idx_tree, j)))
}

/// Algorithm 13. ht_verify (M, SIG_HT, PK.seed, idx_tree, idx_leaf, PK.root)
pub open spec fn spec_ht_verify(m: Seq<u8>, s: Seq<(Seq<Seq<u8>>, Seq<Seq<u8>>)>, pk_seed: Seq<u8>,
                                idx_tree: u64, idx_leaf: u32, pk_root: Seq<u8>) -> bool {
    spec_verify_node(m, s, pk_seed, idx_tree, idx_leaf, 7) == pk_root
}

fn layer_adrs(j: u32, t: u64) -> (r: Adrs)
    ensures r@ == spec_layer_adrs(j, t),
{
    let z = [0u8; 32];
    assert(z@ =~= zeros32());
    set_tree_address(set_layer_address(z, j), t)
}

/// Algorithm 12 lines 7 and 8: idx_leaf and idx_tree for layer j + 1
proof fn lemma_next_layer(idx_tree: u64, tree: u64, j: u32)
    requires j < 7, tree == spec_tree_at(idx_tree, j),
    ensures
        tree >> 8u64 == spec_tree_at(idx_tree, (j + 1) as u32),
        (tree % 256) as u32 == spec_leaf_at(idx_tree, 0, (j + 1) as u32),
        tree % 256 < 256,
{
    let s = (8 * j) as u64;
    let s1 = (8 * (j + 1)) as u64;
    assert((idx_tree >> s) >> 8u64 == idx_tree >> s1) by (bit_vector)
        requires s < 56, s1 == s + 8;
}

/// Algorithm 12. ht_sign (M, SK.seed, PK.seed, idx_tree, idx_leaf)
pub fn ht_sign(m: &[u8; 32], sk_seed: &[u8; 32], pk_seed: &[u8; 32], idx_tree: u64, idx_leaf: u32) -> (r: HtSig)
    requires idx_leaf < 256,
    ensures ht_view(r@) == spec_ht_sign(m@, sk_seed@, pk_seed@, idx_tree, idx_leaf),
{
    let ghost sig_spec = spec_ht_sign(m@, sk_seed@, pk_seed@, idx_tree, idx_leaf);
    let mut tree = idx_tree;
    let mut leaf = idx_leaf;
    let a = layer_adrs(0, tree);                                    // Lines 1 and 2
    assert(idx_tree >> 0u64 == idx_tree) by (bit_vector);
    let s0 = xmss_sign(m, sk_seed, leaf, pk_seed, &a);              // Line 3
    let mut sig = [s0; 8];                                          // Line 4
    let mut root = xmss_pk_from_sig(leaf, &s0, m, pk_seed, &a);     // Line 5
    assert(spec_ht_msg(m@, sk_seed@, pk_seed@, idx_tree, idx_leaf, 0) == m@);
    let mut j: u32 = 1;
    while j < 8                                                     // Line 6
        invariant
            1 <= j <= 8,
            idx_leaf < 256,
            sig_spec == spec_ht_sign(m@, sk_seed@, pk_seed@, idx_tree, idx_leaf),
            tree == spec_tree_at(idx_tree, (j - 1) as u32),
            j < 8 ==> root@ == spec_ht_msg(m@, sk_seed@, pk_seed@, idx_tree, idx_leaf, j),
            forall|l: int| 0 <= l < j ==> xmss_view(#[trigger] sig@[l]) == sig_spec[l],
        decreases 8 - j,
    {
        proof { lemma_next_layer(idx_tree, tree, (j - 1) as u32); }
        leaf = (tree % 256) as u32;                                 // Line 7
        tree = tree >> 8u64;                                        // Line 8
        let a = layer_adrs(j, tree);                                // Lines 9 and 10
        let s = xmss_sign(&root, sk_seed, leaf, pk_seed, &a);       // Line 11
        sig[j as usize] = s;                                        // Line 12
        if j < 7 {                                                  // Line 13
            root = xmss_pk_from_sig(leaf, &s, &root, pk_seed, &a);  // Line 14
        }
        j += 1;
    }
    assert(ht_view(sig@) =~= sig_spec);
    sig                                                             // Line 17
}

/// Algorithm 13. ht_verify (M, SIG_HT, PK.seed, idx_tree, idx_leaf, PK.root)
pub fn ht_verify(m: &[u8; 32], sig: &HtSig, pk_seed: &[u8; 32], idx_tree: u64, idx_leaf: u32,
                 pk_root: &[u8; 32]) -> (r: bool)
    requires idx_leaf < 256,
    ensures r == spec_ht_verify(m@, ht_view(sig@), pk_seed@, idx_tree, idx_leaf, pk_root@),
{
    let ghost s = ht_view(sig@);
    let mut tree = idx_tree;
    let mut leaf = idx_leaf;
    let a = layer_adrs(0, tree);                                    // Lines 1 and 2
    assert(idx_tree >> 0u64 == idx_tree) by (bit_vector);
    let mut node = xmss_pk_from_sig(leaf, &sig[0], m, pk_seed, &a);  // Lines 3 and 4
    let mut j: u32 = 1;
    while j < 8                                                     // Line 5
        invariant
            1 <= j <= 8,
            s == ht_view(sig@),
            tree == spec_tree_at(idx_tree, (j - 1) as u32),
            node@ == spec_verify_node(m@, s, pk_seed@, idx_tree, idx_leaf, (j - 1) as u32),
        decreases 8 - j,
    {
        proof { lemma_next_layer(idx_tree, tree, (j - 1) as u32); }
        leaf = (tree % 256) as u32;                                 // Line 6
        tree = tree >> 8u64;                                        // Line 7
        let a = layer_adrs(j, tree);                                // Lines 8 and 9
        node = xmss_pk_from_sig(leaf, &sig[j as usize], &node, pk_seed, &a);  // Lines 10 and 11
        j += 1;
    }
    eq32(&node, pk_root)                                            // Lines 13 to 17
}

} // verus!
