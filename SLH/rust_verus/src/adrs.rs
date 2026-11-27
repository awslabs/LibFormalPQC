//  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

//! Addresses (FIPS 205 sections 4.2 and 4.3).
//!
//! An address is 32 bytes, as 8 big-endian 32-bit words:
//! word 0 is the layer address, words 1 to 3 the tree address, word 4
//! the type, and words 5 to 7 depend on the type.
//!
//! FIPS 205 updates ADRS in place. Here each setter is a function that
//! returns a new address, and `spec_set_*` gives its result.

use vstd::prelude::*;

verus! {

pub type Adrs = [u8; 32];

/// Address types (FIPS 205 section 4.2)
pub const WOTS_HASH: u32 = 0;
pub const WOTS_PK: u32 = 1;
pub const TREE: u32 = 2;
pub const FORS_TREE: u32 = 3;
pub const FORS_ROOTS: u32 = 4;
pub const WOTS_PRF: u32 = 5;
pub const FORS_PRF: u32 = 6;

/// a with word w set to toByte (v, 4)
pub open spec fn spec_set_word(a: Seq<u8>, w: int, v: u32) -> Seq<u8> {
    a.update(4 * w, (v >> 24u32) as u8)
     .update(4 * w + 1, (v >> 16u32) as u8)
     .update(4 * w + 2, (v >> 8u32) as u8)
     .update(4 * w + 3, v as u8)
}

/// toInt (a[4w : 4w + 4], 4)
pub open spec fn spec_word(a: Seq<u8>, w: int) -> u32 {
    ((a[4 * w] as u32) << 24u32) | ((a[4 * w + 1] as u32) << 16u32)
        | ((a[4 * w + 2] as u32) << 8u32) | (a[4 * w + 3] as u32)
}

pub open spec fn spec_set_layer_address(a: Seq<u8>, l: u32) -> Seq<u8> {
    spec_set_word(a, 0, l)
}

/// ADRS[4 : 16] <- toByte (t, 12). t has 64 bits, so word 1 is zero
pub open spec fn spec_set_tree_address(a: Seq<u8>, t: u64) -> Seq<u8> {
    spec_set_word(spec_set_word(spec_set_word(a, 1, 0), 2, (t >> 32u64) as u32), 3, t as u32)
}

/// ADRS[16 : 20] <- toByte (y, 4), ADRS[20 : 32] <- toByte (0, 12)
pub open spec fn spec_set_type_and_clear(a: Seq<u8>, y: u32) -> Seq<u8> {
    spec_set_word(spec_set_word(spec_set_word(spec_set_word(a, 4, y), 5, 0), 6, 0), 7, 0)
}

pub open spec fn spec_set_key_pair_address(a: Seq<u8>, i: u32) -> Seq<u8> {
    spec_set_word(a, 5, i)
}

pub open spec fn spec_set_chain_address(a: Seq<u8>, i: u32) -> Seq<u8> {
    spec_set_word(a, 6, i)
}

pub open spec fn spec_set_tree_height(a: Seq<u8>, z: u32) -> Seq<u8> {
    spec_set_word(a, 6, z)
}

pub open spec fn spec_set_hash_address(a: Seq<u8>, i: u32) -> Seq<u8> {
    spec_set_word(a, 7, i)
}

pub open spec fn spec_set_tree_index(a: Seq<u8>, i: u32) -> Seq<u8> {
    spec_set_word(a, 7, i)
}

pub open spec fn spec_get_key_pair_address(a: Seq<u8>) -> u32 {
    spec_word(a, 5)
}

fn set_word(a: Adrs, w: usize, v: u32) -> (r: Adrs)
    requires w < 8,
    ensures r@ == spec_set_word(a@, w as int, v),
{
    let mut r = a;
    r[4 * w] = (v >> 24u32) as u8;
    r[4 * w + 1] = (v >> 16u32) as u8;
    r[4 * w + 2] = (v >> 8u32) as u8;
    r[4 * w + 3] = v as u8;
    r
}

fn word(a: &Adrs, w: usize) -> (r: u32)
    requires w < 8,
    ensures r == spec_word(a@, w as int),
{
    ((a[4 * w] as u32) << 24u32) | ((a[4 * w + 1] as u32) << 16u32)
        | ((a[4 * w + 2] as u32) << 8u32) | (a[4 * w + 3] as u32)
}

/// ADRS.setLayerAddress (l)
pub fn set_layer_address(a: Adrs, l: u32) -> (r: Adrs)
    ensures r@ == spec_set_layer_address(a@, l),
{
    set_word(a, 0, l)
}

/// ADRS.setTreeAddress (t)
pub fn set_tree_address(a: Adrs, t: u64) -> (r: Adrs)
    ensures r@ == spec_set_tree_address(a@, t),
{
    set_word(set_word(set_word(a, 1, 0), 2, (t >> 32u64) as u32), 3, t as u32)
}

/// ADRS.setTypeAndClear (y)
pub fn set_type_and_clear(a: Adrs, y: u32) -> (r: Adrs)
    ensures r@ == spec_set_type_and_clear(a@, y),
{
    set_word(set_word(set_word(set_word(a, 4, y), 5, 0), 6, 0), 7, 0)
}

/// ADRS.setKeyPairAddress (i)
pub fn set_key_pair_address(a: Adrs, i: u32) -> (r: Adrs)
    ensures r@ == spec_set_key_pair_address(a@, i),
{
    set_word(a, 5, i)
}

/// ADRS.setChainAddress (i)
pub fn set_chain_address(a: Adrs, i: u32) -> (r: Adrs)
    ensures r@ == spec_set_chain_address(a@, i),
{
    set_word(a, 6, i)
}

/// ADRS.setTreeHeight (z)
pub fn set_tree_height(a: Adrs, z: u32) -> (r: Adrs)
    ensures r@ == spec_set_tree_height(a@, z),
{
    set_word(a, 6, z)
}

/// ADRS.setHashAddress (i)
pub fn set_hash_address(a: Adrs, i: u32) -> (r: Adrs)
    ensures r@ == spec_set_hash_address(a@, i),
{
    set_word(a, 7, i)
}

/// ADRS.setTreeIndex (i)
pub fn set_tree_index(a: Adrs, i: u32) -> (r: Adrs)
    ensures r@ == spec_set_tree_index(a@, i),
{
    set_word(a, 7, i)
}

/// ADRS.getKeyPairAddress ()
pub fn get_key_pair_address(a: &Adrs) -> (r: u32)
    ensures r == spec_get_key_pair_address(a@),
{
    word(a, 5)
}

} // verus!
