//  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

//! Byte strings: concatenation of sequences of n-byte strings, and
//! copying.

use vstd::prelude::*;

verus! {

/// s[0] || s[1] || ... || s[s.len() - 1]
pub open spec fn flat(s: Seq<Seq<u8>>) -> Seq<u8>
    decreases s.len(),
{
    if s.len() == 0 {
        Seq::empty()
    } else {
        flat(s.drop_last()) + s.last()
    }
}

/// The views of an array of n-byte strings
pub open spec fn views32(s: Seq<[u8; 32]>) -> Seq<Seq<u8>> {
    s.map_values(|x: [u8; 32]| x@)
}

/// toByte (0, 32), an all-zero address
pub open spec fn zeros32() -> Seq<u8> {
    Seq::new(32, |i: int| 0u8)
}

/// The concatenation of the first i + 1 strings is the concatenation
/// of the first i, followed by string i
pub proof fn lemma_flat_take(s: Seq<Seq<u8>>, i: int)
    requires 0 <= i < s.len(),
    ensures flat(s.take(i + 1)) == flat(s.take(i)) + s[i],
{
    assert(s.take(i + 1).drop_last() =~= s.take(i));
}

/// If every string has length 32, the concatenation has length 32 s.len()
pub proof fn lemma_flat_len(s: Seq<Seq<u8>>, l: int)
    requires forall|i: int| 0 <= i < s.len() ==> (#[trigger] s[i]).len() == l,
    ensures flat(s).len() == l * s.len(),
    decreases s.len(),
{
    if s.len() > 0 {
        lemma_flat_len(s.drop_last(), l);
        assert(l * s.len() == l * (s.len() - 1) + l) by (nonlinear_arith);
    }
}

pub open spec fn concat2(l: Seq<u8>, r: Seq<u8>) -> Seq<u8> {
    l + r
}

/// L || R, for two n-byte strings
pub fn concat(l: &[u8; 32], r: &[u8; 32]) -> (res: [u8; 64])
    ensures res@ == l@ + r@,
{
    let mut res = [0u8; 64];
    let mut i: usize = 0;
    while i < 32
        invariant
            i <= 32,
            forall|j: int| 0 <= j < i ==> res@[j] == l@[j] && res@[j + 32] == r@[j],
        decreases 32 - i,
    {
        res[i] = l[i];
        res[i + 32] = r[i];
        i += 1;
    }
    assert(res@ =~= l@ + r@);
    res
}

/// Copies src into dst at offset off
pub fn copy_at<const T: usize>(dst: &mut [u8; T], off: usize, src: &[u8])
    requires off + src.len() <= T,
    ensures
        final(dst)@ == old(dst)@.subrange(0, off as int) + src@
            + old(dst)@.subrange(off + src.len(), T as int),
{
    let ghost d0 = dst@;
    let n = src.len();
    let mut i: usize = 0;
    while i < n
        invariant
            n == src.len(),
            off + n <= T,
            i <= n,
            dst@.len() == T,
            forall|j: int| 0 <= j < off || off + n <= j < T ==> #[trigger] dst@[j] == d0[j],
            forall|j: int| 0 <= j < i ==> dst@[off + j] == src@[j],
        decreases n - i,
    {
        dst[off + i] = src[i];
        i += 1;
    }
    assert(dst@ =~= d0.subrange(0, off as int) + src@ + d0.subrange(off + n, T as int));
}

/// Writes the concatenation of the strings in src into dst at offset off
pub fn flat_at<const T: usize, const L: usize>(dst: &mut [u8; T], off: usize, src: &[[u8; 32]; L])
    requires off + 32 * L <= T,
    ensures
        final(dst)@ == old(dst)@.subrange(0, off as int) + flat(views32(src@))
            + old(dst)@.subrange(off + 32 * L, T as int),
{
    let ghost d0 = dst@;
    let ghost s = views32(src@);
    let mut i: usize = 0;
    while i < L
        invariant
            off + 32 * L <= T,
            i <= L,
            s == views32(src@),
            s.len() == L,
            dst@.len() == T,
            dst@.subrange(0, off as int) == d0.subrange(0, off as int),
            dst@.subrange(off as int, off + 32 * i) == flat(s.take(i as int)),
            dst@.subrange(off + 32 * L, T as int) == d0.subrange(off + 32 * L, T as int),
        decreases L - i,
    {
        let ghost before = dst@;
        copy_at(dst, off + 32 * i, src[i].as_slice());
        proof {
            lemma_flat_take(s, i as int);
            assert(dst@.subrange(off as int, off + 32 * (i + 1))
                =~= before.subrange(off as int, off + 32 * i) + src@[i as int]@);
            assert(dst@.subrange(0, off as int) =~= before.subrange(0, off as int));
            assert(dst@.subrange(off + 32 * L, T as int) =~= before.subrange(off + 32 * L, T as int));
        }
        i += 1;
    }
    assert(s.take(L as int) =~= s);
    assert(dst@ =~= dst@.subrange(0, off as int) + dst@.subrange(off as int, off + 32 * L)
        + dst@.subrange(off + 32 * L, T as int));
}

/// The n-byte string at offset off of b
pub fn get32(b: &[u8], off: usize) -> (r: [u8; 32])
    requires off + 32 <= b.len(),
    ensures r@ == b@.subrange(off as int, off + 32),
{
    let mut r = [0u8; 32];
    let mut i: usize = 0;
    while i < 32
        invariant
            off + 32 <= b.len(),
            i <= 32,
            forall|j: int| 0 <= j < i ==> r@[j] == b@[off + j],
        decreases 32 - i,
    {
        r[i] = b[off + i];
        i += 1;
    }
    assert(r@ =~= b@.subrange(off as int, off + 32));
    r
}

} // verus!

verus! {

/// a = b, for two n-byte strings
pub fn eq32(a: &[u8; 32], b: &[u8; 32]) -> (r: bool)
    ensures r == (a@ == b@),
{
    let mut i: usize = 0;
    while i < 32
        invariant
            i <= 32,
            forall|j: int| 0 <= j < i ==> a@[j] == b@[j],
        decreases 32 - i,
    {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    assert(a@ =~= b@);
    true
}

} // verus!
