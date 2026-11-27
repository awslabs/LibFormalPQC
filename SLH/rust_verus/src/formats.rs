//  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

//! The byte formats of signatures (FIPS 205 Figures 11, 13, 14 and 17).
//!
//! `*_to_bytes` writes a signature in the byte format, as the
//! concatenations in Algorithms 10, 12, 16 and 19 do. `*_from_bytes`
//! reads one, as the `getSIG_*` functions in Algorithms 11, 13, 17 and
//! 20 do.

use crate::fors::*;
use crate::ht::*;
use crate::util::*;
use crate::xmss::*;
use vstd::prelude::*;

verus! {

/// SIG_XMSS = sig || AUTH (Figure 11)
pub open spec fn spec_xmss_bytes(s: (Seq<Seq<u8>>, Seq<Seq<u8>>)) -> Seq<u8> {
    flat(s.0) + flat(s.1)
}

/// SIG_HT, the XMSS signatures of layers 0 to d - 1 (Figure 13)
pub open spec fn spec_ht_bytes(s: Seq<(Seq<Seq<u8>>, Seq<Seq<u8>>)>) -> Seq<u8> {
    flat(s.map_values(|x: (Seq<Seq<u8>>, Seq<Seq<u8>>)| spec_xmss_bytes(x)))
}

/// One FORS private key value and its AUTH (Figure 14)
pub open spec fn spec_fors_elem_bytes(e: (Seq<u8>, Seq<Seq<u8>>)) -> Seq<u8> {
    e.0 + flat(e.1)
}

/// SIG_FORS (Figure 14)
pub open spec fn spec_fors_bytes(s: Seq<(Seq<u8>, Seq<Seq<u8>>)>) -> Seq<u8> {
    flat(s.map_values(|e: (Seq<u8>, Seq<Seq<u8>>)| spec_fors_elem_bytes(e)))
}

/// The n-byte strings at offsets base, base + n, ..., of b
pub open spec fn spec_chunks(b: Seq<u8>, base: int, count: int) -> Seq<Seq<u8>> {
    Seq::new(count as nat, |i: int| b.subrange(base + 32 * i, base + 32 * i + 32))
}

/// The XMSS signature in the 2400 bytes b
pub open spec fn spec_parse_xmss(b: Seq<u8>) -> (Seq<Seq<u8>>, Seq<Seq<u8>>) {
    (spec_chunks(b, 0, 67), spec_chunks(b, 2144, 8))
}

/// The hypertree signature in the 19200 bytes b
pub open spec fn spec_parse_ht(b: Seq<u8>) -> Seq<(Seq<Seq<u8>>, Seq<Seq<u8>>)> {
    Seq::new(8, |j: int| spec_parse_xmss(b.subrange(2400 * j, 2400 * j + 2400)))
}

/// The FORS element in the 480 bytes b
pub open spec fn spec_parse_fors_elem(b: Seq<u8>) -> (Seq<u8>, Seq<Seq<u8>>) {
    (b.subrange(0, 32), spec_chunks(b, 32, 14))
}

/// The FORS signature in the 10560 bytes b
pub open spec fn spec_parse_fors(b: Seq<u8>) -> Seq<(Seq<u8>, Seq<Seq<u8>>)> {
    Seq::new(22, |i: int| spec_parse_fors_elem(b.subrange(480 * i, 480 * i + 480)))
}

/// SIG_XMSS as bytes
pub fn xmss_to_bytes(s: &XmssSig) -> (r: [u8; 2400])
    ensures r@ == spec_xmss_bytes(xmss_view(*s)),
{
    let mut r = [0u8; 2400];
    proof {
        lemma_flat_len(views32(s.sig@), 32);
        lemma_flat_len(views32(s.auth@), 32);
    }
    flat_at(&mut r, 0, &s.sig);
    let ghost r1 = r@;
    flat_at(&mut r, 2144, &s.auth);
    assert(r1.subrange(0, 2144) =~= flat(views32(s.sig@)));
    assert(r@ =~= spec_xmss_bytes(xmss_view(*s)));
    r
}

/// SIG_HT as bytes
pub fn ht_to_bytes(s: &HtSig) -> (r: [u8; 19200])
    ensures r@ == spec_ht_bytes(ht_view(s@)),
{
    let ghost xs = ht_view(s@).map_values(|x: (Seq<Seq<u8>>, Seq<Seq<u8>>)| spec_xmss_bytes(x));
    let mut r = [0u8; 19200];
    let mut j: usize = 0;
    while j < 8
        invariant
            j <= 8,
            xs == ht_view(s@).map_values(|x: (Seq<Seq<u8>>, Seq<Seq<u8>>)| spec_xmss_bytes(x)),
            r@.subrange(0, 2400 * j) == flat(xs.take(j as int)),
        decreases 8 - j,
    {
        let b = xmss_to_bytes(&s[j]);
        let ghost before = r@;
        copy_at(&mut r, 2400 * j, b.as_slice());
        proof {
            lemma_flat_take(xs, j as int);
            assert(r@.subrange(0, 2400 * (j + 1)) =~= before.subrange(0, 2400 * j) + b@);
        }
        j += 1;
    }
    assert(xs.take(8) =~= xs);
    assert(r@.subrange(0, 19200) =~= r@);
    r
}

/// One FORS element as bytes
pub fn fors_elem_to_bytes(e: &ForsElem) -> (r: [u8; 480])
    ensures r@ == spec_fors_elem_bytes(fors_elem_view(*e)),
{
    let mut r = [0u8; 480];
    proof { lemma_flat_len(views32(e.auth@), 32); }
    copy_at(&mut r, 0, e.sk.as_slice());
    let ghost r1 = r@;
    flat_at(&mut r, 32, &e.auth);
    assert(r1.subrange(0, 32) =~= e.sk@);
    assert(r@ =~= spec_fors_elem_bytes(fors_elem_view(*e)));
    r
}

/// SIG_FORS as bytes
pub fn fors_to_bytes(s: &ForsSig) -> (r: [u8; 10560])
    ensures r@ == spec_fors_bytes(fors_view(s@)),
{
    let ghost xs = fors_view(s@).map_values(|e: (Seq<u8>, Seq<Seq<u8>>)| spec_fors_elem_bytes(e));
    let mut r = [0u8; 10560];
    let mut i: usize = 0;
    while i < 22
        invariant
            i <= 22,
            xs == fors_view(s@).map_values(|e: (Seq<u8>, Seq<Seq<u8>>)| spec_fors_elem_bytes(e)),
            r@.subrange(0, 480 * i) == flat(xs.take(i as int)),
        decreases 22 - i,
    {
        let b = fors_elem_to_bytes(&s[i]);
        let ghost before = r@;
        copy_at(&mut r, 480 * i, b.as_slice());
        proof {
            lemma_flat_take(xs, i as int);
            assert(r@.subrange(0, 480 * (i + 1)) =~= before.subrange(0, 480 * i) + b@);
        }
        i += 1;
    }
    assert(xs.take(22) =~= xs);
    assert(r@.subrange(0, 10560) =~= r@);
    r
}

/// count n-byte strings from offset off of b
fn chunks_from_bytes<const L: usize>(b: &[u8], off: usize) -> (r: [[u8; 32]; L])
    requires off + 32 * L <= b.len(),
    ensures views32(r@) == spec_chunks(b@, off as int, L as int),
{
    let mut r = [[0u8; 32]; L];
    let mut i: usize = 0;
    while i < L
        invariant
            off + 32 * L <= b.len(),
            i <= L,
            forall|k: int| 0 <= k < i ==> (#[trigger] r@[k])@ == b@.subrange(off + 32 * k, off + 32 * k + 32),
        decreases L - i,
    {
        r[i] = get32(b, off + 32 * i);
        i += 1;
    }
    assert(views32(r@) =~= spec_chunks(b@, off as int, L as int));
    r
}

/// The XMSS signature in b, from offset off
pub fn xmss_from_bytes(b: &[u8], off: usize) -> (r: XmssSig)
    requires off + 2400 <= b.len(),
    ensures xmss_view(r) == spec_parse_xmss(b@.subrange(off as int, off + 2400)),
{
    let sig = chunks_from_bytes::<67>(b, off);
    let auth = chunks_from_bytes::<8>(b, off + 2144);
    let ghost s = b@.subrange(off as int, off + 2400);
    assert(spec_chunks(b@, off as int, 67) =~~= spec_chunks(s, 0, 67));
    assert(spec_chunks(b@, off + 2144, 8) =~~= spec_chunks(s, 2144, 8));
    XmssSig { sig, auth }
}

/// The hypertree signature in b, from offset off
pub fn ht_from_bytes(b: &[u8], off: usize) -> (r: HtSig)
    requires off + 19200 <= b.len(),
    ensures ht_view(r@) == spec_parse_ht(b@.subrange(off as int, off + 19200)),
{
    let ghost s = b@.subrange(off as int, off + 19200);
    let x0 = xmss_from_bytes(b, off);
    let mut r = [x0; 8];
    let mut j: usize = 0;
    while j < 8
        invariant
            off + 19200 <= b.len(),
            j <= 8,
            s == b@.subrange(off as int, off + 19200),
            forall|k: int| 0 <= k < j ==> xmss_view(#[trigger] r@[k]) == spec_parse_ht(s)[k],
        decreases 8 - j,
    {
        r[j] = xmss_from_bytes(b, off + 2400 * j);
        assert(b@.subrange(off + 2400 * j, off + 2400 * j + 2400)
            =~= s.subrange(2400 * j, 2400 * j + 2400));
        j += 1;
    }
    assert(ht_view(r@) =~= spec_parse_ht(s));
    r
}

/// The FORS signature in b, from offset off
pub fn fors_from_bytes(b: &[u8], off: usize) -> (r: ForsSig)
    requires off + 10560 <= b.len(),
    ensures fors_view(r@) == spec_parse_fors(b@.subrange(off as int, off + 10560)),
{
    let ghost s = b@.subrange(off as int, off + 10560);
    let mut r = [ForsElem { sk: [0u8; 32], auth: [[0u8; 32]; 14] }; 22];
    let mut i: usize = 0;
    while i < 22
        invariant
            off + 10560 <= b.len(),
            i <= 22,
            s == b@.subrange(off as int, off + 10560),
            forall|k: int| 0 <= k < i ==> fors_elem_view(#[trigger] r@[k]) == spec_parse_fors(s)[k],
        decreases 22 - i,
    {
        let base = off + 480 * i;
        let sk = get32(b, base);
        let auth = chunks_from_bytes::<14>(b, base + 32);
        let ghost e = s.subrange(480 * i, 480 * i + 480);
        assert(b@.subrange(base as int, base + 32) =~= e.subrange(0, 32));
        assert(spec_chunks(b@, base + 32, 14) =~~= spec_chunks(e, 32, 14));
        r[i] = ForsElem { sk, auth };
        i += 1;
    }
    assert(fors_view(r@) =~= spec_parse_fors(s));
    r
}

} // verus!
