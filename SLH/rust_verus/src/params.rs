//  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

//! Parameters of SLH-DSA-SHAKE-256s (FIPS 205 Table 2), and the sizes
//! derived from them.

use vstd::prelude::*;

verus! {

/// Security parameter n, in bytes
pub const N: usize = 32;
/// Total height of the hypertree h
pub const H: usize = 64;
/// Number of layers of the hypertree d
pub const D: usize = 8;
/// Height of each XMSS tree h'
pub const H_PRIME: usize = 8;
/// Height of each FORS tree a
pub const A: usize = 14;
/// Number of FORS trees k
pub const K: usize = 22;
/// lg_w, the number of bits in a WOTS+ digit
pub const LG_W: usize = 4;
/// Length of the message digest m, in bytes
pub const M: usize = 47;

/// w = 2^lg_w (FIPS 205 equation 5.1)
pub const W: usize = 16;
/// len1 = ceil(8n / lg_w) (5.2)
pub const LEN1: usize = 64;
/// len2 = floor(log2(len1 (w - 1)) / lg_w) + 1 (5.3)
pub const LEN2: usize = 3;
/// len = len1 + len2 (5.4)
pub const LEN: usize = 67;

/// Length of md, ceil(k a / 8) bytes
pub const MD_BYTES: usize = 39;
/// Length of tmp_idx_tree, ceil((h - h') / 8) bytes
pub const TREE_BYTES: usize = 7;
/// Length of tmp_idx_leaf, ceil(h' / 8) bytes
pub const LEAF_BYTES: usize = 1;

/// Lengths of the parts of a signature (FIPS 205 Figures 11, 13, 14 and 17)
pub const XMSS_SIG_BYTES: usize = 2400;   // (len + h') n
pub const HT_SIG_BYTES: usize = 19200;    // d (len + h') n
pub const FORS_ELEM_BYTES: usize = 480;   // (1 + a) n
pub const FORS_SIG_BYTES: usize = 10560;  // k (1 + a) n
/// Length of an SLH-DSA signature, (1 + k (1 + a) + h + d len) n
pub const SIG_BYTES: usize = 29792;
/// Length of an SLH-DSA private key, 4n (Figure 15)
pub const SK_BYTES: usize = 128;
/// Length of an SLH-DSA public key, 2n (Figure 16)
pub const PK_BYTES: usize = 64;

/// Where each part of a signature starts
pub const FORS_START: usize = 32;          // n
pub const HT_START: usize = 10592;         // n + k (1 + a) n

/// The derived values, checked
pub proof fn lemma_parameters()
    ensures
        W == 16 && LEN1 as int == (8 * N as int + LG_W as int - 1) / (LG_W as int) && LEN == LEN1 + LEN2,
        // 2^8 <= len1 (w - 1) < 2^12, so log2 of it is in [8, 12), and len2 = 2 + 1
        256 <= LEN1 * (W - 1) < 4096 && LEN2 == 3,
        MD_BYTES as int == (K * A + 7) as int / 8 && TREE_BYTES as int == (H - H_PRIME + 7) as int / 8
            && LEAF_BYTES as int == (H_PRIME + 7) as int / 8 && M == MD_BYTES + TREE_BYTES + LEAF_BYTES,
        H == D * H_PRIME,
        XMSS_SIG_BYTES == (LEN + H_PRIME) * N && HT_SIG_BYTES == D * XMSS_SIG_BYTES,
        FORS_ELEM_BYTES == (1 + A) * N && FORS_SIG_BYTES == K * FORS_ELEM_BYTES,
        SIG_BYTES == (1 + K * (1 + A) + H + D * LEN) * N,
        SIG_BYTES == N + FORS_SIG_BYTES + HT_SIG_BYTES,
        FORS_START == N && HT_START == N + FORS_SIG_BYTES,
        SK_BYTES == 4 * N && PK_BYTES == 2 * N,
{
}

} // verus!
