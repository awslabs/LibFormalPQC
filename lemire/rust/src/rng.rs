//! Source of 64-bit draws (counterpart of the SPARK package `RNG`).
//!
//! As in SPARK, this is outside the verified world: `random_u64` has no
//! specification, so the verifier assumes nothing about the values it
//! returns. The fairness argument in `crate::lemire` assumes the draws are
//! uniform and independent; that assumption is stated, not proved.
//!
//! The generator is SplitMix64, held per thread and seeded from the
//! standard library's randomly keyed hasher. Like `Ada.Numerics.Discrete_Random`
//! it is a statistical PRNG, not a cryptographically secure one.

use vstd::prelude::*;

verus! {

/// Return the next 64-bit draw. Reads and updates hidden generator state
/// (the SPARK `Entropy` abstract state).
#[verifier::external_body]
pub fn random_u64() -> u64 {
    imp::next()
}

} // verus!

mod imp {
    use std::cell::Cell;
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};

    thread_local! {
        static STATE: Cell<u64> = Cell::new(seed());
    }

    fn seed() -> u64 {
        let mut h = RandomState::new().build_hasher();
        h.write_u64(0x5eed);
        h.finish()
    }

    pub(super) fn next() -> u64 {
        STATE.with(|s| {
            let z = s.get().wrapping_add(0x9E37_79B9_7F4A_7C15);
            s.set(z);
            let z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            let z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        })
    }
}
