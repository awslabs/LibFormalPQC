//! Lemire's nearly divisionless fair bounded random number algorithm,
//! translated from the SPARK/Ada implementation in `../spark` and verified
//! with Verus.
//!
//! Verify with `cargo verus verify` (Verus 0.2026.10.18 on `PATH`); build
//! and test as ordinary Rust with `cargo build` / `cargo test`.

// The compiled (ghost-erased) code contains no `unsafe`. The lint is not applied
// under verification, where `verus!` expands ghost code using `unsafe` blocks.
#![cfg_attr(not(verus_keep_ghost), forbid(unsafe_code))]

pub mod lemire;
pub mod rng;

pub use lemire::random_n;
