//  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

#![no_std]
#![cfg_attr(not(verus_keep_ghost), forbid(unsafe_code))]

use vstd::prelude::*;

verus! {

pub mod params;

#[cfg(feature = "kat")]
pub mod util;
#[cfg(not(feature = "kat"))]
mod util;

#[cfg(feature = "kat")]
pub mod hash;
#[cfg(not(feature = "kat"))]
mod hash;

#[cfg(feature = "kat")]
pub mod adrs;
#[cfg(not(feature = "kat"))]
mod adrs;

#[cfg(feature = "kat")]
pub mod wots;
#[cfg(not(feature = "kat"))]
mod wots;

#[cfg(feature = "kat")]
pub mod xmss;
#[cfg(not(feature = "kat"))]
mod xmss;

#[cfg(feature = "kat")]
pub mod ht;
#[cfg(not(feature = "kat"))]
mod ht;

#[cfg(feature = "kat")]
pub mod fors;
#[cfg(not(feature = "kat"))]
mod fors;

#[cfg(feature = "kat")]
pub mod formats;
#[cfg(not(feature = "kat"))]
mod formats;

#[cfg(feature = "kat")]
pub mod internal;
#[cfg(not(feature = "kat"))]
mod internal;

pub mod api;
pub use api::*;

} // verus!
