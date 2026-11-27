//  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
//  SPDX-License-Identifier: Apache-2.0

//! Benchmarks slh_keygen, slh_sign and slh_verify in CPU cycles.
//!
//!   bench LABEL [KEYGEN_ITER SIGN_ITER VERIFY_ITER]
//!
//! LABEL names the build variant. Each operation is run once to warm
//! up, then timed ITER times. For each operation, one line is written
//! to stdout:
//!
//!   BENCH LABEL OPERATION MEDIAN MIN ITER
//!
//! where MEDIAN and MIN are in cycles, as for the SPARK benchmark, so
//! SLH/checkers/bench_report.py can summarize them. Every signature is
//! checked with slh_verify, outside the timed region.
//!
//! The program exits with a failure status if the cycle counter is not
//! working, for example if it needs root and is not run as root.
//!
//! This is a test program: it uses std, and is not verified by Verus.
//! It calls the cycle counter in SLH/hal/hal.c (from mlkem-native)
//! through a C foreign function interface, which needs `unsafe`. This
//! is the only use of `unsafe` in the repository's Rust code. It needs
//! the `bench` feature, which compiles hal.c (see build.rs).

use std::process::exit;

//  The cycle counter in SLH/hal/hal.h
extern "C" {
    fn enable_cyclecounter();
    fn disable_cyclecounter();
    fn get_cyclecounter() -> u64;
}

fn cycles() -> u64 {
    //  SAFETY: get_cyclecounter takes no arguments and returns an
    //  integer. enable_cyclecounter has been called first
    unsafe { get_cyclecounter() }
}

fn fail(msg: &str) -> ! {
    eprintln!("bench: {}", msg);
    exit(1);
}

fn pattern(seed: u8) -> [u8; 32] {
    core::array::from_fn(|i| seed.wrapping_add(7u8.wrapping_mul(i as u8)))
}

/// Runs op once to warm up, then times it n times, calling check on
/// each result outside the timed region. Prints the median and minimum,
/// and returns the last result
fn time_it<T>(label: &str, name: &str, n: usize, mut op: impl FnMut() -> T, check: impl Fn(&T)) -> T {
    let mut r = op();
    check(&r);
    let mut t = Vec::with_capacity(n);
    for _ in 0..n {
        let start = cycles();
        r = op();
        let stop = cycles();
        if stop <= start {
            fail("the cycle counter is not working. On macOS, run as root. See SLH/hal/README.md");
        }
        t.push(stop - start);
        check(&r);
    }
    t.sort_unstable();
    let median = if n % 2 == 1 { t[n / 2] } else { (t[n / 2 - 1] + t[n / 2]) / 2 };
    println!("BENCH {} {} {} {} {}", label, name, median, t[0], n);
    r
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 && args.len() != 5 {
        eprintln!("usage: bench LABEL [KEYGEN_ITER SIGN_ITER VERIFY_ITER]");
        exit(1);
    }
    let label = &args[1];
    let iter = |i: usize, d: usize| -> usize {
        args.get(i).map(|s| s.parse().unwrap_or_else(|_| fail("bad iteration count"))).unwrap_or(d)
    };
    let (keygen_iter, sign_iter, verify_iter) = (iter(2, 10), iter(3, 10), iter(4, 50));
    if keygen_iter == 0 || sign_iter == 0 || verify_iter == 0 {
        fail("iteration counts must be positive");
    }

    let (sk_seed, sk_prf, pk_seed, addrnd) = (pattern(1), pattern(2), pattern(3), pattern(4));
    let msg = pattern(5);
    let ctx: [u8; 0] = [];

    //  SAFETY: enable_cyclecounter takes no arguments
    unsafe { enable_cyclecounter() };

    let kp = time_it(label, "Keygen", keygen_iter,
                     || slh_dsa::slh_keygen(&sk_seed, &sk_prf, &pk_seed),
                     |kp| if kp.pk[..] != kp.sk[64..] { fail("wrong result for keygen") });

    let sig = time_it(label, "Sign", sign_iter,
                      || slh_dsa::slh_sign(&msg, &ctx, &kp.sk, &addrnd),
                      |sig| if !slh_dsa::slh_verify(&msg, sig, &ctx, &kp.pk) { fail("wrong result for sign") });

    time_it(label, "Verify", verify_iter,
            || slh_dsa::slh_verify(&msg, &sig, &ctx, &kp.pk),
            |ok| if !ok { fail("wrong result for verify") });

    //  SAFETY: disable_cyclecounter takes no arguments
    unsafe { disable_cyclecounter() };
}
