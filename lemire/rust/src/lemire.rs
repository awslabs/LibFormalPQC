//! Lemire's algorithm for a fair random integer in `0 .. bound`
//! (counterpart of the SPARK package `LeMire`).
//!
//! Spec functions, proof functions, `ensures` clauses and `assert`s are
//! ghost: Verus erases them, so they cost nothing at run time. In
//! particular the postcondition of `random_n` quantifies over all 2**64
//! draws and is never executed. The precondition `bound > 0` is both
//! proved at every verified call site and checked at run time (as in the
//! SPARK version, where preconditions remain enabled).

use crate::rng::random_u64;
// Proof-only imports: these lemmas are erased in a normal `cargo build`.
#[cfg(verus_keep_ghost)]
use vstd::arithmetic::div_mod::{
    lemma_div_pos_is_pos, lemma_fundamental_div_mod, lemma_fundamental_div_mod_converse,
    lemma_mod_pos_bound,
};
use vstd::prelude::*;

verus! {

// ---------------------------------------------------------------------
//  Ghost model of one draw of Lemire's algorithm
//
//  All of this is in mathematical integers (`int`), so it is free of
//  modular-arithmetic subtleties. For a bound N and a single 64-bit
//  draw X:
//
//    output(X, N)      = (X * N) / 2**64       the result if accepted
//    low(X, N)         = (X * N) % 2**64       the truncated product
//    threshold(N)      = 2**64 % N             the number of excess draws
//    is_accepted(X, N) = low(X, N) >= threshold(N)
//    per_value(N)      = 2**64 / N
//
//  Fairness theorem (lemma_encode and lemma_decode below): the accepted
//  draws are in one-to-one correspondence with the pairs (R, J) where
//  0 <= R < N and 0 <= J < per_value(N), and the accepted draw
//  corresponding to (R, J) has output R. So every value R in 0 .. N - 1
//  is the output of exactly per_value(N) accepted draws.
//
//  random_n draws X uniformly and independently until it gets an
//  accepted draw (its rejection tests are proved to be exactly
//  "!is_accepted"), then returns the output of that draw (its
//  postcondition). The returned draw is therefore uniform over the
//  N * per_value(N) accepted draws, and each R in 0 .. N - 1 is returned
//  with probability per_value(N) / (N * per_value(N)), which is 1 / N.
//
//  The step from counting to probability, and the assumption that
//  rng::random_u64 is uniform and independent, are outside what Verus
//  can express here. They are stated, not proved.
// ---------------------------------------------------------------------

pub spec const TWO_64: int = 0x1_0000_0000_0000_0000;

pub open spec fn is_bound(n: int) -> bool {
    0 < n < TWO_64
}

pub open spec fn is_draw(x: int) -> bool {
    0 <= x < TWO_64
}

pub open spec fn output(x: int, n: int) -> int {
    (x * n) / TWO_64
}

pub open spec fn low(x: int, n: int) -> int {
    (x * n) % TWO_64
}

pub open spec fn threshold(n: int) -> int
    recommends
        n > 0,
{
    TWO_64 % n
}

pub open spec fn is_accepted(x: int, n: int) -> bool {
    n > 0 && low(x, n) >= threshold(n)
}

pub open spec fn per_value(n: int) -> int
    recommends
        n > 0,
{
    TWO_64 / n
}

/// The smallest accepted draw whose output is r:
/// ceiling((r * 2**64 + threshold(n)) / n)
pub open spec fn first(r: int, n: int) -> int
    recommends
        n > 0,
{
    (r * TWO_64 + threshold(n) + n - 1) / n
}

/// Position of draw x among the accepted draws with the same output
pub open spec fn index(x: int, n: int) -> int
    recommends
        n > 0,
{
    x - first(output(x, n), n)
}

/// The j-th accepted draw whose output is r
pub open spec fn decode(r: int, j: int, n: int) -> int
    recommends
        n > 0,
{
    first(r, n) + j
}

/// `result` is the output of some accepted draw. This quantifies over all
/// 2**64 draws, so it is spec-only and can never be executed.
pub open spec fn is_model_output(bound: u64, result: u64) -> bool {
    exists|x: u64|
        #[trigger] is_accepted(x as int, bound as int) && output(x as int, bound as int)
            == result as int
}

// ---------------------------------------------------------------------
//  Arithmetic helper lemmas
// ---------------------------------------------------------------------

proof fn lemma_mul_le(a: int, b: int, c: int)
    requires
        a <= b,
        c >= 0,
    ensures
        a * c <= b * c,
{
    assert(a * c <= b * c) by (nonlinear_arith)
        requires
            a <= b,
            c >= 0,
    ;
}

proof fn lemma_mul_lt(a: int, b: int, c: int)
    requires
        a < b,
        c > 0,
    ensures
        a * c < b * c,
{
    assert(a * c < b * c) by (nonlinear_arith)
        requires
            a < b,
            c > 0,
    ;
}

/// Cancel a positive factor from both sides of a strict inequality
proof fn lemma_mul_lt_cancel(a: int, b: int, c: int)
    requires
        c > 0,
        a * c < b * c,
    ensures
        a < b,
{
    if b <= a {
        lemma_mul_le(b, a, c);
    }
}

/// (a + b) * c = a * c + b * c
proof fn lemma_mul_add(a: int, b: int, c: int)
    ensures
        (a + b) * c == a * c + b * c,
{
    assert((a + b) * c == a * c + b * c) by (nonlinear_arith);
}

/// If q * d <= a < q * d + d then q is the quotient of a by d
proof fn lemma_div(a: int, d: int, q: int)
    requires
        d > 0,
        q >= 0,
        q * d <= a,
        a < q * d + d,
    ensures
        a / d == q,
        a % d == a - q * d,
{
    lemma_fundamental_div_mod_converse(a, d, q, a - q * d);
}

/// 2**64 = per_value(n) * n + threshold(n)
proof fn lemma_split(n: int)
    requires
        is_bound(n),
    ensures
        TWO_64 == per_value(n) * n + threshold(n),
        0 <= threshold(n) < n,
        per_value(n) >= 1,
{
    lemma_fundamental_div_mod(TWO_64, n);
    lemma_mod_pos_bound(TWO_64, n);
    lemma_div_pos_is_pos(TWO_64, n);
    assert(n * per_value(n) == per_value(n) * n) by (nonlinear_arith);
    if per_value(n) < 1 {
        assert(per_value(n) == 0);
        assert(per_value(n) * n == 0) by (nonlinear_arith)
            requires
                per_value(n) == 0,
        ;
    }
}

/// first(r, n) * n is the smallest multiple of n that is
/// >= r * 2**64 + threshold(n)
proof fn lemma_first(r: int, n: int)
    requires
        is_bound(n),
        r >= 0,
    ensures
        first(r, n) >= 0,
        first(r, n) * n >= r * TWO_64 + threshold(n),
        first(r, n) * n < r * TWO_64 + threshold(n) + n,
{
    let a = r * TWO_64 + threshold(n) + n - 1;
    lemma_split(n);
    lemma_mul_le(0, r, TWO_64);
    assert(a >= 0);
    lemma_fundamental_div_mod(a, n);
    lemma_mod_pos_bound(a, n);
    lemma_div_pos_is_pos(a, n);
    assert(n * (a / n) == (a / n) * n) by (nonlinear_arith);
}

// ---------------------------------------------------------------------
//  Fairness theorem
// ---------------------------------------------------------------------

/// Every accepted draw maps to a pair (r, j) in range, and back
pub proof fn lemma_encode(x: int, n: int)
    requires
        is_bound(n),
        is_draw(x),
        is_accepted(x, n),
    ensures
        0 <= output(x, n) < n,
        0 <= index(x, n) < per_value(n),
        decode(output(x, n), index(x, n), n) == x,
{
    let p = x * n;
    let r = output(x, n);
    let c = first(r, n);
    let k = per_value(n);
    let t = threshold(n);
    lemma_split(n);

    // p = r * 2**64 + low, with t <= low < 2**64
    lemma_mul_le(0, x, n);
    lemma_fundamental_div_mod(p, TWO_64);
    lemma_mod_pos_bound(p, TWO_64);
    lemma_div_pos_is_pos(p, TWO_64);
    assert(TWO_64 * r == r * TWO_64) by (nonlinear_arith);
    assert(p == r * TWO_64 + low(x, n));
    assert(low(x, n) >= t && low(x, n) < TWO_64);
    assert(r >= 0);

    // r < n, because r * 2**64 <= p < 2**64 * n
    lemma_mul_le(0, r, TWO_64);
    lemma_mul_lt(x, TWO_64, n);
    assert(TWO_64 * n == n * TWO_64) by (nonlinear_arith);
    lemma_mul_lt_cancel(r, n, TWO_64);

    // c <= x, because (c - 1) * n < r * 2**64 + t <= p = x * n
    lemma_first(r, n);
    lemma_mul_add(c, -1, n);
    lemma_mul_lt_cancel(c - 1, x, n);

    // x < c + k, because x * n < (r + 1) * 2**64 = r * 2**64 + k * n + t
    // <= c * n + k * n
    assert(p < r * TWO_64 + k * n + t);
    lemma_mul_add(c, k, n);
    lemma_mul_lt_cancel(x, c + k, n);
}

/// Every pair (r, j) in range maps to an accepted draw with output r,
/// and back
pub proof fn lemma_decode(r: int, j: int, n: int)
    requires
        is_bound(n),
        0 <= r < n,
        0 <= j < per_value(n),
    ensures
        is_draw(decode(r, j, n)),
        is_accepted(decode(r, j, n), n),
        output(decode(r, j, n), n) == r,
        index(decode(r, j, n), n) == j,
{
    let t = threshold(n);
    let k = per_value(n);
    let c = first(r, n);
    let x = c + j;
    let p = x * n;
    lemma_split(n);
    lemma_first(r, n);

    // r * 2**64 + t <= p < r * 2**64 + t + k * n = (r + 1) * 2**64
    lemma_mul_le(0, j, n);
    lemma_mul_le(j, k - 1, n);
    lemma_mul_add(k, -1, n);
    lemma_mul_add(c, j, n);
    assert(p == c * n + j * n);
    assert(p >= r * TWO_64 + t);
    assert(p < r * TWO_64 + t + k * n);
    assert(p < r * TWO_64 + TWO_64);

    // So output(x, n) = r and low(x, n) = p - r * 2**64 >= t
    lemma_mul_le(0, r, TWO_64);
    lemma_div(p, TWO_64, r);
    assert(output(x, n) == r);
    assert(low(x, n) >= t);

    // x < 2**64, because x * n < (r + 1) * 2**64 <= n * 2**64
    lemma_mul_le(r + 1, n, TWO_64);
    lemma_mul_add(r, 1, TWO_64);
    assert(TWO_64 * n == n * TWO_64) by (nonlinear_arith);
    lemma_mul_lt_cancel(x, TWO_64, n);
}

// ---------------------------------------------------------------------
//  Link between the machine arithmetic and the model
// ---------------------------------------------------------------------

pub const C2_64: u128 = 0x1_0000_0000_0000_0000;

/// x * n fits in a u128 (so the machine multiplication cannot overflow),
/// truncating it to its low 64 bits gives low and shifting out the low 64
/// bits gives output.
proof fn lemma_draw(x: u64, n: u64)
    requires
        n > 0,
    ensures
        (x as int) * (n as int) <= u128::MAX,
        ((x as int) * (n as int)) % (C2_64 as int) == low(x as int, n as int),
        ((x as int) * (n as int)) / (C2_64 as int) == output(x as int, n as int),
        0 <= low(x as int, n as int) < TWO_64,
        0 <= output(x as int, n as int) < TWO_64,
{
    let bx = x as int;
    let bn = n as int;
    lemma_mul_le(bx, TWO_64 - 1, bn);
    lemma_mul_le(bn, TWO_64 - 1, TWO_64 - 1);
    assert((TWO_64 - 1) * bn == bn * (TWO_64 - 1)) by (nonlinear_arith);
    assert((TWO_64 - 1) * (TWO_64 - 1) < TWO_64 * TWO_64) by (compute_only);
    assert(bx * bn < TWO_64 * TWO_64);
    lemma_mul_le(0, bx, bn);
    lemma_mod_pos_bound(bx * bn, TWO_64);
    lemma_div_pos_is_pos(bx * bn, TWO_64);
    // bx * bn / 2**64 < 2**64
    lemma_fundamental_div_mod(bx * bn, TWO_64);
    if output(bx, bn) >= TWO_64 {
        lemma_mul_le(TWO_64, output(bx, bn), TWO_64);
        assert(TWO_64 * output(bx, bn) == output(bx, bn) * TWO_64) by (nonlinear_arith);
    }
}

/// The machine computation of t is 2**64 % n
proof fn lemma_threshold(n: u64, t: u64)
    requires
        n > 0,
        t == vstd::wrapping::u64_specs::wrapping_sub(0, n) % n,
    ensures
        t as int == threshold(n as int),
{
    let bn = n as int;
    lemma_split(bn);
    assert(vstd::wrapping::u64_specs::wrapping_sub(0, n) as int == TWO_64 - bn);
    // 2**64 - n = (k - 1) * n + threshold(n)
    lemma_mul_le(0, per_value(bn) - 1, bn);
    lemma_mul_add(per_value(bn), -1, bn);
    lemma_div(TWO_64 - bn, bn, per_value(bn) - 1);
}

// ---------------------------------------------------------------------
//  The algorithm
// ---------------------------------------------------------------------

/// Return a uniformly distributed integer in `0 .. bound`, assuming
/// `random_u64` is uniform and independent (see the model above).
///
/// # Panics
///
/// Panics if `bound == 0` (only reachable from unverified callers).
#[verifier::exec_allows_no_decreases_clause]
pub fn random_n(bound: u64) -> (result: u64)
    requires
        bound > 0,
    ensures
        result < bound,
        is_model_output(bound, result),
{
    vstd::pervasive::runtime_assert(bound > 0);

    let b128: u128 = bound as u128;
    let ghost bn: int = bound as int;

    let mut x: u64 = random_u64();
    let mut l: u64;
    let mut m: u128;
    let t: u64;

    assert(is_bound(bn));

    proof {
        lemma_draw(x, bound);
    }
    m = x as u128 * b128;

    // Explicit modular reduction mod 2**64 and type conversion is
    // equivalent to simple truncation of the upper 64 bits
    l = (m % C2_64) as u64;

    if l < bound {
        t = 0u64.wrapping_sub(bound) % bound;
        proof {
            lemma_threshold(bound, t);
        }

        // Rejection sampling: each iteration exits with probability at
        // least 1/2 for a uniform random_u64, so the loop terminates with
        // probability 1, but no iteration bound exists. Hence no
        // `decreases` clause (exec_allows_no_decreases_clause above).
        while l < t
            invariant
                bound > 0,
                b128 == bound,
                bn == bound as int,
                t as int == threshold(bn),
                m == x as int * b128 as int,
                l == (m % C2_64) as u64,
        {
            proof {
                lemma_draw(x, bound);
            }

            // Each rejected draw is exactly one the model rejects
            assert((l as int) < threshold(bn));
            assert(!is_accepted(x as int, bn));

            x = random_u64();
            proof {
                lemma_draw(x, bound);
            }
            m = x as u128 * b128;
            l = (m % C2_64) as u64;
        }

        proof {
            lemma_draw(x, bound);
        }
        assert(l as int >= threshold(bn));
    } else {
        // l >= bound > threshold, so the draw is accepted without
        // computing t
        proof {
            lemma_split(bn);
            lemma_draw(x, bound);
        }
        assert(l as int >= bn);
        assert(l as int >= threshold(bn));
    }

    // The draw being used is exactly one the model accepts
    assert(l as int == low(x as int, bn));
    assert(is_accepted(x as int, bn));

    let r: u64 = (m / C2_64) as u64;
    assert(r as int == output(x as int, bn));

    proof {
        lemma_encode(x as int, bn);
    }
    assert((r as int) < bn);
    assert(r < bound);
    r
}

} // verus!
