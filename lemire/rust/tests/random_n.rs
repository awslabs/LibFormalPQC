use lemire::random_n;

#[test]
fn bound_one_always_zero() {
    for _ in 0..1000 {
        assert_eq!(random_n(1), 0);
    }
}

#[test]
fn results_are_below_bound() {
    for &bound in &[2u64, 3, 7, 10, 1 << 32, (1 << 63) + 1, u64::MAX - 1, u64::MAX] {
        for _ in 0..1000 {
            assert!(random_n(bound) < bound);
        }
    }
}

#[test]
fn small_bound_is_roughly_uniform() {
    const BOUND: u64 = 6;
    const DRAWS: usize = 600_000;
    let mut counts = [0usize; BOUND as usize];
    for _ in 0..DRAWS {
        counts[random_n(BOUND) as usize] += 1;
    }
    let expected = DRAWS / BOUND as usize;
    for &c in &counts {
        // Expected ~100_000 per bucket, std dev ~289; allow a wide margin.
        assert!(c.abs_diff(expected) < 3_000, "counts = {counts:?}");
    }
}

#[test]
#[should_panic]
fn zero_bound_panics() {
    random_n(0);
}
