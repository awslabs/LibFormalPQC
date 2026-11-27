# SLH-DSA Reference Code in Rust, verified with Verus

This crate, `slh_dsa`, implements SLH-DSA, the Stateless Hash-Based
Digital Signature Algorithm (formerly known as SPHINCS+), as specified in
[FIPS 205](https://doi.org/10.6028/NIST.FIPS.205), for the
SLH-DSA-SHAKE-256s parameter set only.

It is a companion to the SPARK implementation in `../spark_ada`, and
follows the same structure. It is written in safe, `no_std` Rust, and
verified with [Verus](https://github.com/verus-lang/verus).

## IMPORTANT WARNING

This implementation is absolutely NOT intended for production or any use
in a "high assurance" setting. In particular:

* Constant-time behaviour is not verified.

* Secret and intermediate values are not erased after use.

* Performance is unlikely to be competitive with other, more optimized,
implementations.

* See also [Limitations](#limitations) below.

## Usage

```toml
[dependencies]
slh_dsa = { path = "path/to/SLH/rust_verus" }
```

```rust
use slh_dsa::*;

// Random values: these shall come from an approved random bit generator
let (sk_seed, sk_prf, pk_seed, addrnd) = ([1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]);

let kp: KeyPair = slh_keygen(&sk_seed, &sk_prf, &pk_seed);
let msg = b"message";
let ctx = b"";                       // At most 255 bytes

let sig: Signature = slh_sign(msg, ctx, &kp.sk, &addrnd);
assert!(slh_verify(msg, &sig, ctx, &kp.pk));
```

The application interface, from FIPS 205 section 10:

| FIPS 205 | Rust |
|----------|------|
| Algorithm 21, `slh_keygen` | `slh_keygen` |
| Algorithm 22, `slh_sign` | `slh_sign`, `slh_sign_deterministic` |
| Algorithm 23, `hash_slh_sign` | `hash_slh_sign`, `hash_slh_sign_deterministic` |
| Algorithm 24, `slh_verify` | `slh_verify` |
| Algorithm 25, `hash_slh_verify` | `hash_slh_verify` |

* Keys and signatures are byte arrays in the formats of FIPS 205
  Figures 15, 16 and 17: `PrivateKey = [u8; 128]`, `PublicKey = [u8; 64]`
  and `Signature = [u8; 29792]`.
* Where FIPS 205 generates random values (SK.seed, SK.prf, PK.seed and
  addrnd), the caller supplies them as parameters. They shall be generated
  by an approved random bit generator. The library never generates random
  values itself.
* The pre-hash functions (`PreHash`) are SHA3-512 and SHAKE256 with a
  512-bit output. These are the ones from FIPS 202 with the security
  strength that FIPS 205 section 10.2 requires for this parameter set.
* The signing functions require the context string `ctx` to be at most
  255 bytes. See [Limitations](#limitations).
* The verification functions return `false` for a context string longer
  than 255 bytes, as FIPS 205 requires.

## Structure

The modules follow FIPS 205 section by section, and the SPARK code
package by package:

| FIPS 205 | Module |
|----------|--------|
| Table 2, parameters | `params` |
| Section 4.1, hash functions | `hash` |
| Sections 4.2 and 4.3, addresses | `adrs` |
| Section 5, WOTS+ | `wots` |
| Section 6, XMSS | `xmss` |
| Section 7, the hypertree | `ht` |
| Section 8, FORS | `fors` |
| Figures 11, 13, 14 and 17, signature formats | `formats` |
| Section 9, internal functions | `internal` |
| Section 10, external functions | `api` (re-exported at the crate root) |

FIPS 205 says that, other than for testing, the internal functions should
not be made available to applications. So all the modules except `params`
and `api` are private, unless the crate is built with the `kat` feature,
which the test programs use.

Each FIPS 205 algorithm is a Rust function with a specification: a Verus
`spec` function, named `spec_*`, that follows the FIPS 205 pseudocode. As
in the SPARK code, the functions are pure: an address (ADRS) is passed by
value, and each address used is a new value built from it, where FIPS 205
updates ADRS in place.

Where FIPS 205 builds M' (Algorithms 22 to 25), the code passes it to the
hash functions in three parts, so no copy or allocation is needed.

All the library code is inside `verus!` blocks. The library is `no_std`,
doesn't use `alloc`, and contains no `unsafe` code
(`#![forbid(unsafe_code)]` in normal builds).

The only dependencies are `vstd`, the Verus standard library, and the
`sha3` crate.

## Verification

Verus proves, automatically, for every function in the library:

* **Freedom from panics.** There is no arithmetic overflow or underflow,
  no division by zero, and no array or slice index out of bounds.
* **Termination.** Every loop and recursive function terminates.
* **Functional correctness with respect to the specifications.** Each
  function's result is the one given by the `spec_*` function for its
  FIPS 205 algorithm. For example, `slh_sign` returns exactly
  `spec_slh_sign_internal (M', SK, addrnd)`, where M' is the FIPS 205
  `toByte (0, 1) || toByte (|ctx|, 1) || ctx || M`, and the specification
  of each part of the signature goes down through FORS, the hypertree,
  XMSS and WOTS+ to the hash functions.

The hash functions are modelled by two uninterpreted specification
functions, `shake256` and `sha3_512`. A few small functions in `hash.rs`,
marked `#[verifier::external_body]`, call the `sha3` crate and are trusted
to compute them. They are the only unverified code in the library.

The round-trip theorems and correctness theorems that the SPARK version
proves (for example, that a signature made with a key from `slh_keygen`
verifies) are not yet proved here. See [Limitations](#limitations).

## Tests

The test programs, in `examples`, check the library against:

* Python reference models of FIPS 205 sections 4 to 9, in
  `SLH/checkers/check_*_kats.py`. These are shared with the SPARK
  implementation. Each model follows the FIPS 205 pseudocode closely,
  including its in-place updates of ADRS, so it is independent of both
  implementations. `examples/tkats.rs` is a port of the SPARK test package
  `SLH.KAT`, and writes the same records.

* The NIST ACVP test vectors for SLH-DSA-SHAKE-256s, in `SLH/acvp`,
  covering key generation, signing and verification, through both the
  internal interface (section 9) and the application interface
  (section 10), with pure and pre-hash signing, and contexts of up to 255
  bytes. The verification tests include modified and wrongly-sized
  signatures and modified messages.

The test programs use `std` and are not verified.

## Getting the tools

The crate was developed on an Apple Silicon Mac running macOS, with:

1. Rust 1.100.0, installed with [rustup](https://rustup.rs). Verus selects
   the toolchain it needs.
2. Verus 0.2026.11.22.1ce6a59, from the
   [Verus releases](https://github.com/verus-lang/verus/releases). Unpack
   it and put the directory containing `verus` and `cargo-verus` on your
   `PATH`.
3. Python 3, to check the test results. Only the standard library is
   used.
4. GNU make, and a C compiler (`cc`), for the benchmark.

`Cargo.toml` pins `vstd` to the version that matches Verus 0.2026.11.22
(`=0.0.0-2026-11-22-0344`). With another version of Verus, change it to
the `vstd` version with the same date (see
<https://crates.io/crates/vstd/versions>).

## Building the library

```
cd SLH/rust_verus
cargo build --release
```

This doesn't need Verus. Verus annotations are erased in a normal build.

## Running the proofs

```
cd SLH/rust_verus
make verify
```

or `cargo verus verify`. This takes a few seconds, and should end with

```
verification results:: 164 verified, 0 errors
```

## Running the tests

```
cd SLH/rust_verus
make
```

This builds the test program `tkats`, runs each group of tests, and
checks the results. It takes under a minute, and should end with:

```
All hash function KATs passed
...
All WOTS+ KATs passed
...
All XMSS KATs passed
...
All hypertree KATs passed
...
All FORS KATs passed
...
All SLH-DSA KATs passed
--- Checking NIST ACVP tests ---
python3 ../checkers/check_acvp.py check results/acvp_results.txt
ACVP KeyGen         10 passed
ACVP SigGen         14 passed
ACVP SigGenPure     14 passed
ACVP SigGenPreHash   4 passed
ACVP SigVer         14 passed
ACVP SigVerPure     14 passed
ACVP SigVerPreHash   3 passed
All ACVP tests passed
```

Each group can be run on its own, with `make check_hash`, `check_wots`,
`check_xmss`, `check_ht`, `check_fors`, `check_slh` or `check_acvp`. The
results are in `results`. `make clean` removes everything built.

## Running the benchmarks

```
cd SLH/rust_verus
make bench
```

builds the benchmark program `examples/bench.rs` once for each build
variant, runs each one, and prints a summary of the median CPU cycles for
`slh_keygen`, `slh_sign` and `slh_verify`, in the same format as the SPARK
benchmarks. The summary is also written to `bench/summary.txt`.

The variants are every combination of the release profile's `opt-level`
(0, 1, 2, 3, s and z; set `BENCH_OPT_LEVELS` to change them) and
`overflow-checks` (on and off; `BENCH_OVERFLOW_CHECKS`). Verus proves that
no arithmetic overflows, so the overflow checks never fail. Rust's array
bounds checks can't be turned off in safe Rust, so they are in every
variant. The `sha3` crate is always built at `opt-level` 3 without
overflow checks, so only this crate differs between variants.

Each operation is run once to warm up, then timed 10 times for keygen and
sign and 50 times for verify. Set `BENCH_ITER` to change these, for
example `make bench BENCH_ITER="3 3 20"`. Every signature is checked with
`slh_verify` outside the timed region.

The cycle counter is the one from mlkem-native, in `SLH/hal` (see
`SLH/hal/README.md`). `build.rs` compiles it with the system C compiler
when the `bench` feature is on. On macOS it uses Apple's private `kperf`
framework, which only works as root, so `make bench` runs each benchmark
with `sudo`, which may ask for your password. On Linux it uses
`perf_event_open`, and needs `/proc/sys/kernel/perf_event_paranoid` to be
2 or less. If the counter doesn't work, the benchmark stops with an error
instead of reporting results.

The benchmark program calls the C cycle counter through Rust's foreign
function interface, which needs `unsafe`. This is the only `unsafe` code
in the crate, and it is not part of the library.

## Limitations

* **Preconditions are only checked by Verus.** The signing functions
  require `ctx.len() <= 255`. This is a Verus `requires` clause, which is
  only enforced when the caller is verified with Verus too. An unverified
  Rust caller that passes a longer context string gets a signature of the
  wrong M' (the length byte wraps around), not an error. Check the length
  before calling.

* **No round-trip or correctness theorems yet.** The specifications say
  what each function computes, following FIPS 205, but there is no proof
  yet that verification accepts a valid signature. The SPARK version has
  these proofs. The tests check it here.

* **The specifications of `base_2b` are specialized.** FIPS 205 Algorithm
  4 is not implemented as written. For WOTS+ (b = 4), the specification and
  code take the 4-bit nibbles of each byte directly. For FORS (b = 14),
  `spec_fors_index` gives each output as bits 14i to 14i + 13 of md,
  computed from the three bytes that contain them. These are the values
  Algorithm 4 computes, but that is checked by the tests, not proved.

* **The hash functions are trusted.** The proofs treat SHAKE256 and
  SHA3-512 as uninterpreted functions, and trust the `sha3` crate to
  compute them. They say nothing about the security of SLH-DSA.

* **`sha3` is pinned to 0.11.0.** Version 0.12 moved SHAKE256 into a
  separate `shake` crate, which isn't an allowed dependency here.

* **Stack use.** The library doesn't allocate, so large values live on the
  stack. A signature is 29,792 bytes, and signing and verifying also hold
  the FORS and hypertree signatures in structured form. Verus doesn't
  prove the absence of stack overflow. The default stack of the main
  thread is enough. Threads with small stacks may not be.

* **No SHA-2.** The pre-hash functions are SHA3-512 and SHAKE256 only, and
  only the SHAKE parameter set SLH-DSA-SHAKE-256s is implemented.
