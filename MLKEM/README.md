# LibMLKEM - A new, formal reference implementation of FIPS 203 ML-KEM

This library presents a new reference implementation of
FIPS 203 ML-KEM (the algorithm formerly known as Kyber),
as specified in the 13th August 2024 issue of FIPS 203.

## Important warning

These implementations are absolutely NOT intended for production or any use
in a "high assurance" setting. In particular:

* While the code may be written in a "constant time" style, this property is not formally verified at
the level of the generated code and micro-architecture, and is not guranteed to be preserved by all compilers.

* Secondly, intermediate values are not sanitized at present, as required by FIPS 203 3.3

* Finally, performance is unlikely to be competetive with other, more optimized, implementations.

# Languages and tools

At this point, the first implementation is in the SPARK Ada subset -
a subset of Ada that is amenable to formal verification with the
SPARK Pro toolset. The SPARK implementation meets all of the
verification goals stated above, ands also provides static verification
of worst-case stack usage, and structural coverage analysis of the KATs.

See the README file in the `spark_ada` subdirectory for more
information.

Some efforts to reproduce the verification of the ML-KEM NTT in Rust
lie in the `rust/verus` subdirectory.
