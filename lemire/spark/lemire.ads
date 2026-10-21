--  Ghost code, postconditions and assertions are for proof only. In
--  particular the postcondition quantifies over all 2**64 draws, so it
--  must not be executed. Preconditions remain checked at run time.
pragma Assertion_Policy (Ghost => Ignore, Post => Ignore, Assert => Ignore);

with Interfaces; use Interfaces;
with SPARK.Big_Integers; use SPARK.Big_Integers;
with RNG;
package LeMire
  with SPARK_Mode => On
is
   subtype U64 is Interfaces.Unsigned_64;

   ---------------------------------------------------------------------
   --  Ghost model of one draw of Lemire's algorithm
   --
   --  All of this is in mathematical integers (Big_Integer), so it is
   --  free of modular-arithmetic subtleties. For a bound N and a single
   --  64-bit draw X:
   --
   --    Output (X, N)      = (X * N) / 2**64       the result if accepted
   --    Low (X, N)         = (X * N) mod 2**64     the truncated product
   --    Threshold (N)      = 2**64 mod N           the number of excess draws
   --    Is_Accepted (X, N) = Low (X, N) >= Threshold (N)
   --    Per_Value (N)      = 2**64 / N
   --
   --  Fairness theorem (Lemma_Encode and Lemma_Decode below):
   --  the accepted draws are in one-to-one correspondence with the
   --  pairs (R, J) where 0 <= R < N and 0 <= J < Per_Value (N), and the
   --  accepted draw corresponding to (R, J) has Output = R. So every
   --  value R in 0 .. N - 1 is the output of exactly Per_Value (N)
   --  accepted draws.
   --
   --  Random_N draws X uniformly and independently until it gets an
   --  accepted draw (its rejection tests are proved to be exactly
   --  "not Is_Accepted"), then returns Output of that draw (its
   --  postcondition). The returned draw is therefore uniform over the
   --  N * Per_Value (N) accepted draws, and each R in 0 .. N - 1 is
   --  returned with probability Per_Value (N) / (N * Per_Value (N)),
   --  which is 1 / N.
   --
   --  The step from counting to probability, and the assumption that
   --  RNG.Random_U64 is uniform and independent, are outside what
   --  SPARK can express. They are stated here, not proved.
   ---------------------------------------------------------------------

   package U64_Conv is new
     SPARK.Big_Integers.Unsigned_Conversions (U64);

   function Big (X : U64) return Big_Integer is
     (U64_Conv.To_Big_Integer (X))
     with Ghost;

   Two_64 : constant Big_Integer := 18_446_744_073_709_551_616
     with Ghost;

   function Is_Bound (N : Big_Integer) return Boolean is
     (N > 0 and N < Two_64)
     with Ghost;

   function Is_Draw (X : Big_Integer) return Boolean is
     (X >= 0 and X < Two_64)
     with Ghost;

   function Output (X, N : Big_Integer) return Big_Integer is
     ((X * N) / Two_64)
     with Ghost;

   function Low (X, N : Big_Integer) return Big_Integer is
     ((X * N) mod Two_64)
     with Ghost;

   function Threshold (N : Big_Integer) return Big_Integer is
     (Two_64 mod N)
     with Ghost, Pre => N > 0;

   function Is_Accepted (X, N : Big_Integer) return Boolean is
     (N > 0 and then Low (X, N) >= Threshold (N))
     with Ghost;

   function Per_Value (N : Big_Integer) return Big_Integer is
     (Two_64 / N)
     with Ghost, Pre => N > 0;

   --  The smallest accepted draw whose output is R:
   --  ceiling ((R * 2**64 + Threshold (N)) / N)
   function First (R, N : Big_Integer) return Big_Integer is
     ((R * Two_64 + Threshold (N) + N - 1) / N)
     with Ghost, Pre => N > 0;

   --  Position of draw X among the accepted draws with the same output
   function Index (X, N : Big_Integer) return Big_Integer is
     (X - First (Output (X, N), N))
     with Ghost, Pre => N > 0;

   --  The J-th accepted draw whose output is R
   function Decode (R, J, N : Big_Integer) return Big_Integer is
     (First (R, N) + J)
     with Ghost, Pre => N > 0;

   --  Every accepted draw maps to a pair (R, J) in range, and back
   procedure Lemma_Encode (X, N : Big_Integer)
     with Ghost,
          Global => null,
          Pre    => Is_Bound (N) and then Is_Draw (X)
                      and then Is_Accepted (X, N),
          Post   => Output (X, N) >= 0 and then Output (X, N) < N
                      and then Index (X, N) >= 0
                      and then Index (X, N) < Per_Value (N)
                      and then Decode (Output (X, N), Index (X, N), N) = X;

   --  Every pair (R, J) in range maps to an accepted draw with output R,
   --  and back
   procedure Lemma_Decode (R, J, N : Big_Integer)
     with Ghost,
          Global => null,
          Pre    => Is_Bound (N)
                      and then R >= 0 and then R < N
                      and then J >= 0 and then J < Per_Value (N),
          Post   => Is_Draw (Decode (R, J, N))
                      and then Is_Accepted (Decode (R, J, N), N)
                      and then Output (Decode (R, J, N), N) = R
                      and then Index (Decode (R, J, N), N) = J;

   --  Result is the output of some accepted draw. This quantifies over
   --  all 2**64 draws, so it is for proof only and must never be
   --  executed (see the Assertion_Policy at the top of this file).
   function Is_Model_Output (Bound, Result : U64) return Boolean is
     (for some X in U64 =>
        Is_Accepted (Big (X), Big (Bound))
          and then Output (Big (X), Big (Bound)) = Big (Result))
     with Ghost;

   function Random_N (Bound : in U64) return U64
     with Global => RNG.Entropy,
          Volatile_Function,
          Pre  => Bound > 0,
          Post => Random_N'Result < Bound
                    and then Is_Model_Output (Bound, Random_N'Result);

end LeMire;
