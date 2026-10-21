--  Ghost code, postconditions and assertions are for proof only. In
--  particular the postcondition quantifies over all 2**64 draws, so it
--  must not be executed. Preconditions remain checked at run time.
pragma Assertion_Policy (Ghost => Ignore, Post => Ignore, Assert => Ignore);

package body LeMire
  with SPARK_Mode => On
is
   use RNG;

   package U128BI is new
     SPARK.Big_Integers.Unsigned_Conversions (Unsigned_128);

   subtype U128 is Unsigned_128;

   C2_64 : constant := U64'Modulus;

   ---------------------------------------------------------------------
   --  Arithmetic helper lemmas
   ---------------------------------------------------------------------

   procedure Lemma_Mul_Le (A, B, C : Big_Integer)
     with Ghost,
          Global => null,
          Pre    => A <= B and C >= 0,
          Post   => A * C <= B * C;

   procedure Lemma_Mul_Le (A, B, C : Big_Integer) is null;

   procedure Lemma_Mul_Lt (A, B, C : Big_Integer)
     with Ghost,
          Global => null,
          Pre    => A < B and C > 0,
          Post   => A * C < B * C;

   procedure Lemma_Mul_Lt (A, B, C : Big_Integer) is null;

   --  Cancel a positive factor from both sides of a strict inequality
   procedure Lemma_Mul_Lt_Cancel (A, B, C : Big_Integer)
     with Ghost,
          Global => null,
          Pre    => C > 0 and A * C < B * C,
          Post   => A < B;

   procedure Lemma_Mul_Lt_Cancel (A, B, C : Big_Integer) is
   begin
      if B <= A then
         Lemma_Mul_Le (B, A, C);
      end if;
   end Lemma_Mul_Lt_Cancel;

   --  If Q * D <= A < Q * D + D then Q is the quotient of A by D
   procedure Lemma_Div (A, D, Q : Big_Integer)
     with Ghost,
          Global => null,
          Pre    => D > 0 and Q >= 0 and Q * D <= A and A < Q * D + D,
          Post   => A / D = Q and A mod D = A - Q * D;

   procedure Lemma_Div (A, D, Q : Big_Integer) is
      Q2 : constant Big_Integer := A / D;
      R2 : constant Big_Integer := A mod D;
   begin
      pragma Assert (A >= 0);
      pragma Assert (A = Q2 * D + R2);
      pragma Assert (R2 >= 0 and R2 < D);
      if Q2 < Q then
         Lemma_Mul_Le (Q2 + 1, Q, D);
      elsif Q < Q2 then
         Lemma_Mul_Le (Q + 1, Q2, D);
      end if;
   end Lemma_Div;

   --  2**64 = Per_Value (N) * N + Threshold (N)
   procedure Lemma_Split (N : Big_Integer)
     with Ghost,
          Global => null,
          Pre    => Is_Bound (N),
          Post   => Two_64 = Per_Value (N) * N + Threshold (N)
                      and Threshold (N) >= 0 and Threshold (N) < N
                      and Per_Value (N) >= 1;

   procedure Lemma_Split (N : Big_Integer) is
   begin
      pragma Assert (Two_64 = Per_Value (N) * N + Threshold (N));
      pragma Assert (Threshold (N) >= 0 and Threshold (N) < N);
      if Per_Value (N) < 1 then
         pragma Assert (Per_Value (N) = 0);
      end if;
   end Lemma_Split;

   --  First (R, N) * N is the smallest multiple of N that is
   --  >= R * 2**64 + Threshold (N)
   procedure Lemma_First (R, N : Big_Integer)
     with Ghost,
          Global => null,
          Pre    => Is_Bound (N) and R >= 0,
          Post   => First (R, N) >= 0
                      and First (R, N) * N >= R * Two_64 + Threshold (N)
                      and First (R, N) * N < R * Two_64 + Threshold (N) + N;

   procedure Lemma_First (R, N : Big_Integer) is
      A : constant Big_Integer := R * Two_64 + Threshold (N) + N - 1;
   begin
      Lemma_Split (N);
      Lemma_Mul_Le (0, R, Two_64);
      pragma Assert (A >= 0);
      pragma Assert (A = (A / N) * N + A mod N);
      pragma Assert (A mod N >= 0 and A mod N < N);
   end Lemma_First;

   ---------------------------------------------------------------------
   --  Fairness theorem
   ---------------------------------------------------------------------

   procedure Lemma_Encode (X, N : Big_Integer) is
      P : constant Big_Integer := X * N;
      R : constant Big_Integer := Output (X, N);
      C : constant Big_Integer := First (R, N);
      K : constant Big_Integer := Per_Value (N);
      T : constant Big_Integer := Threshold (N);
   begin
      Lemma_Split (N);

      --  P = R * 2**64 + Low, with T <= Low < 2**64
      Lemma_Mul_Le (0, X, N);
      pragma Assert (P = R * Two_64 + Low (X, N));
      pragma Assert (Low (X, N) >= T and Low (X, N) < Two_64);
      pragma Assert (R >= 0);

      --  R < N, because R * 2**64 <= P < 2**64 * N
      Lemma_Mul_Le (0, R, Two_64);
      Lemma_Mul_Lt (X, Two_64, N);
      Lemma_Mul_Lt_Cancel (R, N, Two_64);

      --  C <= X, because (C - 1) * N < R * 2**64 + T <= P = X * N
      Lemma_First (R, N);
      Lemma_Mul_Lt_Cancel (C - 1, X, N);

      --  X < C + K, because X * N < (R + 1) * 2**64 = R * 2**64 + K * N + T
      --  <= C * N + K * N
      pragma Assert (P < R * Two_64 + K * N + T);
      Lemma_Mul_Lt_Cancel (X, C + K, N);
   end Lemma_Encode;

   procedure Lemma_Decode (R, J, N : Big_Integer) is
      T : constant Big_Integer := Threshold (N);
      K : constant Big_Integer := Per_Value (N);
      C : constant Big_Integer := First (R, N);
      X : constant Big_Integer := C + J;
      P : constant Big_Integer := X * N;
   begin
      Lemma_Split (N);
      Lemma_First (R, N);

      --  R * 2**64 + T <= P < R * 2**64 + T + K * N = (R + 1) * 2**64
      Lemma_Mul_Le (0, J, N);
      Lemma_Mul_Le (J, K - 1, N);
      pragma Assert (P = C * N + J * N);
      pragma Assert (P >= R * Two_64 + T);
      pragma Assert (P < R * Two_64 + T + K * N);
      pragma Assert (P < R * Two_64 + Two_64);

      --  So Output (X, N) = R and Low (X, N) = P - R * 2**64 >= T
      Lemma_Mul_Le (0, R, Two_64);
      Lemma_Div (P, Two_64, R);
      pragma Assert (Output (X, N) = R);
      pragma Assert (Low (X, N) >= T);

      --  X < 2**64, because X * N < (R + 1) * 2**64 <= N * 2**64
      Lemma_Mul_Le (R + 1, N, Two_64);
      Lemma_Mul_Lt_Cancel (X, Two_64, N);
   end Lemma_Decode;

   ---------------------------------------------------------------------
   --  Link between the machine arithmetic and the model
   ---------------------------------------------------------------------

   --  M = X * N does not wrap around in Unsigned_128, so truncating M to
   --  its low 64 bits gives Low and shifting out the low 64 bits gives
   --  Output.
   procedure Lemma_Draw (X, N : U64; M : U128)
     with Ghost,
          Global => null,
          Pre    => N > 0 and M = U128 (X) * U128 (N),
          Post   => U128BI.To_Big_Integer (M) = Big (X) * Big (N)
                      and Big (U64 (M mod C2_64)) = Low (Big (X), Big (N))
                      and Big (U64 (M / C2_64)) =
                            Output (Big (X), Big (N));

   procedure Lemma_Draw (X, N : U64; M : U128) is
      BX : constant Big_Integer := Big (X);
      BN : constant Big_Integer := Big (N);
   begin
      Lemma_Mul_Le (BX, Two_64 - 1, BN);
      Lemma_Mul_Le (BN, Two_64 - 1, Two_64 - 1);
      pragma Assert (BX * BN < Two_64 * Two_64);
      pragma Assert (U128BI.To_Big_Integer (M) = BX * BN);
   end Lemma_Draw;

   --  The machine computation of T is 2**64 mod N
   procedure Lemma_Threshold (N, T : U64)
     with Ghost,
          Global => null,
          Pre    => N > 0 and then T = (-N) mod N,
          Post   => Big (T) = Threshold (Big (N));

   procedure Lemma_Threshold (N, T : U64) is
      BN : constant Big_Integer := Big (N);
   begin
      Lemma_Split (BN);
      pragma Assert (Big (-N) = Two_64 - BN);
      --  2**64 - N = (K - 1) * N + Threshold (N)
      Lemma_Mul_Le (0, Per_Value (BN) - 1, BN);
      Lemma_Div (Two_64 - BN, BN, Per_Value (BN) - 1);
   end Lemma_Threshold;

   ---------------------------------------------------------------------
   --  The algorithm
   ---------------------------------------------------------------------

   function Random_N (Bound : in U64) return U64 is
      B128 : constant U128 := U128 (Bound);
      BN   : constant Big_Integer := Big (Bound) with Ghost;

      X       : U64 := Random_U64;
      L, T, R : U64;
      M       : U128;
   begin
      pragma Assert (Is_Bound (BN));

      M := U128 (X) * B128;
      Lemma_Draw (X, Bound, M);

      --  Explicit modular reduction mod 2**64 and type conversion
      --  is equivalent to simple truncation of the upper 64 bits
      L := U64 (M mod C2_64);

      if L < Bound then
         T := (-Bound) mod Bound;
         Lemma_Threshold (Bound, T);

         while L < T loop
            pragma Loop_Invariant
              (M = U128 (X) * B128 and then L = U64 (M mod C2_64));
            Lemma_Draw (X, Bound, M);

            --  Each rejected draw is exactly one the model rejects
            pragma Assert (Big (L) < Threshold (BN));
            pragma Assert (not Is_Accepted (Big (X), BN));

            X := Random_U64;
            M := U128 (X) * B128;
            L := U64 (M mod C2_64);
         end loop;
         pragma Annotate
           (GNATprove, Intentional,
            "loop might be nonterminating",
            "Rejection sampling: each iteration exits with probability " &
            "at least 1/2 for a uniform Random_U64, so the loop " &
            "terminates with probability 1, but no iteration bound exists.");

         Lemma_Draw (X, Bound, M);
         pragma Assert (Big (L) >= Threshold (BN));
      else
         --  L >= Bound > Threshold, so the draw is accepted without
         --  computing T
         Lemma_Split (BN);
         pragma Assert (Big (L) >= BN);
         pragma Assert (Big (L) >= Threshold (BN));
      end if;

      --  The draw being used is exactly one the model accepts
      pragma Assert (Big (L) = Low (Big (X), BN));
      pragma Assert (Is_Accepted (Big (X), BN));

      R := U64 (M / C2_64);
      pragma Assert (Big (R) = Output (Big (X), BN));

      Lemma_Encode (Big (X), BN);
      pragma Assert (Big (R) < BN);
      pragma Assert (R < Bound);
      return R;
   end Random_N;

end LeMire;
