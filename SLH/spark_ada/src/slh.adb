--  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
--  SPDX-License-Identifier: Apache-2.0

with SHA3;  use SHA3;
with SHAKE; use SHAKE;

package body SLH
  with SPARK_Mode => On
is
   --==============================================================================
   --  Notation, Naming and Operators
   --==============================================================================
   --
   --  This section lays out a few notational conventions for readers
   --  that might not be familiar with Ada or SPARK, and notes a few
   --  important differences between the notation used in FIPS 205 and
   --  that appearing here.
   --
   --  Assignment and Equality
   --  -----------------------
   --
   --  As in Pascal, SPARK uses ":=" for assignment and "=" for equality.
   --  The latter is predefined for most types, and always returns the predefined
   --  Boolean type. The "not equals" operator is denoted "/="
   --
   --  Concatenation
   --  -------------
   --
   --  FIPS 205 uses "||" for concatenation of sequences and/or arrays.
   --  In SPARK, all one-dimensional arrays have a predefined concatentation
   --  index operator, denoted "&".
   --
   --  Ranges and Array Slices
   --  -----------------------
   --
   --  Ranges of integers in SPARK (denoted "X .. Y") are _inclusive_
   --  at both ends. Similarly a "slice" of an array object, denoted
   --  A (X .. Y), is all the elements of A from the X'th to the Y'th
   --  element inclusive.
   --
   --  Naming
   --  ------
   --
   --  Where FIPS 205 uses accented characters such as the UNICODE code-point
   --  "Latin Capital A with Circumflex", this code uses a suffix on a simple
   --  name (e.g. "A_Hat" in this case) and sticks to the simple Latin_1 subset
   --  of the character set. Other than that, the code maintains the names of all
   --  types and variables from FIPS 205.
   --==============================================================================

   --=======================================
   --  Local packages and subprograms
   --=======================================

   --  The specification of package Hash is in the private part of slh.ads

   package body Hash
   is
      --  PRF_Msg (SK.prf, opt_rand, M) = SHAKE256 (SK.prf || opt_rand || M, 8n)
      function PRF_Msg (SK_Prf : in Bytes_N; Opt_Rand : in Bytes_N; M : in Byte_Seq) return Bytes_N
      is
         C      : SHAKE256.Context;
         Result : Bytes_N;
      begin
         SHAKE256.Init (C);
         SHAKE256.Update (C, SHAKE256.Byte_Array (SK_Prf));
         SHAKE256.Update (C, SHAKE256.Byte_Array (Opt_Rand));
         SHAKE256.Update (C, SHAKE256.Byte_Array (M));
         SHAKE256.Extract (C, SHAKE256.Byte_Array (Result));
         pragma  Unreferenced (C);
         return Result;
      end PRF_Msg;

      --  H_Msg (R, PK.seed, PK.root, M) = SHAKE256 (R || PK.seed || PK.root || M, 8m)
      function H_Msg (R : in Bytes_N; PK_Seed : in Bytes_N; PK_Root : in Bytes_N; M : in Byte_Seq) return Bytes_M
      is
         C      : SHAKE256.Context;
         Result : Bytes_M;
      begin
         SHAKE256.Init (C);
         SHAKE256.Update (C, SHAKE256.Byte_Array (R));
         SHAKE256.Update (C, SHAKE256.Byte_Array (PK_Seed));
         SHAKE256.Update (C, SHAKE256.Byte_Array (PK_Root));
         SHAKE256.Update (C, SHAKE256.Byte_Array (M));
         SHAKE256.Extract (C, SHAKE256.Byte_Array (Result));
         pragma  Unreferenced (C);
         return Result;
      end H_Msg;

      --  PRF (PK.seed, SK.seed, ADRS) = SHAKE256 (PK.seed || ADRS || SK.seed, 8n)
      --
      --  Note that SK.seed is hashed _after_ ADRS, even though it is
      --  the second parameter.
      function PRF (PK_Seed : in Bytes_N; SK_Seed : in Bytes_N; ADRS : in ADRS_Bytes) return Bytes_N
      is
         C      : SHAKE256.Context;
         Result : Bytes_N;
      begin
         SHAKE256.Init (C);
         SHAKE256.Update (C, SHAKE256.Byte_Array (PK_Seed));
         SHAKE256.Update (C, SHAKE256.Byte_Array (ADRS));
         SHAKE256.Update (C, SHAKE256.Byte_Array (SK_Seed));
         SHAKE256.Extract (C, SHAKE256.Byte_Array (Result));
         pragma  Unreferenced (C);
         return Result;
      end PRF;

      --  T_L (PK.seed, ADRS, M_L) = SHAKE256 (PK.seed || ADRS || M_L, 8n)
      function T_L (PK_Seed : in Bytes_N; ADRS : in ADRS_Bytes; M_L : in Byte_Seq) return Bytes_N
      is
         C      : SHAKE256.Context;
         Result : Bytes_N;
      begin
         SHAKE256.Init (C);
         SHAKE256.Update (C, SHAKE256.Byte_Array (PK_Seed));
         SHAKE256.Update (C, SHAKE256.Byte_Array (ADRS));
         SHAKE256.Update (C, SHAKE256.Byte_Array (M_L));
         SHAKE256.Extract (C, SHAKE256.Byte_Array (Result));
         pragma  Unreferenced (C);
         return Result;
      end T_L;

      --  H (PK.seed, ADRS, M2) = SHAKE256 (PK.seed || ADRS || M2, 8n)
      function H (PK_Seed : in Bytes_N; ADRS : in ADRS_Bytes; M2 : in Bytes_2N) return Bytes_N
      is
         C      : SHAKE256.Context;
         Result : Bytes_N;
      begin
         SHAKE256.Init (C);
         SHAKE256.Update (C, SHAKE256.Byte_Array (PK_Seed));
         SHAKE256.Update (C, SHAKE256.Byte_Array (ADRS));
         SHAKE256.Update (C, SHAKE256.Byte_Array (M2));
         SHAKE256.Extract (C, SHAKE256.Byte_Array (Result));
         pragma  Unreferenced (C);
         return Result;
      end H;

      --  F (PK.seed, ADRS, M1) = SHAKE256 (PK.seed || ADRS || M1, 8n)
      function F (PK_Seed : in Bytes_N; ADRS : in ADRS_Bytes; M1 : in Bytes_N) return Bytes_N
      is
         C      : SHAKE256.Context;
         Result : Bytes_N;
      begin
         SHAKE256.Init (C);
         SHAKE256.Update (C, SHAKE256.Byte_Array (PK_Seed));
         SHAKE256.Update (C, SHAKE256.Byte_Array (ADRS));
         SHAKE256.Update (C, SHAKE256.Byte_Array (M1));
         SHAKE256.Extract (C, SHAKE256.Byte_Array (Result));
         pragma  Unreferenced (C);
         return Result;
      end F;

      function Pre_Hash (PH : in Pre_Hash_Function; Msg : in Byte_Seq) return Bytes_64
      is
         Result : Bytes_64;
      begin
         case PH is
            when PH_SHA3_512 =>
               --  PH_M <- SHA3-512 (M)
               declare
                  C : SHA3_512.Context;
                  D : SHA3_512.Digest_Type;
               begin
                  SHA3_512.Init (C);
                  SHA3_512.Update (C, SHA3_512.Byte_Array (Msg));
                  SHA3_512.Final (C, D);
                  pragma Unreferenced (C);
                  Result := Bytes_64 (D);
               end;
            when PH_SHAKE256 =>
               --  PH_M <- SHAKE256 (M, 512)
               declare
                  C : SHAKE256.Context;
               begin
                  SHAKE256.Init (C);
                  SHAKE256.Update (C, SHAKE256.Byte_Array (Msg));
                  SHAKE256.Extract (C, SHAKE256.Byte_Array (Result));
                  pragma Unreferenced (C);
               end;
         end case;
         return Result;
      end Pre_Hash;

   end Hash;

   --  The specification of package ADRS is in the private part of slh.ads

   package body ADRS
   is
      --  Sets word W of A to toByte (V, 4), leaving all other bytes unchanged.
      --  All the setters below are implemented with this procedure.
      procedure Set_Word (A : in out ADRS_Bytes; W : in Word_Index; V : in U32)
        with Global => null,
             Post   => Word (A, W) = V and
                       (for all I in Index_32 =>
                          (if I / 4 /= W then A (I) = A'Old (I)));

      procedure Set_Word (A : in out ADRS_Bytes; W : in Word_Index; V : in U32)
      is
      begin
         A (4 * W)     := Byte (Shift_Right (V, 24));
         A (4 * W + 1) := Byte (Shift_Right (V, 16) and 16#FF#);
         A (4 * W + 2) := Byte (Shift_Right (V, 8) and 16#FF#);
         A (4 * W + 3) := Byte (V and 16#FF#);
      end Set_Word;

      procedure Set_Layer_Address (A : in out ADRS_Bytes; L : in U32)
      is
      begin
         Set_Word (A, 0, L);
      end Set_Layer_Address;

      procedure Set_Tree_Address (A : in out ADRS_Bytes; T : in U64)
      is
      begin
         Set_Word (A, 1, 0);
         Set_Word (A, 2, U32 (Shift_Right (T, 32)));
         Set_Word (A, 3, U32 (T and 16#FFFF_FFFF#));
      end Set_Tree_Address;

      procedure Set_Type_And_Clear (A : in out ADRS_Bytes; Y : in ADRS_Type)
      is
      begin
         Set_Word (A, 4, ADRS_Type'Pos (Y));
         A (20 .. 31) := (others => 0);
      end Set_Type_And_Clear;

      procedure Set_Key_Pair_Address (A : in out ADRS_Bytes; I : in U32)
      is
      begin
         Set_Word (A, 5, I);
      end Set_Key_Pair_Address;

      procedure Set_Chain_Address (A : in out ADRS_Bytes; I : in U32)
      is
      begin
         Set_Word (A, 6, I);
      end Set_Chain_Address;

      procedure Set_Tree_Height (A : in out ADRS_Bytes; I : in U32)
      is
      begin
         Set_Word (A, 6, I);
      end Set_Tree_Height;

      procedure Set_Hash_Address (A : in out ADRS_Bytes; I : in U32)
      is
      begin
         Set_Word (A, 7, I);
      end Set_Hash_Address;

      procedure Set_Tree_Index (A : in out ADRS_Bytes; I : in U32)
      is
      begin
         Set_Word (A, 7, I);
      end Set_Tree_Index;

   end ADRS;

   --  The specification of package Conversions is in the private part of slh.ads

   package body Conversions
   is
      function To_Int (X : in Byte_Seq) return U64
      is
         Total : U64 := 0;
      begin
         for I in X'Range loop
            Total := 256 * Total + U64 (X (I));
            pragma Loop_Invariant
              (for all J in X'First .. I =>
                 Byte_Of (Total, Natural (I - J)) = X (J));
            pragma Loop_Invariant
              (if I - X'First < 7 then
                 Shift_Right (Total, 8 * Natural (I - X'First + 1)) = 0);
         end loop;
         return Total;
      end To_Int;

      procedure To_Byte (X : in U64; S : out Byte_Seq)
      is
         Total : U64     := X;
         K     : Natural := 0; --  i in Algorithm 3
      begin
         S := (others => 0);
         --  Algorithm 3 sets S[n - 1 - i] for i in 0 .. n - 1.
         --  Here, I = S'Last - K, so I runs from S'Last down to S'First
         for I in reverse S'Range loop
            pragma Loop_Invariant (K = Natural (S'Last - I));
            pragma Loop_Invariant
              (Total = (if K < 8 then Shift_Right (X, 8 * K) else 0));
            pragma Loop_Invariant
              (for all J in I + 1 .. S'Last =>
                 S (J) = Byte_Of (X, Natural (S'Last - J)));

            --  Total mod 256, the least significant 8 bits of Total
            S (I) := Byte (Total and 16#FF#);
            pragma Assert (S (I) = Byte_Of (X, K));

            Total := Shift_Right (Total, 8);
            K := K + 1;
         end loop;
      end To_Byte;

      ------------------------------------------------------
      --  Lemmas for the proof of Base_2b
      --
      --  These are ghost procedures. Their postconditions are
      --  proved once, here, and then assumed at each call.
      --  Most have a null body, so the provers prove the
      --  postcondition from the precondition alone. The two
      --  "_Holds" lemmas have ghost loops that step the provers
      --  through one bit at a time.
      ------------------------------------------------------

      --  Multiplication by a non-negative B is monotonic
      procedure Lemma_Mul_Le (P, Q : in N32; B : in Base_2b_Bits)
        with Ghost,
             Global => null,
             Pre    => P <= Q and Q <= 2**16,
             Post   => P * I32 (B) <= Q * I32 (B);

      procedure Lemma_Mul_Le (P, Q : in N32; B : in Base_2b_Bits)
      is null;

      --  Line 6 of Algorithm 4, Total <- (Total << 8) + V, appends the
      --  8 bits of V below the least significant Bits bits of Total
      procedure Lemma_Append (T : in U32; V : in Byte; Bits : in N32)
        with Ghost,
             Global => null,
             Pre    => Bits <= 23,
             Post   =>
               (for all K in 0 .. Bits + 7 =>
                  (Shift_Right (Shift_Left (T, 8) + U32 (V), Natural (Bits + 7 - K)) and 1) =
                    (if K < Bits
                     then Shift_Right (T, Natural (Bits - 1 - K)) and 1
                     else U32 (Shift_Right (V, Natural (7 - (K - Bits))) and 1)));

      procedure Lemma_Append (T : in U32; V : in Byte; Bits : in N32)
      is null;

      --  Line 11 of Algorithm 4, (Total >> Bits) mod 2**B, where Bits is
      --  the value after line 10, extracts the B bits of Total that
      --  precede the least significant Bits bits.
      procedure Lemma_Extract (T : in U32; Bits : in N32; B : in Base_2b_Bits)
        with Ghost,
             Global => null,
             Pre    => Bits <= 7,
             Post   =>
               Shift_Right (Shift_Right (T, Natural (Bits)) and (Shift_Left (1, B) - 1), B) = 0 and
               (for all J in 0 .. B - 1 =>
                  (Shift_Right (Shift_Right (T, Natural (Bits)) and (Shift_Left (1, B) - 1), B - 1 - J) and 1) =
                    (Shift_Right (T, Natural (Bits) + B - 1 - J) and 1));

      procedure Lemma_Extract (T : in U32; Bits : in N32; B : in Base_2b_Bits)
      is null;

      --  True if the least significant Bits bits of Total are
      --  bits Start .. Start + Bits - 1 of X
      function Holds (X : in Byte_Seq; Total : in U32; Bits : in N32; Start : in N32) return Boolean
      is (for all K in 0 .. Bits - 1 =>
            (Shift_Right (Total, Natural (Bits - 1 - K)) and 1) = Bit (X, Start + K))
        with Ghost,
             Global => null,
             Pre    => X'First = 0 and Bits <= 31 and Start <= 2**30;

      --  (P + 1) * B = P * B + B
      procedure Lemma_Mul_Succ (P : in N32; B : in Base_2b_Bits)
        with Ghost,
             Global => null,
             Pre    => P < 2**16,
             Post   => (P + 1) * I32 (B) = P * I32 (B) + I32 (B);

      procedure Lemma_Mul_Succ (P : in N32; B : in Base_2b_Bits)
      is null;

      --  Bits 8 * P .. 8 * P + 7 of X are the bits of byte X (P)
      procedure Lemma_Byte_Bits (X : in Byte_Seq; P : in N32)
        with Ghost,
             Global => null,
             Pre    => X'First = 0 and X'Last < 2**24 and P <= X'Last,
             Post   => (for all J in N32 range 0 .. 7 =>
                          Bit (X, 8 * P + J) =
                            U32 (Shift_Right (X (P), 7 - Natural (J)) and 1));

      procedure Lemma_Byte_Bits (X : in Byte_Seq; P : in N32)
      is null;

      --  Lines 6 to 8 of Algorithm 4 preserve Holds: after appending
      --  byte X (P) to Total, Total holds 8 more bits of X
      procedure Lemma_Append_Holds (X     : in Byte_Seq;
                                    T     : in U32;
                                    Bits  : in N32;
                                    Start : in N32;
                                    P     : in N32)
        with Ghost,
             Global => null,
             Pre    => X'First = 0 and then
                       X'Last < 2**24 and then
                       Bits <= 23 and then
                       P <= X'Last and then
                       Start <= 2**29 and then
                       Start + Bits = 8 * P and then
                       Holds (X, T, Bits, Start),
             Post   => Holds (X, Shift_Left (T, 8) + U32 (X (P)), Bits + 8, Start);

      procedure Lemma_Append_Holds (X     : in Byte_Seq;
                                    T     : in U32;
                                    Bits  : in N32;
                                    Start : in N32;
                                    P     : in N32)
      is
         T2 : constant U32 := Shift_Left (T, 8) + U32 (X (P));
      begin
         Lemma_Append (T, X (P), Bits);
         Lemma_Byte_Bits (X, P);
         for K in N32 range 0 .. Bits + 7 loop
            if K >= Bits then
               pragma Assert (Start + K = 8 * P + (K - Bits));
            end if;
            pragma Assert ((Shift_Right (T2, Natural (Bits + 8 - 1 - K)) and 1) =
                             Bit (X, Start + K));
            pragma Loop_Invariant
              (for all K2 in 0 .. K =>
                 (Shift_Right (T2, Natural (Bits + 8 - 1 - K2)) and 1) =
                   Bit (X, Start + K2));
         end loop;
      end Lemma_Append_Holds;

      --  Lines 10 and 11 of Algorithm 4. If Total holds Bits + B bits
      --  of X, starting at Start, then (Total >> Bits) mod 2**B is bits
      --  Start .. Start + B - 1 of X, and Total still holds the
      --  following Bits bits of X
      procedure Lemma_Extract_Holds (X     : in Byte_Seq;
                                     T     : in U32;
                                     Bits  : in N32;
                                     B     : in Base_2b_Bits;
                                     Start : in N32)
        with Ghost,
             Global => null,
             Pre    => X'First = 0 and then
                       Bits <= 7 and then
                       Start <= 2**29 and then
                       Holds (X, T, Bits + I32 (B), Start),
             Post   =>
               Is_Bits_Of (X, Shift_Right (T, Natural (Bits)) and (Shift_Left (1, B) - 1), B, Start) and then
               Holds (X, T, Bits, Start + I32 (B));

      procedure Lemma_Extract_Holds (X     : in Byte_Seq;
                                     T     : in U32;
                                     Bits  : in N32;
                                     B     : in Base_2b_Bits;
                                     Start : in N32)
      is
         R : constant U32 := Shift_Right (T, Natural (Bits)) and (Shift_Left (1, B) - 1);
      begin
         Lemma_Extract (T, Bits, B);
         for J in 0 .. B - 1 loop
            pragma Assert (Natural (Bits) + B - 1 - J = Natural (Bits + I32 (B) - 1 - I32 (J)));
            pragma Assert ((Shift_Right (R, B - 1 - J) and 1) = Bit (X, Start + I32 (J)));
            pragma Loop_Invariant
              (for all J2 in 0 .. J =>
                 (Shift_Right (R, B - 1 - J2) and 1) = Bit (X, Start + I32 (J2)));
         end loop;
         for K in N32 range 0 .. Bits - 1 loop
            pragma Assert (Bits - 1 - K = Bits + I32 (B) - 1 - (K + I32 (B)));
            pragma Assert ((Shift_Right (T, Natural (Bits + I32 (B) - 1 - (K + I32 (B)))) and 1) =
                             Bit (X, Start + (K + I32 (B))));
            pragma Assert ((Shift_Right (T, Natural (Bits - 1 - K)) and 1) =
                             Bit (X, Start + I32 (B) + K));
            pragma Loop_Invariant
              (for all K2 in 0 .. K =>
                 (Shift_Right (T, Natural (Bits - 1 - K2)) and 1) =
                   Bit (X, Start + I32 (B) + K2));
         end loop;
         pragma Assert (Start + I32 (B) > Start);
      end Lemma_Extract_Holds;

      --  Lines 5 to 9 of Algorithm 4. Reads bytes of X into Total
      --  until Total holds at least B bits that have not been output.
      --  In_Idx * 8 - Bits is the index of the first bit of X that is
      --  held in Total but not yet output. It is unchanged.
      procedure Refill (X      : in     Byte_Seq;
                        B      : in     Base_2b_Bits;
                        Total  : in out U32;
                        In_Idx : in out N32;
                        Bits   : in out N32)
        with Global            => null,
             Always_Terminates => True,
             Pre               => X'First = 0 and then
                                  X'Last < 2**24 and then
                                  Bits < 8 and then
                                  In_Idx <= X'Length and then
                                  In_Idx * 8 >= Bits and then
                                  In_Idx * 8 - Bits + I32 (B) <= 8 * X'Length and then
                                  Holds (X, Total, Bits, In_Idx * 8 - Bits),
             Post              => Bits >= I32 (B) and then
                                  Bits < I32 (B) + 8 and then
                                  In_Idx <= X'Length and then
                                  In_Idx * 8 >= Bits and then
                                  In_Idx * 8 - Bits = In_Idx'Old * 8 - Bits'Old and then
                                  Holds (X, Total, Bits, In_Idx * 8 - Bits);

      procedure Refill (X      : in     Byte_Seq;
                        B      : in     Base_2b_Bits;
                        Total  : in out U32;
                        In_Idx : in out N32;
                        Bits   : in out N32)
      is
         Start : constant N32 := In_Idx * 8 - Bits with Ghost;
      begin
         while Bits < I32 (B) loop
            pragma Loop_Invariant (Bits < I32 (B));
            pragma Loop_Invariant (Start + I32 (B) <= 8 * X'Length);
            pragma Loop_Invariant (In_Idx * 8 = Start + Bits);
            pragma Loop_Invariant (In_Idx * 8 < 8 * X'Length);
            pragma Loop_Invariant (In_Idx < X'Length);
            pragma Loop_Invariant (Holds (X, Total, Bits, Start));
            pragma Loop_Variant (Increases => Bits);

            Lemma_Append_Holds (X, Total, Bits, Start, In_Idx);
            Total  := Shift_Left (Total, 8) + U32 (X (In_Idx));
            In_Idx := In_Idx + 1;
            Bits   := Bits + 8;
         end loop;
      end Refill;

      procedure Base_2b (X : in Byte_Seq; B : in Base_2b_Bits; Base_B : out U32_Seq)
      is
         BI     : constant I32 := I32 (B);
         Mask   : constant U32 := Shift_Left (1, B) - 1; --  for "mod 2**B"
         In_Idx : N32 := 0;
         Bits   : N32 := 0;
         Total  : U32 := 0;

         --  Number of bits of X output so far, so Consumed = Out_Idx * B
         Consumed : N32 := 0 with Ghost;
      begin
         Base_B := (others => 0);
         for Out_Idx in Base_B'Range loop
            --  On entry to each iteration, In_Idx bytes of X have been
            --  read, of which the last Bits bits are not yet output,
            --  and are held in the least significant Bits bits of Total
            pragma Loop_Invariant (Bits < 8);
            pragma Loop_Invariant (Out_Idx < 2**16);
            pragma Loop_Invariant (Consumed = Out_Idx * BI);
            pragma Loop_Invariant (Consumed <= 8 * X'Length);
            pragma Loop_Invariant (In_Idx <= X'Length);
            pragma Loop_Invariant (In_Idx * 8 = Consumed + Bits);
            pragma Loop_Invariant (Holds (X, Total, Bits, Consumed));
            pragma Loop_Invariant
              (for all O in 0 .. Out_Idx - 1 =>
                 Is_Bits_Of (X, Base_B (O), B, O * BI));

            --  This output needs bits Consumed .. Consumed + B - 1,
            --  all of which are in X
            Lemma_Mul_Le (Out_Idx + 1, I32 (Base_B'Length), B);
            Lemma_Mul_Succ (Out_Idx, B);
            pragma Assert (Consumed + BI <= 8 * X'Length);

            Refill (X, B, Total, In_Idx, Bits);

            Bits := Bits - BI;
            Lemma_Extract_Holds (X, Total, Bits, B, Consumed);
            Base_B (Out_Idx) := Shift_Right (Total, Natural (Bits)) and Mask;

            --  Base_B (Out_Idx) is bits Out_Idx * B .. Out_Idx * B + B - 1 of X
            pragma Assert (Is_Bits_Of (X, Base_B (Out_Idx), B, Out_Idx * BI));

            Consumed := Consumed + BI;
         end loop;
      end Base_2b;

   end Conversions;

   --  The specification of package WOTS is in the private part of slh.ads

   package body WOTS
   is
      function Flatten (V : in WOTS_Array) return Bytes_Len_N
      is
         R : Bytes_Len_N := (others => 0);
      begin
         for I in Index_Len loop
            R (I * N .. I * N + N - 1) := V (I);
            pragma Loop_Invariant
              (for all I2 in 0 .. I =>
                 (for all J in Index_N => R (I2 * N + J) = V (I2) (J)));
         end loop;
         return R;
      end Flatten;

      function With_Hash_Address (A : in ADRS_Bytes; J : in U32) return ADRS_Bytes
      is
         R : ADRS_Bytes := A;
      begin
         ADRS.Set_Hash_Address (R, J);
         return R;
      end With_Hash_Address;

      function Chain_ADRS (A : in ADRS_Bytes; I : in Index_Len) return ADRS_Bytes
      is
         R : ADRS_Bytes := A;
      begin
         ADRS.Set_Chain_Address (R, U32 (I));
         return R;
      end Chain_ADRS;

      function SK_ADRS (A : in ADRS_Bytes; I : in Index_Len) return ADRS_Bytes
      is
         SK_A : ADRS_Bytes := A;
      begin
         ADRS.Set_Type_And_Clear (SK_A, ADRS.WOTS_PRF);
         ADRS.Set_Key_Pair_Address (SK_A, ADRS.Get_Key_Pair_Address (A));
         ADRS.Set_Chain_Address (SK_A, U32 (I));
         return SK_A;
      end SK_ADRS;

      function WOTS_PK_ADRS (A : in ADRS_Bytes) return ADRS_Bytes
      is
         WOTS_PK_A : ADRS_Bytes := A;
      begin
         ADRS.Set_Type_And_Clear (WOTS_PK_A, ADRS.WOTS_PK);
         ADRS.Set_Key_Pair_Address (WOTS_PK_A, ADRS.Get_Key_Pair_Address (A));
         return WOTS_PK_A;
      end WOTS_PK_ADRS;

      procedure Lemma_Chain_Spec (X       : in Bytes_N;
                                  I       : in Chain_Index;
                                  S       : in Chain_Index;
                                  PK_Seed : in Bytes_N;
                                  A       : in ADRS_Bytes)
      is
         pragma Annotate (GNATprove, Unhide_Info, "Expression_Function_Body", Chain_Spec);
      begin
         null;
      end Lemma_Chain_Spec;

      --  Logical (rather than Ada) equality of N-byte strings. If
      --  Eq (X, Y), then any function gives the same result for X and Y
      function Eq (X, Y : in Bytes_N) return Boolean
        with Ghost,
             Global   => null,
             Annotate => (GNATprove, Logical_Equal);

      --  GNATprove interprets Eq as logical equality, so this body is
      --  not analyzed. It is only executed when assertions are enabled.
      --  For arrays of bytes with the same bounds, logical equality and
      --  Ada equality are the same.
      function Eq (X, Y : in Bytes_N) return Boolean
        with SPARK_Mode => Off
      is
      begin
         return X = Y;
      end Eq;

      --  Equal N-byte strings are logically equal
      procedure Lemma_Eq (X, Y : in Bytes_N)
        with Ghost,
             Global => null,
             Pre    => X = Y,
             Post   => Eq (X, Y);

      procedure Lemma_Eq (X, Y : in Bytes_N)
      is null;

      function Eq_Len_N (X, Y : in Bytes_Len_N) return Boolean
        with Ghost,
             Global   => null,
             Annotate => (GNATprove, Logical_Equal);

      --  As for Eq above
      function Eq_Len_N (X, Y : in Bytes_Len_N) return Boolean
        with SPARK_Mode => Off
      is
      begin
         return X = Y;
      end Eq_Len_N;

      procedure Lemma_Eq_Len_N (X, Y : in Bytes_Len_N)
        with Ghost,
             Global => null,
             Pre    => X = Y,
             Post   => Eq_Len_N (X, Y);

      procedure Lemma_Eq_Len_N (X, Y : in Bytes_Len_N)
      is null;

      --  Equal arrays of N-byte strings have equal concatenations
      procedure Lemma_Flatten_Eq (X, Y : in WOTS_Array)
        with Ghost,
             Global => null,
             Pre    => (for all I in Index_Len => X (I) = Y (I)),
             Post   => Eq_Len_N (Flatten (X), Flatten (Y));

      procedure Lemma_Flatten_Eq (X, Y : in WOTS_Array)
      is
         FX : constant Bytes_Len_N := Flatten (X);
         FY : constant Bytes_Len_N := Flatten (Y);
      begin
         for K in Index_Len_N loop
            pragma Assert (K = (K / N) * N + K mod N);
            pragma Assert (FX (K) = X (K / N) (K mod N));
            pragma Assert (FY (K) = Y (K / N) (K mod N));
            pragma Loop_Invariant (for all K2 in 0 .. K => FX (K2) = FY (K2));
         end loop;
         Lemma_Eq_Len_N (FX, FY);
      end Lemma_Flatten_Eq;


      --  One step of the chain. If Prev is the value of the chain from
      --  X after K - 1 steps, then F applied to Prev with hash address
      --  I + K - 1 is the value after K steps
      procedure Lemma_Chain_Step (X       : in Bytes_N;
                                  I       : in Chain_Index;
                                  K       : in Chain_Index;
                                  PK_Seed : in Bytes_N;
                                  A       : in ADRS_Bytes;
                                  Prev    : in Bytes_N)
        with Ghost,
             Global => null,
             Pre    => K >= 1 and then
                       I + K <= W - 1 and then
                       Prev = Chain_Spec (X, I, K - 1, PK_Seed, A),
             Post   => Hash.F (PK_Seed, With_Hash_Address (A, U32 (I + K - 1)), Prev) =
                         Chain_Spec (X, I, K, PK_Seed, A);

      procedure Lemma_Chain_Step (X       : in Bytes_N;
                                  I       : in Chain_Index;
                                  K       : in Chain_Index;
                                  PK_Seed : in Bytes_N;
                                  A       : in ADRS_Bytes;
                                  Prev    : in Bytes_N)
      is
      begin
         Lemma_Chain_Spec (X, I, K, PK_Seed, A);
         Lemma_Eq (Prev, Chain_Spec (X, I, K - 1, PK_Seed, A));
      end Lemma_Chain_Step;

      function Chain (X       : in Bytes_N;
                      I       : in Chain_Index;
                      S       : in Chain_Index;
                      PK_Seed : in Bytes_N;
                      A       : in ADRS_Bytes) return Bytes_N
      is
         Tmp      : Bytes_N := X;  --  Line 1
         ADRS_Tmp : ADRS_Bytes;
      begin
         Lemma_Chain_Spec (X, I, 0, PK_Seed, A);
         --  When S = 0, this range is null, and the loop does nothing
         for J in Chain_Index range I .. I + S - 1 loop
            --  Tmp is the value after J - I steps, so after the
            --  next step it is the value after J - I + 1 steps
            Lemma_Chain_Step (X, I, J - I + 1, PK_Seed, A, Tmp);

            ADRS_Tmp := With_Hash_Address (A, U32 (J));   --  Line 3
            Tmp      := Hash.F (PK_Seed, ADRS_Tmp, Tmp);  --  Line 4
            pragma Loop_Invariant (Tmp = Chain_Spec (X, I, J - I + 1, PK_Seed, A));
         end loop;
         pragma Assert (Tmp = Chain_Spec (X, I, S, PK_Seed, A));
         return Tmp;
      end Chain;

      procedure Lemma_Chain_Compose (X       : in Bytes_N;
                                     I       : in Chain_Index;
                                     S1      : in Chain_Index;
                                     S2      : in Chain_Index;
                                     PK_Seed : in Bytes_N;
                                     A       : in ADRS_Bytes)
      is
         Y : constant Bytes_N := Chain_Spec (X, I, S1, PK_Seed, A) with Ghost;
      begin
         --  Induction on S2
         if S2 = 0 then
            --  Both sides are Y
            Lemma_Chain_Spec (Y, I + S1, 0, PK_Seed, A);
         else
            --  P is the value of both sides for S2 - 1, and both sides
            --  for S2 apply F to P with the hash address I + S1 + S2 - 1
            Lemma_Chain_Compose (X, I, S1, S2 - 1, PK_Seed, A);
            declare
               P : constant Bytes_N := Chain_Spec (X, I, S1 + S2 - 1, PK_Seed, A) with Ghost;
            begin
               Lemma_Chain_Step (Y, I + S1, S2, PK_Seed, A, P);
               Lemma_Chain_Step (X, I, S1 + S2, PK_Seed, A, P);
            end;
         end if;
      end Lemma_Chain_Compose;

      --  Each output of base_2b (X, lg_w, out_len) is less than w
      procedure Lemma_Base_W (X : in Byte_Seq; V : in U32; Start : in N32)
        with Ghost,
             Global => null,
             Pre    => X'First = 0 and then
                       Start <= 2**30 and then
                       Conversions.Is_Bits_Of (X, V, LG_W, Start),
             Post   => V < W;

      procedure Lemma_Base_W (X : in Byte_Seq; V : in U32; Start : in N32)
      is null;

      function Msg_With_Checksum (M : in Bytes_N) return Base_W_Msg
      is
         --  Length of toByte (csum, Ceiling (len2 * lg_w / 8)) in line 7
         Csum_Len : constant := (Len2 * LG_W + 7) / 8;

         Msg1      : U32_Seq (0 .. Len1 - 1);
         Msg2      : U32_Seq (0 .. Len2 - 1);
         Csum_Byte : Byte_Seq (0 .. Csum_Len - 1);
         Csum      : U32 := 0;   --  Line 1
         Msg       : Base_W_Msg := (others => 0);
      begin
         --  Line 2
         Conversions.Base_2b (M, LG_W, Msg1);

         --  Lines 3 to 5
         for I in Msg1'Range loop
            Lemma_Base_W (M, Msg1 (I), I * LG_W);
            Msg (I) := Chain_Index (Msg1 (I));
            Csum := Csum + U32 (W - 1 - Msg (I));
            pragma Loop_Invariant (Csum <= U32 (I + 1) * (W - 1));
         end loop;

         --  Line 6. For lg_w = 4, this is a left shift by 4
         pragma Assert (Csum <= Len1 * (W - 1));
         Csum := Shift_Left (Csum, (8 - ((Len2 * LG_W) mod 8)) mod 8);

         --  Line 7. Csum <= 15_360 < 2**16, so Csum fits in
         --  Csum_Len = 2 bytes, and toByte loses no bits
         pragma Assert (Csum <= 15_360);
         Conversions.To_Byte (U64 (Csum), Csum_Byte);
         Conversions.Base_2b (Csum_Byte, LG_W, Msg2);
         for I in Msg2'Range loop
            Lemma_Base_W (Csum_Byte, Msg2 (I), I * LG_W);
            Msg (Len1 + I) := Chain_Index (Msg2 (I));
         end loop;

         return Msg;
      end Msg_With_Checksum;

      function PK_Gen_Values (SK_Seed : in Bytes_N;
                              PK_Seed : in Bytes_N;
                              A       : in ADRS_Bytes) return WOTS_Array
      is
         Tmp : WOTS_Array := (others => (others => 0));
         SK  : Bytes_N;
      begin
         --  Lines 4 to 9
         for I in Index_Len loop
            --  Lines 5 and 6
            SK := Hash.PRF (PK_Seed, SK_Seed, SK_ADRS (A, I));
            --  Lines 7 and 8
            Tmp (I) := Chain (SK, 0, W - 1, PK_Seed, Chain_ADRS (A, I));
            pragma Loop_Invariant
              (for all J in 0 .. I =>
                 Tmp (J) =
                   Chain_Spec (Hash.PRF (PK_Seed, SK_Seed, SK_ADRS (A, J)),
                               0, W - 1, PK_Seed, Chain_ADRS (A, J)));
         end loop;
         return Tmp;
      end PK_Gen_Values;

      function Wots_PK_Gen (SK_Seed : in Bytes_N;
                            PK_Seed : in Bytes_N;
                            A       : in ADRS_Bytes) return Bytes_N
      is
      begin
         --  Lines 10 to 14
         return Hash.T_L (PK_Seed, WOTS_PK_ADRS (A), Flatten (PK_Gen_Values (SK_Seed, PK_Seed, A)));
      end Wots_PK_Gen;

      function Wots_Sign (M       : in Bytes_N;
                          SK_Seed : in Bytes_N;
                          PK_Seed : in Bytes_N;
                          A       : in ADRS_Bytes) return WOTS_Array
      is
         --  Lines 1 to 7
         Msg : constant Base_W_Msg := Msg_With_Checksum (M);
         Sig : WOTS_Array := (others => (others => 0));
         SK  : Bytes_N;
      begin
         --  Lines 11 to 16
         for I in Index_Len loop
            --  Lines 12 and 13
            SK := Hash.PRF (PK_Seed, SK_Seed, SK_ADRS (A, I));
            --  Lines 14 and 15
            Sig (I) := Chain (SK, 0, Msg (I), PK_Seed, Chain_ADRS (A, I));
            pragma Loop_Invariant
              (for all J in 0 .. I =>
                 Sig (J) =
                   Chain_Spec (Hash.PRF (PK_Seed, SK_Seed, SK_ADRS (A, J)),
                               0, Msg (J), PK_Seed, Chain_ADRS (A, J)));
         end loop;
         return Sig;
      end Wots_Sign;

      function PK_From_Sig_Values (Sig     : in WOTS_Array;
                                   M       : in Bytes_N;
                                   PK_Seed : in Bytes_N;
                                   A       : in ADRS_Bytes) return WOTS_Array
      is
         --  Lines 1 to 7
         Msg : constant Base_W_Msg := Msg_With_Checksum (M);
         Tmp : WOTS_Array := (others => (others => 0));
      begin
         --  Lines 8 to 11
         for I in Index_Len loop
            Tmp (I) := Chain (Sig (I), Msg (I), W - 1 - Msg (I), PK_Seed, Chain_ADRS (A, I));
            pragma Loop_Invariant
              (for all J in 0 .. I =>
                 Tmp (J) =
                   Chain_Spec (Sig (J), Msg (J), W - 1 - Msg (J),
                               PK_Seed, Chain_ADRS (A, J)));
         end loop;
         return Tmp;
      end PK_From_Sig_Values;

      function Wots_PK_From_Sig (Sig     : in WOTS_Array;
                                 M       : in Bytes_N;
                                 PK_Seed : in Bytes_N;
                                 A       : in ADRS_Bytes) return Bytes_N
      is
      begin
         --  Lines 12 to 16
         return Hash.T_L (PK_Seed, WOTS_PK_ADRS (A), Flatten (PK_From_Sig_Values (Sig, M, PK_Seed, A)));
      end Wots_PK_From_Sig;

      procedure Theorem_Round_Trip (M       : in Bytes_N;
                                    SK_Seed : in Bytes_N;
                                    PK_Seed : in Bytes_N;
                                    A       : in ADRS_Bytes)
      is
         Msg  : constant Base_W_Msg := Msg_With_Checksum (M);
         Sig  : constant WOTS_Array := Wots_Sign (M, SK_Seed, PK_Seed, A);
         From : constant WOTS_Array := PK_From_Sig_Values (Sig, M, PK_Seed, A);
         Gen  : constant WOTS_Array := PK_Gen_Values (SK_Seed, PK_Seed, A);
      begin
         --  Chain I of the signature is Msg (I) steps along chain I from
         --  the secret value. PK_From_Sig_Values takes the remaining
         --  W - 1 - Msg (I) steps, which reaches the end of chain I
         for I in Index_Len loop
            Lemma_Chain_Compose (Hash.PRF (PK_Seed, SK_Seed, SK_ADRS (A, I)),
                                 0, Msg (I), W - 1 - Msg (I),
                                 PK_Seed, Chain_ADRS (A, I));
            Lemma_Eq (Sig (I), Chain_Spec (Hash.PRF (PK_Seed, SK_Seed, SK_ADRS (A, I)),
                                           0, Msg (I), PK_Seed, Chain_ADRS (A, I)));
            pragma Assert (From (I) = Gen (I));
            pragma Loop_Invariant (for all J in 0 .. I => From (J) = Gen (J));
         end loop;
         Lemma_Flatten_Eq (From, Gen);
      end Theorem_Round_Trip;

   end WOTS;

   --  The specification of package XMSS is in the private part of slh.ads

   package body XMSS
   is
      ------------------------------------------------------
      --  Logical equality, as in the body of WOTS. GNATprove
      --  interprets each Eq function as logical equality, so
      --  if Eq (X, Y), then any function gives the same result
      --  for X and Y. The bodies are only executed when
      --  assertions are enabled.
      ------------------------------------------------------

      function Eq_N (X, Y : in Bytes_N) return Boolean
        with Ghost,
             Global   => null,
             Annotate => (GNATprove, Logical_Equal);

      function Eq_N (X, Y : in Bytes_N) return Boolean
        with SPARK_Mode => Off
      is
      begin
         return X = Y;
      end Eq_N;

      procedure Lemma_Eq_N (X, Y : in Bytes_N)
        with Ghost,
             Global => null,
             Pre    => X = Y,
             Post   => Eq_N (X, Y);

      procedure Lemma_Eq_N (X, Y : in Bytes_N)
      is null;

      function Eq_2N (X, Y : in Bytes_2N) return Boolean
        with Ghost,
             Global   => null,
             Annotate => (GNATprove, Logical_Equal);

      function Eq_2N (X, Y : in Bytes_2N) return Boolean
        with SPARK_Mode => Off
      is
      begin
         return X = Y;
      end Eq_2N;

      procedure Lemma_Eq_2N (X, Y : in Bytes_2N)
        with Ghost,
             Global => null,
             Pre    => X = Y,
             Post   => Eq_2N (X, Y);

      procedure Lemma_Eq_2N (X, Y : in Bytes_2N)
      is null;

      function Eq_WOTS (X, Y : in WOTS_Array) return Boolean
        with Ghost,
             Global   => null,
             Annotate => (GNATprove, Logical_Equal);

      function Eq_WOTS (X, Y : in WOTS_Array) return Boolean
        with SPARK_Mode => Off
      is
      begin
         return X = Y;
      end Eq_WOTS;

      procedure Lemma_Eq_WOTS (X, Y : in WOTS_Array)
        with Ghost,
             Global => null,
             Pre    => X = Y,
             Post   => Eq_WOTS (X, Y);

      procedure Lemma_Eq_WOTS (X, Y : in WOTS_Array)
      is
      begin
         for I in Index_Len loop
            Lemma_Eq_N (X (I), Y (I));
            pragma Loop_Invariant (for all J in 0 .. I => Eq_N (X (J), Y (J)));
         end loop;
      end Lemma_Eq_WOTS;

      function Concat (L, R : in Bytes_N) return Bytes_2N
      is
         Result : Bytes_2N := (others => 0);
      begin
         Result (0 .. N - 1)     := L;
         Result (N .. 2 * N - 1) := R;
         return Result;
      end Concat;

      ------------------------------------------------------
      --  Addresses
      ------------------------------------------------------

      function Leaf_ADRS (A : in ADRS_Bytes; I : in Node_Index) return ADRS_Bytes
      is
         R : ADRS_Bytes := A;
      begin
         ADRS.Set_Type_And_Clear (R, ADRS.WOTS_HASH);
         ADRS.Set_Key_Pair_Address (R, I);
         return R;
      end Leaf_ADRS;

      function Tree_ADRS (A : in ADRS_Bytes; Z : in Tree_Height; I : in Node_Index) return ADRS_Bytes
      is
         R : ADRS_Bytes := A;
      begin
         ADRS.Set_Type_And_Clear (R, ADRS.TREE);
         ADRS.Set_Tree_Height (R, U32 (Z));
         ADRS.Set_Tree_Index (R, I);
         return R;
      end Tree_ADRS;

      ------------------------------------------------------
      --  Algorithm 9
      ------------------------------------------------------

      procedure Lemma_XMSS_Node (SK_Seed : in Bytes_N;
                                 I       : in Node_Index;
                                 Z       : in Tree_Height;
                                 PK_Seed : in Bytes_N;
                                 A       : in ADRS_Bytes)
      is
         pragma Annotate (GNATprove, Unhide_Info, "Expression_Function_Body", XMSS_Node);
      begin
         null;
      end Lemma_XMSS_Node;

      ------------------------------------------------------
      --  Algorithm 10
      ------------------------------------------------------

      function XMSS_Sign (M       : in Bytes_N;
                          SK_Seed : in Bytes_N;
                          Idx     : in Node_Index;
                          PK_Seed : in Bytes_N;
                          A       : in ADRS_Bytes) return XMSS_Sig
      is
         K      : Node_Index;
         Result : XMSS_Sig := (Sig  => (others => (others => 0)),
                               Auth => (others => (others => 0)));
      begin
         --  Lines 1 to 4. Build the authentication path
         for J in Auth_Index loop
            K := Sibling (Idx, J);                                       --  Line 2
            Result.Auth (J) := XMSS_Node (SK_Seed, K, J, PK_Seed, A);    --  Line 3
            pragma Loop_Invariant
              (for all J2 in 0 .. J =>
                 Result.Auth (J2) = XMSS_Node (SK_Seed, Sibling (Idx, J2), J2, PK_Seed, A));
         end loop;

         --  Lines 5 to 8
         Result.Sig := WOTS.Wots_Sign (M, SK_Seed, PK_Seed, Leaf_ADRS (A, Idx));
         return Result;
      end XMSS_Sign;

      ------------------------------------------------------
      --  Algorithm 11
      ------------------------------------------------------

      procedure Lemma_Path_Node (Leaf    : in Bytes_N;
                                 Idx     : in Node_Index;
                                 Auth    : in Auth_Path;
                                 K       : in Tree_Height;
                                 PK_Seed : in Bytes_N;
                                 A       : in ADRS_Bytes)
      is
         pragma Annotate (GNATprove, Unhide_Info, "Expression_Function_Body", Path_Node);
      begin
         null;
      end Lemma_Path_Node;

      function XMSS_PK_From_Sig (Idx     : in Node_Index;
                                 S       : in XMSS_Sig;
                                 M       : in Bytes_N;
                                 PK_Seed : in Bytes_N;
                                 A       : in ADRS_Bytes) return Bytes_N
      is
         Node_0 : Bytes_N;
         Node_1 : Bytes_N;
         T      : Node_Index;  --  The tree index in ADRS

         Leaf : Bytes_N with Ghost;
      begin
         --  Lines 1 to 5. Compute the WOTS+ public key from the WOTS+ signature
         Node_0 := WOTS.Wots_PK_From_Sig (S.Sig, M, PK_Seed, Leaf_ADRS (A, Idx));
         Leaf   := Node_0;
         Lemma_Path_Node (Leaf, Idx, S.Auth, 0, PK_Seed, A);

         --  Lines 6 to 18. Compute the root from the WOTS+ public key and AUTH
         T := Idx;  --  Line 7
         for K in Auth_Index loop
            pragma Loop_Invariant (T = Shift_Right (Idx, Natural (K)));
            pragma Loop_Invariant (Node_0 = Path_Node (Leaf, Idx, S.Auth, K, PK_Seed, A));

            Lemma_Path_Node (Leaf, Idx, S.Auth, K + 1, PK_Seed, A);
            if (Shift_Right (Idx, Natural (K)) and 1) = 0 then  --  Line 10
               T := T / 2;                                                       --  Line 11
               Lemma_Eq_2N (Concat (Node_0, S.Auth (K)),
                            Concat (Path_Node (Leaf, Idx, S.Auth, K, PK_Seed, A), S.Auth (K)));
               Node_1 := Hash.H (PK_Seed, Tree_ADRS (A, K + 1, T),
                                 Concat (Node_0, S.Auth (K)));                   --  Line 12
            else
               T := (T - 1) / 2;                                                 --  Line 14
               Lemma_Eq_2N (Concat (S.Auth (K), Node_0),
                            Concat (S.Auth (K), Path_Node (Leaf, Idx, S.Auth, K, PK_Seed, A)));
               Node_1 := Hash.H (PK_Seed, Tree_ADRS (A, K + 1, T),
                                 Concat (S.Auth (K), Node_0));                   --  Line 15
            end if;
            pragma Assert (T = Shift_Right (Idx, Natural (K + 1)));
            Node_0 := Node_1;  --  Line 17
         end loop;
         return Node_0;
      end XMSS_PK_From_Sig;

      ------------------------------------------------------
      --  Correctness
      ------------------------------------------------------

      procedure Theorem_Round_Trip (M       : in Bytes_N;
                                    SK_Seed : in Bytes_N;
                                    Idx     : in Node_Index;
                                    PK_Seed : in Bytes_N;
                                    A       : in ADRS_Bytes)
      is
         S    : constant XMSS_Sig   := XMSS_Sign (M, SK_Seed, Idx, PK_Seed, A);
         LA   : constant ADRS_Bytes := Leaf_ADRS (A, Idx);
         Leaf : constant Bytes_N    := WOTS.Wots_PK_From_Sig (S.Sig, M, PK_Seed, LA);
         P    : Node_Index;  --  Index of the node of height K on the path
         C    : Node_Index;  --  Index of its child on the path
      begin
         --  The leaf. S.Sig is a WOTS+ signature of M with the key of
         --  leaf Idx, so by the WOTS+ round trip theorem, Leaf is the
         --  WOTS+ public key of leaf Idx, which is the value of the leaf
         Lemma_Eq_WOTS (S.Sig, WOTS.Wots_Sign (M, SK_Seed, PK_Seed, LA));
         WOTS.Theorem_Round_Trip (M, SK_Seed, PK_Seed, LA);
         Lemma_XMSS_Node (SK_Seed, Idx, 0, PK_Seed, A);
         Lemma_Path_Node (Leaf, Idx, S.Auth, 0, PK_Seed, A);
         pragma Assert (Path_Node (Leaf, Idx, S.Auth, 0, PK_Seed, A) =
                          XMSS_Node (SK_Seed, Idx, 0, PK_Seed, A));

         --  Induction on K. The node of height K on the path from leaf
         --  Idx to the root has index P = Floor (Idx / 2**K), and its
         --  children are nodes 2P and 2P + 1 of height K - 1. One of these
         --  is C = Floor (Idx / 2**(K - 1)), which is on the path, and the
         --  other is C xor 1, which is Auth (K - 1). Path_Node puts them
         --  in the order given by the parity of C, which is the order of
         --  the children in XMSS_Node
         for K in Tree_Height range 1 .. H_Tick loop
            P := Shift_Right (Idx, Natural (K));
            C := Shift_Right (Idx, Natural (K - 1));
            pragma Assert (C / 2 = P);
            pragma Assert (Sibling (Idx, K - 1) = (C xor 1));

            Lemma_Path_Node (Leaf, Idx, S.Auth, K, PK_Seed, A);
            Lemma_XMSS_Node (SK_Seed, P, K, PK_Seed, A);

            if (C and 1) = 0 then
               pragma Assert (C = 2 * P and (C xor 1) = 2 * P + 1);
               Lemma_Eq_2N (Concat (Path_Node (Leaf, Idx, S.Auth, K - 1, PK_Seed, A), S.Auth (K - 1)),
                            Concat (XMSS_Node (SK_Seed, 2 * P, K - 1, PK_Seed, A),
                                    XMSS_Node (SK_Seed, 2 * P + 1, K - 1, PK_Seed, A)));
            else
               pragma Assert (C = 2 * P + 1 and (C xor 1) = 2 * P);
               Lemma_Eq_2N (Concat (S.Auth (K - 1), Path_Node (Leaf, Idx, S.Auth, K - 1, PK_Seed, A)),
                            Concat (XMSS_Node (SK_Seed, 2 * P, K - 1, PK_Seed, A),
                                    XMSS_Node (SK_Seed, 2 * P + 1, K - 1, PK_Seed, A)));
            end if;

            pragma Loop_Invariant
              (Path_Node (Leaf, Idx, S.Auth, K, PK_Seed, A) =
                 XMSS_Node (SK_Seed, Shift_Right (Idx, Natural (K)), K, PK_Seed, A));
         end loop;

         --  The node of height H_Tick on the path is the root
         pragma Assert (Shift_Right (Idx, H_Tick) = 0);
      end Theorem_Round_Trip;

   end XMSS;

   package body HT
   is
      ------------------------------------------------------
      --  Logical equality, as in the bodies of WOTS and XMSS
      ------------------------------------------------------

      function Eq_N (X, Y : in Bytes_N) return Boolean
        with Ghost,
             Global   => null,
             Annotate => (GNATprove, Logical_Equal);

      function Eq_N (X, Y : in Bytes_N) return Boolean
        with SPARK_Mode => Off
      is
      begin
         return X = Y;
      end Eq_N;

      procedure Lemma_Eq_N (X, Y : in Bytes_N)
        with Ghost,
             Global => null,
             Pre    => X = Y,
             Post   => Eq_N (X, Y);

      procedure Lemma_Eq_N (X, Y : in Bytes_N)
      is null;

      --  Equality of each component of an XMSS_Sig, then of the record
      function Eq_WOTS (X, Y : in WOTS_Array) return Boolean
        with Ghost,
             Global   => null,
             Annotate => (GNATprove, Logical_Equal);

      function Eq_WOTS (X, Y : in WOTS_Array) return Boolean
        with SPARK_Mode => Off
      is
      begin
         return X = Y;
      end Eq_WOTS;

      procedure Lemma_Eq_WOTS (X, Y : in WOTS_Array)
        with Ghost,
             Global => null,
             Pre    => X = Y,
             Post   => Eq_WOTS (X, Y);

      procedure Lemma_Eq_WOTS (X, Y : in WOTS_Array)
      is
      begin
         for I in Index_Len loop
            Lemma_Eq_N (X (I), Y (I));
            pragma Loop_Invariant (for all J in 0 .. I => Eq_N (X (J), Y (J)));
         end loop;
      end Lemma_Eq_WOTS;

      function Eq_Auth (X, Y : in Auth_Path) return Boolean
        with Ghost,
             Global   => null,
             Annotate => (GNATprove, Logical_Equal);

      function Eq_Auth (X, Y : in Auth_Path) return Boolean
        with SPARK_Mode => Off
      is
      begin
         return X = Y;
      end Eq_Auth;

      procedure Lemma_Eq_Auth (X, Y : in Auth_Path)
        with Ghost,
             Global => null,
             Pre    => X = Y,
             Post   => Eq_Auth (X, Y);

      procedure Lemma_Eq_Auth (X, Y : in Auth_Path)
      is
      begin
         for I in Auth_Index loop
            Lemma_Eq_N (X (I), Y (I));
            pragma Loop_Invariant (for all J in 0 .. I => Eq_N (X (J), Y (J)));
         end loop;
      end Lemma_Eq_Auth;

      function Eq_Sig (X, Y : in XMSS_Sig) return Boolean
        with Ghost,
             Global   => null,
             Annotate => (GNATprove, Logical_Equal);

      function Eq_Sig (X, Y : in XMSS_Sig) return Boolean
        with SPARK_Mode => Off
      is
      begin
         return X = Y;
      end Eq_Sig;

      procedure Lemma_Eq_Sig (X, Y : in XMSS_Sig)
        with Ghost,
             Global => null,
             Pre    => X = Y,
             Post   => Eq_Sig (X, Y);

      procedure Lemma_Eq_Sig (X, Y : in XMSS_Sig)
      is
      begin
         Lemma_Eq_WOTS (X.Sig, Y.Sig);
         Lemma_Eq_Auth (X.Auth, Y.Auth);
      end Lemma_Eq_Sig;

      ------------------------------------------------------
      --  Addresses
      ------------------------------------------------------

      function Layer_ADRS (J : in Layer_Index; T : in Tree_Index) return ADRS_Bytes
      is
         R : ADRS_Bytes := (others => 0);
      begin
         ADRS.Set_Layer_Address (R, U32 (J));
         ADRS.Set_Tree_Address (R, T);
         return R;
      end Layer_ADRS;

      ------------------------------------------------------
      --  Algorithm 12
      ------------------------------------------------------

      function HT_Sign (M        : in Bytes_N;
                        SK_Seed  : in Bytes_N;
                        PK_Seed  : in Bytes_N;
                        Idx_Tree : in Tree_Index;
                        Idx_Leaf : in Node_Index) return HT_Sig
      is
         Tree   : Tree_Index := Idx_Tree;
         Leaf   : Node_Index := Idx_Leaf;
         Root   : Bytes_N;
         Result : HT_Sig := (others => (Sig  => (others => (others => 0)),
                                        Auth => (others => (others => 0))));
      begin
         --  Lines 1 to 4
         Result (0) := XMSS.XMSS_Sign (M, SK_Seed, Leaf, PK_Seed, Layer_ADRS (0, Tree));

         --  Line 5. By the XMSS round trip theorem, Root is the
         --  root of the tree at layer 0
         Root := XMSS.XMSS_PK_From_Sig (Leaf, Result (0), M, PK_Seed, Layer_ADRS (0, Tree));
         XMSS.Theorem_Round_Trip (M, SK_Seed, Leaf, PK_Seed, Layer_ADRS (0, Tree));
         pragma Assert (Root = Layer_Root (SK_Seed, PK_Seed, Idx_Tree, 0));

         for J in Layer_Index range 1 .. D - 1 loop
            Leaf := Node_Index (Tree and (2**H_Tick - 1));  --  Line 7
            Tree := Shift_Right (Tree, H_Tick);             --  Line 8
            pragma Assert (Tree = Tree_At (Idx_Tree, J));
            pragma Assert (Leaf = Leaf_At (Idx_Tree, Idx_Leaf, J));

            --  Lines 9 to 12
            Lemma_Eq_N (Root, Layer_Msg (M, SK_Seed, PK_Seed, Idx_Tree, J));
            Result (J) := XMSS.XMSS_Sign (Root, SK_Seed, Leaf, PK_Seed, Layer_ADRS (J, Tree));

            --  Lines 13 to 15
            if J < D - 1 then
               Root := XMSS.XMSS_PK_From_Sig (Leaf, Result (J), Root, PK_Seed, Layer_ADRS (J, Tree));
               XMSS.Theorem_Round_Trip (Layer_Msg (M, SK_Seed, PK_Seed, Idx_Tree, J),
                                        SK_Seed, Leaf, PK_Seed, Layer_ADRS (J, Tree));
               pragma Assert (Root = Layer_Root (SK_Seed, PK_Seed, Idx_Tree, J));
            end if;

            pragma Loop_Invariant (Tree = Tree_At (Idx_Tree, J));
            pragma Loop_Invariant (if J < D - 1 then Root = Layer_Root (SK_Seed, PK_Seed, Idx_Tree, J));
            pragma Loop_Invariant
              (for all J2 in 0 .. J =>
                 Result (J2) =
                   XMSS.XMSS_Sign (Layer_Msg (M, SK_Seed, PK_Seed, Idx_Tree, J2),
                                   SK_Seed,
                                   Leaf_At (Idx_Tree, Idx_Leaf, J2),
                                   PK_Seed,
                                   Layer_ADRS (J2, Tree_At (Idx_Tree, J2))));
         end loop;
         return Result;  --  Line 17
      end HT_Sign;

      ------------------------------------------------------
      --  Algorithm 13
      ------------------------------------------------------

      function Layer_PK (X        : in Bytes_N;
                         S        : in HT_Sig;
                         PK_Seed  : in Bytes_N;
                         Idx_Tree : in Tree_Index;
                         Idx_Leaf : in Node_Index;
                         J        : in Layer_Index) return Bytes_N
      is
      begin
         return XMSS.XMSS_PK_From_Sig (Leaf_At (Idx_Tree, Idx_Leaf, J),
                                       S (J),
                                       X,
                                       PK_Seed,
                                       Layer_ADRS (J, Tree_At (Idx_Tree, J)));
      end Layer_PK;

      procedure Lemma_Verify_Node (M        : in Bytes_N;
                                   S        : in HT_Sig;
                                   PK_Seed  : in Bytes_N;
                                   Idx_Tree : in Tree_Index;
                                   Idx_Leaf : in Node_Index;
                                   J        : in Layer_Index)
      is
         pragma Annotate (GNATprove, Unhide_Info, "Expression_Function_Body", Verify_Node);
      begin
         null;
      end Lemma_Verify_Node;

      function HT_Verify (M        : in Bytes_N;
                          S        : in HT_Sig;
                          PK_Seed  : in Bytes_N;
                          Idx_Tree : in Tree_Index;
                          Idx_Leaf : in Node_Index;
                          PK_Root  : in Bytes_N) return Boolean
      is
         Tree : Tree_Index := Idx_Tree;
         Leaf : Node_Index := Idx_Leaf;
         Node : Bytes_N;
      begin
         --  Lines 1 to 4
         Node := XMSS.XMSS_PK_From_Sig (Leaf, S (0), M, PK_Seed, Layer_ADRS (0, Tree));
         Lemma_Verify_Node (M, S, PK_Seed, Idx_Tree, Idx_Leaf, 0);

         for J in Layer_Index range 1 .. D - 1 loop
            Leaf := Node_Index (Tree and (2**H_Tick - 1));  --  Line 6
            Tree := Shift_Right (Tree, H_Tick);             --  Line 7
            pragma Assert (Tree = Tree_At (Idx_Tree, J));
            pragma Assert (Leaf = Leaf_At (Idx_Tree, Idx_Leaf, J));

            --  Lines 8 to 11
            Lemma_Verify_Node (M, S, PK_Seed, Idx_Tree, Idx_Leaf, J);
            Lemma_Eq_N (Node, Verify_Node (M, S, PK_Seed, Idx_Tree, Idx_Leaf, J - 1));
            Node := XMSS.XMSS_PK_From_Sig (Leaf, S (J), Node, PK_Seed, Layer_ADRS (J, Tree));

            pragma Loop_Invariant (Tree = Tree_At (Idx_Tree, J));
            pragma Loop_Invariant (Node = Verify_Node (M, S, PK_Seed, Idx_Tree, Idx_Leaf, J));
         end loop;

         --  Lines 13 to 17
         return Node = PK_Root;
      end HT_Verify;

      ------------------------------------------------------
      --  Correctness
      ------------------------------------------------------

      procedure Theorem_Round_Trip (M        : in Bytes_N;
                                    SK_Seed  : in Bytes_N;
                                    PK_Seed  : in Bytes_N;
                                    Idx_Tree : in Tree_Index;
                                    Idx_Leaf : in Node_Index)
      is
         S : constant HT_Sig := HT_Sign (M, SK_Seed, PK_Seed, Idx_Tree, Idx_Leaf);
      begin
         --  Induction on J. Layer J of S is the XMSS signature of
         --  Layer_Msg (J), and by induction the message given to
         --  xmss_pkFromSig at layer J is also Layer_Msg (J), so by the
         --  XMSS round trip theorem, the node computed at layer J is
         --  the root of the tree at layer J
         for J in Layer_Index loop
            Lemma_Verify_Node (M, S, PK_Seed, Idx_Tree, Idx_Leaf, J);
            if J > 0 then
               Lemma_Eq_N (Verify_Node (M, S, PK_Seed, Idx_Tree, Idx_Leaf, J - 1),
                           Layer_Root (SK_Seed, PK_Seed, Idx_Tree, J - 1));
            end if;
            Lemma_Eq_Sig (S (J),
                          XMSS.XMSS_Sign (Layer_Msg (M, SK_Seed, PK_Seed, Idx_Tree, J),
                                          SK_Seed,
                                          Leaf_At (Idx_Tree, Idx_Leaf, J),
                                          PK_Seed,
                                          Layer_ADRS (J, Tree_At (Idx_Tree, J))));
            XMSS.Theorem_Round_Trip (Layer_Msg (M, SK_Seed, PK_Seed, Idx_Tree, J),
                                     SK_Seed,
                                     Leaf_At (Idx_Tree, Idx_Leaf, J),
                                     PK_Seed,
                                     Layer_ADRS (J, Tree_At (Idx_Tree, J)));

            pragma Loop_Invariant
              (Verify_Node (M, S, PK_Seed, Idx_Tree, Idx_Leaf, J) =
                 Layer_Root (SK_Seed, PK_Seed, Idx_Tree, J));
         end loop;

         --  The top layer has a single tree
         pragma Assert (Tree_At (Idx_Tree, D - 1) = 0);
      end Theorem_Round_Trip;

   end HT;

   package body FORS
   is
      ------------------------------------------------------
      --  Logical equality, as in the bodies of WOTS and XMSS
      ------------------------------------------------------

      function Eq_N (X, Y : in Bytes_N) return Boolean
        with Ghost,
             Global   => null,
             Annotate => (GNATprove, Logical_Equal);

      function Eq_N (X, Y : in Bytes_N) return Boolean
        with SPARK_Mode => Off
      is
      begin
         return X = Y;
      end Eq_N;

      procedure Lemma_Eq_N (X, Y : in Bytes_N)
        with Ghost,
             Global => null,
             Pre    => X = Y,
             Post   => Eq_N (X, Y);

      procedure Lemma_Eq_N (X, Y : in Bytes_N)
      is null;

      function Eq_2N (X, Y : in Bytes_2N) return Boolean
        with Ghost,
             Global   => null,
             Annotate => (GNATprove, Logical_Equal);

      function Eq_2N (X, Y : in Bytes_2N) return Boolean
        with SPARK_Mode => Off
      is
      begin
         return X = Y;
      end Eq_2N;

      procedure Lemma_Eq_2N (X, Y : in Bytes_2N)
        with Ghost,
             Global => null,
             Pre    => X = Y,
             Post   => Eq_2N (X, Y);

      procedure Lemma_Eq_2N (X, Y : in Bytes_2N)
      is null;

      function Eq_K_N (X, Y : in Bytes_K_N) return Boolean
        with Ghost,
             Global   => null,
             Annotate => (GNATprove, Logical_Equal);

      function Eq_K_N (X, Y : in Bytes_K_N) return Boolean
        with SPARK_Mode => Off
      is
      begin
         return X = Y;
      end Eq_K_N;

      procedure Lemma_Eq_K_N (X, Y : in Bytes_K_N)
        with Ghost,
             Global => null,
             Pre    => X = Y,
             Post   => Eq_K_N (X, Y);

      procedure Lemma_Eq_K_N (X, Y : in Bytes_K_N)
      is null;

      function Flatten (R : in FORS_Roots) return Bytes_K_N
      is
         Result : Bytes_K_N := (others => 0);
      begin
         for I in FORS_Tree_Index loop
            Result (I * N .. I * N + N - 1) := R (I);
            pragma Loop_Invariant
              (for all I2 in 0 .. I =>
                 (for all J in Index_N => Result (I2 * N + J) = R (I2) (J)));
         end loop;
         return Result;
      end Flatten;

      --  Equal arrays of roots have equal concatenations
      procedure Lemma_Flatten_Eq (X, Y : in FORS_Roots)
        with Ghost,
             Global => null,
             Pre    => (for all I in FORS_Tree_Index => X (I) = Y (I)),
             Post   => Eq_K_N (Flatten (X), Flatten (Y));

      procedure Lemma_Flatten_Eq (X, Y : in FORS_Roots)
      is
         FX : constant Bytes_K_N := Flatten (X);
         FY : constant Bytes_K_N := Flatten (Y);
      begin
         for J in Index_K_N loop
            pragma Assert (J = (J / N) * N + J mod N);
            pragma Assert (FX (J) = X (J / N) (J mod N));
            pragma Assert (FY (J) = Y (J / N) (J mod N));
            pragma Loop_Invariant (for all J2 in 0 .. J => FX (J2) = FY (J2));
         end loop;
         Lemma_Eq_K_N (FX, FY);
      end Lemma_Flatten_Eq;

      ------------------------------------------------------
      --  Addresses
      ------------------------------------------------------

      function SK_ADRS (Adr : in ADRS_Bytes; Idx : in FORS_Node_Index) return ADRS_Bytes
      is
         SK_A : ADRS_Bytes := Adr;                                          --  Line 1
      begin
         ADRS.Set_Type_And_Clear (SK_A, ADRS.FORS_PRF);                     --  Line 2
         ADRS.Set_Key_Pair_Address (SK_A, ADRS.Get_Key_Pair_Address (Adr)); --  Line 3
         ADRS.Set_Tree_Index (SK_A, Idx);                                   --  Line 4
         return SK_A;
      end SK_ADRS;

      function Node_ADRS (Adr : in ADRS_Bytes; Z : in FORS_Height; I : in FORS_Node_Index)
                          return ADRS_Bytes
      is
         R : ADRS_Bytes := Adr;
      begin
         ADRS.Set_Tree_Height (R, U32 (Z));
         ADRS.Set_Tree_Index (R, I);
         return R;
      end Node_ADRS;

      function Roots_ADRS (Adr : in ADRS_Bytes) return ADRS_Bytes
      is
         PK_A : ADRS_Bytes := Adr;                                          --  Line 21
      begin
         ADRS.Set_Type_And_Clear (PK_A, ADRS.FORS_ROOTS);                   --  Line 22
         ADRS.Set_Key_Pair_Address (PK_A, ADRS.Get_Key_Pair_Address (Adr)); --  Line 23
         return PK_A;
      end Roots_ADRS;

      ------------------------------------------------------
      --  Algorithm 15
      ------------------------------------------------------

      procedure Lemma_FORS_Node (SK_Seed : in Bytes_N;
                                 I       : in FORS_Node_Index;
                                 Z       : in FORS_Height;
                                 PK_Seed : in Bytes_N;
                                 Adr     : in ADRS_Bytes)
      is
         pragma Annotate (GNATprove, Unhide_Info, "Expression_Function_Body", FORS_Node);
      begin
         null;
      end Lemma_FORS_Node;

      ------------------------------------------------------
      --  Algorithm 16
      ------------------------------------------------------

      function Msg_Indices (MD : in Bytes_MD) return FORS_Indices
      is
         Ind    : U32_Seq (FORS_Tree_Index);
         Result : FORS_Indices;  --  Every element is set by the loop
      begin
         Conversions.Base_2b (MD, A, Ind);
         for I in FORS_Tree_Index loop
            --  By the postcondition of Base_2b, Shift_Right (Ind (I), A) = 0
            pragma Assert (Conversions.Is_Bits_Of (MD, Ind (I), A, I * A));
            Result (I) := FORS_Leaf (Ind (I));
         end loop;
         return Result;
      end Msg_Indices;

      function FORS_Sign (MD      : in Bytes_MD;
                          SK_Seed : in Bytes_N;
                          PK_Seed : in Bytes_N;
                          Adr     : in ADRS_Bytes) return FORS_Sig
      is
         Indices : constant FORS_Indices := Msg_Indices (MD);  --  Line 2
         G       : FORS_Node_Index;
         Result  : FORS_Sig := (others => (SK   => (others => 0),
                                           Auth => (others => (others => 0))));  --  Line 1
      begin
         for I in FORS_Tree_Index loop
            G := Leaf_Index (I, Indices (I));

            --  Line 4
            Result (I).SK := FORS_SK_Gen (SK_Seed, PK_Seed, Adr, G);

            --  Lines 5 to 9. Sibling (G, J) is i * 2**(a - j) + s
            for J in FORS_Auth_Index loop
               Result (I).Auth (J) := FORS_Node (SK_Seed, Sibling (G, J), J, PK_Seed, Adr);
               pragma Loop_Invariant
                 (for all J2 in 0 .. J =>
                    Result (I).Auth (J2) = FORS_Node (SK_Seed, Sibling (G, J2), J2, PK_Seed, Adr));
               pragma Loop_Invariant (Result (I).SK = FORS_SK_Gen (SK_Seed, PK_Seed, Adr, G));
               pragma Loop_Invariant
                 (for all I2 in 0 .. I - 1 =>
                    Result (I2) = Result'Loop_Entry (I2));
            end loop;

            pragma Loop_Invariant
              (for all I2 in 0 .. I =>
                 Result (I2).SK =
                   FORS_SK_Gen (SK_Seed, PK_Seed, Adr, Leaf_Index (I2, Indices (I2))) and
                 (for all J in FORS_Auth_Index =>
                    Result (I2).Auth (J) =
                      FORS_Node (SK_Seed, Sibling (Leaf_Index (I2, Indices (I2)), J), J,
                                 PK_Seed, Adr)));
         end loop;
         return Result;  --  Line 11
      end FORS_Sign;

      ------------------------------------------------------
      --  Algorithm 17
      ------------------------------------------------------

      procedure Lemma_Path_Node (Leaf    : in Bytes_N;
                                 G       : in FORS_Node_Index;
                                 Auth    : in FORS_Auth;
                                 Z       : in FORS_Height;
                                 PK_Seed : in Bytes_N;
                                 Adr     : in ADRS_Bytes)
      is
         pragma Annotate (GNATprove, Unhide_Info, "Expression_Function_Body", Path_Node);
      begin
         null;
      end Lemma_Path_Node;

      function Roots_From_Sig (S       : in FORS_Sig;
                               MD      : in Bytes_MD;
                               PK_Seed : in Bytes_N;
                               Adr     : in ADRS_Bytes) return FORS_Roots
      is
         Indices : constant FORS_Indices := Msg_Indices (MD);
         Result  : FORS_Roots := (others => (others => 0));
      begin
         for I in FORS_Tree_Index loop
            Result (I) := Tree_Root_From_Sig (S (I), Leaf_Index (I, Indices (I)), PK_Seed, Adr);
            pragma Loop_Invariant
              (for all I2 in 0 .. I =>
                 Result (I2) =
                   Tree_Root_From_Sig (S (I2), Leaf_Index (I2, Indices (I2)), PK_Seed, Adr));
         end loop;
         return Result;
      end Roots_From_Sig;

      function FORS_PK_From_Sig (S       : in FORS_Sig;
                                 MD      : in Bytes_MD;
                                 PK_Seed : in Bytes_N;
                                 Adr     : in ADRS_Bytes) return Bytes_N
      is
         Indices : constant FORS_Indices := Msg_Indices (MD);  --  Line 1
         G       : FORS_Node_Index;  --  i * 2**a + indices[i]
         T       : FORS_Node_Index;  --  The tree index in ADRS
         Node_0  : Bytes_N;
         Node_1  : Bytes_N;
         Root    : FORS_Roots := (others => (others => 0));

         Leaf : Bytes_N with Ghost;
      begin
         for I in FORS_Tree_Index loop
            G := Leaf_Index (I, Indices (I));

            --  Lines 3 to 6. Compute the leaf
            T      := G;
            Node_0 := Hash.F (PK_Seed, Node_ADRS (Adr, 0, T), S (I).SK);
            Leaf   := Node_0;
            Lemma_Path_Node (Leaf, G, S (I).Auth, 0, PK_Seed, Adr);

            --  Lines 7 to 18. Compute the root from the leaf and AUTH
            for J in FORS_Auth_Index loop
               pragma Loop_Invariant (T = Shift_Right (G, Natural (J)));
               pragma Loop_Invariant (Node_0 = Path_Node (Leaf, G, S (I).Auth, J, PK_Seed, Adr));
               pragma Loop_Invariant
                 (for all I2 in 0 .. I - 1 =>
                    Root (I2) =
                      Tree_Root_From_Sig (S (I2), Leaf_Index (I2, Indices (I2)), PK_Seed, Adr));

               Lemma_Path_Node (Leaf, G, S (I).Auth, J + 1, PK_Seed, Adr);
               --  indices[i] and G have the same low A bits
               pragma Assert ((Shift_Right (Indices (I), Natural (J)) and 1) =
                                (Shift_Right (G, Natural (J)) and 1));
               if (Shift_Right (Indices (I), Natural (J)) and 1) = 0 then  --  Line 10
                  T := T / 2;                                                --  Line 11
                  Lemma_Eq_2N (XMSS.Concat (Node_0, S (I).Auth (J)),
                               XMSS.Concat (Path_Node (Leaf, G, S (I).Auth, J, PK_Seed, Adr),
                                            S (I).Auth (J)));
                  Node_1 := Hash.H (PK_Seed, Node_ADRS (Adr, J + 1, T),
                                    XMSS.Concat (Node_0, S (I).Auth (J)));   --  Line 12
               else
                  T := (T - 1) / 2;                                          --  Line 14
                  Lemma_Eq_2N (XMSS.Concat (S (I).Auth (J), Node_0),
                               XMSS.Concat (S (I).Auth (J),
                                            Path_Node (Leaf, G, S (I).Auth, J, PK_Seed, Adr)));
                  Node_1 := Hash.H (PK_Seed, Node_ADRS (Adr, J + 1, T),
                                    XMSS.Concat (S (I).Auth (J), Node_0));   --  Line 15
               end if;
               pragma Assert (T = Shift_Right (G, Natural (J + 1)));
               Node_0 := Node_1;  --  Line 17
            end loop;

            Root (I) := Node_0;  --  Line 19
            pragma Loop_Invariant
              (for all I2 in 0 .. I =>
                 Root (I2) =
                   Tree_Root_From_Sig (S (I2), Leaf_Index (I2, Indices (I2)), PK_Seed, Adr));
         end loop;

         --  Lines 21 to 25
         Lemma_Flatten_Eq (Root, Roots_From_Sig (S, MD, PK_Seed, Adr));
         return Hash.T_L (PK_Seed, Roots_ADRS (Adr), Flatten (Root));
      end FORS_PK_From_Sig;

      ------------------------------------------------------
      --  Correctness
      ------------------------------------------------------

      function PK_Roots (SK_Seed : in Bytes_N;
                         PK_Seed : in Bytes_N;
                         Adr     : in ADRS_Bytes) return FORS_Roots
      is
         Result : FORS_Roots := (others => (others => 0));
      begin
         for I in FORS_Tree_Index loop
            Result (I) := FORS_Node (SK_Seed, U32 (I), A, PK_Seed, Adr);
            pragma Loop_Invariant
              (for all I2 in 0 .. I =>
                 Result (I2) = FORS_Node (SK_Seed, U32 (I2), A, PK_Seed, Adr));
         end loop;
         return Result;
      end PK_Roots;

      --  The root computed from a valid signature element for leaf G
      --  is the root of the tree that contains G. As for the XMSS
      --  round trip theorem, by induction on the height
      procedure Lemma_Tree_Root (E       : in FORS_Elem;
                                 G       : in FORS_Node_Index;
                                 SK_Seed : in Bytes_N;
                                 PK_Seed : in Bytes_N;
                                 Adr     : in ADRS_Bytes)
        with Ghost,
             Global => null,
             Pre    => Valid_Node (G, 0) and then
                       E.SK = FORS_SK_Gen (SK_Seed, PK_Seed, Adr, G) and then
                       (for all J in FORS_Auth_Index =>
                          E.Auth (J) = FORS_Node (SK_Seed, Sibling (G, J), J, PK_Seed, Adr)),
             Post   => Tree_Root_From_Sig (E, G, PK_Seed, Adr) =
                         FORS_Node (SK_Seed, Shift_Right (G, A), A, PK_Seed, Adr);

      procedure Lemma_Tree_Root (E       : in FORS_Elem;
                                 G       : in FORS_Node_Index;
                                 SK_Seed : in Bytes_N;
                                 PK_Seed : in Bytes_N;
                                 Adr     : in ADRS_Bytes)
      is
         Leaf : constant Bytes_N := Hash.F (PK_Seed, Node_ADRS (Adr, 0, G), E.SK);
         P    : FORS_Node_Index;  --  Index of the node of height Z on the path
         C    : FORS_Node_Index;  --  Index of its child on the path
      begin
         --  The leaf
         Lemma_Eq_N (E.SK, FORS_SK_Gen (SK_Seed, PK_Seed, Adr, G));
         Lemma_FORS_Node (SK_Seed, G, 0, PK_Seed, Adr);
         Lemma_Path_Node (Leaf, G, E.Auth, 0, PK_Seed, Adr);
         pragma Assert (Path_Node (Leaf, G, E.Auth, 0, PK_Seed, Adr) =
                          FORS_Node (SK_Seed, G, 0, PK_Seed, Adr));

         --  Induction on Z, as in XMSS.Theorem_Round_Trip
         for Z in FORS_Height range 1 .. A loop
            P := Shift_Right (G, Natural (Z));
            C := Shift_Right (G, Natural (Z - 1));
            pragma Assert (C / 2 = P);
            pragma Assert (Sibling (G, Z - 1) = (C xor 1));
            pragma Assert (Valid_Node (P, Z));

            Lemma_Path_Node (Leaf, G, E.Auth, Z, PK_Seed, Adr);
            Lemma_FORS_Node (SK_Seed, P, Z, PK_Seed, Adr);

            if (C and 1) = 0 then
               pragma Assert (C = 2 * P and (C xor 1) = 2 * P + 1);
               Lemma_Eq_2N (XMSS.Concat (Path_Node (Leaf, G, E.Auth, Z - 1, PK_Seed, Adr),
                                         E.Auth (Z - 1)),
                            XMSS.Concat (FORS_Node (SK_Seed, 2 * P, Z - 1, PK_Seed, Adr),
                                         FORS_Node (SK_Seed, 2 * P + 1, Z - 1, PK_Seed, Adr)));
            else
               pragma Assert (C = 2 * P + 1 and (C xor 1) = 2 * P);
               Lemma_Eq_2N (XMSS.Concat (E.Auth (Z - 1),
                                         Path_Node (Leaf, G, E.Auth, Z - 1, PK_Seed, Adr)),
                            XMSS.Concat (FORS_Node (SK_Seed, 2 * P, Z - 1, PK_Seed, Adr),
                                         FORS_Node (SK_Seed, 2 * P + 1, Z - 1, PK_Seed, Adr)));
            end if;

            pragma Loop_Invariant
              (Path_Node (Leaf, G, E.Auth, Z, PK_Seed, Adr) =
                 FORS_Node (SK_Seed, Shift_Right (G, Natural (Z)), Z, PK_Seed, Adr));
         end loop;
      end Lemma_Tree_Root;

      procedure Theorem_Round_Trip (MD      : in Bytes_MD;
                                    SK_Seed : in Bytes_N;
                                    PK_Seed : in Bytes_N;
                                    Adr     : in ADRS_Bytes)
      is
         S       : constant FORS_Sig     := FORS_Sign (MD, SK_Seed, PK_Seed, Adr);
         Indices : constant FORS_Indices := Msg_Indices (MD);
         Roots   : constant FORS_Roots   := Roots_From_Sig (S, MD, PK_Seed, Adr);
      begin
         --  Each root computed from S is the root of its tree
         for I in FORS_Tree_Index loop
            Lemma_Tree_Root (S (I), Leaf_Index (I, Indices (I)), SK_Seed, PK_Seed, Adr);
            pragma Loop_Invariant
              (for all I2 in 0 .. I =>
                 Roots (I2) = PK_Roots (SK_Seed, PK_Seed, Adr) (I2));
         end loop;

         --  So T_k gives the same result for both arrays of roots
         Lemma_Flatten_Eq (Roots, PK_Roots (SK_Seed, PK_Seed, Adr));
      end Theorem_Round_Trip;

   end FORS;

   --=======================================
   --  Byte formats of signatures
   --=======================================

   package body Formats
   is
      function XMSS_To_Bytes (S : in XMSS_Sig) return Bytes_XMSS_Sig
      is
         R : Bytes_XMSS_Sig := (others => 0);
      begin
         for I in Index_Len loop
            R (I * N .. I * N + N - 1) := S.Sig (I);
            pragma Loop_Invariant
              (for all I2 in 0 .. I =>
                 (for all B in Index_N => R (I2 * N + B) = S.Sig (I2) (B)));
         end loop;
         for J in Auth_Index loop
            R (Len * N + J * N .. Len * N + J * N + N - 1) := S.Auth (J);
            pragma Loop_Invariant
              (for all I in Index_Len =>
                 (for all B in Index_N => R (I * N + B) = S.Sig (I) (B)));
            pragma Loop_Invariant
              (for all J2 in 0 .. J =>
                 (for all B in Index_N => R (Len * N + J2 * N + B) = S.Auth (J2) (B)));
         end loop;
         return R;
      end XMSS_To_Bytes;

      function XMSS_From_Bytes (X : in Bytes_XMSS_Sig) return XMSS_Sig
      is
         S : XMSS_Sig := (Sig  => (others => (others => 0)),
                          Auth => (others => (others => 0)));
      begin
         for I in Index_Len loop
            S.Sig (I) := X (I * N .. I * N + N - 1);
            pragma Loop_Invariant
              (for all I2 in 0 .. I =>
                 (for all B in Index_N => S.Sig (I2) (B) = X (I2 * N + B)));
         end loop;
         for J in Auth_Index loop
            S.Auth (J) := X (Len * N + J * N .. Len * N + J * N + N - 1);
            pragma Loop_Invariant
              (for all I in Index_Len =>
                 (for all B in Index_N => S.Sig (I) (B) = X (I * N + B)));
            pragma Loop_Invariant
              (for all J2 in 0 .. J =>
                 (for all B in Index_N => S.Auth (J2) (B) = X (Len * N + J2 * N + B)));
         end loop;
         return S;
      end XMSS_From_Bytes;

      procedure Lemma_XMSS_Bytes (X : in Bytes_XMSS_Sig; S : in XMSS_Sig)
      is null;

      function HT_To_Bytes (S : in HT_Sig) return Bytes_HT_Sig
      is
         L : constant := XMSS_Sig_Bytes;
         R : Bytes_HT_Sig := (others => 0);
      begin
         for J in Layer_Index loop
            R (J * L .. J * L + L - 1) := XMSS_To_Bytes (S (J));
            pragma Loop_Invariant
              (for all J2 in 0 .. J => R (J2 * L .. J2 * L + L - 1) = XMSS_To_Bytes (S (J2)));
         end loop;
         return R;
      end HT_To_Bytes;

      function HT_From_Bytes (X : in Bytes_HT_Sig) return HT_Sig
      is
         L : constant := XMSS_Sig_Bytes;
         S : HT_Sig := (others => (Sig  => (others => (others => 0)),
                                   Auth => (others => (others => 0))));
      begin
         for J in Layer_Index loop
            S (J) := XMSS_From_Bytes (X (J * L .. J * L + L - 1));
            pragma Loop_Invariant
              (for all J2 in 0 .. J => S (J2) = XMSS_From_Bytes (X (J2 * L .. J2 * L + L - 1)));
         end loop;
         return S;
      end HT_From_Bytes;

      procedure Lemma_HT_Bytes (X : in Bytes_HT_Sig; S : in HT_Sig)
      is
         L : constant := XMSS_Sig_Bytes;
      begin
         for J in Layer_Index loop
            Lemma_XMSS_Bytes (X (J * L .. J * L + L - 1), S (J));
            pragma Loop_Invariant
              (for all J2 in 0 .. J => HT_From_Bytes (X) (J2) = S (J2));
         end loop;
      end Lemma_HT_Bytes;

      function FORS_Elem_To_Bytes (E : in FORS_Elem) return Bytes_FORS_Elem
      is
         R : Bytes_FORS_Elem := (others => 0);
      begin
         R (0 .. N - 1) := E.SK;
         for J in FORS_Auth_Index loop
            R (N + J * N .. N + J * N + N - 1) := E.Auth (J);
            pragma Loop_Invariant (for all B in Index_N => R (B) = E.SK (B));
            pragma Loop_Invariant
              (for all J2 in 0 .. J =>
                 (for all B in Index_N => R (N + J2 * N + B) = E.Auth (J2) (B)));
         end loop;
         return R;
      end FORS_Elem_To_Bytes;

      function FORS_Elem_From_Bytes (X : in Bytes_FORS_Elem) return FORS_Elem
      is
         E : FORS_Elem := (SK   => (others => 0),
                           Auth => (others => (others => 0)));
      begin
         E.SK := X (0 .. N - 1);
         for J in FORS_Auth_Index loop
            E.Auth (J) := X (N + J * N .. N + J * N + N - 1);
            pragma Loop_Invariant (for all B in Index_N => E.SK (B) = X (B));
            pragma Loop_Invariant
              (for all J2 in 0 .. J =>
                 (for all B in Index_N => E.Auth (J2) (B) = X (N + J2 * N + B)));
         end loop;
         return E;
      end FORS_Elem_From_Bytes;

      procedure Lemma_FORS_Elem_Bytes (X : in Bytes_FORS_Elem; E : in FORS_Elem)
      is null;

      function FORS_To_Bytes (S : in FORS_Sig) return Bytes_FORS_Sig
      is
         L : constant := FORS_Elem_Bytes;
         R : Bytes_FORS_Sig := (others => 0);
      begin
         for I in FORS_Tree_Index loop
            R (I * L .. I * L + L - 1) := FORS_Elem_To_Bytes (S (I));
            pragma Loop_Invariant
              (for all I2 in 0 .. I => R (I2 * L .. I2 * L + L - 1) = FORS_Elem_To_Bytes (S (I2)));
         end loop;
         return R;
      end FORS_To_Bytes;

      function FORS_From_Bytes (X : in Bytes_FORS_Sig) return FORS_Sig
      is
         L : constant := FORS_Elem_Bytes;
         S : FORS_Sig := (others => (SK   => (others => 0),
                                     Auth => (others => (others => 0))));
      begin
         for I in FORS_Tree_Index loop
            S (I) := FORS_Elem_From_Bytes (X (I * L .. I * L + L - 1));
            pragma Loop_Invariant
              (for all I2 in 0 .. I => S (I2) = FORS_Elem_From_Bytes (X (I2 * L .. I2 * L + L - 1)));
         end loop;
         return S;
      end FORS_From_Bytes;

      procedure Lemma_FORS_Bytes (X : in Bytes_FORS_Sig; S : in FORS_Sig)
      is
         L : constant := FORS_Elem_Bytes;
      begin
         for I in FORS_Tree_Index loop
            Lemma_FORS_Elem_Bytes (X (I * L .. I * L + L - 1), S (I));
            pragma Loop_Invariant
              (for all I2 in 0 .. I => FORS_From_Bytes (X) (I2) = S (I2));
         end loop;
      end Lemma_FORS_Bytes;

      function Get_R (S : in Signature) return Bytes_N
      is
      begin
         return S (0 .. N - 1);
      end Get_R;

      function Get_SIG_FORS (S : in Signature) return Bytes_FORS_Sig
      is
      begin
         return S (FORS_Start .. HT_Start - 1);
      end Get_SIG_FORS;

      function Get_SIG_HT (S : in Signature) return Bytes_HT_Sig
      is
      begin
         return S (HT_Start .. Sig_Bytes - 1);
      end Get_SIG_HT;
   end Formats;

   --=======================================
   --  SLH-DSA internal functions
   --=======================================

   ------------------------------------------------------
   --  Logical equality, as in the bodies of WOTS, XMSS,
   --  HT and FORS
   ------------------------------------------------------

   function Eq_N (X, Y : in Bytes_N) return Boolean
     with Ghost,
          Global   => null,
          Annotate => (GNATprove, Logical_Equal);

   function Eq_N (X, Y : in Bytes_N) return Boolean
     with SPARK_Mode => Off
   is
   begin
      return X = Y;
   end Eq_N;

   procedure Lemma_Eq_N (X, Y : in Bytes_N)
     with Ghost,
          Global => null,
          Pre    => X = Y,
          Post   => Eq_N (X, Y);

   procedure Lemma_Eq_N (X, Y : in Bytes_N)
   is null;

   function Eq_XMSS_Sig (X, Y : in XMSS_Sig) return Boolean
     with Ghost,
          Global   => null,
          Annotate => (GNATprove, Logical_Equal);

   function Eq_XMSS_Sig (X, Y : in XMSS_Sig) return Boolean
     with SPARK_Mode => Off
   is
   begin
      return X = Y;
   end Eq_XMSS_Sig;

   function Eq_WOTS (X, Y : in WOTS_Array) return Boolean
     with Ghost,
          Global   => null,
          Annotate => (GNATprove, Logical_Equal);

   function Eq_WOTS (X, Y : in WOTS_Array) return Boolean
     with SPARK_Mode => Off
   is
   begin
      return X = Y;
   end Eq_WOTS;

   function Eq_Auth (X, Y : in Auth_Path) return Boolean
     with Ghost,
          Global   => null,
          Annotate => (GNATprove, Logical_Equal);

   function Eq_Auth (X, Y : in Auth_Path) return Boolean
     with SPARK_Mode => Off
   is
   begin
      return X = Y;
   end Eq_Auth;

   procedure Lemma_Eq_XMSS_Sig (X, Y : in XMSS_Sig)
     with Ghost,
          Global => null,
          Pre    => X = Y,
          Post   => Eq_XMSS_Sig (X, Y);

   procedure Lemma_Eq_XMSS_Sig (X, Y : in XMSS_Sig)
   is
   begin
      for I in Index_Len loop
         Lemma_Eq_N (X.Sig (I), Y.Sig (I));
         pragma Loop_Invariant (for all J in 0 .. I => Eq_N (X.Sig (J), Y.Sig (J)));
      end loop;
      pragma Assert (Eq_WOTS (X.Sig, Y.Sig));
      for I in Auth_Index loop
         Lemma_Eq_N (X.Auth (I), Y.Auth (I));
         pragma Loop_Invariant (for all J in 0 .. I => Eq_N (X.Auth (J), Y.Auth (J)));
      end loop;
      pragma Assert (Eq_Auth (X.Auth, Y.Auth));
   end Lemma_Eq_XMSS_Sig;

   function Eq_HT_Sig (X, Y : in HT_Sig) return Boolean
     with Ghost,
          Global   => null,
          Annotate => (GNATprove, Logical_Equal);

   function Eq_HT_Sig (X, Y : in HT_Sig) return Boolean
     with SPARK_Mode => Off
   is
   begin
      return X = Y;
   end Eq_HT_Sig;

   procedure Lemma_Eq_HT_Sig (X, Y : in HT_Sig)
     with Ghost,
          Global => null,
          Pre    => X = Y,
          Post   => Eq_HT_Sig (X, Y);

   procedure Lemma_Eq_HT_Sig (X, Y : in HT_Sig)
   is
   begin
      for J in Layer_Index loop
         Lemma_Eq_XMSS_Sig (X (J), Y (J));
         pragma Loop_Invariant (for all J2 in 0 .. J => Eq_XMSS_Sig (X (J2), Y (J2)));
      end loop;
   end Lemma_Eq_HT_Sig;

   function Eq_FORS_Auth (X, Y : in FORS_Auth) return Boolean
     with Ghost,
          Global   => null,
          Annotate => (GNATprove, Logical_Equal);

   function Eq_FORS_Auth (X, Y : in FORS_Auth) return Boolean
     with SPARK_Mode => Off
   is
   begin
      return X = Y;
   end Eq_FORS_Auth;

   function Eq_FORS_Elem (X, Y : in FORS_Elem) return Boolean
     with Ghost,
          Global   => null,
          Annotate => (GNATprove, Logical_Equal);

   function Eq_FORS_Elem (X, Y : in FORS_Elem) return Boolean
     with SPARK_Mode => Off
   is
   begin
      return X = Y;
   end Eq_FORS_Elem;

   procedure Lemma_Eq_FORS_Elem (X, Y : in FORS_Elem)
     with Ghost,
          Global => null,
          Pre    => X = Y,
          Post   => Eq_FORS_Elem (X, Y);

   procedure Lemma_Eq_FORS_Elem (X, Y : in FORS_Elem)
   is
   begin
      Lemma_Eq_N (X.SK, Y.SK);
      for J in FORS_Auth_Index loop
         Lemma_Eq_N (X.Auth (J), Y.Auth (J));
         pragma Loop_Invariant (for all J2 in 0 .. J => Eq_N (X.Auth (J2), Y.Auth (J2)));
      end loop;
      pragma Assert (Eq_FORS_Auth (X.Auth, Y.Auth));
   end Lemma_Eq_FORS_Elem;

   function Eq_FORS_Sig (X, Y : in FORS_Sig) return Boolean
     with Ghost,
          Global   => null,
          Annotate => (GNATprove, Logical_Equal);

   function Eq_FORS_Sig (X, Y : in FORS_Sig) return Boolean
     with SPARK_Mode => Off
   is
   begin
      return X = Y;
   end Eq_FORS_Sig;

   procedure Lemma_Eq_FORS_Sig (X, Y : in FORS_Sig)
     with Ghost,
          Global => null,
          Pre    => X = Y,
          Post   => Eq_FORS_Sig (X, Y);

   procedure Lemma_Eq_FORS_Sig (X, Y : in FORS_Sig)
   is
   begin
      for I in FORS_Tree_Index loop
         Lemma_Eq_FORS_Elem (X (I), Y (I));
         pragma Loop_Invariant (for all I2 in 0 .. I => Eq_FORS_Elem (X (I2), Y (I2)));
      end loop;
   end Lemma_Eq_FORS_Sig;

   --  Byte strings with equal bytes are equal
   procedure Lemma_Bytes_Eq (X, Y : in Bytes_N)
     with Ghost,
          Global => null,
          Pre    => (for all B in Index_N => X (B) = Y (B)),
          Post   => X = Y;

   procedure Lemma_Bytes_Eq (X, Y : in Bytes_N)
   is null;

   ------------------------------------------------------
   --  The message digest and FORS address
   ------------------------------------------------------

   function Split_Digest (Digest : in Bytes_M) return Digest_Parts
   is
      --  Lengths of tmp_idx_tree and tmp_idx_leaf in bytes
      Tree_Bytes : constant := (H - H_Tick + 7) / 8;  --  Ceiling ((h - h') / 8)
      Leaf_Bytes : constant := (H_Tick + 7) / 8;      --  Ceiling (h' / 8)
      pragma Assert (MD_Bytes + Tree_Bytes + Leaf_Bytes = M);

      Tree_Start : constant := MD_Bytes;
      Leaf_Start : constant := MD_Bytes + Tree_Bytes;

      Result : Digest_Parts;
   begin
      --  Line 6 of Algorithm 19 (line 9 of Algorithm 20)
      Result.MD := Digest (0 .. MD_Bytes - 1);

      --  Lines 7 and 9 of Algorithm 19 (lines 10 and 12 of Algorithm 20)
      Result.Idx_Tree :=
        Conversions.To_Int (Digest (Tree_Start .. Tree_Start + Tree_Bytes - 1)) mod 2**(H - H_Tick);

      --  Lines 8 and 10 of Algorithm 19 (lines 11 and 13 of Algorithm 20)
      Result.Idx_Leaf :=
        U32 (Conversions.To_Int (Digest (Leaf_Start .. Leaf_Start + Leaf_Bytes - 1)) mod 2**H_Tick);

      return Result;
   end Split_Digest;

   function FORS_ADRS (P : in Digest_Parts) return ADRS_Bytes
   is
      R : ADRS_Bytes := (others => 0);
   begin
      ADRS.Set_Tree_Address (R, P.Idx_Tree);
      ADRS.Set_Type_And_Clear (R, ADRS.FORS_TREE);
      ADRS.Set_Key_Pair_Address (R, P.Idx_Leaf);
      return R;
   end FORS_ADRS;

   ------------------------------------------------------
   --  Algorithm 18
   ------------------------------------------------------

   function SLH_Keygen_Internal (SK_Seed : in Bytes_N;
                                 SK_Prf  : in Bytes_N;
                                 PK_Seed : in Bytes_N) return Key_Parts
   is
      --  Lines 1 and 2
      Adr     : constant ADRS_Bytes := HT.Layer_ADRS (D - 1, 0);
      --  Line 3
      PK_Root : constant Bytes_N := XMSS.XMSS_Node (SK_Seed, 0, H_Tick, PK_Seed, Adr);
   begin
      --  Line 4
      return (SK => (SK_Seed => SK_Seed,
                     SK_Prf  => SK_Prf,
                     PK_Seed => PK_Seed,
                     PK_Root => PK_Root),
              PK => (PK_Seed => PK_Seed,
                     PK_Root => PK_Root));
   end SLH_Keygen_Internal;

   ------------------------------------------------------
   --  Algorithm 19
   ------------------------------------------------------

   function SLH_Sign_Internal (Msg    : in Byte_Seq;
                               SK     : in SK_Parts;
                               Addrnd : in Bytes_N) return Signature
   is
      --  Lines 2 and 3
      R       : constant Bytes_N      := Randomizer (Msg, SK, Addrnd);
      --  Lines 5 to 10
      P       : constant Digest_Parts := Digest_Of (Msg, R, SK.PK_Seed, SK.PK_Root);
      --  Lines 1 and 11 to 13
      Adr     : constant ADRS_Bytes   := FORS_ADRS (P);
      --  Line 14
      SF      : constant FORS_Sig     := FORS.FORS_Sign (P.MD, SK.SK_Seed, SK.PK_Seed, Adr);
      --  Line 16
      PK_FORS : constant Bytes_N      := FORS.FORS_PK_From_Sig (SF, P.MD, SK.PK_Seed, Adr);
      --  Line 17
      SH      : constant HT_Sig       := HT.HT_Sign (PK_FORS, SK.SK_Seed, SK.PK_Seed,
                                                     P.Idx_Tree, P.Idx_Leaf);
      Result  : Signature := (others => 0);
   begin
      Result (0 .. N - 1)                 := R;                            --  Line 4
      pragma Assert (for all B in Index_N => Result (B) = R (B));
      Result (FORS_Start .. HT_Start - 1) := Formats.FORS_To_Bytes (SF);  --  Line 15
      pragma Assert (for all B in Index_N => Result (B) = R (B));
      Result (HT_Start .. Sig_Bytes - 1)  := Formats.HT_To_Bytes (SH);    --  Line 18
      pragma Assert (for all B in Index_N => Result (B) = R (B));

      --  Parsing Result gives R, SF and SH
      Lemma_Bytes_Eq (Formats.Get_R (Result), R);
      Formats.Lemma_FORS_Bytes (Formats.Get_SIG_FORS (Result), SF);
      Formats.Lemma_HT_Bytes (Formats.Get_SIG_HT (Result), SH);
      return Result;  --  Line 19
   end SLH_Sign_Internal;

   function SLH_Sign_Internal_Deterministic (Msg : in Byte_Seq;
                                             SK  : in SK_Parts) return Signature
   is
   begin
      return SLH_Sign_Internal (Msg, SK, SK.PK_Seed);
   end SLH_Sign_Internal_Deterministic;

   ------------------------------------------------------
   --  Algorithm 20
   ------------------------------------------------------

   function SLH_Verify_Internal (Msg : in Byte_Seq;
                                 Sig : in Signature;
                                 PK  : in PK_Parts) return Boolean
   is
      --  Lines 1 to 3. Sig'Length = Sig_Bytes, since Sig is a Signature

      --  Lines 5 to 7
      R       : constant Bytes_N      := Formats.Get_R (Sig);
      SF      : constant FORS_Sig     := Formats.FORS_From_Bytes (Formats.Get_SIG_FORS (Sig));
      SH      : constant HT_Sig       := Formats.HT_From_Bytes (Formats.Get_SIG_HT (Sig));
      --  Lines 8 to 13
      P       : constant Digest_Parts := Digest_Of (Msg, R, PK.PK_Seed, PK.PK_Root);
      --  Lines 4 and 14 to 16
      Adr     : constant ADRS_Bytes   := FORS_ADRS (P);
      --  Line 17
      PK_FORS : constant Bytes_N      := FORS.FORS_PK_From_Sig (SF, P.MD, PK.PK_Seed, Adr);
   begin
      --  Line 18
      return HT.HT_Verify (PK_FORS, SH, PK.PK_Seed, P.Idx_Tree, P.Idx_Leaf, PK.PK_Root);
   end SLH_Verify_Internal;

   ------------------------------------------------------
   --  Correctness
   ------------------------------------------------------

   procedure Theorem_Correctness (SK_Seed : in Bytes_N;
                                  SK_Prf  : in Bytes_N;
                                  PK_Seed : in Bytes_N;
                                  Msg     : in Byte_Seq;
                                  Addrnd  : in Bytes_N)
   is
      KP      : constant Key_Parts     := SLH_Keygen_Internal (SK_Seed, SK_Prf, PK_Seed);
      S       : constant Signature    := SLH_Sign_Internal (Msg, KP.SK, Addrnd);

      --  The values computed by SLH_Sign_Internal
      R       : constant Bytes_N      := Randomizer (Msg, KP.SK, Addrnd);
      P       : constant Digest_Parts := Digest_Of (Msg, R, KP.SK.PK_Seed, KP.SK.PK_Root);
      Adr     : constant ADRS_Bytes   := FORS_ADRS (P);
      SF      : constant FORS_Sig     := FORS.FORS_Sign (P.MD, KP.SK.SK_Seed, KP.SK.PK_Seed, Adr);
      PK_FORS : constant Bytes_N      := FORS.FORS_PK_From_Sig (SF, P.MD, KP.SK.PK_Seed, Adr);
      SH      : constant HT_Sig       := HT.HT_Sign (PK_FORS, KP.SK.SK_Seed, KP.SK.PK_Seed,
                                                     P.Idx_Tree, P.Idx_Leaf);
   begin
      --  The public key and its copy in the private key are equal,
      --  and R in S is the randomizer, so SLH_Verify_Internal computes
      --  the same digest, and so the same idx_tree, idx_leaf and ADRS
      Lemma_Eq_N (KP.PK.PK_Seed, KP.SK.PK_Seed);
      Lemma_Eq_N (KP.PK.PK_Root, KP.SK.PK_Root);
      Lemma_Eq_N (Formats.Get_R (S), R);

      --  The FORS signature parsed from S is SF, so SLH_Verify_Internal
      --  computes the FORS public key PK_FORS, as SLH_Sign_Internal does
      Lemma_Eq_FORS_Sig (Formats.FORS_From_Bytes (Formats.Get_SIG_FORS (S)), SF);

      --  The hypertree signature parsed from S is the hypertree
      --  signature of PK_FORS, so by the hypertree round trip theorem,
      --  it verifies against the root of the top layer tree
      Lemma_Eq_HT_Sig (Formats.HT_From_Bytes (Formats.Get_SIG_HT (S)), SH);
      HT.Theorem_Round_Trip (PK_FORS, KP.SK.SK_Seed, KP.SK.PK_Seed, P.Idx_Tree, P.Idx_Leaf);

      --  That root is PK.root
      Lemma_Eq_N (KP.SK.SK_Seed, SK_Seed);
      Lemma_Eq_N (KP.SK.PK_Seed, PK_Seed);
      Lemma_Eq_N (KP.PK.PK_Root, Root_Of (SK_Seed, PK_Seed));
   end Theorem_Correctness;

   --=======================================
   --  Support for the external functions
   --=======================================

   function SK_To_Bytes (S : in SK_Parts) return Private_Key
   is
      R : Private_Key := (others => 0);
   begin
      R (0 .. N - 1)         := S.SK_Seed;
      R (N .. 2 * N - 1)     := S.SK_Prf;
      pragma Assert (for all B in Index_N => R (B) = S.SK_Seed (B));
      R (2 * N .. 3 * N - 1) := S.PK_Seed;
      pragma Assert (for all B in Index_N => R (B) = S.SK_Seed (B) and R (N + B) = S.SK_Prf (B));
      R (3 * N .. 4 * N - 1) := S.PK_Root;
      return R;
   end SK_To_Bytes;

   function SK_From_Bytes (X : in Private_Key) return SK_Parts
   is
   begin
      return (SK_Seed => X (0 .. N - 1),
              SK_Prf  => X (N .. 2 * N - 1),
              PK_Seed => X (2 * N .. 3 * N - 1),
              PK_Root => X (3 * N .. 4 * N - 1));
   end SK_From_Bytes;

   function PK_To_Bytes (P : in PK_Parts) return Public_Key
   is
      R : Public_Key := (others => 0);
   begin
      R (0 .. N - 1)     := P.PK_Seed;
      R (N .. 2 * N - 1) := P.PK_Root;
      return R;
   end PK_To_Bytes;

   function PK_From_Bytes (X : in Public_Key) return PK_Parts
   is
   begin
      return (PK_Seed => X (0 .. N - 1),
              PK_Root => X (N .. 2 * N - 1));
   end PK_From_Bytes;

   procedure Lemma_SK_Bytes (X : in Private_Key; S : in SK_Parts)
   is null;

   procedure Lemma_PK_Bytes (X : in Public_Key; P : in PK_Parts)
   is null;

   function PK_Seed_Of (SK : in Private_Key) return Bytes_N
   is
   begin
      return SK (2 * N .. 3 * N - 1);
   end PK_Seed_Of;

   procedure Lemma_Pure_Message_Unique (X, Y : in Byte_Seq; Msg : in Byte_Seq; Ctx : in Byte_Seq)
   is
      C : constant I32 := Ctx'Length;
   begin
      for K in X'Range loop
         if K >= 2 + C then
            pragma Assert (X (2 + C + (K - 2 - C)) = Msg (Msg'First + (K - 2 - C)));
            pragma Assert (Y (2 + C + (K - 2 - C)) = Msg (Msg'First + (K - 2 - C)));
         elsif K >= 2 then
            pragma Assert (X (2 + (K - 2)) = Ctx (Ctx'First + (K - 2)));
            pragma Assert (Y (2 + (K - 2)) = Ctx (Ctx'First + (K - 2)));
         end if;
         pragma Loop_Invariant (for all K2 in X'First .. K => X (K2) = Y (K2));
      end loop;
   end Lemma_Pure_Message_Unique;

   procedure Lemma_Pre_Hash_Message_Unique (X, Y : in Byte_Seq;
                                            Ctx  : in Byte_Seq;
                                            OID  : in Bytes_OID;
                                            PH_M : in Bytes_64)
   is
      C : constant I32 := Ctx'Length;
   begin
      for K in X'Range loop
         if K >= 2 + C + OID_Bytes then
            pragma Assert (X (2 + C + OID_Bytes + (K - 2 - C - OID_Bytes)) =
                             PH_M (K - 2 - C - OID_Bytes));
            pragma Assert (Y (2 + C + OID_Bytes + (K - 2 - C - OID_Bytes)) =
                             PH_M (K - 2 - C - OID_Bytes));
         elsif K >= 2 + C then
            pragma Assert (X (2 + C + (K - 2 - C)) = OID (K - 2 - C));
            pragma Assert (Y (2 + C + (K - 2 - C)) = OID (K - 2 - C));
         elsif K >= 2 then
            pragma Assert (X (2 + (K - 2)) = Ctx (Ctx'First + (K - 2)));
            pragma Assert (Y (2 + (K - 2)) = Ctx (Ctx'First + (K - 2)));
         end if;
         pragma Loop_Invariant (for all K2 in X'First .. K => X (K2) = Y (K2));
      end loop;
   end Lemma_Pre_Hash_Message_Unique;

   procedure Build_Pure_Message (Msg     : in     Byte_Seq;
                                 Ctx     : in     Byte_Seq;
                                 M_Prime :    out Byte_Seq)
   is
      C : constant I32 := Ctx'Length;
   begin
      M_Prime := (others => 0);
      M_Prime (0) := 0;                       --  toByte (0, 1)
      M_Prime (1) := Byte (C);                --  toByte (|ctx|, 1)
      M_Prime (2 .. 1 + C) := Ctx;            --  ctx
      pragma Assert (M_Prime (0) = 0 and M_Prime (1) = Byte (C));
      M_Prime (2 + C .. M_Prime'Last) := Msg;  --  M
      pragma Assert (M_Prime (0) = 0 and M_Prime (1) = Byte (C));
   end Build_Pure_Message;

   procedure Build_Pre_Hash_Message (Ctx     : in     Byte_Seq;
                                     OID     : in     Bytes_OID;
                                     PH_M    : in     Bytes_64;
                                     M_Prime :    out Byte_Seq)
   is
      C : constant I32 := Ctx'Length;
   begin
      M_Prime := (others => 0);
      M_Prime (0) := 1;                                            --  toByte (1, 1)
      M_Prime (1) := Byte (C);                                     --  toByte (|ctx|, 1)
      M_Prime (2 .. 1 + C) := Ctx;                                 --  ctx
      pragma Assert (M_Prime (0) = 1 and M_Prime (1) = Byte (C));
      M_Prime (2 + C .. 1 + C + OID_Bytes) := OID;                 --  OID
      pragma Assert (M_Prime (0) = 1 and M_Prime (1) = Byte (C));
      M_Prime (2 + C + OID_Bytes .. M_Prime'Last) := PH_M;         --  PH_M
      pragma Assert (M_Prime (0) = 1 and M_Prime (1) = Byte (C));
   end Build_Pre_Hash_Message;

   function Pure_Message (Msg : in Byte_Seq; Ctx : in Byte_Seq) return Byte_Seq
   is
      R : Byte_Seq (0 .. 2 + Ctx'Length + Msg'Length - 1);
   begin
      Build_Pure_Message (Msg, Ctx, R);
      return R;
   end Pure_Message;

   function Pre_Hash_Message (Msg : in Byte_Seq; Ctx : in Byte_Seq; PH : in Pre_Hash_Function)
                              return Byte_Seq
   is
      R : Byte_Seq (0 .. Pre_Hash_Message_Length + Ctx'Length - 1);
   begin
      Build_Pre_Hash_Message (Ctx, OIDs (PH), Hash.Pre_Hash (PH, Msg), R);
      return R;
   end Pre_Hash_Message;

   ------------------------------------------------------
   --  Logical equality, as above
   ------------------------------------------------------

   function Eq_Seq (X, Y : in Byte_Seq) return Boolean
     with Ghost,
          Global   => null,
          Annotate => (GNATprove, Logical_Equal);

   function Eq_Seq (X, Y : in Byte_Seq) return Boolean
     with SPARK_Mode => Off
   is
   begin
      return X = Y;
   end Eq_Seq;

   procedure Lemma_Eq_Seq (X, Y : in Byte_Seq)
     with Ghost,
          Global => null,
          Pre    => X'First = Y'First and X'Last = Y'Last and X = Y,
          Post   => Eq_Seq (X, Y);

   procedure Lemma_Eq_Seq (X, Y : in Byte_Seq)
   is null;

   function Eq_SK_Parts (X, Y : in SK_Parts) return Boolean
     with Ghost,
          Global   => null,
          Annotate => (GNATprove, Logical_Equal);

   function Eq_SK_Parts (X, Y : in SK_Parts) return Boolean
     with SPARK_Mode => Off
   is
   begin
      return X = Y;
   end Eq_SK_Parts;

   procedure Lemma_Eq_SK_Parts (X, Y : in SK_Parts)
     with Ghost,
          Global => null,
          Pre    => X = Y,
          Post   => Eq_SK_Parts (X, Y);

   procedure Lemma_Eq_SK_Parts (X, Y : in SK_Parts)
   is
   begin
      Lemma_Eq_N (X.SK_Seed, Y.SK_Seed);
      Lemma_Eq_N (X.SK_Prf, Y.SK_Prf);
      Lemma_Eq_N (X.PK_Seed, Y.PK_Seed);
      Lemma_Eq_N (X.PK_Root, Y.PK_Root);
   end Lemma_Eq_SK_Parts;

   function Eq_PK_Parts (X, Y : in PK_Parts) return Boolean
     with Ghost,
          Global   => null,
          Annotate => (GNATprove, Logical_Equal);

   function Eq_PK_Parts (X, Y : in PK_Parts) return Boolean
     with SPARK_Mode => Off
   is
   begin
      return X = Y;
   end Eq_PK_Parts;

   procedure Lemma_Eq_PK_Parts (X, Y : in PK_Parts)
     with Ghost,
          Global => null,
          Pre    => X = Y,
          Post   => Eq_PK_Parts (X, Y);

   procedure Lemma_Eq_PK_Parts (X, Y : in PK_Parts)
   is
   begin
      Lemma_Eq_N (X.PK_Seed, Y.PK_Seed);
      Lemma_Eq_N (X.PK_Root, Y.PK_Root);
   end Lemma_Eq_PK_Parts;

   --=======================================
   --  Exported subprograms
   --=======================================

   ------------------------------------------------------
   --  Algorithm 21
   ------------------------------------------------------

   function SLH_Keygen (SK_Seed : in Bytes_N;
                        SK_Prf  : in Bytes_N;
                        PK_Seed : in Bytes_N) return Key_Pair
     with Refined_Post =>
            SLH_Keygen'Result =
              (SK => SK_To_Bytes (SLH_Keygen_Internal (SK_Seed, SK_Prf, PK_Seed).SK),
               PK => PK_To_Bytes (SLH_Keygen_Internal (SK_Seed, SK_Prf, PK_Seed).PK))
   is
      --  Lines 1 to 6. The caller provides SK.seed, SK.prf and PK.seed

      --  Line 7
      KI : constant Key_Parts := SLH_Keygen_Internal (SK_Seed, SK_Prf, PK_Seed);
   begin
      return (SK => SK_To_Bytes (KI.SK),
              PK => PK_To_Bytes (KI.PK));
   end SLH_Keygen;

   ------------------------------------------------------
   --  Algorithm 22
   ------------------------------------------------------

   function SLH_Sign (Msg    : in Byte_Seq;
                      Ctx    : in Byte_Seq;
                      SK     : in Private_Key;
                      Addrnd : in Bytes_N) return Signature
     with Refined_Post =>
            SLH_Sign'Result = SLH_Sign_Internal (Pure_Message (Msg, Ctx), SK_From_Bytes (SK), Addrnd)
   is
      --  Lines 1 to 7. The precondition requires |ctx| <= 255,
      --  and the caller provides addrnd

      --  Line 8
      M_Prime : Byte_Seq (0 .. 2 + Ctx'Length + Msg'Length - 1);
   begin
      Build_Pure_Message (Msg, Ctx, M_Prime);
      Lemma_Pure_Message_Unique (M_Prime, Pure_Message (Msg, Ctx), Msg, Ctx);
      Lemma_Eq_Seq (M_Prime, Pure_Message (Msg, Ctx));

      --  Lines 9 and 10
      return SLH_Sign_Internal (M_Prime, SK_From_Bytes (SK), Addrnd);
   end SLH_Sign;

   function SLH_Sign_Deterministic (Msg : in Byte_Seq;
                                    Ctx : in Byte_Seq;
                                    SK  : in Private_Key) return Signature
   is
   begin
      --  opt_rand is PK.seed in Algorithm 19 line 2
      return SLH_Sign (Msg, Ctx, SK, PK_Seed_Of (SK));
   end SLH_Sign_Deterministic;

   ------------------------------------------------------
   --  Algorithm 23
   ------------------------------------------------------

   function Hash_SLH_Sign (Msg    : in Byte_Seq;
                           Ctx    : in Byte_Seq;
                           PH     : in Pre_Hash_Function;
                           SK     : in Private_Key;
                           Addrnd : in Bytes_N) return Signature
     with Refined_Post =>
            Hash_SLH_Sign'Result =
              SLH_Sign_Internal (Pre_Hash_Message (Msg, Ctx, PH), SK_From_Bytes (SK), Addrnd)
   is
      --  Lines 1 to 7. The precondition requires |ctx| <= 255,
      --  and the caller provides addrnd

      M_Prime : Byte_Seq (0 .. Pre_Hash_Message_Length + Ctx'Length - 1);
   begin
      --  Lines 8 to 24
      Build_Pre_Hash_Message (Ctx, OIDs (PH), Hash.Pre_Hash (PH, Msg), M_Prime);
      Lemma_Pre_Hash_Message_Unique (M_Prime, Pre_Hash_Message (Msg, Ctx, PH),
                                     Ctx, OIDs (PH), Hash.Pre_Hash (PH, Msg));
      Lemma_Eq_Seq (M_Prime, Pre_Hash_Message (Msg, Ctx, PH));

      --  Lines 25 and 26
      return SLH_Sign_Internal (M_Prime, SK_From_Bytes (SK), Addrnd);
   end Hash_SLH_Sign;

   function Hash_SLH_Sign_Deterministic (Msg : in Byte_Seq;
                                         Ctx : in Byte_Seq;
                                         PH  : in Pre_Hash_Function;
                                         SK  : in Private_Key) return Signature
   is
   begin
      --  opt_rand is PK.seed in Algorithm 19 line 2
      return Hash_SLH_Sign (Msg, Ctx, PH, SK, PK_Seed_Of (SK));
   end Hash_SLH_Sign_Deterministic;

   ------------------------------------------------------
   --  Algorithm 24
   ------------------------------------------------------

   function SLH_Verify (Msg : in Byte_Seq;
                        Sig : in Signature;
                        Ctx : in Byte_Seq;
                        PK  : in Public_Key) return Boolean
     with Refined_Post =>
            SLH_Verify'Result =
              (Valid_Context (Ctx) and then
               SLH_Verify_Internal (Pure_Message (Msg, Ctx), Sig, PK_From_Bytes (PK)))
   is
   begin
      --  Lines 1 to 3
      if not Valid_Context (Ctx) then
         return False;
      end if;

      declare
         --  Line 4
         M_Prime : Byte_Seq (0 .. 2 + Ctx'Length + Msg'Length - 1);
      begin
         Build_Pure_Message (Msg, Ctx, M_Prime);
         Lemma_Pure_Message_Unique (M_Prime, Pure_Message (Msg, Ctx), Msg, Ctx);
         Lemma_Eq_Seq (M_Prime, Pure_Message (Msg, Ctx));

         --  Line 5
         return SLH_Verify_Internal (M_Prime, Sig, PK_From_Bytes (PK));
      end;
   end SLH_Verify;

   ------------------------------------------------------
   --  Algorithm 25
   ------------------------------------------------------

   function Hash_SLH_Verify (Msg : in Byte_Seq;
                             Sig : in Signature;
                             Ctx : in Byte_Seq;
                             PH  : in Pre_Hash_Function;
                             PK  : in Public_Key) return Boolean
     with Refined_Post =>
            Hash_SLH_Verify'Result =
              (Valid_Context (Ctx) and then
               SLH_Verify_Internal (Pre_Hash_Message (Msg, Ctx, PH), Sig, PK_From_Bytes (PK)))
   is
   begin
      --  Lines 1 to 3
      if not Valid_Context (Ctx) then
         return False;
      end if;

      declare
         M_Prime : Byte_Seq (0 .. Pre_Hash_Message_Length + Ctx'Length - 1);
      begin
         --  Lines 4 to 20
         Build_Pre_Hash_Message (Ctx, OIDs (PH), Hash.Pre_Hash (PH, Msg), M_Prime);
         Lemma_Pre_Hash_Message_Unique (M_Prime, Pre_Hash_Message (Msg, Ctx, PH),
                                        Ctx, OIDs (PH), Hash.Pre_Hash (PH, Msg));
         Lemma_Eq_Seq (M_Prime, Pre_Hash_Message (Msg, Ctx, PH));

         --  Line 21
         return SLH_Verify_Internal (M_Prime, Sig, PK_From_Bytes (PK));
      end;
   end Hash_SLH_Verify;

   ------------------------------------------------------
   --  Correctness
   --
   --  Signing and verifying build the same M', and the keys
   --  from SLH_Keygen parse to the keys from SLH_Keygen_Internal,
   --  so these follow from Theorem_Correctness for M'
   ------------------------------------------------------

   procedure Theorem_Correctness_Pure (SK_Seed : in Bytes_N;
                                       SK_Prf  : in Bytes_N;
                                       PK_Seed : in Bytes_N;
                                       Msg     : in Byte_Seq;
                                       Ctx     : in Byte_Seq;
                                       Addrnd  : in Bytes_N)
   is
      KI : constant Key_Parts := SLH_Keygen_Internal (SK_Seed, SK_Prf, PK_Seed);
      KP : constant Key_Pair  := SLH_Keygen (SK_Seed, SK_Prf, PK_Seed);
      MP : constant Byte_Seq  := Pure_Message (Msg, Ctx);
      S  : constant Signature := SLH_Sign (Msg, Ctx, KP.SK, Addrnd);
   begin
      --  The keys from SLH_Keygen parse to the keys from SLH_Keygen_Internal
      Lemma_SK_Bytes (KP.SK, KI.SK);
      Lemma_PK_Bytes (KP.PK, KI.PK);
      Lemma_Eq_SK_Parts (SK_From_Bytes (KP.SK), KI.SK);
      Lemma_Eq_PK_Parts (PK_From_Bytes (KP.PK), KI.PK);

      --  So S is the internal signature of M', which verifies
      pragma Assert (S = SLH_Sign_Internal (MP, KI.SK, Addrnd));
      Lemma_Eq_Seq (S, SLH_Sign_Internal (MP, KI.SK, Addrnd));
      Theorem_Correctness (SK_Seed, SK_Prf, PK_Seed, MP, Addrnd);
      pragma Assert (SLH_Verify_Internal (MP, S, KI.PK));
      pragma Assert (SLH_Verify_Internal (Pure_Message (Msg, Ctx), S, PK_From_Bytes (KP.PK)));
   end Theorem_Correctness_Pure;

   procedure Theorem_Correctness_Pre_Hash (SK_Seed : in Bytes_N;
                                           SK_Prf  : in Bytes_N;
                                           PK_Seed : in Bytes_N;
                                           Msg     : in Byte_Seq;
                                           Ctx     : in Byte_Seq;
                                           PH      : in Pre_Hash_Function;
                                           Addrnd  : in Bytes_N)
   is
      KI : constant Key_Parts := SLH_Keygen_Internal (SK_Seed, SK_Prf, PK_Seed);
      KP : constant Key_Pair  := SLH_Keygen (SK_Seed, SK_Prf, PK_Seed);
      MP : constant Byte_Seq  := Pre_Hash_Message (Msg, Ctx, PH);
      S  : constant Signature := Hash_SLH_Sign (Msg, Ctx, PH, KP.SK, Addrnd);
   begin
      --  As for Theorem_Correctness_Pure
      Lemma_SK_Bytes (KP.SK, KI.SK);
      Lemma_PK_Bytes (KP.PK, KI.PK);
      Lemma_Eq_SK_Parts (SK_From_Bytes (KP.SK), KI.SK);
      Lemma_Eq_PK_Parts (PK_From_Bytes (KP.PK), KI.PK);

      pragma Assert (S = SLH_Sign_Internal (MP, KI.SK, Addrnd));
      Lemma_Eq_Seq (S, SLH_Sign_Internal (MP, KI.SK, Addrnd));
      Theorem_Correctness (SK_Seed, SK_Prf, PK_Seed, MP, Addrnd);
      pragma Assert (SLH_Verify_Internal (MP, S, KI.PK));
      pragma Assert (SLH_Verify_Internal (Pre_Hash_Message (Msg, Ctx, PH), S, PK_From_Bytes (KP.PK)));
   end Theorem_Correctness_Pre_Hash;

end SLH;
