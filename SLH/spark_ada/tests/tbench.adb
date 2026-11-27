--  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
--  SPDX-License-Identifier: Apache-2.0

with Ada.Command_Line; use Ada.Command_Line;
with Ada.Text_IO;      use Ada.Text_IO;
with Interfaces;       use Interfaces;
with Cycles;
with SLH;              use SLH;

--  Benchmarks SLH_Keygen, SLH_Sign and SLH_Verify in CPU cycles.
--
--    tbench LABEL [KEYGEN_ITER SIGN_ITER VERIFY_ITER]
--
--  LABEL names the build variant. Each operation is run once to warm
--  up, then timed ITER times. For each operation, one line is written
--  to stdout:
--
--    BENCH LABEL OPERATION MEDIAN MIN ITER
--
--  where MEDIAN and MIN are in cycles. SLH/checkers/bench_report.py reads
--  these lines. Every signature is checked with SLH_Verify, outside the
--  timed region, so a broken build can't produce results.
--
--  The program exits with a failure status if the cycle counter is not
--  working, for example if it needs root and is not run as root.
procedure TBench
is
   subtype Cycle_Count is Unsigned_64;
   type Cycle_Array is array (Positive range <>) of Cycle_Count;

   Bad_Counter : exception;
   Bad_Result  : exception;

   Keygen_Iter : Positive := 10;
   Sign_Iter   : Positive := 10;
   Verify_Iter : Positive := 50;

   --  Fixed inputs. The values don't matter
   function Pattern (Seed : Byte) return Bytes_N
   is
      R : Bytes_N;
   begin
      for I in R'Range loop
         R (I) := Seed + 7 * Byte (I mod 256);
      end loop;
      return R;
   end Pattern;

   SK_Seed : constant Bytes_N := Pattern (1);
   SK_Prf  : constant Bytes_N := Pattern (2);
   PK_Seed : constant Bytes_N := Pattern (3);
   Addrnd  : constant Bytes_N := Pattern (4);
   Msg     : constant Byte_Seq (0 .. 31) := Pattern (5);
   Ctx     : constant Byte_Seq (1 .. 0) := (others => 0);

   KP  : Key_Pair;
   Sig : Signature;

   --  Sorts X into ascending order. Insertion sort, since X is short
   procedure Sort (X : in out Cycle_Array)
   is
      T : Cycle_Count;
      J : Natural;
   begin
      for I in X'First + 1 .. X'Last loop
         T := X (I);
         J := I - 1;
         while J >= X'First and then X (J) > T loop
            X (J + 1) := X (J);
            J := J - 1;
         end loop;
         X (J + 1) := T;
      end loop;
   end Sort;

   procedure Report (Op : in String; X : in out Cycle_Array)
   is
      Median : Cycle_Count;
      N      : constant Positive := X'Length;
   begin
      Sort (X);
      if N mod 2 = 1 then
         Median := X (X'First + N / 2);
      else
         Median := (X (X'First + N / 2 - 1) + X (X'First + N / 2)) / 2;
      end if;
      if X (X'First) = 0 then
         raise Bad_Counter;
      end if;
      Put_Line ("BENCH " & Argument (1) & " " & Op &
                  Median'Img & X (X'First)'Img & N'Img);
   end Report;

   procedure Do_Keygen
   is
   begin
      KP := SLH_Keygen (SK_Seed, SK_Prf, PK_Seed);
   end Do_Keygen;

   procedure Do_Sign
   is
   begin
      Sig := SLH_Sign (Msg, Ctx, KP.SK, Addrnd);
   end Do_Sign;

   Verified : Boolean;

   procedure Do_Verify
   is
   begin
      Verified := SLH_Verify (Msg, Sig, Ctx, KP.PK);
   end Do_Verify;

   --  Runs Op once to warm up, then times it N times. After each run,
   --  Check is called outside the timed region
   generic
      with procedure Op;
      with procedure Check;
   procedure Time_It (Name : in String; N : in Positive);

   procedure Time_It (Name : in String; N : in Positive)
   is
      T     : Cycle_Array (1 .. N);
      Start : Cycle_Count;
      Stop  : Cycle_Count;
   begin
      Op;
      Check;
      for I in T'Range loop
         Start := Cycles.Get_Cycle_Counter;
         Op;
         Stop := Cycles.Get_Cycle_Counter;
         if Stop <= Start then
            raise Bad_Counter;
         end if;
         T (I) := Stop - Start;
         Check;
      end loop;
      Report (Name, T);
   end Time_It;

   procedure Check_Keygen
   is
   begin
      if KP.PK /= KP.SK (2 * N .. 4 * N - 1) then
         raise Bad_Result;
      end if;
   end Check_Keygen;

   procedure Check_Sign
   is
   begin
      if not SLH_Verify (Msg, Sig, Ctx, KP.PK) then
         raise Bad_Result;
      end if;
   end Check_Sign;

   procedure Check_Verify
   is
   begin
      if not Verified then
         raise Bad_Result;
      end if;
   end Check_Verify;

   procedure Time_Keygen is new Time_It (Do_Keygen, Check_Keygen);
   procedure Time_Sign is new Time_It (Do_Sign, Check_Sign);
   procedure Time_Verify is new Time_It (Do_Verify, Check_Verify);
begin
   if Argument_Count /= 1 and Argument_Count /= 4 then
      Put_Line (Standard_Error,
                "usage: tbench LABEL [KEYGEN_ITER SIGN_ITER VERIFY_ITER]");
      Set_Exit_Status (Failure);
      return;
   end if;
   if Argument_Count = 4 then
      Keygen_Iter := Positive'Value (Argument (2));
      Sign_Iter   := Positive'Value (Argument (3));
      Verify_Iter := Positive'Value (Argument (4));
   end if;

   Cycles.Enable_Cycle_Counter;
   Time_Keygen ("Keygen", Keygen_Iter);
   Time_Sign ("Sign", Sign_Iter);
   Time_Verify ("Verify", Verify_Iter);
   Cycles.Disable_Cycle_Counter;
exception
   when Bad_Counter =>
      Put_Line (Standard_Error,
                "tbench: the cycle counter is not working. On macOS, " &
                  "run as root. See SLH/hal/README.md");
      Set_Exit_Status (Failure);
   when Bad_Result =>
      Put_Line (Standard_Error, "tbench: wrong result for " & Argument (1));
      Set_Exit_Status (Failure);
end TBench;
