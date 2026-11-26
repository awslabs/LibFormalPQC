--  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
--  SPDX-License-Identifier: Apache-2.0

with Ada.Text_IO; use Ada.Text_IO;
with SLH.Debug;

package body SLH.KAT
  with SPARK_Mode => Off
is
   --  Output format, one record per test case:
   --
   --    Function = <name>
   --    Count = <n>
   --    <Input_Name> = <hex>      (one line per input, in parameter order)
   --    Result = <hex>
   --    <blank line>

   --  SHAKE256 has a rate of 136 bytes. The message lengths below
   --  are chosen so that the total input to SHAKE256 falls just
   --  below, on, and just above one and two multiples of the rate,
   --  for both PRF_Msg (64 bytes before M) and H_Msg (96 bytes before M)
   type Length_List is array (Positive range <>) of N32;

   Msg_Lengths : constant Length_List :=
     (0, 1, 39, 40, 41, 71, 72, 73, 135, 136, 137, 175, 176, 177, 1000);

   --  Values of L for T_L. 3 crosses the rate boundary,
   --  K is used for FORS roots and Len = 2N + 3 for WOTS+ public keys
   L_Values : constant Length_List := (1, 2, 3, K, 2 * N + Len2);

   Fixed_Cases : constant := 8;

   --  Simple xorshift32 generator for reproducible test inputs.
   --  The quality of the randomness does not matter here.
   State : Unsigned_32 := 16#5EED_1205#;

   function Next_Byte return Byte;

   function Next_Byte return Byte
   is
   begin
      State := State xor Shift_Left (State, 13);
      State := State xor Shift_Right (State, 17);
      State := State xor Shift_Left (State, 5);
      return Byte (State and 16#FF#);
   end Next_Byte;

   procedure Fill (D : out Byte_Seq);

   procedure Fill (D : out Byte_Seq)
   is
   begin
      for I in D'Range loop
         D (I) := Next_Byte;
      end loop;
   end Fill;

   procedure Header (Name : in String; Count : in Natural);

   procedure Header (Name : in String; Count : in Natural)
   is
   begin
      Put_Line ("Function = " & Name);
      Put_Line ("Count =" & Count'Img);
   end Header;

   procedure PRF_Msg_KATs;
   procedure H_Msg_KATs;
   procedure PRF_KATs;
   procedure T_L_KATs;
   procedure H_KATs;
   procedure F_KATs;

   procedure PRF_Msg_KATs
   is
      SK_Prf   : Bytes_N;
      Opt_Rand : Bytes_N;
      Count    : Natural := 0;
   begin
      for Len of Msg_Lengths loop
         declare
            M : Byte_Seq (0 .. Len - 1);
         begin
            Fill (SK_Prf);
            Fill (Opt_Rand);
            Fill (M);
            Header ("PRF_Msg", Count);
            Debug.Put_Line ("SK_Prf = ", SK_Prf);
            Debug.Put_Line ("Opt_Rand = ", Opt_Rand);
            Debug.Put_Line ("M = ", M);
            Debug.Put_Line ("Result = ", Hash.PRF_Msg (SK_Prf, Opt_Rand, M));
            New_Line;
            Count := Count + 1;
         end;
      end loop;
   end PRF_Msg_KATs;

   procedure H_Msg_KATs
   is
      R       : Bytes_N;
      PK_Seed : Bytes_N;
      PK_Root : Bytes_N;
      Count   : Natural := 0;
   begin
      for Len of Msg_Lengths loop
         declare
            M : Byte_Seq (0 .. Len - 1);
         begin
            Fill (R);
            Fill (PK_Seed);
            Fill (PK_Root);
            Fill (M);
            Header ("H_Msg", Count);
            Debug.Put_Line ("R = ", R);
            Debug.Put_Line ("PK_Seed = ", PK_Seed);
            Debug.Put_Line ("PK_Root = ", PK_Root);
            Debug.Put_Line ("M = ", M);
            Debug.Put_Line ("Result = ", Hash.H_Msg (R, PK_Seed, PK_Root, M));
            New_Line;
            Count := Count + 1;
         end;
      end loop;
   end H_Msg_KATs;

   procedure PRF_KATs
   is
      PK_Seed : Bytes_N;
      SK_Seed : Bytes_N;
      ADRS    : ADRS_Bytes;
   begin
      for Count in 0 .. Fixed_Cases - 1 loop
         Fill (PK_Seed);
         Fill (SK_Seed);
         Fill (ADRS);
         Header ("PRF", Count);
         Debug.Put_Line ("PK_Seed = ", PK_Seed);
         Debug.Put_Line ("SK_Seed = ", SK_Seed);
         Debug.Put_Line ("ADRS = ", ADRS);
         Debug.Put_Line ("Result = ", Hash.PRF (PK_Seed, SK_Seed, ADRS));
         New_Line;
      end loop;
   end PRF_KATs;

   procedure T_L_KATs
   is
      PK_Seed : Bytes_N;
      ADRS    : ADRS_Bytes;
      Count   : Natural := 0;
   begin
      for L of L_Values loop
         declare
            M_L : Byte_Seq (0 .. L * N - 1);
         begin
            Fill (PK_Seed);
            Fill (ADRS);
            Fill (M_L);
            Header ("T_L", Count);
            Debug.Put_Line ("PK_Seed = ", PK_Seed);
            Debug.Put_Line ("ADRS = ", ADRS);
            Debug.Put_Line ("M_L = ", M_L);
            Debug.Put_Line ("Result = ", Hash.T_L (PK_Seed, ADRS, M_L));
            New_Line;
            Count := Count + 1;
         end;
      end loop;
   end T_L_KATs;

   procedure H_KATs
   is
      PK_Seed : Bytes_N;
      ADRS    : ADRS_Bytes;
      M2      : Bytes_2N;
   begin
      for Count in 0 .. Fixed_Cases - 1 loop
         Fill (PK_Seed);
         Fill (ADRS);
         Fill (M2);
         Header ("H", Count);
         Debug.Put_Line ("PK_Seed = ", PK_Seed);
         Debug.Put_Line ("ADRS = ", ADRS);
         Debug.Put_Line ("M2 = ", M2);
         Debug.Put_Line ("Result = ", Hash.H (PK_Seed, ADRS, M2));
         New_Line;
      end loop;
   end H_KATs;

   procedure F_KATs
   is
      PK_Seed : Bytes_N;
      ADRS    : ADRS_Bytes;
      M1      : Bytes_N;
   begin
      for Count in 0 .. Fixed_Cases - 1 loop
         Fill (PK_Seed);
         Fill (ADRS);
         Fill (M1);
         Header ("F", Count);
         Debug.Put_Line ("PK_Seed = ", PK_Seed);
         Debug.Put_Line ("ADRS = ", ADRS);
         Debug.Put_Line ("M1 = ", M1);
         Debug.Put_Line ("Result = ", Hash.F (PK_Seed, ADRS, M1));
         New_Line;
      end loop;
   end F_KATs;

   procedure Hash_KATs
   is
   begin
      PRF_Msg_KATs;
      H_Msg_KATs;
      PRF_KATs;
      T_L_KATs;
      H_KATs;
      F_KATs;
   end Hash_KATs;

   ----------------------------------------------------------
   --  WOTS+ KATs
   ----------------------------------------------------------

   use WOTS;

   procedure Put_Int (Name : in String; V : in Integer);

   procedure Put_Int (Name : in String; V : in Integer)
   is
   begin
      Put_Line (Name & " =" & V'Img);
   end Put_Int;

   --  A WOTS+ address. Odd cases are fully random. Even cases
   --  are as set up by FIPS 205 Algorithms 10, 11 and 12: a random
   --  layer address, tree address and key pair address, with the
   --  type WOTS_HASH, and chain and hash addresses zero.
   procedure Fill_ADRS (A : out ADRS_Bytes; Count : in Natural);

   procedure Fill_ADRS (A : out ADRS_Bytes; Count : in Natural)
   is
      Key_Parts : ADRS_Bytes;
   begin
      Fill (A);
      if Count mod 2 = 0 then
         Fill (Key_Parts);
         ADRS.Set_Type_And_Clear (A, ADRS.WOTS_HASH);
         ADRS.Set_Key_Pair_Address (A, ADRS.Word (Key_Parts, 0));
      end if;
   end Fill_ADRS;

   --  Message M for case Count. Cases 0 and 1 give the largest and
   --  smallest checksums. Other cases are random.
   procedure Fill_M (M : out Bytes_N; Count : in Natural);

   procedure Fill_M (M : out Bytes_N; Count : in Natural)
   is
   begin
      case Count is
         when 0      => M := (others => 16#00#);
         when 1      => M := (others => 16#FF#);
         when others => Fill (M);
      end case;
   end Fill_M;

   type Chain_Case is record
      I, S : Chain_Index;
   end record;

   type Chain_Case_List is array (Positive range <>) of Chain_Case;

   Chain_Cases : constant Chain_Case_List :=
     ((0, 0), (0, 1), (0, 15), (15, 0), (14, 1), (1, 14),
      (3, 7), (7, 8), (5, 0), (8, 3));

   procedure Chain_KATs;
   procedure PK_Gen_KATs;
   procedure Sign_KATs;
   procedure PK_From_Sig_KATs;
   procedure Round_Trip_KATs;

   procedure Chain_KATs
   is
      X       : Bytes_N;
      PK_Seed : Bytes_N;
      A       : ADRS_Bytes;
      Count   : Natural := 0;
   begin
      for C of Chain_Cases loop
         Fill (X);
         Fill (PK_Seed);
         Fill_ADRS (A, Count);
         Header ("Chain", Count);
         Debug.Put_Line ("X = ", X);
         Put_Int ("I", Integer (C.I));
         Put_Int ("S", Integer (C.S));
         Debug.Put_Line ("PK_Seed = ", PK_Seed);
         Debug.Put_Line ("ADRS = ", A);
         Debug.Put_Line ("Result = ", Chain (X, C.I, C.S, PK_Seed, A));
         New_Line;
         Count := Count + 1;
      end loop;
   end Chain_KATs;

   procedure PK_Gen_KATs
   is
      SK_Seed : Bytes_N;
      PK_Seed : Bytes_N;
      A       : ADRS_Bytes;
   begin
      for Count in 0 .. Fixed_Cases - 1 loop
         Fill (SK_Seed);
         Fill (PK_Seed);
         Fill_ADRS (A, Count);
         Header ("WOTS_PK_Gen", Count);
         Debug.Put_Line ("SK_Seed = ", SK_Seed);
         Debug.Put_Line ("PK_Seed = ", PK_Seed);
         Debug.Put_Line ("ADRS = ", A);
         Debug.Put_Line ("Result = ", Wots_PK_Gen (SK_Seed, PK_Seed, A));
         New_Line;
      end loop;
   end PK_Gen_KATs;

   procedure Sign_KATs
   is
      M       : Bytes_N;
      SK_Seed : Bytes_N;
      PK_Seed : Bytes_N;
      A       : ADRS_Bytes;
   begin
      for Count in 0 .. Fixed_Cases - 1 loop
         Fill_M (M, Count);
         Fill (SK_Seed);
         Fill (PK_Seed);
         Fill_ADRS (A, Count);
         Header ("WOTS_Sign", Count);
         Debug.Put_Line ("M = ", M);
         Debug.Put_Line ("SK_Seed = ", SK_Seed);
         Debug.Put_Line ("PK_Seed = ", PK_Seed);
         Debug.Put_Line ("ADRS = ", A);
         Debug.Put_Line ("Result = ", Flatten (Wots_Sign (M, SK_Seed, PK_Seed, A)));
         New_Line;
      end loop;
   end Sign_KATs;

   --  wots_pkFromSig on random signatures, which need not be valid
   procedure PK_From_Sig_KATs
   is
      Sig     : WOTS_Array;
      M       : Bytes_N;
      PK_Seed : Bytes_N;
      A       : ADRS_Bytes;
   begin
      for Count in 0 .. Fixed_Cases - 1 loop
         for I in Sig'Range loop
            Fill (Sig (I));
         end loop;
         Fill_M (M, Count);
         Fill (PK_Seed);
         Fill_ADRS (A, Count);
         Header ("WOTS_PK_From_Sig", Count);
         Debug.Put_Line ("Sig = ", Flatten (Sig));
         Debug.Put_Line ("M = ", M);
         Debug.Put_Line ("PK_Seed = ", PK_Seed);
         Debug.Put_Line ("ADRS = ", A);
         Debug.Put_Line ("Result = ", Wots_PK_From_Sig (Sig, M, PK_Seed, A));
         New_Line;
      end loop;
   end PK_From_Sig_KATs;

   --  Signs M, then computes the public key from the signature, and
   --  generates the public key. Both keys are written out, so that
   --  the checker can confirm that they are equal, and correct.
   procedure Round_Trip_KATs
   is
      M       : Bytes_N;
      SK_Seed : Bytes_N;
      PK_Seed : Bytes_N;
      A       : ADRS_Bytes;
   begin
      for Count in 0 .. Fixed_Cases - 1 loop
         Fill_M (M, Count);
         Fill (SK_Seed);
         Fill (PK_Seed);
         Fill_ADRS (A, Count);
         Header ("WOTS_Round_Trip", Count);
         Debug.Put_Line ("M = ", M);
         Debug.Put_Line ("SK_Seed = ", SK_Seed);
         Debug.Put_Line ("PK_Seed = ", PK_Seed);
         Debug.Put_Line ("ADRS = ", A);
         Debug.Put_Line ("PK_Gen = ", Wots_PK_Gen (SK_Seed, PK_Seed, A));
         Debug.Put_Line ("PK_From_Sig = ",
                         Wots_PK_From_Sig (Wots_Sign (M, SK_Seed, PK_Seed, A),
                                           M, PK_Seed, A));
         New_Line;
      end loop;
   end Round_Trip_KATs;

   procedure WOTS_KATs
   is
   begin
      Chain_KATs;
      PK_Gen_KATs;
      Sign_KATs;
      PK_From_Sig_KATs;
      Round_Trip_KATs;
   end WOTS_KATs;

   ----------------------------------------------------------
   --  XMSS KATs
   ----------------------------------------------------------

   use XMSS;

   --  SIG_XMSS = sig || AUTH, as in FIPS 205 Figure 11
   function To_Bytes (S : in XMSS_Sig) return Bytes_XMSS_Sig
     renames Formats.XMSS_To_Bytes;

   --  Leaf indices for the signing KATs: the first and last
   --  leaves, and some others
   type Idx_List is array (Positive range <>) of Node_Index;

   Sign_Idx : constant Idx_List := (0, 255, 1, 128, 77, 170);

   type Node_Case is record
      I : Node_Index;
      Z : Tree_Height;
   end record;

   type Node_Case_List is array (Positive range <>) of Node_Case;

   Node_Cases : constant Node_Case_List :=
     ((0, 0), (255, 0), (0, 1), (127, 1), (5, 2), (31, 3),
      (3, 4), (15, 4), (1, 7), (0, 8));

   procedure XMSS_Node_KATs;
   procedure XMSS_Sign_KATs;
   procedure XMSS_PK_From_Sig_KATs;
   procedure XMSS_Round_Trip_KATs;

   procedure XMSS_Node_KATs
   is
      SK_Seed : Bytes_N;
      PK_Seed : Bytes_N;
      A       : ADRS_Bytes;
      Count   : Natural := 0;
   begin
      for C of Node_Cases loop
         Fill (SK_Seed);
         Fill (PK_Seed);
         Fill (A);
         Header ("XMSS_Node", Count);
         Debug.Put_Line ("SK_Seed = ", SK_Seed);
         Put_Int ("I", Integer (C.I));
         Put_Int ("Z", Integer (C.Z));
         Debug.Put_Line ("PK_Seed = ", PK_Seed);
         Debug.Put_Line ("ADRS = ", A);
         Debug.Put_Line ("Result = ", XMSS_Node (SK_Seed, C.I, C.Z, PK_Seed, A));
         New_Line;
         Count := Count + 1;
      end loop;
   end XMSS_Node_KATs;

   procedure XMSS_Sign_KATs
   is
      M       : Bytes_N;
      SK_Seed : Bytes_N;
      PK_Seed : Bytes_N;
      A       : ADRS_Bytes;
      Count   : Natural := 0;
   begin
      for Idx of Sign_Idx (1 .. 3) loop
         Fill_M (M, Count);
         Fill (SK_Seed);
         Fill (PK_Seed);
         Fill (A);
         Header ("XMSS_Sign", Count);
         Debug.Put_Line ("M = ", M);
         Debug.Put_Line ("SK_Seed = ", SK_Seed);
         Put_Int ("Idx", Integer (Idx));
         Debug.Put_Line ("PK_Seed = ", PK_Seed);
         Debug.Put_Line ("ADRS = ", A);
         Debug.Put_Line ("Result = ", To_Bytes (XMSS_Sign (M, SK_Seed, Idx, PK_Seed, A)));
         New_Line;
         Count := Count + 1;
      end loop;
   end XMSS_Sign_KATs;

   --  xmss_pkFromSig on random signatures, which need not be valid
   procedure XMSS_PK_From_Sig_KATs
   is
      S       : XMSS_Sig;
      M       : Bytes_N;
      PK_Seed : Bytes_N;
      A       : ADRS_Bytes;
      Count   : Natural := 0;
   begin
      for Idx of Sign_Idx loop
         for I in S.Sig'Range loop
            Fill (S.Sig (I));
         end loop;
         for J in S.Auth'Range loop
            Fill (S.Auth (J));
         end loop;
         Fill_M (M, Count);
         Fill (PK_Seed);
         Fill (A);
         Header ("XMSS_PK_From_Sig", Count);
         Put_Int ("Idx", Integer (Idx));
         Debug.Put_Line ("Sig_XMSS = ", To_Bytes (S));
         Debug.Put_Line ("M = ", M);
         Debug.Put_Line ("PK_Seed = ", PK_Seed);
         Debug.Put_Line ("ADRS = ", A);
         Debug.Put_Line ("Result = ", XMSS_PK_From_Sig (Idx, S, M, PK_Seed, A));
         New_Line;
         Count := Count + 1;
      end loop;
   end XMSS_PK_From_Sig_KATs;

   --  Signs M, then computes the root from the signature, and
   --  computes the root of the XMSS tree. Both are written out, so
   --  that the checker can confirm that they are equal, and correct.
   procedure XMSS_Round_Trip_KATs
   is
      M       : Bytes_N;
      SK_Seed : Bytes_N;
      PK_Seed : Bytes_N;
      A       : ADRS_Bytes;
      Count   : Natural := 0;
   begin
      for Idx of Sign_Idx (4 .. 6) loop
         Fill_M (M, Count);
         Fill (SK_Seed);
         Fill (PK_Seed);
         Fill (A);
         Header ("XMSS_Round_Trip", Count);
         Debug.Put_Line ("M = ", M);
         Debug.Put_Line ("SK_Seed = ", SK_Seed);
         Put_Int ("Idx", Integer (Idx));
         Debug.Put_Line ("PK_Seed = ", PK_Seed);
         Debug.Put_Line ("ADRS = ", A);
         Debug.Put_Line ("Root = ", XMSS_Node (SK_Seed, 0, H_Tick, PK_Seed, A));
         Debug.Put_Line ("PK_From_Sig = ",
                         XMSS_PK_From_Sig (Idx, XMSS_Sign (M, SK_Seed, Idx, PK_Seed, A),
                                           M, PK_Seed, A));
         New_Line;
         Count := Count + 1;
      end loop;
   end XMSS_Round_Trip_KATs;

   procedure XMSS_KATs
   is
   begin
      XMSS_Node_KATs;
      XMSS_Sign_KATs;
      XMSS_PK_From_Sig_KATs;
      XMSS_Round_Trip_KATs;
   end XMSS_KATs;

   ----------------------------------------------------------
   --  Hypertree KATs
   ----------------------------------------------------------

   use HT;

   --  SIG_HT, the XMSS signatures of layers 0 to D - 1 in order,
   --  as in FIPS 205 Figure 13
   function To_Bytes (S : in HT_Sig) return Bytes_HT_Sig
     renames Formats.HT_To_Bytes;

   type HT_Case is record
      Idx_Tree : Tree_Index;
      Idx_Leaf : Node_Index;
   end record;

   type HT_Case_List is array (Positive range <>) of HT_Case;

   --  The first and last trees and leaves, and some others
   HT_Cases : constant HT_Case_List :=
     ((0, 0),
      (Tree_Index'Last, 255),
      (16#00A5_5A3C_C3F0_0F96#, 77));

   procedure Put_Bool (Name : in String; V : in Boolean);

   procedure Put_Bool (Name : in String; V : in Boolean)
   is
   begin
      Put_Line (Name & " = " & (if V then "TRUE" else "FALSE"));
   end Put_Bool;

   procedure HT_Input (M        : in Bytes_N;
                       SK_Seed  : in Bytes_N;
                       PK_Seed  : in Bytes_N;
                       Idx_Tree : in Tree_Index;
                       Idx_Leaf : in Node_Index);

   procedure HT_Input (M        : in Bytes_N;
                       SK_Seed  : in Bytes_N;
                       PK_Seed  : in Bytes_N;
                       Idx_Tree : in Tree_Index;
                       Idx_Leaf : in Node_Index)
   is
   begin
      Debug.Put_Line ("M = ", M);
      Debug.Put_Line ("SK_Seed = ", SK_Seed);
      Debug.Put_Line ("PK_Seed = ", PK_Seed);
      Put_Line ("Idx_Tree =" & Idx_Tree'Img);
      Put_Int ("Idx_Leaf", Integer (Idx_Leaf));
   end HT_Input;

   procedure HT_Verify_KATs;
   procedure HT_Round_Trip_KATs;

   --  ht_verify on random signatures, which need not be valid,
   --  so the result is expected to be FALSE
   procedure HT_Verify_KATs
   is
      S       : HT_Sig;
      M       : Bytes_N;
      PK_Seed : Bytes_N;
      PK_Root : Bytes_N;
      Count   : Natural := 0;
   begin
      for C of HT_Cases loop
         for J in Layer_Index loop
            for I in Index_Len loop
               Fill (S (J).Sig (I));
            end loop;
            for I in Auth_Index loop
               Fill (S (J).Auth (I));
            end loop;
         end loop;
         Fill_M (M, Count);
         Fill (PK_Seed);
         Fill (PK_Root);
         Header ("HT_Verify", Count);
         Debug.Put_Line ("M = ", M);
         Debug.Put_Line ("Sig_HT = ", To_Bytes (S));
         Debug.Put_Line ("PK_Seed = ", PK_Seed);
         Put_Line ("Idx_Tree =" & C.Idx_Tree'Img);
         Put_Int ("Idx_Leaf", Integer (C.Idx_Leaf));
         Debug.Put_Line ("PK_Root = ", PK_Root);
         Put_Bool ("Result", HT_Verify (M, S, PK_Seed, C.Idx_Tree, C.Idx_Leaf, PK_Root));
         New_Line;
         Count := Count + 1;
      end loop;
   end HT_Verify_KATs;

   --  Signs M, and computes PK.root, the root of the XMSS tree at
   --  the top layer. Then verifies the signature against PK.root,
   --  which should give TRUE, and verifies a signature with one
   --  byte changed, a different PK.root, and a different idx_leaf,
   --  which should each give FALSE. The checker recomputes all of
   --  these with the reference model.
   procedure HT_Round_Trip_KATs
   is
      M       : Bytes_N;
      SK_Seed : Bytes_N;
      PK_Seed : Bytes_N;
      PK_Root : Bytes_N;
      Bad     : Bytes_N;
      S       : HT_Sig;
      T       : HT_Sig;
      Count   : Natural := 0;
   begin
      for C of HT_Cases (1 .. 2) loop
         Fill_M (M, Count);
         Fill (SK_Seed);
         Fill (PK_Seed);
         Header ("HT_Round_Trip", Count);
         HT_Input (M, SK_Seed, PK_Seed, C.Idx_Tree, C.Idx_Leaf);

         S := HT_Sign (M, SK_Seed, PK_Seed, C.Idx_Tree, C.Idx_Leaf);
         PK_Root := XMSS_Node (SK_Seed, 0, H_Tick, PK_Seed, Layer_ADRS (D - 1, 0));
         Debug.Put_Line ("Sig_HT = ", To_Bytes (S));
         Debug.Put_Line ("PK_Root = ", PK_Root);

         Put_Bool ("Verify", HT_Verify (M, S, PK_Seed, C.Idx_Tree, C.Idx_Leaf, PK_Root));

         T := S;
         T (3).Auth (5) (7) := T (3).Auth (5) (7) xor 1;
         Put_Bool ("Verify_Tampered_Sig",
                   HT_Verify (M, T, PK_Seed, C.Idx_Tree, C.Idx_Leaf, PK_Root));

         Bad := PK_Root;
         Bad (0) := Bad (0) xor 1;
         Put_Bool ("Verify_Wrong_Root",
                   HT_Verify (M, S, PK_Seed, C.Idx_Tree, C.Idx_Leaf, Bad));

         Put_Bool ("Verify_Wrong_Leaf",
                   HT_Verify (M, S, PK_Seed, C.Idx_Tree, C.Idx_Leaf xor 1, PK_Root));
         New_Line;
         Count := Count + 1;
      end loop;
   end HT_Round_Trip_KATs;

   procedure HT_KATs
   is
   begin
      HT_Verify_KATs;
      HT_Round_Trip_KATs;
   end HT_KATs;

   ----------------------------------------------------------
   --  FORS KATs
   ----------------------------------------------------------

   --  SIG_FORS, the private key value and AUTH of each tree
   --  in order, as in FIPS 205 Figure 14
   function To_Bytes (S : in FORS_Sig) return Bytes_FORS_Sig
     renames Formats.FORS_To_Bytes;

   --  md with every index 0, every index 2**a - 1, then random
   procedure Fill_MD (MD : out Bytes_MD; Count : in Natural);

   procedure Fill_MD (MD : out Bytes_MD; Count : in Natural)
   is
   begin
      case Count is
         when 0      => MD := (others => 16#00#);
         when 1      => MD := (others => 16#FF#);
         when others => Fill (MD);
      end case;
   end Fill_MD;

   type FORS_Node_Case is record
      I : FORS_Node_Index;
      Z : FORS_Height;
   end record;

   type FORS_Node_Case_List is array (Positive range <>) of FORS_Node_Case;

   --  The first and last leaves, some inner nodes, and the
   --  roots of the first and last trees
   FORS_Node_Cases : constant FORS_Node_Case_List :=
     ((0, 0), (K * 2**A - 1, 0), (12_345, 0), (5, 1), (K * 2**(A - 1) - 1, 1),
      (1_000, 6), (K * 2**3 - 1, 11), (0, A), (K - 1, A));

   type FORS_Idx_List is array (Positive range <>) of FORS_Node_Index;

   FORS_SK_Idx : constant FORS_Idx_List := (0, 1, 16_384, K * 2**A - 1, 200_000);

   procedure FORS_SK_Gen_KATs;
   procedure FORS_Node_KATs;
   procedure FORS_Sign_KATs;
   procedure FORS_PK_From_Sig_KATs;
   procedure FORS_Round_Trip_KATs;

   procedure FORS_SK_Gen_KATs
   is
      SK_Seed : Bytes_N;
      PK_Seed : Bytes_N;
      Adr     : ADRS_Bytes;
      Count   : Natural := 0;
   begin
      for Idx of FORS_SK_Idx loop
         Fill (SK_Seed);
         Fill (PK_Seed);
         Fill (Adr);
         Header ("FORS_SK_Gen", Count);
         Debug.Put_Line ("SK_Seed = ", SK_Seed);
         Debug.Put_Line ("PK_Seed = ", PK_Seed);
         Debug.Put_Line ("ADRS = ", Adr);
         Put_Int ("Idx", Integer (Idx));
         Debug.Put_Line ("Result = ", FORS.FORS_SK_Gen (SK_Seed, PK_Seed, Adr, Idx));
         New_Line;
         Count := Count + 1;
      end loop;
   end FORS_SK_Gen_KATs;

   procedure FORS_Node_KATs
   is
      SK_Seed : Bytes_N;
      PK_Seed : Bytes_N;
      Adr     : ADRS_Bytes;
      Count   : Natural := 0;
   begin
      for C of FORS_Node_Cases loop
         Fill (SK_Seed);
         Fill (PK_Seed);
         Fill (Adr);
         Header ("FORS_Node", Count);
         Debug.Put_Line ("SK_Seed = ", SK_Seed);
         Put_Int ("I", Integer (C.I));
         Put_Int ("Z", Integer (C.Z));
         Debug.Put_Line ("PK_Seed = ", PK_Seed);
         Debug.Put_Line ("ADRS = ", Adr);
         Debug.Put_Line ("Result = ", FORS.FORS_Node (SK_Seed, C.I, C.Z, PK_Seed, Adr));
         New_Line;
         Count := Count + 1;
      end loop;
   end FORS_Node_KATs;

   procedure FORS_Sign_KATs
   is
      MD      : Bytes_MD;
      SK_Seed : Bytes_N;
      PK_Seed : Bytes_N;
      Adr     : ADRS_Bytes;
   begin
      for Count in 0 .. 2 loop
         Fill_MD (MD, Count);
         Fill (SK_Seed);
         Fill (PK_Seed);
         Fill (Adr);
         Header ("FORS_Sign", Count);
         Debug.Put_Line ("MD = ", MD);
         Debug.Put_Line ("SK_Seed = ", SK_Seed);
         Debug.Put_Line ("PK_Seed = ", PK_Seed);
         Debug.Put_Line ("ADRS = ", Adr);
         Debug.Put_Line ("Result = ", To_Bytes (FORS.FORS_Sign (MD, SK_Seed, PK_Seed, Adr)));
         New_Line;
      end loop;
   end FORS_Sign_KATs;

   --  fors_pkFromSig on random signatures, which need not be valid
   procedure FORS_PK_From_Sig_KATs
   is
      S       : FORS_Sig;
      MD      : Bytes_MD;
      PK_Seed : Bytes_N;
      Adr     : ADRS_Bytes;
   begin
      for Count in 0 .. 3 loop
         for I in FORS_Tree_Index loop
            Fill (S (I).SK);
            for J in FORS_Auth_Index loop
               Fill (S (I).Auth (J));
            end loop;
         end loop;
         Fill_MD (MD, Count);
         Fill (PK_Seed);
         Fill (Adr);
         Header ("FORS_PK_From_Sig", Count);
         Debug.Put_Line ("Sig_FORS = ", To_Bytes (S));
         Debug.Put_Line ("MD = ", MD);
         Debug.Put_Line ("PK_Seed = ", PK_Seed);
         Debug.Put_Line ("ADRS = ", Adr);
         Debug.Put_Line ("Result = ", FORS.FORS_PK_From_Sig (S, MD, PK_Seed, Adr));
         New_Line;
      end loop;
   end FORS_PK_From_Sig_KATs;

   --  Signs MD, then computes the FORS public key from the signature,
   --  and computes the FORS public key from the roots of the K trees.
   --  Both are written out, so that the checker can confirm that they
   --  are equal, and correct.
   procedure FORS_Round_Trip_KATs
   is
      MD      : Bytes_MD;
      SK_Seed : Bytes_N;
      PK_Seed : Bytes_N;
      Adr     : ADRS_Bytes;
      Roots   : FORS_Roots;
   begin
      for Count in 0 .. 2 loop
         Fill_MD (MD, Count);
         Fill (SK_Seed);
         Fill (PK_Seed);
         Fill (Adr);
         Header ("FORS_Round_Trip", Count);
         Debug.Put_Line ("MD = ", MD);
         Debug.Put_Line ("SK_Seed = ", SK_Seed);
         Debug.Put_Line ("PK_Seed = ", PK_Seed);
         Debug.Put_Line ("ADRS = ", Adr);
         for I in FORS_Tree_Index loop
            Roots (I) := FORS.FORS_Node (SK_Seed, U32 (I), A, PK_Seed, Adr);
         end loop;
         Debug.Put_Line ("PK = ", Hash.T_L (PK_Seed, FORS.Roots_ADRS (Adr), FORS.Flatten (Roots)));
         Debug.Put_Line ("PK_From_Sig = ",
                         FORS.FORS_PK_From_Sig (FORS.FORS_Sign (MD, SK_Seed, PK_Seed, Adr),
                                                MD, PK_Seed, Adr));
         New_Line;
      end loop;
   end FORS_Round_Trip_KATs;

   procedure FORS_KATs
   is
   begin
      FORS_SK_Gen_KATs;
      FORS_Node_KATs;
      FORS_Sign_KATs;
      FORS_PK_From_Sig_KATs;
      FORS_Round_Trip_KATs;
   end FORS_KATs;

   ----------------------------------------------------------
   --  SLH-DSA internal function KATs
   ----------------------------------------------------------

   --  Signs a message with a new key pair, then verifies the
   --  signature, and verifies the signature with one byte changed in
   --  each of R, SIG_FORS and SIG_HT, a different message, and a
   --  different PK.root. The checker recomputes all of these with
   --  the reference model, and checks that only the first is TRUE.
   procedure SLH_Round_Trip_KATs
   is
      SK_Seed : Bytes_N;
      SK_Prf  : Bytes_N;
      PK_Seed : Bytes_N;
      Addrnd  : Bytes_N;
      KP      : Key_Parts;
      S       : Signature;
      T       : Signature;
      Bad_PK  : PK_Parts;
   begin
      for Count in 0 .. 1 loop
         declare
            Msg     : Byte_Seq (0 .. N32 (Count) * 100 - 1);
            Bad_Msg : Byte_Seq (0 .. N32 (Count) * 100);
         begin
            Fill (SK_Seed);
            Fill (SK_Prf);
            Fill (PK_Seed);
            Fill (Addrnd);
            Fill (Msg);
            Bad_Msg := Msg & Byte'(0);
            KP := SLH_Keygen_Internal (SK_Seed, SK_Prf, PK_Seed);

            Header ("SLH_Round_Trip", Count);
            Debug.Put_Line ("SK_Seed = ", SK_Seed);
            Debug.Put_Line ("SK_Prf = ", SK_Prf);
            Debug.Put_Line ("PK_Seed = ", PK_Seed);
            Debug.Put_Line ("Msg = ", Msg);
            --  Count 0 is deterministic, count 1 is hedged
            if Count = 0 then
               S := SLH_Sign_Internal_Deterministic (Msg, KP.SK);
            else
               Debug.Put_Line ("Addrnd = ", Addrnd);
               S := SLH_Sign_Internal (Msg, KP.SK, Addrnd);
            end if;
            Debug.Put_Line ("SK = ", SK_To_Bytes (KP.SK));
            Debug.Put_Line ("PK = ", PK_To_Bytes (KP.PK));
            Debug.Put_Line ("Sig = ", S);

            Put_Bool ("Verify", SLH_Verify_Internal (Msg, S, KP.PK));
            T := S;
            T (5) := T (5) xor 1;
            Put_Bool ("Verify_Tampered_R", SLH_Verify_Internal (Msg, T, KP.PK));
            T := S;
            T (FORS_Start + 1000) := T (FORS_Start + 1000) xor 1;
            Put_Bool ("Verify_Tampered_FORS", SLH_Verify_Internal (Msg, T, KP.PK));
            T := S;
            T (HT_Start + 10000) := T (HT_Start + 10000) xor 1;
            Put_Bool ("Verify_Tampered_HT", SLH_Verify_Internal (Msg, T, KP.PK));
            Put_Bool ("Verify_Wrong_Msg", SLH_Verify_Internal (Bad_Msg, S, KP.PK));
            Bad_PK := KP.PK;
            Bad_PK.PK_Root (0) := Bad_PK.PK_Root (0) xor 1;
            Put_Bool ("Verify_Wrong_Root", SLH_Verify_Internal (Msg, S, Bad_PK));
            New_Line;
         end;
      end loop;
   end SLH_Round_Trip_KATs;

   procedure SLH_KATs
   is
   begin
      SLH_Round_Trip_KATs;
   end SLH_KATs;

   ----------------------------------------------------------
   --  NIST ACVP test vectors
   ----------------------------------------------------------

   --  Longest input line, and longest byte string
   Max_Line  : constant := 200_000;
   Max_Bytes : constant := Max_Line / 2;

   Line     : String (1 .. Max_Line);
   Line_Len : Natural;

   --  The byte string fields of the current record. Each is stored in
   --  its own buffer, with its length. The Function, tcId and HashAlg
   --  fields are strings, stored in Func, TcId and Alg below
   type Field is (F_SK_Seed, F_SK_Prf, F_PK_Seed,
                  F_SK, F_PK, F_Message, F_Context, F_Addrnd, F_Signature);

   --  These have no default values, to avoid elaboration code.
   --  ACVP_Tests calls Reset before reading the first record.
   type Buffer is record
      Present : Boolean;
      Length  : N32;
      Data    : Byte_Seq (0 .. Max_Bytes - 1);
   end record;

   type Buffer_Array is array (Field) of Buffer;

   Bufs     : Buffer_Array;
   Func     : String (1 .. 16);
   Func_Len : Natural;
   TcId     : String (1 .. 16);
   TcId_Len : Natural;
   Alg      : String (1 .. 16);
   Alg_Len  : Natural;

   function Hex_Digit (C : in Character) return Byte
   is (case C is
          when '0' .. '9' => Character'Pos (C) - Character'Pos ('0'),
          when 'a' .. 'f' => Character'Pos (C) - Character'Pos ('a') + 10,
          when 'A' .. 'F' => Character'Pos (C) - Character'Pos ('A') + 10,
          when others     => raise Constraint_Error with "bad hex digit");

   procedure Set_Field (Key : in String; Value : in String);

   procedure Set_Field (Key : in String; Value : in String)
   is
      procedure Set_Bytes (F : in Field);

      procedure Set_Bytes (F : in Field)
      is
      begin
         if Value'Length mod 2 /= 0 or Value'Length / 2 > Max_Bytes then
            raise Constraint_Error with "bad hex string for " & Key;
         end if;
         Bufs (F).Present := True;
         Bufs (F).Length  := N32 (Value'Length / 2);
         for I in 0 .. Bufs (F).Length - 1 loop
            Bufs (F).Data (I) :=
              16 * Hex_Digit (Value (Value'First + 2 * Natural (I))) +
                   Hex_Digit (Value (Value'First + 2 * Natural (I) + 1));
         end loop;
      end Set_Bytes;
   begin
      if Key = "Function" then
         Func_Len := Value'Length;
         Func (1 .. Func_Len) := Value;
      elsif Key = "tcId" then
         TcId_Len := Value'Length;
         TcId (1 .. TcId_Len) := Value;
      elsif Key = "HashAlg" then
         Alg_Len := Value'Length;
         Alg (1 .. Alg_Len) := Value;
      elsif Key = "SK_Seed" then
         Set_Bytes (F_SK_Seed);
      elsif Key = "SK_Prf" then
         Set_Bytes (F_SK_Prf);
      elsif Key = "PK_Seed" then
         Set_Bytes (F_PK_Seed);
      elsif Key = "SK" then
         Set_Bytes (F_SK);
      elsif Key = "PK" then
         Set_Bytes (F_PK);
      elsif Key = "Message" then
         Set_Bytes (F_Message);
      elsif Key = "Context" then
         Set_Bytes (F_Context);
      elsif Key = "Addrnd" then
         Set_Bytes (F_Addrnd);
      elsif Key = "Signature" then
         Set_Bytes (F_Signature);
      else
         raise Constraint_Error with "unknown field " & Key;
      end if;
   end Set_Field;

   --  Checks that field F is present, and has length L
   procedure Check (F : in Field; L : in N32);

   procedure Check (F : in Field; L : in N32)
   is
   begin
      if not Bufs (F).Present or else Bufs (F).Length /= L then
         raise Constraint_Error with "field missing or of wrong length";
      end if;
   end Check;

   --  The pre-hash function named by HashAlg
   function PH return Pre_Hash_Function;

   function PH return Pre_Hash_Function
   is
      Name : constant String := Alg (1 .. Alg_Len);
   begin
      if Name = "SHA3-512" then
         return PH_SHA3_512;
      elsif Name = "SHAKE-256" then
         return PH_SHAKE256;
      else
         raise Constraint_Error with "unsupported pre-hash " & Name;
      end if;
   end PH;

   --  Runs the test in the current record
   procedure Run_Test;

   procedure Run_Test
   is
      Name : constant String := Func (1 .. Func_Len);
   begin
      Header (Name, 0);
      Put_Line ("tcId = " & TcId (1 .. TcId_Len));
      if Name = "KeyGen" then
         --  Algorithm 21 (which calls Algorithm 18)
         Check (F_SK_Seed, N);
         Check (F_SK_Prf, N);
         Check (F_PK_Seed, N);
         declare
            KP : constant Key_Pair :=
              SLH_Keygen (Bufs (F_SK_Seed).Data (0 .. N - 1),
                          Bufs (F_SK_Prf).Data (0 .. N - 1),
                          Bufs (F_PK_Seed).Data (0 .. N - 1));
         begin
            Debug.Put_Line ("SK = ", KP.SK);
            Debug.Put_Line ("PK = ", KP.PK);
         end;
      elsif Name = "SigGen" or Name = "SigGenPure" or Name = "SigGenPreHash" then
         Check (F_SK, SK_Bytes);
         Check (F_Message, Bufs (F_Message).Length);
         if Name /= "SigGen" then
            Check (F_Context, Bufs (F_Context).Length);
            if not Valid_Context (Bufs (F_Context).Data (0 .. Bufs (F_Context).Length - 1)) then
               raise Constraint_Error with "context too long";
            end if;
         end if;
         if Bufs (F_Addrnd).Present then
            Check (F_Addrnd, N);
         end if;
         declare
            SK     : Private_Key renames Bufs (F_SK).Data (0 .. SK_Bytes - 1);
            Msg    : Byte_Seq renames Bufs (F_Message).Data (0 .. Bufs (F_Message).Length - 1);
            Ctx    : Byte_Seq renames Bufs (F_Context).Data (0 .. Bufs (F_Context).Length - 1);
            Addrnd : Bytes_N renames Bufs (F_Addrnd).Data (0 .. N - 1);
            Hedged : constant Boolean := Bufs (F_Addrnd).Present;
         begin
            if Name = "SigGen" then
               --  Algorithm 19
               if Hedged then
                  Debug.Put_Line ("Signature = ",
                                  SLH_Sign_Internal (Msg, SK_From_Bytes (SK), Addrnd));
               else
                  Debug.Put_Line ("Signature = ",
                                  SLH_Sign_Internal_Deterministic (Msg, SK_From_Bytes (SK)));
               end if;
            elsif Name = "SigGenPure" then
               --  Algorithm 22
               if Hedged then
                  Debug.Put_Line ("Signature = ", SLH_Sign (Msg, Ctx, SK, Addrnd));
               else
                  Debug.Put_Line ("Signature = ", SLH_Sign_Deterministic (Msg, Ctx, SK));
               end if;
            else
               --  Algorithm 23
               if Hedged then
                  Debug.Put_Line ("Signature = ", Hash_SLH_Sign (Msg, Ctx, PH, SK, Addrnd));
               else
                  Debug.Put_Line ("Signature = ", Hash_SLH_Sign_Deterministic (Msg, Ctx, PH, SK));
               end if;
            end if;
         end;
      elsif Name = "SigVer" or Name = "SigVerPure" or Name = "SigVerPreHash" then
         Check (F_PK, PK_Bytes);
         Check (F_Message, Bufs (F_Message).Length);
         Check (F_Signature, Bufs (F_Signature).Length);
         if Name /= "SigVer" then
            Check (F_Context, Bufs (F_Context).Length);
         end if;
         declare
            PK  : Public_Key renames Bufs (F_PK).Data (0 .. PK_Bytes - 1);
            Msg : Byte_Seq renames Bufs (F_Message).Data (0 .. Bufs (F_Message).Length - 1);
            Ctx : Byte_Seq renames Bufs (F_Context).Data (0 .. Bufs (F_Context).Length - 1);
            Sig : Signature renames Bufs (F_Signature).Data (0 .. Sig_Bytes - 1);
         begin
            --  Algorithm 20 lines 1 to 3. A signature of the wrong
            --  length can't be a Signature, so it is rejected here
            if Bufs (F_Signature).Length /= Sig_Bytes then
               Put_Bool ("Result", False);
            elsif Name = "SigVer" then
               --  Algorithm 20
               Put_Bool ("Result", SLH_Verify_Internal (Msg, Sig, PK_From_Bytes (PK)));
            elsif Name = "SigVerPure" then
               --  Algorithm 24
               Put_Bool ("Result", SLH_Verify (Msg, Sig, Ctx, PK));
            else
               --  Algorithm 25
               Put_Bool ("Result", Hash_SLH_Verify (Msg, Sig, Ctx, PH, PK));
            end if;
         end;
      else
         raise Constraint_Error with "unknown function " & Name;
      end if;
      New_Line;
   end Run_Test;

   procedure ACVP_Tests
   is
      procedure Reset;

      procedure Reset
      is
      begin
         Func_Len := 0;
         TcId_Len := 0;
         Alg_Len  := 0;
         for F in Bufs'Range loop
            Bufs (F).Present := False;
            Bufs (F).Length  := 0;
         end loop;
      end Reset;

      Sep : Natural;
   begin
      Reset;
      while not End_Of_File loop
         Get_Line (Line, Line_Len);
         if Line_Len = Line'Last then
            raise Constraint_Error with "input line too long";
         end if;
         if Line_Len = 0 then
            if Func_Len > 0 then
               Run_Test;
            end if;
            Reset;
         else
            Sep := 0;
            for I in 1 .. Line_Len - 2 loop
               if Line (I .. I + 2) = " = " then
                  Sep := I;
                  exit;
               end if;
            end loop;
            if Sep = 0 then
               raise Constraint_Error with "expected 'Key = Value'";
            end if;
            Set_Field (Line (1 .. Sep - 1), Line (Sep + 3 .. Line_Len));
         end if;
      end loop;
      if Func_Len > 0 then
         Run_Test;
      end if;
   end ACVP_Tests;

end SLH.KAT;
