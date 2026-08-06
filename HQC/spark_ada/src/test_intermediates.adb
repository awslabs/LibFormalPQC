with Ada.Text_IO; use Ada.Text_IO;
with SHAKE;
with HQC;
procedure Test_Intermediates
is
   Ctx : SHAKE.SHAKE256.Context;
   Seed : HQC.Seed_Bytes;
   EK : HQC.Encapsulation_Key;
   DK : HQC.Decapsulation_Key;
   DFR : constant Integer := -HQC.Param.DFR_EXP;

   Entropy : constant HQC.Byte_Seq (0 .. 47) :=
     (0,   1,  2,  3,  4,  5,  6,  7,  8,  9,
      10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
      20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
      30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
      40, 41, 42, 43, 44, 45, 46, 47);
   PBytes : constant HQC.Byte_Seq (1 .. 0) := (others => 0);

   M    : HQC.Security_Bytes;
   Salt : HQC.Salt_Bytes;

   CT   : HQC.Ciphertext;
   SS1 : HQC.Shared_Secret := (others => 0);
   SS2 : HQC.Shared_Secret := (others => 0);
begin
   New_Line;
   Put_Line ("*********");
   Put_Line ("  " & HQC.Param.CRYPTO_ALGNAME);
   Put_Line ("*********");
   New_Line;
   Put ("N:" & HQC.Param.N'Img & "   N1:" & HQC.Param.N1'Img & "   N2:" & HQC.Param.N2'Img & "   OMEGA:" & HQC.Param.OMEGA'Img);
   Put ("   OMEGA_R:" & HQC.Param.OMEGA_R'Img & "   Failure rate: 2^" & DFR'Img & "   Sec:" & HQC.Param.SECURITY'Img & " bits");
   New_Line (4);

   HQC.Dbg.Set_Debug (True);

   Put_Line ("### KEYGEN ###");
   New_Line;

   HQC.PRNG_Init (Ctx, Entropy, PBytes);
   HQC.PRNG_Get_Bytes (Ctx, Seed);

   HQC.Dbg.Put_Line ("Seed_Bytes:", Seed);
   HQC.Dbg.New_Line;

   HQC.KeyPair (Seed, EK, DK);

   HQC.Dbg.Put_Line ("pk:", EK);
   HQC.Dbg.New_Line;
   HQC.Dbg.Put_Line ("sk:", DK);
   HQC.Dbg.New_Line;

   New_Line (2);
   Put_Line ("### ENCAPS ###");
   New_Line;

   HQC.PRNG_Get_Bytes (Ctx, M);
   HQC.PRNG_Get_Bytes (Ctx, Salt);
   HQC.Enc (EK, M, Salt, CT, SS1);

   New_Line (2);
   Put_Line ("### DECAPS ###");
   New_Line;

   HQC.Dec (DK, CT, SS2);

   HQC.Dbg.Put_Line ("ciphertext:", CT);
   HQC.Dbg.New_Line;
   HQC.Dbg.Put_Line ("secret1:", SS1);
   HQC.Dbg.New_Line;
   HQC.Dbg.Put_Line ("secret2:", SS2);
   HQC.Dbg.New_Line;

end Test_Intermediates;
