with Ada.Text_IO;
with SHAKE;
with HQC; use type HQC.Byte_Seq;

procedure Test_KAT
is
   Entropy : constant HQC.Byte_Seq (0 .. 47) :=
     (0,   1,  2,  3,  4,  5,  6,  7,  8,  9,
      10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
      20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
      30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
      40, 41, 42, 43, 44, 45, 46, 47);
   PBytes : constant HQC.Byte_Seq (1 .. 0) := (others => 0);
   Ctx1 : SHAKE.SHAKE256.Context;
   Ctx2 : SHAKE.SHAKE256.Context;
   Seed1 : HQC.Byte_Seq (0 .. 47);
   Seed2 : HQC.Seed_Bytes;

   EK : HQC.Encapsulation_Key;
   DK : HQC.Decapsulation_Key;

   M    : HQC.Security_Bytes;
   Salt : HQC.Salt_Bytes;

   CT  : HQC.Ciphertext;
   SS1 : HQC.Shared_Secret := (others => 0);
   SS2 : HQC.Shared_Secret := (others => 0);
begin
   HQC.PRNG_Init (Ctx1, Entropy, PBytes);

   Ada.Text_IO.Put_Line ("# " & HQC.Param.CRYPTO_ALGNAME);
   Ada.Text_IO.New_Line;
   for I in Natural range 0 .. 99 loop
      HQC.Dbg.Set_Debug (False);
      HQC.PRNG_Get_Bytes (Ctx1, Seed1);
      HQC.PRNG_Init (Ctx2, Seed1, PBytes);
      HQC.PRNG_Get_Bytes (Ctx2, Seed2);
      HQC.KeyPair (Seed2, EK, DK);

      HQC.PRNG_Get_Bytes (Ctx2, M);
      HQC.PRNG_Get_Bytes (Ctx2, Salt);
      HQC.Enc (EK, M, Salt, CT, SS1);
      HQC.Dec (DK, CT, SS2);


      HQC.Dbg.Set_Debug (True);
      HQC.Dbg.Put_Line ("count =" & I'Img);
      HQC.Dbg.Put_Line ("seed =", Seed1);
      HQC.Dbg.Put_Line ("pk =", EK);
      HQC.Dbg.Put_Line ("sk =", DK);
      HQC.Dbg.Put_Line ("ct =", CT);
      HQC.Dbg.Put_Line ("ss =", SS1);

      if SS1 /= SS2 then
         HQC.Dbg.Put_Line ("ss2 FAILS =", SS2);
         return;
      end if;

      Ada.Text_IO.New_Line;
   end loop;

end Test_KAT;
