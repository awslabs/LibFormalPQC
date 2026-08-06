with Ada.Text_IO;
with Ada.Unchecked_Conversion;

with SHA3;

package body HQC
  with SPARK_Mode => On
is
   subtype Index_1   is I32 range 0 .. 0;
   subtype Index_2   is I32 range 0 .. 1;
   subtype Index_3   is I32 range 0 .. 2;
   subtype Index_4   is I32 range 0 .. 3;
   subtype Index_8   is I32 range 0 .. 7;
   subtype Index_16  is I32 range 0 .. 15;
   subtype Index_256 is I32 range 0 .. 255;
   subtype Index_258 is I32 range 0 .. 257;

   subtype U32_Bit is U32 range 0 .. 1;
   subtype U16_Bit is U16 range 0 .. 1;
   subtype U8_Bit  is U8  range 0 .. 1;

   subtype U8_Two_Bits is U8 range 0 .. 3;

   function SL (Value : Unsigned_16; Amount : Natural) return Unsigned_16 renames Shift_Left;
   function SL (Value : Unsigned_32; Amount : Natural) return Unsigned_32 renames Shift_Left;
   function SL (Value : Unsigned_64; Amount : Natural) return Unsigned_64 renames Shift_Left;

   function SR (Value : Unsigned_8;  Amount : Natural) return Unsigned_8  renames Shift_Right;
   function SR (Value : Unsigned_16; Amount : Natural) return Unsigned_16 renames Shift_Right;
   function SR (Value : Unsigned_32; Amount : Natural) return Unsigned_32 renames Shift_Right;
   function SR (Value : Unsigned_64; Amount : Natural) return Unsigned_64 renames Shift_Right;

   subtype Index_N1  is I32 range 0 .. Param.N1 - 1;
   subtype Bytes_N1  is Byte_Seq (Index_N1);

   function To_Bytes1 is new Ada.Unchecked_Conversion (U64_Seq_N_Bits_As_Words,
                                                       Seq_N_Bits_As_Bytes_Padded);

   package body Dbg
     with SPARK_Mode => Off
   is
      Debug_On : Boolean := False;

      subtype Nibble is Byte range 0 .. 15;

      procedure Put_Nibble (N : in Nibble)
      is
      begin
         case N is
            when 0 .. 9 =>
               Ada.Text_IO.Put (Character'Val (Character'Pos ('0') + N));
            when 10 .. 15 =>
               Ada.Text_IO.Put (Character'Val (Character'Pos ('a') + (N - 10)));
         end case;
      end Put_Nibble;

      procedure Put_Byte (N : in Byte)
      is
      begin
         Put_Nibble (N / 16);
         Put_Nibble (N mod 16);
      end Put_Byte;

      procedure New_Line (N : in Positive := 1)
      is
      begin
         if Debug_On then
            Ada.Text_IO.New_Line (Ada.Text_IO.Positive_Count (N));
         end if;
      end New_Line;

      procedure Put (S : in String)
      is
      begin
         if Debug_On then
            Ada.Text_IO.Put (S);
         end if;
      end Put;

      procedure Put_Line (S : in String)
      is
      begin
         if Debug_On then
            Ada.Text_IO.Put_Line (S);
         end if;
      end Put_Line;

      procedure Set_Debug (Enable : in Boolean)
      is
      begin
         Debug_On := Enable;
      end Set_Debug;

      procedure Put (S : in String := "";
                     V : in Byte_Seq)
      is
      begin
         if Debug_On then
            Ada.Text_IO.Put (S & ' ');
            for I in V'Range loop
               Put_Byte (V (I));
            end loop;
         end if;
      end Put;

      procedure Put_Line (S : in String := "";
                          V : in Byte_Seq)
      is
      begin
         if Debug_On then
            Put (S, V);
            Ada.Text_IO.New_Line (1);
         end if;
      end Put_Line;

      procedure Put (S : in String := "";
                     V : in U64_Seq;
                     C : in N32)
      is
      begin
         if Debug_On then
            Ada.Text_IO.Put (S & ' ');
            if C = 0 then
               return;
            end if;

            for I in N32 range 0 .. C - 1 loop
               declare
                  WOffset : constant N32 := I / 8;
                  Shift   : constant Natural := (Natural (I) mod 8) * 8;
                  CB      : constant Byte := Byte (SR (V (WOffset), Shift) mod 256);
               begin
                  Put_Byte (CB);
               end;
            end loop;
         end if;
      end Put;


      procedure Put_Line (S : in String := "";
                          V : in U64_Seq;
                          C : in N32)
      is
      begin
         if Debug_On then
            Put (S, V, C);
            Ada.Text_IO.New_Line (2);
         end if;
      end Put_Line;

      procedure Put (S : in String := "";
                     V : in U32_Seq;
                     C : in N32)
      is
      begin
         if Debug_On then
            Ada.Text_IO.Put (S & ' ');
            if C = 0 then
               return;
            end if;

            for I in N32 range 0 .. C - 1 loop
               declare
                  WOffset : constant N32 := I / 4;
                  Shift   : constant Natural := (Natural (I) mod 4) * 8;
                  CB      : constant Byte := Byte (SR (V (WOffset), Shift) mod 256);
               begin
                  Put_Byte (CB);
               end;
            end loop;
         end if;
      end Put;


      procedure Put_Line (S : in String := "";
                          V : in U32_Seq;
                          C : in N32)
      is
      begin
         if Debug_On then
            Put (S, V, C);
            Ada.Text_IO.New_Line (2);
         end if;
      end Put_Line;

   end Dbg;

   package GF
   is
      --  This table is only OK for Param.M = 8
      pragma Assert (Param.M = 8);
      subtype Log_Table is U16_Seq (Index_256)
        with Dynamic_Predicate => (for all I in Index_256 => Log_Table (I) in 0 .. Param.GF_MUL_ORDER);

      Log : constant Log_Table :=
        (0,   0,   1,   25,  2,   50,  26,  198, 3,   223, 51,  238, 27,  104, 199, 75,  4,   100, 224, 14,  52,  141,
         239, 129, 28,  193, 105, 248, 200, 8,   76,  113, 5,   138, 101, 47,  225, 36,  15,  33,  53,  147, 142, 218,
         240, 18,  130, 69,  29,  181, 194, 125, 106, 39,  249, 185, 201, 154, 9,   120, 77,  228, 114, 166, 6,   191,
         139, 98,  102, 221, 48,  253, 226, 152, 37,  179, 16,  145, 34,  136, 54,  208, 148, 206, 143, 150, 219, 189,
         241, 210, 19,  92,  131, 56,  70,  64,  30,  66,  182, 163, 195, 72,  126, 110, 107, 58,  40,  84,  250, 133,
         186, 61,  202, 94,  155, 159, 10,  21,  121, 43,  78,  212, 229, 172, 115, 243, 167, 87,  7,   112, 192, 247,
         140, 128, 99,  13,  103, 74,  222, 237, 49,  197, 254, 24,  227, 165, 153, 119, 38,  184, 180, 124, 17,  68,
         146, 217, 35,  32,  137, 46,  55,  63,  209, 91,  149, 188, 207, 205, 144, 135, 151, 178, 220, 252, 190, 97,
         242, 86,  211, 171, 20,  42,  93,  158, 132, 60,  57,  83,  71,  109, 65,  162, 31,  45,  67,  216, 183, 123,
         164, 118, 196, 23,  73,  236, 127, 12,  111, 246, 108, 161, 59,  82,  41,  157, 85,  170, 251, 96,  134, 177,
         187, 204, 62,  90,  203, 89,  95,  176, 156, 169, 160, 81,  11,  245, 22,  235, 122, 117, 44,  215, 79,  174,
         213, 233, 230, 231, 173, 232, 116, 214, 244, 234, 168, 80,  88,  175);

      subtype Exp_Table is U16_Seq (Index_258)
        with Dynamic_Predicate => (for all I in Index_256 => Exp_Table (I) in 0 .. Param.GF_MUL_ORDER);

      Exp : constant Exp_Table :=
        (1,   2,   4,   8,   16,  32,  64,  128, 29,  58,  116, 232, 205, 135, 19,  38,  76,  152, 45,  90,  180, 117,
         234, 201, 143, 3,   6,   12,  24,  48,  96,  192, 157, 39,  78,  156, 37,  74,  148, 53,  106, 212, 181, 119,
         238, 193, 159, 35,  70,  140, 5,   10,  20,  40,  80,  160, 93,  186, 105, 210, 185, 111, 222, 161, 95,  190,
         97,  194, 153, 47,  94,  188, 101, 202, 137, 15,  30,  60,  120, 240, 253, 231, 211, 187, 107, 214, 177, 127,
         254, 225, 223, 163, 91,  182, 113, 226, 217, 175, 67,  134, 17,  34,  68,  136, 13,  26,  52,  104, 208, 189,
         103, 206, 129, 31,  62,  124, 248, 237, 199, 147, 59,  118, 236, 197, 151, 51,  102, 204, 133, 23,  46,  92,
         184, 109, 218, 169, 79,  158, 33,  66,  132, 21,  42,  84,  168, 77,  154, 41,  82,  164, 85,  170, 73,  146,
         57,  114, 228, 213, 183, 115, 230, 209, 191, 99,  198, 145, 63,  126, 252, 229, 215, 179, 123, 246, 241, 255,
         227, 219, 171, 75,  150, 49,  98,  196, 149, 55,  110, 220, 165, 87,  174, 65,  130, 25,  50,  100, 200, 141,
         7,   14,  28,  56,  112, 224, 221, 167, 83,  166, 81,  162, 89,  178, 121, 242, 249, 239, 195, 155, 43,  86,
         172, 69,  138, 9,   18,  36,  72,  144, 61,  122, 244, 245, 247, 243, 251, 235, 203, 139, 11,  22,  44,  88,
         176, 125, 250, 233, 207, 131, 27,  54,  108, 216, 173, 71,  142, 1,   2,   4);


      --  Reduces X to M bits, so Reduce'Result <= Param.M_Mask
      function Reduce (X : in U16) return U16
        with Global => null,
             Post   => Reduce'Result <= Param.M_Mask;

      function Carryless_Mul (A, B : in U8) return U16
        with Global => null;

      --  Reduces X to M bits, so Mul'Result <= Param.M_Mask
      function Mul (A, B : in U16) return U16
        with Global => null,
             Post   => Mul'Result <= Param.M_Mask;

      --  Reduces X to M bits, so Mul'Result <= Param.M_Mask
      function Square (A : in U16) return U16
        with Global => null,
             Post   => Square'Result <= Param.M_Mask;

      --  Reduces X to M bits, so Inverse'Result <= Param.M_Mask
      function Inverse (A : in U16) return U16
        with Global => null,
             Post   => Inverse'Result <= Param.M_Mask;

   end GF;

   package body GF
   is
      function Reduce (X : in U16) return U16
      is
         XRM, LX : U16;
      begin
         LX := X;

         XRM := SR (LX, Param.M);
         pragma Assert (XRM <= Param.M_Mask);

         LX  := (LX and Param.M_Mask);
         LX  := LX xor XRM;
         LX  := LX xor SL (XRM, 2) xor SL (XRM, 3) xor SL (XRM, 4);
         pragma Assert (LX <= 4095);

         XRM := SR (LX, Param.M);
         pragma Assert (XRM <= 15);

         LX  := (LX and Param.M_Mask);
         LX  := LX xor XRM;
         LX  := LX xor SL (XRM, 2) xor SL (XRM, 3) xor SL (XRM, 4);
         pragma Assert (LX <= Param.M_Mask);

         return LX;
      end Reduce;

      function Carryless_Mul (A, B : in U8) return U16
      is
         subtype UAI is I32 range 0 .. 3;
         type UA is array (UAI) of U16;
         H, L, G : U16;
         U       : UA := (others => 0);
         Tmp1    : U16 := U16 (A) and 3;
         Tmp2    : U32;
         Mask    : U16;
      begin
         U (1) := U16 (B) and 127;
         U (2) := U (1) * 2;
         U (3) := U (2) xor U (1);

         G := 0;
         for I in UAI loop
            declare
               Tmp2 : constant U32 := U32 (Tmp1) - U32 (I);
               Tmp3 : constant U32_Bit := SR (Tmp2 or -Tmp2, 31); --  Should be 0 or 1
               Tmp4 : constant U16_Bit := 1 - U16 (Tmp3);
            begin
               G := G xor (U (I) and -Tmp4);
            end;
         end loop;

         L := G;
         H := 0;

         for I in UAI range 1 .. 3 loop
            declare
               LI   : constant Natural := Natural (I) * 2; --  2, 4 or 6
               Tmp3 : constant U8_Two_Bits := SR (A, LI) and 3;
            begin
               G := 0;
               for J in UAI loop
                  declare
                     Tmp4 : constant U32 := U32 (Tmp3) - U32 (J);
                     Tmp5 : constant U32_Bit := Shift_Right (Tmp4 or -Tmp4, 31); --  Should be 0 or 1
                     Tmp6 : constant U16_Bit := 1 - U16 (Tmp5);
                  begin
                     G := G xor (U (J) and -U16 (Tmp6));
                  end;
               end loop;
               L := L xor (SL (G, LI));
               H := H xor (SR (G, (8 - LI)));
            end;
         end loop;

         Mask := -U16 (Shift_Right (B, 7) and 1);
         L := L xor (SL (U16 (A), 7) and Mask);
         H := H xor (SR (U16 (A), 1) and Mask);

         return ((H and 255) * 256) + (L and 255);
      end Carryless_Mul;


      function Mul (A, B : in U16) return U16
      is
      begin
         return Reduce (Carryless_Mul (U8 (A and 255),
                                       U8 (B and 255)));
      end Mul;

      function Square (A : in U16) return U16
      is
         B : U32 := U32 (A);
         S : U32 := B and 1;
      begin
         for I in Natural range 1 .. Param.M - 1 loop
            B := B * 2;
            S := S xor (B and SL (1, 2 * I));
         end loop;
         return Reduce (U16 (S and 65535));
      end Square;

      function Inverse (A : in U16) return U16
      is
         Inv    : U16; --  ineffective initialization here in C code
         T1, T2 : U16;
      begin
         Inv := Square (A);    --  A**2
         T1  := Mul (Inv, A);  --  A**3
         Inv := Square (Inv);  --  A**4
         T2  := Mul (Inv, T1); --  A**7
         T1  := Mul (Inv, T2); --  A**11
         Inv := Mul (T1, Inv); --  A**15
         Inv := Square (Inv);  --  A**30
         Inv := Square (Inv);  --  A**60
         Inv := Square (Inv);  --  A**120
         Inv := Mul (Inv, T2); --  A**127
         Inv := Square (Inv);  --  A**254
         return Inv;
      end Inverse;

   end GF;

   package GF2X
   is
      Karatsuba_Threshold : constant := 16;

      function Schoolbook_Mul (A, B : in U64_Seq) return U64_Seq
        with Global => null,
             Pre => A'Last < N32'Last / 2 and then
                    (A'First = 0 and
                     B'First = 0 and
                     A'Length = B'Length),
             Post => Schoolbook_Mul'Result'Length = 2 * A'Length;

      function Karatsuba_Mul (A, B : in U64_Seq) return U64_Seq
        with Global => null,
             Pre => A'Last < N32'Last / 2 and then
                    (A'First = 0 and
                     B'First = 0 and
                     A'Length = B'Length),
             Post => Karatsuba_Mul'Result'Length = 2 * A'Length;

      function Reduce (A : in U64_Seq_2N_Bits_As_Words) return U64_Seq_N_Bits_As_Words
        with Global => null;

      function Mul (A, B : in U64_Seq_N_Bits_As_Words) return U64_Seq_N_Bits_As_Words
        with Global => null;
   end GF2X;

   package body GF2X
   is
      subtype U64_Bit_Index is Natural range 0 .. 63;

      function Schoolbook_Mul (A, B : in U64_Seq) return U64_Seq
      is
         subtype A_Index is N32 range 0 .. A'Length - 1;
         subtype R_Index is N32 range 0 .. A'Length * 2 - 1;
         subtype RT is U64_Seq (R_Index);
         R  : RT := (others => 0);
      begin
         for I in A'Range loop
            declare
               AI : constant U64 := A (I);
            begin
               for Bit in U64_Bit_Index loop
                  declare
                     Mask : constant U64 := -(SR (AI, Bit) and 1);
                     Base : constant A_Index := I;
                     Sh   : constant Natural := Bit;
                     Inv  : constant Natural := 64 - Sh;
                  begin
                     if Sh = 0 then
                        for J in A'Range loop
                           R (Base + J) := R (Base + J) xor (B (J) and Mask);
                        end loop;
                     else
                        for J in A'Range loop
                           R (Base + J)       := R (Base + J)     xor
                                                 (SL (B (J), Sh) and Mask);
                           R ((Base + J) + 1) := R ((Base + J) + 1) xor
                                                 (SR (B (J), Inv) and Mask);
                        end loop;
                     end if;
                  end;
               end loop;
            end;
         end loop;
         return R;
      end Schoolbook_Mul;

      function Karatsuba_Mul (A, B : in U64_Seq) return U64_Seq
      is
         subtype R_Index is N32 range 0 .. A'Length * 2 - 1;
         subtype RT is U64_Seq (R_Index);
      begin
         if A'Length <= Karatsuba_Threshold then
            return Schoolbook_Mul (A, B);
         else
            declare
               M  : constant N32 := A'Length / 2;
               N0 : constant N32 := M;
               N1 : constant N32 := A'Length - M;

               subtype Low_Index  is N32 range 0 .. N0 - 1;
               subtype High_Index is N32 range 0 .. N1 - 1;
               subtype Low_Part   is U64_Seq (Low_Index);
               subtype High_Part  is U64_Seq (High_Index);

               subtype N0_Result_Index  is N32 range 0 .. (N0 * 2) - 1;
               subtype N0_Result        is U64_Seq (N0_Result_Index);
               subtype N1_Result_Index  is N32 range 0 .. (N1 * 2) - 1;
               subtype N1_Result        is U64_Seq (N1_Result_Index);

               A_Low  : constant  Low_Part :=  Low_Part (A (Low_Index));
               B_Low  : constant  Low_Part :=  Low_Part (B (Low_Index));
               A_High : constant High_Part := High_Part (A (N0 .. A'Last));
               B_High : constant High_Part := High_Part (B (N0 .. B'Last));

               ZMid   : N1_Result;
               TA, TB : High_Part;

               Z0 : constant N0_Result := Karatsuba_Mul (A_Low, B_Low);
               pragma Annotate (GNATprove, False_Positive, "Always_Terminates", "OK");
               Z2 : constant N1_Result := Karatsuba_Mul (A_High, B_High);
               pragma Annotate (GNATprove, False_Positive, "Always_Terminates", "OK");

               R : RT := Z0 & Z2;
            begin
               for I in High_Index loop
                  TA (I) := A (M + I) xor (if I < N0 then A (I) else 0);
                  TB (I) := B (M + I) xor (if I < N0 then B (I) else 0);
               end loop;

               ZMid := Karatsuba_Mul (TA, TB);
               pragma Annotate (GNATprove, False_Positive, "Always_Terminates", "OK");

               for I in N1_Result_Index loop
                  declare
                     Z0_Item : constant U64 := (if I < 2 * N0 then Z0 (I) else 0);
                     -- Z2_Item : constant U64 := (if I < 2 * N1 then Z2 (I) else 0); -- RCC "else 0" branch is unreachable
                     Z2_Item : constant U64 := Z2 (I);
                  begin
                     R (M + I) := R (M + I) xor ZMid (I) xor Z0_Item xor Z2_Item;
                  end;
               end loop;
               return R;
            end;
         end if;
      end Karatsuba_Mul;

      function Reduce (A : in U64_Seq_2N_Bits_As_Words) return U64_Seq_N_Bits_As_Words
      is
         Final_Word_Bitmask : constant := 2**(Param.N mod 64) - 1;

         ShiftC : constant Natural := Natural (U32 (Param.N) and 16#3F#);

         O : U64_Seq_N_Bits_As_Words;
      begin
         for I in O'Range loop
            declare
               R : constant U64 := SR (A ((I + Param.VEC_N_SIZE_64) - 1), ShiftC);
               C : constant U64 := SL (A (I + Param.VEC_N_SIZE_64), (64 - ShiftC));
            begin
               O (I) := A (I) xor R xor C;
            end;
         end loop;
         O (O'Last) := O (O'Last) and Final_Word_Bitmask;
         return O;
      end Reduce;

      function Mul (A, B : in U64_Seq_N_Bits_As_Words) return U64_Seq_N_Bits_As_Words
      is
      begin
         return Reduce (Karatsuba_Mul (A, B));
      end Mul;
   end GF2X;

   package Reed_Muller
   is
      type RM_Codeword_U32 is array (Index_4) of U32
        with Size        => 128,
             Object_Size => 128,
             Alignment   => 8;

      subtype RM_Codeword_U64 is U64_Seq (Index_2);
      pragma Warnings (GNATprove, Off, "implementation-defined value", Reason => "Understood");
      pragma Assert (RM_Codeword_U64'Size        = RM_Codeword_U32'Size);
      pragma Assert (RM_Codeword_U64'Object_Size = RM_Codeword_U32'Object_Size);
      pragma Assert (RM_Codeword_U64'Alignment   = RM_Codeword_U32'Alignment);

      function To_U64 is new Ada.Unchecked_Conversion (RM_Codeword_U32, RM_Codeword_U64);

      --  Each RM_Codeword_U32 is 128 bits, or 2 * 64 bit words
      --  RMMF * RM_Codeword_U32 is therefore 2 * RMMF U64 elements
      Msg_Words_Count : constant := Param.VEC_N1_SIZE_64;
      pragma Assert (Msg_Words_Count = 6 or  --  HQC-1
                     Msg_Words_Count = 7 or  --  HQC-3
                     Msg_Words_Count = 12);  --  HQC-5

      subtype Msg_Words_Index is N32 range 0 .. Msg_Words_Count - 1;
      subtype Msg_Words is U64_Seq (Msg_Words_Index);
      pragma Assert (Msg_Words'Size = 384 or --  HQC-1
                     Msg_Words'Size = 448 or --  HQC-3
                     Msg_Words'Size = 768);  --  HQC-5

      --  For HQC-1, 46 bytes significant, which is  6 U64s, where last 2 bytes are unused padding
      --  For HQC-3, 56 bytes significant, which is  7 U64s with no padding
      --  For HQC-5, 90 bytes significant, which is 12 U64s, where last 6 bytes are unused padding
      subtype Msg_Bytes_Index is N32 range 0 .. (Msg_Words_Count * 8) - 1;
      subtype Msg_Bytes is Byte_Seq (Msg_Bytes_Index);

      function To_Bytes is new Ada.Unchecked_Conversion (Msg_Words, Msg_Bytes);
      function To_Words is new Ada.Unchecked_Conversion (Msg_Bytes, Msg_Words);

      subtype CDW_Index is N32 range 0 .. Param.VEC_N1N2_SIZE_64 - 1;
      subtype CDW_Words is U64_Seq (CDW_Index);

      --  expands 8 bits to 128 bits
      function Encode (Msg : in U8) return RM_Codeword_U32
        with Global => null;

      function Encode (Msg : in Msg_Words) return CDW_Words
        with Global => null;

      function Decode (CDW : in CDW_Words) return Msg_Words
        with Global => null;
   end Reed_Muller;

   package body Reed_Muller
   is
      subtype I16 is Integer_16;

      function Mask (Bit : in U8) return U32
        is (Boolean'Pos ((Bit and 1) = 1) * 16#FFFF_FFFF#);

      --  Expands 8 bits to 128 bits. OR... 1 byte to 16 bytes
      function Encode (Msg : in U8) return RM_Codeword_U32
      is
         Word0 : U32;
         Word1 : U32;
         Word2 : U32;
         Word3 : U32;
      begin
         Word0 := Mask (SR (Msg, 7));

         Word0 := Word0 xor (Mask (SR (Msg, 0)) and 16#aaaa_aaaa#);
         Word0 := Word0 xor (Mask (SR (Msg, 1)) and 16#cccc_cccc#);
         Word0 := Word0 xor (Mask (SR (Msg, 2)) and 16#f0f0_f0f0#);
         Word0 := Word0 xor (Mask (SR (Msg, 3)) and 16#ff00_ff00#);
         Word0 := Word0 xor (Mask (SR (Msg, 4)) and 16#ffff_0000#);

         Word1 := Word0 xor Mask (SR (Msg, 5));
         Word3 := Word1 xor Mask (SR (Msg, 6));
         Word2 := Word3 xor Mask (SR (Msg, 5));

         return RM_Codeword_U32'(Word0, Word1, Word2, Word3);
      end Encode;

      function Encode (Msg : in Msg_Words) return CDW_Words
      is
         LM : constant Bytes_N1 := Bytes_N1 (To_Bytes (Msg)(Index_N1'Range));
         R  : CDW_Words with Relaxed_Initialization;
      begin
         R := (others => 0);
         for I in LM'Range loop
            pragma Loop_Invariant (R (0 .. (I * Param.RMMF) * 2 - 1)'Initialized);
            declare
               L  : constant RM_Codeword_U64 := To_U64 (Encode (LM (I)));
               RI : constant N32 := (I * Param.RMMF) * 2;
            begin
               --  Each codeword is 128 bits, so occupies 2 elements of R,
               --  and each is repeated RMMF times
               for J in N32 range 0 .. Param.RMMF - 1 loop
                  R (RI + (J * 2) .. (RI + (J * 2)) + 1) := L;
                  pragma Loop_Invariant (R (0 .. (RI + (J * 2)) + 1)'Initialized);
               end loop;
            end;
         end loop;
         pragma Assert (R'Initialized);
         return R;
      end Encode;

      subtype RMMF_Index is I16 range 0 .. Param.RMMF - 1;

      type RMMF_Codewords is array (RMMF_Index) of RM_Codeword_U32;
      pragma Assert (RMMF_Codewords'Size = 384 or  --  HQC-1
                     RMMF_Codewords'Size = 640);   --  HQC-3

      -- Each RM_Codeword_U32 is 128 bits, so 2 * U64 words
      subtype RMMF_Codewords_As_Words_Index is N32 range 0 .. (Param.RMMF * 2) - 1;
      subtype RMMF_Codewords_As_Words is U64_Seq (RMMF_Codewords_As_Words_Index);

      pragma Assert (RMMF_Codewords_As_Words'Size        = RMMF_Codewords'Size);
      pragma Assert (RMMF_Codewords_As_Words'Object_Size = RMMF_Codewords'Object_Size);
      pragma Assert (RMMF_Codewords_As_Words'Alignment   = RMMF_Codewords'Alignment);
      function To_RMMF_Codewords is new Ada.Unchecked_Conversion (RMMF_Codewords_As_Words, RMMF_Codewords);

      type Expanded_CDW is array (Index_128) of I16;

      subtype Simple_Expanded_CDW is Expanded_CDW
        with Dynamic_Predicate => (for all K in Index_128 => Simple_Expanded_CDW (K) in 0 .. Param.RMMF);

      subtype Transformed_Codeword is I16 range -(128 * Param.RMMF) .. (128 * Param.RMMF);
      subtype Transformed_Expanded_CDW is Expanded_CDW
        with Dynamic_Predicate => (for all K in Index_128 =>
                                    Transformed_Expanded_CDW (K) in Transformed_Codeword);

      subtype Final_Transformed_Codeword is I16 range -(192 * Param.RMMF) .. (192 * Param.RMMF);
      subtype Final_Transformed_Expanded_CDW is Expanded_CDW
       with Dynamic_Predicate => (for all K in Index_128 =>
                                    Final_Transformed_Expanded_CDW (K) in Final_Transformed_Codeword);

      function Expand_And_Sum (Src : in RMMF_Codewords) return Simple_Expanded_CDW
        with Global => null;

      function Expand_And_Sum (Src : in RMMF_Codewords) return Simple_Expanded_CDW
      is
         R : Expanded_CDW := (others => 0);
      begin
         for Copy in RMMF_Index loop
            for Part in Index_4 loop
               for Bit in Index_32 loop
                  R (Part * 32 + Bit) := R (Part * 32 + Bit) +
                                         I16 (SR (Src (Copy)(Part), Natural (Bit)) and 1);
                  pragma Loop_Invariant (for all K in Index_128 range 0 .. Part * 32 + Bit =>
                                           R (K) in 0 .. Copy + 1);
                  pragma Loop_Invariant (for all K in Index_128 range (Part * 32 + Bit) + 1 .. 127 =>
                                           R (K) in 0 .. Copy);
               end loop;
               pragma Loop_Invariant (for all K in Index_128 range 0 .. Part * 32 + 31 =>
                                        R (K) in 0 .. Copy + 1);
               pragma Loop_Invariant (for all K in Index_128 range (Part + 1) * 32 .. 127 =>
                                        R (K) in 0 .. Copy);
            end loop;
            pragma Loop_Invariant (for all K in R'Range => R (K) in 0 .. Copy + 1);
         end loop;
         pragma Assert (for all K in R'Range => R (K) in 0 .. Param.RMMF);
         return R;
      end Expand_And_Sum;


      procedure Single_Hadamard (Src       : in     Expanded_CDW;
                                 Dst       :    out Expanded_CDW;
                                 Src_Bound : in     Transformed_Codeword)
        with Global => null,
             Relaxed_Initialization => Dst,
             Pre  => Src_Bound in 0 .. Transformed_Codeword'Last / 2 and then
                     (for all K in Src'Range => Src (K) in -Src_Bound .. Src_Bound),
             Post => Dst'Initialized and then
                     (for all K in Src'Range => Dst (K) in -(Src_Bound * 2) .. (Src_Bound * 2));

      procedure Single_Hadamard (Src       : in     Expanded_CDW;
                                 Dst       :    out Expanded_CDW;
                                 Src_Bound : in     Transformed_Codeword)
      is
      begin
         for I in Index_128 range 0 .. 63 loop
            Dst (I)      := Src (2 * I) + Src (2 * I + 1);
            Dst (I + 64) := Src (2 * I) - Src (2 * I + 1);
            pragma Loop_Invariant (for all K in Index_128 range 0 .. I =>
                                     Dst (K)'Initialized and then Dst (K) in -(Src_Bound * 2) .. (Src_Bound * 2));
            pragma Loop_Invariant (for all K in Index_128 range 64 .. I + 64 =>
                                     Dst (K)'Initialized and then Dst (K) in -(Src_Bound * 2) .. (Src_Bound * 2));
         end loop;
      end Single_Hadamard;


      function Hadamard (Src : in Simple_Expanded_CDW) return Transformed_Expanded_CDW
        with Global => null;

      function Hadamard (Src : in Simple_Expanded_CDW) return Transformed_Expanded_CDW
      is
         T1, T2 : Expanded_CDW;
      begin
         --  7 passes. Codewords double in max magnitude for each pass.
         Single_Hadamard (Src, T1,      Param.RMMF);
         Single_Hadamard (T1,  T2,  2 * Param.RMMF);
         Single_Hadamard (T2,  T1,  4 * Param.RMMF);
         Single_Hadamard (T1,  T2,  8 * Param.RMMF);
         Single_Hadamard (T2,  T1, 16 * Param.RMMF);
         Single_Hadamard (T1,  T2, 32 * Param.RMMF);
         Single_Hadamard (T2,  T1, 64 * Param.RMMF);
         return T1;
      end Hadamard;

      function Find_Peaks (Src : in Final_Transformed_Expanded_CDW) return U8
        with Global => null;

      function Find_Peaks (Src : in Final_Transformed_Expanded_CDW) return U8
      is
         T, Absolute    : Final_Transformed_Codeword;
         Peak_Value     : Final_Transformed_Codeword := 0;
         Peak_Abs_Value : Final_Transformed_Codeword := 0;
         Peak_Pos       : I32 range 0 .. 255 := 0;
      begin
         --  RCC: neither this nor reference code are CCT
         for I in Index_128 loop
            T        := Src (I);
            Absolute := abs (T);
            if Absolute > Peak_Abs_Value then
               Peak_Value     := T;
               Peak_Pos       := I;
               Peak_Abs_Value := Absolute;
            end if;
            pragma Loop_Invariant (Peak_Pos in Index_128);
         end loop;

         if Peak_Value > 0 then
            Peak_Pos := Peak_Pos + 128;
         end if;
         return U8 (Peak_Pos);
      end Find_Peaks;

      function Decode (CDW : in CDW_Words) return Msg_Words
      is
#if HQC_PARAM = 3 then
         --  For HQC-3, output is 7 Words (56 bytes). All are assigned below, so not init here required
         R : Msg_Bytes;
#else
         --  For HQC-1, output is  6 Words (48 bytes), but only first 46 are filled, so initialize all to 0 here
         --  For HQC-5, output is 12 Words (96 bytes), but only first 90 are filled, so initialize all to 0 here
         R : Msg_Bytes := (others => 0);
#end if;
      begin
         for I in Msg_Bytes_Index range 0 .. Param.VEC_N1_SIZE_BYTES - 1 loop
            declare
               T1 : constant RMMF_Codewords_As_Words := RMMF_Codewords_As_Words (CDW ((I * 2) * Param.RMMF ..
                                                                                      ((I + 1) * 2) * Param.RMMF - 1));
               T2 : constant RMMF_Codewords := To_RMMF_Codewords (T1);
               T3 : constant Simple_Expanded_CDW := Expand_And_Sum (T2);
               T4 : Final_Transformed_Expanded_CDW := Hadamard (T3);
            begin
               T4 (0) := T4 (0) - Param.RMMF * 64;
               R (I) := Find_Peaks (T4);
            end;
         end loop;
         return To_Words (R);
      end Decode;

   end Reed_Muller;

   package FFT
   is
      subtype Betas_Count is N32 range 1 .. Param.M - 1;
      subtype Betas_Index is N32 range 0 .. Param.M - 2;
      type Betas is array (Betas_Index range <>) of U16;

      subtype All_Betas is Betas (Betas_Index)
        with Dynamic_Predicate => (for all K in Betas_Index => All_Betas (K) = 2 ** (Param.M - 1 - Natural (K)));

      Max_Sum : constant := 2 ** Param.M;

      Error_Length : constant := 2 ** Param.M;
      subtype Error_Index is N32 range 0 .. Error_Length - 1;
      subtype Errors is Byte_Seq (Error_Index);

      subtype U16_1  is U16_Seq (Index_1);
      subtype U16_2  is U16_Seq (Index_2);
      subtype U16_4  is U16_Seq (Index_4);
      subtype U16_8  is U16_Seq (Index_8);
      subtype U16_16 is U16_Seq (Index_16);
      subtype U16_32 is U16_Seq (Index_32);

      procedure Compute_FFT_Betas (B : out All_Betas)
        with Global => null;

      procedure Compute_Subset_Sums (Subset_Sums : out    U16_Seq;
                                     Set         :     in Betas;
                                     Set_Size    :     in Betas_Count)
        with Global => null,
             Pre    => Subset_Sums'First = 0 and then
                       Subset_Sums'Last  >= 0 and then
                       Subset_Sums'Last  = 2**Natural (Set_Size) - 1 and then
                       Set'Length = Set_Size and then
                       Set'First = 0 and then
                       Set'Last  = Set_Size - 1;

      --  As Compute_Subset_Sums, but with stronger pre-condition that implies
      --  a stronger post-condition. Needed to prove FFT_Retrieve_Error_Poly
      procedure Compute_Initial_Subset_Sums (Subset_Sums : out    U16_Seq;
                                             Set         :     in Betas;
                                             Set_Size    :     in Betas_Count)
        with Global => null,
             Pre    => Subset_Sums'First = 0 and then
                       Subset_Sums'Last  >= 0 and then
                       Subset_Sums'Last  = 2**Natural (Set_Size) - 1 and then
                       Set'Length = Set_Size and then
                       Set'First = 0 and then
                       Set'Last  = Set_Size - 1 and then
                       (for all K in Set'Range => Set (K) = 2 ** (Param.M - 1 - Natural (K))),
             Post   => (for all K in Subset_Sums'Range => Subset_Sums (K) <= Max_Sum - 2 ** (Param.M - Natural (Set_Size)));


      procedure FFT_Rec (W        :    out U16_Seq;
                         F        : in     U16_Seq;
                         F_Coeffs : in     N32; -- number of coeffs in F
                         M        : in     Betas_Count; -- Number of Betas
                         M_F      : in     Param.FFT_Power;
                         B        : in     Betas)
        with Always_Terminates,
             Global => null,
             Subprogram_Variant => (Decreases => M_F),
             Pre    => M = M_F + (Param.M - Param.FFT) and then
                       F_Coeffs <= Param.PDELTA + 1 and then
                       W'First = 0 and then
                       W'Length = 2 ** Natural (M) and then
                       W'Last = 2 ** Natural (M) - 1 and then
                       F'First = 0 and then
                       F'Length = 2 ** Natural (M_F) and then
                       F'Last   = 2 ** Natural (M_F) - 1 and then
                       B'First = 0 and then
                       B'Last = M - 1 and then
                       B'Length = M;

      procedure FFT (W        :    out U16_Seq;
                     F        : in     U16_Seq;
                     F_Coeffs : in     N32)
        with Always_Terminates,
             Global => null,
             Pre    => F_Coeffs <= Param.PDELTA + 1 and then
                       F'First = 0 and then
                       (F'Length = 2 ** Natural (Param.FFT)) and then
                       W'First = 0 and then
                       (W'Length = 2 ** Natural (Param.M));

      procedure Retrieve_Error_Poly (Error :    out Errors;
                                     W     : in     U16_Seq)
        with Global => null,
             Pre    => W'First = 0 and then
                       (W'Length = 2 ** Natural (Param.M));

   end FFT;



   package body FFT
   is
      procedure Radix (F0 : out U16_Seq; F1 : out U16_Seq; F : in U16_Seq; M_F : Param.FFT_Power)
        with Always_Terminates,
             Global => null,
                Pre => (F0'First = 0 and F1'First = 0 and F'First = 0) and then
                       ((F'Length = 2 ** Natural (M_F)) and
                        F0'Length = F'Length / 2 and
                        F1'Length = F'Length / 2);

      procedure Compute_FFT_Betas (B : out All_Betas)
      is
         subtype Some_Betas is Betas (Betas_Index); -- no constraint
         LB : Some_Betas;
      begin
         LB := (others => 0);
         for I in B'Range loop
            LB (I) := 2**(Param.M - 1 - Natural (I));
            pragma Loop_Invariant (for all K in Betas_Index range 0 .. I => LB (K) = 2 ** (Param.M - 1 - Natural (K)));
         end loop;
         B := All_Betas (LB);
      end Compute_FFT_Betas;

      procedure Compute_Initial_Subset_Sums (Subset_Sums : out    U16_Seq;
                                             Set         :     in Betas;
                                             Set_Size    :     in Betas_Count)
      is
      begin
         Subset_Sums := (others => 0);
         for I in Natural range 0 .. Natural (Set_Size) - 1 loop
            for J in N32 range 0 .. 2**I - 1 loop
               --  Upper-bound on elements already set is 2 times bigger than...
               pragma Loop_Invariant (for all K in N32 range 0 .. N32 (2**I) - 1 =>
                                        Subset_Sums (K) <= Max_Sum - 2 ** (Param.M - I));
               --  Upper-bound on elements about to be set
               pragma Loop_Invariant (for all K in N32 range N32 (2**I) .. (N32 (2**I) + J) - 1 =>
                                        Subset_Sums (K) <= Max_Sum - 2 ** (Param.M - 1 - I));

               --  From the pre-condition we know upper-bound on Set (I)
               pragma Assert (Set (N32 (I))   <= 2 ** (Param.M - 1 - I));
               --  From the second clause of the loop invariant, we have an upper-bound on Subset_Sums (J)
               pragma Assert (Subset_Sums (J) <= Max_Sum - 2 ** (Param.M - I));
               --  So summing those 2 inequalities yields an upper-bound on the new element to be set here,
               --  and this re-establishes the loop invariant

               --  NOTE: "+" here is equivalent to "xor" given the pre-condition that all values
               --  of Set are distinct powers of 2. The use of "+" here allows automated proof
               --  of the second loop invariant above
               Subset_Sums (N32 (2**I) + J) := Set (N32 (I)) + Subset_Sums (J);
            end loop;
            --  On termination, J = 2**I - 1, so...
            pragma Loop_Invariant (for all K in N32 range 0 .. (N32 (2**I) + 2**I) - 1 =>
                                     Subset_Sums (K) <= Max_Sum - 2 ** ((Param.M - 1) - I));
         end loop;

         --  (2**I + 2**I - 1) = 2**(I+1) - 1 and
         --  I = Set_Size - 1
         --    ==>
         --  (2**I + 2**I - 1 = 2**(I+1) - 1 = 2**Set_Size - 1 = Subset_Sums'Last
         --    ==>
         --  All elements of Subset_Sums have been initialized, so
         pragma Assert (for all K in N32 range 0 .. Subset_Sums'Last =>
                          Subset_Sums (K) <= Max_Sum - 2 ** (Param.M - Natural (Set_Size)));

      end Compute_Initial_Subset_Sums;

      procedure Compute_Subset_Sums (Subset_Sums : out    U16_Seq;
                                     Set         :     in Betas;
                                     Set_Size    :     in Betas_Count)
      is
      begin
         Subset_Sums := (others => 0);
         for I in Natural range 0 .. Natural (Set_Size) - 1 loop
            for J in N32 range 0 .. 2**I - 1 loop
               --  NOTE: "xor" is required here, since in this case we do not assume that
               --  all member of Set are distinct powers of 2.
               Subset_Sums (N32 (2**I) + J) := Set (N32 (I)) xor Subset_Sums (J);
            end loop;
         end loop;
      end Compute_Subset_Sums;

      procedure Radix2 (F0 : out U16_2; F1 : out U16_2; F : in U16_4)
        with Global => null,
             Pre    => F'Length = 4 and F0'Length = 2 and F1'Length = 2
      is
         F00, F01 : U16;
         F10, F11 : U16;
      begin
         F00 := F (0);
         F01 := F (2) xor F (3);
         F10 := F (1) xor F01;
         F11 := F (3);

         F0 := U16_2'(F00, F01);
         F1 := U16_2'(F10, F11);
      end Radix2;

      procedure Radix3 (F0 : out U16_4; F1 : out U16_4; F : in U16_8)
        with Global => null,
             Pre    => F'Length = 8 and F0'Length = 4 and F1'Length = 4
      is
         F00, F01, F02, F03 : U16;
         F10, F11, F12, F13 : U16;
      begin
         F00 := F (0);
         F02 := F (4) xor F (6);
         F03 := F (6) xor F (7);
         F11 := F (3) xor F (5) xor F (7);
         F12 := F (5) xor F (6);
         F13 := F (7);
         F01 := F (2) xor F02 xor F11;
         F10 := F (1) xor F01;

         F0 := U16_4'(F00, F01, F02, F03);
         F1 := U16_4'(F10, F11, F12, F13);
      end Radix3;

      procedure Radix4 (F0 : out U16_8; F1 : out U16_8; F : in U16_16)

        with Global => null,
             Pre    => F'Length = 16 and F0'Length = 8 and F1'Length = 8
      is
         F00, F01, F02, F03, F04, F05, F06, F07 : U16;
         F10, F11, F12, F13, F14, F15, F16, F17 : U16;
      begin
         F04 := F (8)  xor F (12);
         F06 := F (12) xor F (14);
         F07 := F (14) xor F (15);
         F15 := F (11) xor F (13);
         F16 := F (13) xor F (14);
         F17 := F (15);
         F05 := F (10) xor F (12) xor F15;
         F14 := F (9)  xor F (13) xor F05;
         F00 := F (0);
         F13 := F (7) xor F (11) xor F (15);
         F03 := F (6) xor F (10) xor F (14) xor F13;
         F02 := F (4) xor F04 xor F03 xor F13;
         F11 := F (3) xor F (5) xor F (9) xor F (13) xor F13;
         F12 := F (3) xor F11 xor F03;
         F01 := F (2) xor F02 xor F11;
         F10 := F (1) xor F01;

         F0 := U16_8'(F00, F01, F02, F03, F04, F05, F06, F07);
         F1 := U16_8'(F10, F11, F12, F13, F14, F15, F16, F17);
      end Radix4;

      procedure Radix5 (F0 : out U16_16; F1 : out U16_16; F : in U16_32)
        with Global => null,
             Pre    => F'Length = 32 and F0'Length = 16 and F1'Length = 16
      is
         Q, R           : U16_16;
         Q0, Q1, R0, R1 : U16_8;
         QH : constant U16_8 := F (24 .. 31);
      begin
         Q := QH & QH;
         R := F (0 .. 15);
         for I in N32 range 0 .. 7 loop
            Q (I)     := Q (I)     xor F (16 + I); -- refs F (16 .. 23);
            R (I + 8) := R (I + 8) xor Q (I);
         end loop;
         Radix4 (Q0, Q1, Q);
         Radix4 (R0, R1, R);
         F0 := R0 & Q0;
         F1 := R1 & Q1;
      end Radix5;

      procedure Radix (F0 : out U16_Seq; F1 : out U16_Seq; F : in U16_Seq; M_F : Param.FFT_Power)
      is
      begin
         case M_F is
            when 1 =>
               F0 := U16_1'(0 => F (0));
               F1 := U16_1'(0 => F (1));
            when 2 =>
               Radix2 (F0, F1, F);
            when 3 =>
               Radix3 (F0, F1, F);
            when 4 =>
               Radix4 (F0, F1, F);
            when 5 =>
               pragma Assert (M_F = 5);
               pragma Assert (F'Length = 2 ** Natural (M_F));
               pragma Assert (F'Length = 32);
               pragma Assert (F0'Length = 16);
               pragma Assert (F1'Length = 16);
               Radix5 (F0, F1, F);
         end case;
      end Radix;

      procedure FFT_Rec (W        :    out U16_Seq;
                         F        : in     U16_Seq;
                         F_Coeffs : in     N32; -- number of coeffs in F
                         M        : in     Betas_Count; -- Number of Betas
                         M_F      : in     Param.FFT_Power;
                         B        : in     Betas)
      is
         FL : U16_Seq := F;
         Half_F_Length : constant N32 := F'Length / 2;
         subtype Half_F_Index is N32 range 0 .. Half_F_Length - 1;
         subtype Half_F is U16_Seq (Half_F_Index);
         F0, F1 : Half_F;

         subtype This_Betas_Index is N32 range 0 .. M - 1;
         subtype This_Betas is Betas (This_Betas_Index);

         subtype Next_Betas_Index is N32 range 0 .. M - 2;
         subtype Next_Betas is Betas (Next_Betas_Index);

         subtype Gammas_Sums_Index is N32 range 0 .. 2 ** (Natural (M) - 1) - 1;
         subtype Gammas_Sums is U16_Seq (Gammas_Sums_Index);

         Gammas : Next_Betas;
         Deltas : Next_Betas;
         GSums  : Gammas_Sums;
         U, V   : Gammas_Sums;

         subtype Offset_T is N32 range 1 .. 2 ** (Natural (Betas_Count'Last) - 1);

         function M_To_Offset (X : in Betas_Count) return Offset_T
           with Global => null,
                Post   => M_To_Offset'Result = 2 ** (Natural (X) - 1)
         is
            T1, T2 : Natural;
            R : Offset_T;
         begin
            T1 := Natural (X) - 1;
            pragma Assert (T1 in 0 .. Natural (Betas_Count'Last) - 1);
            T2 := 2 ** T1;
            pragma Assert (T2  = 2 ** (Natural (X) - 1));
            R := Offset_T (T2);
            pragma Assert (R  = Offset_T (2 ** (Natural (X) - 1)));
            return R;
         end M_To_Offset;
      begin
         W := (others => 0);

         if M_F = 1 then
            declare
               Tmp : This_Betas := (others => 0);
               X   : N32 := 1;
            begin
               for I in N32 range 0 .. M - 1 loop
                  Tmp (I) := GF.Mul (B (I), FL (1));
               end loop;
               W (0) := FL (0);
               for J in N32 range 0 .. M - 1 loop
                  pragma Loop_Invariant (X  = 2 ** Natural (J));
                  pragma Loop_Invariant (X <= 2 ** Natural (M - 1));

                  for K in N32 range 0 .. X - 1 loop
                     W (X + K) := W (K) xor Tmp (J);
                  end loop;
                  X := X * 2;
               end loop;
            end;
         else
            pragma Assert (M_F in 2 .. Param.FFT_Power'Last);
            pragma Assert (M > Param.M - Param.FFT);
            --  Step 2: compute g
            if B (M - 1) /= 1 then
               declare
                  Beta_M_Pow : U16 := 1;
                  X          : constant N32 := 2 ** Natural (M_F);
               begin
                  for I in N32 range 1 .. X - 1 loop
                     Beta_M_Pow := GF.Mul (Beta_M_Pow, B (M - 1));
                     FL (I) := GF.Mul (Beta_M_Pow, FL (I));
                  end loop;
               end;
            end if;

            --  Step 3
            Radix (F0, F1, FL, M_F);

            --  Step 4 : compute gammas and deltas
            for I in Next_Betas_Index loop
               Gammas (I) := GF.Mul (B (I), GF.Inverse (B (M - 1)));
            end loop;

            for I in Next_Betas_Index loop
               Deltas (I) := GF.Square (Gammas (I)) xor Gammas (I);
            end loop;

            Compute_Subset_Sums (GSums, Gammas, M - 1);

            --  Step 5
            FFT_Rec (U, F0, (F_Coeffs + 1) / 2, M - 1, M_F - 1, Deltas);

            pragma Assert (M >= 1 and M <= 7);

            declare
               K : constant Offset_T := M_To_Offset (M);
            begin
               pragma Assert (K in W'Range);
               pragma Assert (K + (K - 1) <= W'Last);

               if F_Coeffs <= 3 then
                  W (0) := U (0);
                  W (K) := U (0) xor F1 (0);
                  for I in N32 range 1 .. K - 1 loop
                     pragma Loop_Invariant (K + I in W'Range);
                     W (I)     := U (I) xor GF.Mul (GSums (I), F1 (0));
                     W (K + I) := W (I) xor F1 (0);
                  end loop;
               else
                  FFT_Rec (V, F1, F_Coeffs / 2, M - 1, M_F - 1, Deltas);

                  --  Step 6
                  W (K .. (K + K) - 1) := V (0 .. K - 1);
                  W (0) := U (0);
                  W (K) := W (K) xor U (0);
                  for I in N32 range 1 .. K - 1 loop
                     pragma Loop_Invariant (K + I in W'Range);
                     W (I)     := U (I) xor GF.Mul (GSums (I), V (I));
                     W (K + I) :=  W (K + I) xor W (I);
                  end loop;
               end if;
            end;
         end if;

      end FFT_Rec;

      procedure FFT (W        :    out U16_Seq;
                     F        : in     U16_Seq;
                     F_Coeffs : in     N32)
      is
         subtype Betas_Sums_Index is N32 range 0 .. 2 ** (Param.M - 1) - 1;
         subtype Betas_Sums_Type is U16_Seq (Betas_Sums_Index);

         Half_F_Length : constant N32 := F'Length / 2;
         subtype Half_F_Index is N32 range 0 .. Half_F_Length - 1;
         subtype Half_F is U16_Seq (Half_F_Index);

         subtype Deltas_Index is N32 range 0 .. Param.M - 2;
         subtype Deltas_Type is Betas (Deltas_Index);
         Deltas : Deltas_Type;

         Betas_Sums : Betas_Sums_Type;
         B      : All_Betas;
         F0, F1 : Half_F;
         U, V   : Betas_Sums_Type;
      begin
         W := (others => 0);
         Compute_FFT_Betas (B);
         Compute_Subset_Sums (Betas_Sums, B, Param.M - 1);
         Radix (F0, F1, F, Param.FFT);
         for I in Deltas_Index loop
            Deltas (I) := GF.Square (B (I)) xor B (I);
         end loop;

         FFT_Rec (U, F0, (F_Coeffs + 1) / 2, Param.M - 1, Param.FFT - 1, Deltas);
         FFT_Rec (V, F1,       F_Coeffs / 2, Param.M - 1, Param.FFT - 1, Deltas);

         declare
            K : constant N32 := 2 ** (Param.M - 1);
         begin
            W (K .. K + K - 1) := V (0 .. K - 1);
            W (0) := U (0);
            W (K) := W (K) xor U (0);
            for I in N32 range 1 .. K - 1 loop
               W (I)     := U (I) xor GF.Mul (Betas_Sums (I), V (I));
               W (K + I) :=  W (K + I) xor W (I);
            end loop;
         end;
      end FFT;


      procedure Retrieve_Error_Poly (Error :    out Errors;
                                     W     : in     U16_Seq)
      is
         K : constant N32 := 2 ** (Param.M - 1);

         subtype Gammas_Sums_Index is N32 range 0 .. 2 ** (Param.M - 1) - 1;
         subtype Gammas_Sums is U16_Seq (Gammas_Sums_Index);

         Gammas : All_Betas;
         GSums  : Gammas_Sums;
         Index  : Error_Index;
      begin
         Error := (others => 0);
         Compute_FFT_Betas (Gammas);
         Compute_Initial_Subset_Sums (GSums, Gammas, Param.M - 1);

         Error (0) := Error (0) xor 1 xor U8 (Shift_Right (-W (0), 15));
         Error (0) := Error (0) xor 1 xor U8 (Shift_Right (-W (K), 15));

         for I in N32 range 1 .. K - 1 loop
            Index := Error_Index (Param.GF_MUL_ORDER - GF.Log (Index_256 (GSums (I))));
            Error (Index) := Error (Index) xor 1 xor U8 (Shift_Right (-W (I), 15));

            Index := Error_Index ((Param.GF_MUL_ORDER - GF.Log (Index_256 (GSums (I)))) xor 1);
            Error (Index) := Error (Index) xor 1 xor U8 (Shift_Right (-W (K + I), 15));
         end loop;
      end Retrieve_Error_Poly;

   end FFT;

   package Reed_Solomon
   is
      subtype Syndrome_Table is U16_Seq (Param.RS_Row_Index);

      subtype Sigma_Index is N32 range 0 .. 2 ** Natural (Param.FFT) - 1;

      subtype Sigma_Table is U16_Seq (Sigma_Index);

      subtype Z_Table is U16_Seq (Index_N1);

      subtype Delta_Index  is N32 range 0 .. Param.PDELTA - 1;
      subtype Error_Table is U16_Seq (Delta_Index);


      subtype RS_Msg_Words_Index is N32 range 0 .. Param.VEC_K_SIZE_64 - 1;
      subtype RS_Msg_Words is U64_Seq (RS_Msg_Words_Index);

      subtype RS_Msg_Bytes_Index is N32 range 0 .. Param.K - 1;
      subtype RS_Msg_Bytes is Byte_Seq (RS_Msg_Bytes_Index);

      --  K bytes is exactly K/8 64-bit words
      pragma Assert (Param.K mod 8 = 0);

      --  RCC - not portable. Depends on little-endian words
      function To_Bytes2 is new Ada.Unchecked_Conversion (RS_Msg_Words, RS_Msg_Bytes);
      function To_Words is new Ada.Unchecked_Conversion (RS_Msg_Bytes, RS_Msg_Words);

      function Encode (Msg : in RS_Msg_Words) return Reed_Muller.Msg_Words
        with Global => null;

      --  Unused in production build
      --  function Compute_Generator_Poly return RS_G_Table
      --    with Global => null;

      function Decode (CDW : in Reed_Muller.Msg_Words) return RS_Msg_Words
        with Global => null;

   end Reed_Solomon;

   package body Reed_Solomon
   is
      subtype RS_CDW_Bytes_Index is N32 range 0 .. Param.VEC_N1_SIZE_BYTES - 1;
      subtype RS_CDW_Bytes is Byte_Seq (RS_CDW_Bytes_Index);

      --  Same but padded out to nearest 64-bit boundary
      subtype RS_CDW_Bytes_Padded_Index is N32 range 0 .. Reed_Muller.Msg_Words_Count * 8 - 1;
      subtype RS_CDW_Bytes_Padded is Byte_Seq (RS_CDW_Bytes_Padded_Index);

      --  RCC - not portable. Depends on little-endian words
      function CDW_Bytes_To_Words is new Ada.Unchecked_Conversion (RS_CDW_Bytes_Padded, Reed_Muller.Msg_Words);

      function Encode (Msg : in RS_Msg_Words) return Reed_Muller.Msg_Words
      is
         Msg_Bytes  : RS_Msg_Bytes;
         Gate_Value : U8;
         CDW_Bytes  : RS_CDW_Bytes_Padded := (others => 0);
         Tmp        : Param.RS_G_Table := (others => 0);
      begin
         Msg_Bytes := To_Bytes2 (Msg);
         for I in RS_Msg_Bytes_Index loop
            Gate_Value := Msg_Bytes (Param.K - 1 - I) xor CDW_Bytes (Param.N1 - Param.K - 1);

            for J in Param.RS_G_Index loop
               Tmp (J) := U8 (GF.Mul (U16 (Gate_Value), U16 (Param.RS_Poly_Coeffs (J))));
            end loop;

            for K in reverse N32 range 1 .. Param.N1 - Param.K - 1 loop
               CDW_Bytes (K) := CDW_Bytes (K - 1) xor Tmp (K);
            end loop;

            CDW_Bytes (0) := Tmp (0);
         end loop;

         CDW_Bytes (Param.N1 - Param.K .. Param.N1 - 1) := Msg_Bytes (0 .. Param.K - 1);
         return CDW_Bytes_To_Words (CDW_Bytes);
      end Encode;


      --  Unused in production build
      --  function Compute_Generator_Poly return RS_G_Table
      --  is
      --    R : RS_G_Table := (others => 0);
      --    Tmp_Degree : RS_G_Index;
      --  begin
      --    R (0) := 1;
      --    Tmp_Degree := 0;
      --    for I in RS_G_Index range 1 .. RS_G_Index'Last loop
      --       for J in reverse RS_G_Index range 1 .. Tmp_Degree loop
      --          R (J) := U8 (GF.Exp ((Index_256 (GF.Log (Index_256 (R (J)))) + I) mod Param.GF_MUL_ORDER)) xor
      --                   R (J - 1);
      --       end loop;
      --       R (0) := U8 (GF.Exp ((Index_256 (GF.Log (Index_256 (R (0)))) + I) mod Param.GF_MUL_ORDER));
      --       Tmp_Degree := Tmp_Degree + 1;
      --       pragma Loop_Invariant (Tmp_Degree = I);
      --       R (Tmp_Degree) := 1;
      --    end loop;
      --    return R;
      --  end Compute_Generator_Poly;


      function Compute_Syndromes (CDW : in RS_CDW_Bytes) return Syndrome_Table
        with Global => null
      is
         R : Syndrome_Table := (others => 0);
      begin
         for I in Param.RS_Row_Index loop
            for J in RS_CDW_Bytes_Index range 1 .. RS_CDW_Bytes_Index'Last loop
               R (I) := R (I) xor GF.Mul (U16 (CDW (J)), Param.Alpha_IJ_Pow (I)(J - 1));
            end loop;
            R (I) := R (I) xor U16 (CDW (0));
         end loop;
         return R;
      end Compute_Syndromes;

      procedure Compute_ELP (Sigma     : out    Sigma_Table;
                             Deg_Sigma : out    U16;
                             Syndromes :     in Syndrome_Table)
        with Always_Terminates, Global => null
      is
         Sigma_Copy, X_Sigma_P : Sigma_Table;
         Deg_Sigma_P, Deg_Sigma_Copy, Deg_X, Deg_X_Sigma_P : U16;
         DD, D, D_P, PP : U16;
         Mask1, Mask2, Mask12 : U16;
         I, K : N32;
      begin
         Sigma       := Sigma_Table'(1, others => 0);
         Sigma_Copy  := Sigma_Table'(others => 0);
         X_Sigma_P   := Sigma_Table'(0, others => 1);
         Deg_Sigma_P := 0;
         Deg_Sigma   := 0;
         D           := Syndromes (0);
         D_P         := 1;
         PP          := -1; --  = 16#FFFF# is well defined in Ada

         for Mu in Param.RS_Row_Index loop
            --  RCC: why not copy the final element too?
            Sigma_Copy (0 .. Sigma_Index'Last - 1) := Sigma (0 .. Sigma_Index'Last - 1);
            Deg_Sigma_Copy := Deg_Sigma;
            DD := GF.Mul (D, GF.Inverse (D_P));

            I := 1;
            while (I <= Mu + 1 and I <= Param.PDELTA) loop
               pragma Loop_Variant (Increases => I);
               Sigma (I) := Sigma (I) xor (GF.Mul (DD, X_Sigma_P (I)));
               I := I + 1;
            end loop;

            Deg_X         := U16 (Mu) - PP;
            Deg_X_Sigma_P := Deg_X + Deg_Sigma_P;

            Mask1 := (if D = 0 then 0 else 16#FFFF#);
            Mask2 := (if Deg_X_Sigma_P > Deg_Sigma then 16#FFFF# else 0);
            Mask12 := Mask1 and Mask2;
            Deg_Sigma := Deg_Sigma xor (Mask12 and (Deg_X_Sigma_P xor Deg_Sigma));

            exit when Mu = Param.RS_Row_Index'Last;

            PP  := PP  xor (Mask12 and (U16 (Mu) xor PP));
            D_P := D_P xor (Mask12 and (D xor D_P));

            for J in reverse Sigma_Index range 1 .. Sigma_Index'Last loop
               X_Sigma_P (J) := (Mask12 and Sigma_Copy (J - 1)) xor ((not Mask12) and X_Sigma_P (J - 1));
            end loop;

            Deg_Sigma_P := Deg_Sigma_P xor (Mask12 and (Deg_Sigma_Copy xor Deg_Sigma_P));
            D := Syndromes (Mu + 1);

            K := 1;
            while (K <= Mu + 1 and K <= Param.PDELTA) loop
               pragma Loop_Variant (Increases => K);
               D := D xor (GF.Mul (Sigma (K), Syndromes ((Mu + 1) - K)));
               K := K + 1;
            end loop;
         end loop;

      end Compute_ELP;

      function Compute_Roots (Sigma : in Sigma_Table) return FFT.Errors
        with Global => null
      is
         R : FFT.Errors;
         W : U16_Seq (FFT.Error_Index);
      begin
         FFT.FFT (W, Sigma, Param.PDELTA + 1);
         FFT.Retrieve_Error_Poly (R, W);
         return R;
      end Compute_Roots;

      function Compute_Z_Poly (Sigma     : in Sigma_Table;
                               Degree    : in U16;
                               Syndromes : in Syndrome_Table) return Z_Table
        with Global => null
      is
         Z : Z_Table := Z_Table'(1, others => 0);
         Mask  : U16;
      begin
         for I in Sigma_Index range 1 .. Sigma_Index'Last loop
            Mask  := -Shift_Right ((U16 (I) - Degree) - 1, 15);
            Z (I) := Mask and Sigma (I);
         end loop;

         Z (1) := Z (1) xor Syndromes (0);

         for I in Sigma_Index range 2 .. Sigma_Index'Last loop
            Mask  := -Shift_Right ((U16 (I) - Degree) - 1, 15);
            Z (I) := Z (I) xor (Mask and Syndromes (I - 1));

            for J in Sigma_Index range 1 .. I - 1 loop
               Z (I) := Z (I) xor (Mask and GF.Mul (Sigma (J), Syndromes ((I - J) - 1)));
            end loop;
         end loop;
         return Z;
      end Compute_Z_Poly;

      function Compute_Error_Values (Z : in Z_Table; Error : in FFT.Errors) return Z_Table
      is
         Error_Values : Z_Table;
         Beta_J, E_J  : Error_Table;
         Delta_Real_Value : U16;

         procedure Compute_Beta
           with Global => (Output => (Beta_J, Delta_Real_Value),
                           Input  => Error)
         is
            Delta_Counter : U16 := 0;
            Found, Mask1, Mask2 : U16;
         begin
            Beta_J := (others => 0);
            for I in Index_N1 loop
               Found := 0;
               Mask1 := (if Error (I) = 0 then 0 else 16#FFFF#);
               for J in Delta_Index loop
                  Mask2 := (if U16 (J) = Delta_Counter then 16#FFFF# else 0);
                  Beta_J (J) := Beta_J (J) + (Mask1 and Mask2 and GF.Exp (I));
                  Found := Found + (Mask1 and Mask2 and 1);
               end loop;
               Delta_Counter := Delta_Counter + Found;
            end loop;
            Delta_Real_Value := Delta_Counter;
         end Compute_Beta;

         procedure Compute_E
           with Global => (Output => E_J,
                           Input  => (Delta_Real_Value, Beta_J, Z))
         is
            Tmp1, Tmp2, Inverse, Inverse_Power_J, Mask1 : U16;
         begin
            for I in Delta_Index loop
               Tmp1 := 1;
               Tmp2 := 1;
               Inverse := GF.Inverse (Beta_J (I));
               Inverse_Power_J := 1;

               for J in N32 range 1 .. Param.PDELTA loop
                  Inverse_Power_J := GF.Mul (Inverse_Power_J, Inverse);
                  Tmp1 := Tmp1 xor GF.Mul (Inverse_Power_J, Z (J));
               end loop;

               for K in Delta_Index range 1 .. Delta_Index'Last loop
                  Tmp2 := GF.Mul (Tmp2,
                                  (1 xor GF.Mul (Inverse, Beta_J ((I + K) mod Param.PDELTA))));
               end loop;

               Mask1 := (if U16 (I) < Delta_Real_Value then 16#FFFF# else 0);
               E_J (I) := Mask1 and GF.Mul (Tmp1, GF.Inverse (Tmp2));
            end loop;
         end Compute_E;

         procedure Compute_Error_Values
           with Global => (Output => Error_Values,
                           Input  => (Error, E_J))
         is
            Delta_Counter : U16 := 0;
            Found, Mask1, Mask2 : U16;
         begin
            Error_Values := (others => 0);
            for I in Index_N1 loop
               Found := 0;
               Mask1 := (if Error (I) = 0 then 0 else 16#FFFF#);
               for J in Delta_Index loop
                  Mask2 := (if U16 (J) = Delta_Counter then 16#FFFF# else 0);
                  Error_Values (I) := Error_Values (I) + (Mask1 and Mask2 and E_J (J));
                  Found := Found + (Mask1 and Mask2 and 1);
               end loop;
               Delta_Counter := Delta_Counter + Found;
            end loop;
         end Compute_Error_Values;

      begin
         Compute_Beta;
         Compute_E;
         Compute_Error_Values;
         return Error_Values;
      end Compute_Error_Values;

      procedure Correct_Errors (CDW : in out RS_CDW_Bytes; Error_Values : in Z_Table)
        with Global => null
      is
      begin
         for I in CDW'Range loop
            --  RCC U16 to U8 conversion here truncates... OK?
            CDW (I) := CDW (I) xor U8 (Error_Values (I) and 16#FF#);
         end loop;
      end Correct_Errors;

      function Decode (CDW : in Reed_Muller.Msg_Words) return RS_Msg_Words
      is
         Tmp_Bytes : constant Reed_Muller.Msg_Bytes := Reed_Muller.To_Bytes (CDW);
         CDW_Bytes : RS_CDW_Bytes := RS_CDW_Bytes (Tmp_Bytes (RS_CDW_Bytes_Index));
         Syndromes : constant Syndrome_Table := Compute_Syndromes (CDW_Bytes);
         Sigma     : Sigma_Table;
         Deg_Sigma : U16;
         Error     : FFT.Errors;
         Z         : Z_Table;
         Error_Values : Z_Table;
      begin
         Compute_ELP (Sigma, Deg_Sigma, Syndromes);
         Error := Compute_Roots (Sigma);
         Z := Compute_Z_Poly (Sigma, Deg_Sigma, Syndromes);
         Error_Values := Compute_Error_Values (Z, Error);
         Correct_Errors (CDW_Bytes, Error_Values);


         declare
            First_Coeff : Boolean := True;
         begin
            Dbg.Put ("The syndromes:");
            for I in Syndromes'Range loop
               Dbg.Put (Syndromes (I)'Img);
            end loop;
            Dbg.New_Line (2);
            Dbg.Put ("The error locator polynomial: sigma(x) =");
            if Sigma (0) /= 0 then
               Dbg.Put (Sigma (0)'Img);
               First_Coeff := False;
            end if;
            for I in Sigma_Index range 1 .. Sigma_Index'Last loop
               if Sigma (I) /= 0 then
                  if not First_Coeff then
                     Dbg.Put (" + ");
                  end if;
                  First_Coeff := False;
                  if Sigma (I) /= 1 then
                     Dbg.Put (Sigma (I)'Img);
                  end if;
                  if I = 1 then
                     Dbg.Put ("x");
                  else
                     Dbg.Put ("x^" & I'Img);
                  end if;
               end if;
            end loop;
            if First_Coeff then
               Dbg.Put ("0");
            end if;

            Dbg.New_Line (2);
            Dbg.Put ("The polynomial: z(x) =");
            First_Coeff := True;
            if Z (0) /= 0 then
               Dbg.Put (Z (0)'Img);
               First_Coeff := False;
            end if;
            for I in Index_N1 range 1 .. Index_N1'Last loop
               if Z (I) /= 0 then
                  if not First_Coeff then
                     Dbg.Put (" + ");
                  end if;
                  First_Coeff := False;
                  if Z (I) /= 1 then
                     Dbg.Put (Z (I)'Img);
                  end if;
                  if I = 1 then
                     Dbg.Put ("x");
                  else
                     Dbg.Put ("x^" & I'Img);
                  end if;
               end if;
            end loop;
            if First_Coeff then
               Dbg.Put ("0");
            end if;


            declare
               J : Index_N1 := 0;
            begin
               Dbg.New_Line (2);
               Dbg.Put ("The pairs of (error locator numbers, error values):");
               for I in Index_N1 loop
                  pragma Loop_Invariant (J <= I);
                  if Error (I) /= 0 then
                     declare
                        I_Str  : constant String := I'Img;
                        I_Str2 : constant String := String (I_Str (2 .. I_Str'Last));
                     begin
                        Dbg.Put ("(" & I_Str2 & "," & Error_Values (J)'Img & ") ");
                        if I < Index_N1'Last then
                           J := J + 1;
                        end if;
                     end;
                  end if;
               end loop;
            end;
            Dbg.New_Line;
         end;


         --  Msg is 2 64-bit words, so 16 bytes
         --  K = 16, G = 31
         --  CDW_Bytes is indexed on 0 .. 45 (N1 = 46)
         --     memcpy(msg, cdw_bytes + (PARAM_G - 1), PARAM_K);
         --  == memcpy(msg, cdw_bytes + 30, 16);
         --  == memcpy(msg, &cdw_bytes[30], 16);

         --  RCC Zeroize CDW_Bytes here. TBD
         --  RCC not portable - depends on little-endian words
         return To_Words (RS_Msg_Bytes (CDW_Bytes (Param.G - 1 .. CDW_Bytes'Last)));

      end Decode;

   end Reed_Solomon;

   package Code
   is
      function Encode (M : in Reed_Solomon.RS_Msg_Words) return Reed_Muller.CDW_Words
        with Global => null;

      function Decode (M : in Reed_Muller.CDW_Words) return Reed_Solomon.RS_Msg_Words
        with Global => null;
   end Code;

   package body Code
   is
      function Encode (M : in Reed_Solomon.RS_Msg_Words) return Reed_Muller.CDW_Words
      is
         T : Reed_Muller.Msg_Words;
         R : Reed_Muller.CDW_Words;
      begin
         T := Reed_Solomon.Encode (M);
         Dbg.Put_Line ("Reed-Solomon code word:", T, Param.VEC_N1_SIZE_BYTES);
         R := Reed_Muller.Encode (T);
         Dbg.Put_Line ("Concatenated code word:", R, Param.VEC_N1N2_SIZE_BYTES);
         return R;
      end Encode;

      function Decode (M : in Reed_Muller.CDW_Words) return Reed_Solomon.RS_Msg_Words
      is
         T : Reed_Muller.Msg_Words;
         R : Reed_Solomon.RS_Msg_Words;
      begin
         T := Reed_Muller.Decode (M);
         R := Reed_Solomon.Decode (T);
         Dbg.New_Line (2);
         Dbg.Put_Line ("Reed-Muller decoding result (the input for the Reed-Solomon decoding algorithm):",
                       T, Param.VEC_N1_SIZE_BYTES);
         return R;
      end Decode;
   end Code;

   package Symmetric
   is
      procedure PRNG_Init (PRNG_Ctx               :    out SHAKE.SHAKE256.Context;
                           Entropy_Input          : in     Byte_Seq;
                           Personalization_String : in     Byte_Seq)
        with Global => null,
             Pre    => Entropy_Input'First          in 0 .. 1 and
                       Entropy_Input'Last           in 0 .. 48 and
                       Personalization_String'First in 0 .. 1 and
                       Personalization_String'Last  in 0 .. 48;

      procedure PRNG_Get_Bytes (PRNG_Ctx : in out SHAKE.SHAKE256.Context;
                                Output   :    out Byte_Seq)
        with Global => null,
             Pre    => Output'First = 0 and
                       Output'Length <= 48;

      procedure XOF_Init (XOF_Ctx :    out SHAKE.SHAKE256.Context;
                          Seed    : in     Byte_Seq)
        with Global => null,
             Pre    => Seed'First = 0 and
                       Seed'Length <= 32;

      procedure XOF_Get_Bytes (XOF_Ctx : in out SHAKE.SHAKE256.Context;
                               Output  :    out Byte_Seq)
        with Global => null,
             Pre    => Output'First = 0 and
                       Output'Length <= 8192;

      function Hash_I (Seed : in Seed_Bytes) return Bytes_64
        with Global => null;

      function Hash_H (EK_KEM : in Encapsulation_Key) return Bytes_32
        with Global => null;

      function Hash_G (Hash_EK_KEM : in Seed_Bytes;
                       M           : in Security_Bytes;
                       Salt        : in Salt_Bytes) return Bytes_64
        with Global => null;

      function Hash_J (Hash_EK_KEM : in Seed_Bytes;
                       Sigma       : in Security_Bytes;
                       C_KEM       : in Ciphertext_KEM_T) return Bytes_32
        with Global => null;

   end Symmetric;

   package body Symmetric
   is
      use SHA3;

      HQC_PRNG_DOMAIN : constant := 0;
      HQC_XOF_DOMAIN  : constant := 1;

      HQC_G_FCT_DOMAIN : constant := 0;
      HQC_H_FCT_DOMAIN : constant := 1;
      HQC_I_FCT_DOMAIN : constant := 2;
      HQC_J_FCT_DOMAIN : constant := 3;

      procedure PRNG_Init (PRNG_Ctx               :    out SHAKE.SHAKE256.Context;
                           Entropy_Input          : in     Byte_Seq;
                           Personalization_String : in     Byte_Seq)
      is
         D : constant SHAKE.SHAKE256.Byte_Array (0 .. 0) := (0 => HQC_PRNG_DOMAIN);
      begin
         SHAKE.SHAKE256.Init (PRNG_Ctx);
         if Entropy_Input'Length >= 1 then
               SHAKE.SHAKE256.Update (PRNG_Ctx, SHAKE.SHAKE256.Byte_Array (Entropy_Input));
         end if;
         if Personalization_String'Length >= 1 then
               SHAKE.SHAKE256.Update (PRNG_Ctx, SHAKE.SHAKE256.Byte_Array (Personalization_String));
         end if;
         SHAKE.SHAKE256.Update (PRNG_Ctx, D);
      end PRNG_Init;

      procedure PRNG_Get_Bytes (PRNG_Ctx : in out SHAKE.SHAKE256.Context;
                                Output   :    out Byte_Seq)
      is
      begin
         SHAKE.SHAKE256.Extract (PRNG_Ctx, SHAKE.SHAKE256.Byte_Array (Output));
      end PRNG_Get_Bytes;

      procedure XOF_Init (XOF_Ctx :    out SHAKE.SHAKE256.Context;
                          Seed    : in     Byte_Seq)
      is
         D : constant SHAKE.SHAKE256.Byte_Array (0 .. 0) := (0 => HQC_XOF_DOMAIN);
      begin
         SHAKE.SHAKE256.Init (XOF_Ctx);
         SHAKE.SHAKE256.Update (XOF_Ctx, SHAKE.SHAKE256.Byte_Array (Seed));
         SHAKE.SHAKE256.Update (XOF_Ctx, D);
      end XOF_Init;

      procedure XOF_Get_Bytes (XOF_Ctx : in out SHAKE.SHAKE256.Context;
                               Output  :    out Byte_Seq)
      is
      begin
         SHAKE.SHAKE256.Extract (XOF_Ctx, SHAKE.SHAKE256.Byte_Array (Output));
      end XOF_Get_Bytes;

      function Hash_I (Seed : in Seed_Bytes) return Bytes_64
      is
         C : SHA3_512.Context;
         D : constant SHA3_512.Byte_Array (0 .. 0) := (0 => HQC_I_FCT_DOMAIN);
         R : Bytes_64;
      begin
         SHA3_512.Init (C);
         SHA3_512.Update (C, SHA3_512.Byte_Array (Seed));
         SHA3_512.Update (C, D);
         SHA3_512.Final (C, SHA3_512.Byte_Array (R));
         pragma Unreferenced (C);
         return R;
      end Hash_I;

      function Hash_H (EK_KEM : Encapsulation_Key) return Bytes_32
      is
         C : SHA3_256.Context;
         D : constant SHA3_256.Byte_Array (0 .. 0) := (0 => HQC_H_FCT_DOMAIN);
         R : Bytes_32;
      begin
         SHA3_256.Init (C);
         SHA3_256.Update (C, SHA3_256.Byte_Array (EK_KEM));
         SHA3_256.Update (C, D);
         SHA3_256.Final (C, SHA3_256.Byte_Array (R));
         pragma Unreferenced (C);
         return R;
      end Hash_H;

      function Hash_G (Hash_EK_KEM : in Seed_Bytes;
                       M           : in Security_Bytes;
                       Salt        : in Salt_Bytes) return Bytes_64
      is
         C : SHA3_512.Context;
         D : constant SHA3_512.Byte_Array (0 .. 0) := (0 => HQC_G_FCT_DOMAIN);
         R : Bytes_64;
      begin
         SHA3_512.Init (C);
         SHA3_512.Update (C, SHA3_512.Byte_Array (Hash_EK_KEM));
         SHA3_512.Update (C, SHA3_512.Byte_Array (M));
         SHA3_512.Update (C, SHA3_512.Byte_Array (Salt));
         SHA3_512.Update (C, D);
         SHA3_512.Final (C, SHA3_512.Byte_Array (R));
         pragma Unreferenced (C);
         return R;
      end Hash_G;

      function Hash_J (Hash_EK_KEM : in Seed_Bytes;
                       Sigma       : in Security_Bytes;
                       C_KEM       : in Ciphertext_KEM_T) return Bytes_32
      is
         C : SHA3_256.Context;
         D : constant SHA3_256.Byte_Array (0 .. 0) := (0 => HQC_J_FCT_DOMAIN);
         R : Bytes_32;

         function To_Bytes is new Ada.Unchecked_Conversion (U64_Seq_N_Bits_As_Words, Seq_N_Bits_As_Bytes_Padded);

         --  Convert U from VEC_N_SIZE_64 words to VEC_N_SIZE_64*8 bytes, then slice out the first VEC_N_SIZE_BYTES of them
         U : constant Seq_N_Bits_As_Bytes := Seq_N_Bits_As_Bytes (To_Bytes (C_KEM.C_PKE.U)(Index_N_Bits_As_Bytes));
         --  Same for V, but slice out the first VEC_N1N2_SIZE_BYTES of them
         V : constant Seq_N1N2_Bits_As_Bytes := Seq_N1N2_Bits_As_Bytes (To_Bytes (C_KEM.C_PKE.V)(Index_N1N2_Bits_As_Bytes));
      begin
         SHA3_256.Init (C);
         SHA3_256.Update (C, SHA3_256.Byte_Array (Hash_EK_KEM));
         SHA3_256.Update (C, SHA3_256.Byte_Array (Sigma));

         pragma Assert (U'Length = Param.VEC_N_SIZE_BYTES);
         SHA3_256.Update (C, SHA3_256.Byte_Array (U));

         pragma Assert (V'Length = Param.VEC_N1N2_SIZE_BYTES);
         SHA3_256.Update (C, SHA3_256.Byte_Array (V));

         SHA3_256.Update (C, SHA3_256.Byte_Array (C_KEM.Salt));
         SHA3_256.Update (C, D);
         SHA3_256.Final (C, SHA3_256.Byte_Array (R));
         pragma Unreferenced (C);
         return R;
      end Hash_J;

   end Symmetric;

   package Vector
   is
      subtype Support_Index is N32 range 0 .. Param.OMEGA_R - 1;
      subtype Support_Vector is U32_Seq (Support_Index);

      subtype Weights is N32 range Param.OMEGA_MIN .. Param.OMEGA_MAX;

      function Add (V1, V2 : in U64_Seq) return U64_Seq
        with Global => null,
             Pre    => V1'First = V2'First and
                       V1'Last = V2'Last,
             Post =>   V1'First = Add'Result'First and
                       V1'Last = Add'Result'Last;


      function Compare (V1, V2 : in Byte_Seq) return U8_Bit
        with Global => null,
             Pre    => V1'First = V2'First and
                       V1'Last = V2'Last;

      --  Make N1N2 dynamic here to ensure that potentially dead
      --  code gets analysed and proved.
      procedure Truncate (V    : in out U64_Seq_N_Bits_As_Words;
                          N1N2 : in     N32)
        with Global => null,
             Pre    => N1N2 >= Param.N1N2_Min and
                       N1N2 <= Param.N1N2_Max and
                       N1N2 < Param.N;

      procedure Set_Random (Ctx : in out SHAKE.SHAKE256.Context;
                            V   :    out U64_Seq_N_Bits_As_Words)
        with Global => null;

      procedure Sample_Fixed_Weight1 (Ctx     : in out SHAKE.SHAKE256.Context;
                                      V       :    out U64_Seq_N_Bits_As_Words;
                                      Weight  : in     Weights)
        with Always_Terminates,
             Global => null,
             Pre    => Param.OMEGA_R = Param.OMEGA_E and then
                       (Weight = Param.OMEGA_R or Weight = Param.OMEGA) and then
                       Weight < Support_Index'Last;

      procedure Sample_Fixed_Weight2 (Ctx     : in out SHAKE.SHAKE256.Context;
                                      V       :    out U64_Seq_N_Bits_As_Words;
                                      Weight  : in     Weights)
        with Always_Terminates,
             Global => null,
             Pre    => Param.OMEGA_R = Param.OMEGA_E and then
                       (Weight = Param.OMEGA_R or Weight = Param.OMEGA) and then
                       Weight <= Support_Vector'Length;

   end Vector;

   package body Vector
   is
      subtype Support_Bytes_Index is N32 range 0 .. (Param.OMEGA_R * 4) - 1;
      subtype Support_Vector_Bytes is Byte_Seq (Support_Bytes_Index);

      function Compare_U32 (V1, V2 : in U32) return U32
        with Global => null,
             Post   => Compare_U32'Result = 0 or Compare_U32'Result = 1
      is
      begin
         return SR ((V1 - V2) or (V2 - V1), 31) xor 1;
      end Compare_U32;

      function Barrett_Reduce (X : in U32) return U32
      is
         Q : U64;
         R : U32;
         Reduce_Flag, Mask : U32;
      begin
         Q := SR (U64 (X) * Param.N_MU, 32);
         Q := Q * Param.N;

         --  RCC: C silently truncates from u64 to u32 here.
         --  To satisfy SPARK, we need to prove that Q < 2**32
         pragma Assert (Q < (2**32));
         R := X - U32 (Q);

         Reduce_Flag := SR (R - Param.N, 31) xor 1;
         pragma Assert (Reduce_Flag = 0 or Reduce_Flag = 1);

         Mask := -Reduce_Flag;
         pragma Assert (Mask = 0 or Mask = U32'Last);

         R := R - (Param.N and Mask);
         return R;
      end Barrett_Reduce;

      procedure Generate_Random_Support1 (Ctx     : in out SHAKE.SHAKE256.Context;
                                          Support :    out Support_Vector;
                                          Weight  : in     Weights)
        with Always_Terminates,
             Global => null,
             Pre    => Weight < Support_Index'Last
      is
         Rand_Bytes : Byte_Seq (Index_3);

         subtype N32_Bit is N32 range 0 .. 1;
         Inc : N32_Bit;

         subtype I_Index is N32 range 0 .. Param.OMEGA_R;
         I   : I_Index;
      begin
         Support := (others => 0);
         I := 0;

         while (I < Weight) loop
            pragma Annotate (GNATprove, False_Positive, "loop might be nonterminating", "probabilistic termination");

            pragma Loop_Invariant (I <  N32 (Weight));
            pragma Loop_Invariant (Weight < Support_Index'Last);
            pragma Loop_Invariant (I <= Support_Index'Last);

            loop
               pragma Annotate (GNATprove, False_Positive, "loop might be nonterminating", "probabilistic termination");
               pragma Loop_Invariant (I <  Weight);
               pragma Loop_Invariant (Weight < Support_Index'Last);
               pragma Loop_Invariant (I <= Support_Index'Last);

               --  Read exactly 3 bytes per sample (matching C reference)
               Symmetric.XOF_Get_Bytes (Ctx, Rand_Bytes);

               --  Little-endian: first byte is least significant
               Support (I) := U32 (Rand_Bytes (0))
                           or SL (U32 (Rand_Bytes (1)), 8)
                           or SL (U32 (Rand_Bytes (2)), 16);

               exit when Support (I) < Param.UTILS_REJECTION_THRESHOLD;

            end loop;

            Support (I) := Barrett_Reduce (Support (I));

            Inc := 1;

            for K in N32 range 0 .. I - 1 loop
               if Support (K) = Support (I) then
                  Inc := 0;
               end if;
            end loop;

            I := I + Inc;
         end loop;

      end Generate_Random_Support1;

      procedure Generate_Random_Support2 (Ctx     : in out SHAKE.SHAKE256.Context;
                                          Support :    out Support_Vector;
                                          Weight  : in     Weights)
        with Always_Terminates,
             Global => null,
             Pre    => Param.OMEGA_R = Param.OMEGA_E and then
                       (Weight = Param.OMEGA_R or Weight = Param.OMEGA)
      is
         function To_Words is new Ada.Unchecked_Conversion (Support_Vector_Bytes, Support_Vector);
         Rand_Bytes : Support_Vector_Bytes;
         Rand_U32   : Support_Vector;
         Buff       : U64;
         Found      : U32;
         Mask       : U32;
      begin
         Symmetric.XOF_Get_Bytes (Ctx, Rand_Bytes);
         Rand_U32 := To_Words (Rand_Bytes);

         for I in Support_Index loop
            Buff := U64 (Rand_U32 (I));
            Support (I) := U32 (I) + U32 (SR (Buff * (Param.N - U64 (I)), 32));
         end loop;

         for I in reverse Support_Index range 0 .. Weight - 1 loop
            Found := 0;

            for J in Support_Index range I + 1 .. Weight - 1 loop
               Found := Found or Compare_U32 (Support (J), Support (I));
            end loop;
            Mask := -Found;
            Support (I) := (Mask and U32 (I)) xor ((not Mask) and Support (I));
         end loop;

      end Generate_Random_Support2;

      procedure Write_Support_To_Vector (V       :    out U64_Seq_N_Bits_As_Words;
                                         Support : in     Support_Vector;
                                         Weight  : in     Weights)
        with Global => null,
             Pre    => Param.OMEGA_R = Param.OMEGA_E and
                       (Weight = Param.OMEGA_R or Weight = Param.OMEGA)
      is
         Index_Tab : Support_Vector := (others => 0);
         Bit_Tab   : U64_Seq (Support_Index) := (others => 0);
         Pos       : Natural;
         Val       : U64;
      begin
         --  RCC full init here to avoid DFA below, so V can be "out"
         V := (others => 0);

         for I in Support_Index range 0 .. Weight - 1 loop
            Index_Tab (I) := SR (Support (I), 6);
            Pos := Natural (Support (I) and 16#3F#);
            Bit_Tab (I) := 2 ** Pos;
         end loop;

         for I in V'Range loop
            Val := 0;
            for J in Support_Index range 0 .. Weight - 1 loop
               declare
                  Tmp  : constant U32 := U32 (I) - Index_Tab (J);
                  Val1 : constant U64 := U64 (SR (Tmp or -Tmp, 31)) xor 1;
                  pragma Assert (Val1 = 0 or Val1 = 1);
                  Mask : constant U64 := -Val1;
                  pragma Assert (Mask = 0 or Mask = 16#FFFF_FFFF_FFFF_FFFF#);
               begin
                  Val := Val or (Bit_Tab (J) and Mask);
               end;
            end loop;
            V (I) := V (I) or Val;
         end loop;
      end Write_Support_To_Vector;

      procedure Sample_Fixed_Weight1 (Ctx     : in out SHAKE.SHAKE256.Context;
                                      V       :    out U64_Seq_N_Bits_As_Words;
                                      Weight  : in     Weights)
      is
         Support : Support_Vector;
      begin
         Generate_Random_Support1 (Ctx, Support, Weight);
         Write_Support_To_Vector (V, Support, Weight);
      end Sample_Fixed_Weight1;

      procedure Sample_Fixed_Weight2 (Ctx     : in out SHAKE.SHAKE256.Context;
                                      V       :    out U64_Seq_N_Bits_As_Words;
                                      Weight  : in     Weights)
      is
         Support : Support_Vector;
      begin
         Generate_Random_Support2 (Ctx, Support, Weight);
         Write_Support_To_Vector (V, Support, Weight);
      end Sample_Fixed_Weight2;

      function Add (V1, V2 : in U64_Seq) return U64_Seq
      is
         R : U64_Seq (V1'Range);
      begin
         for I in V1'Range loop
            R (I) := V1 (I) xor V2 (I);
         end loop;
         return R;
      end Add;

      function Compare (V1, V2 : in Byte_Seq) return U8_Bit
      is
         R : U16 := 16#0100#;
      begin
         for I in V1'Range loop
            R := R or U16 (V1 (I) xor V2 (I));
            pragma Loop_Invariant (R >= 16#0100# and R <= 16#01FF#);
         end loop;
         R := R - 1;
         pragma Assert (R >= 16#00FF# and R <= 16#01FE#);
         return U8_Bit (SR (R, 8));
      end Compare;

      procedure Truncate (V    : in out U64_Seq_N_Bits_As_Words;
                          N1N2 :        in N32)
      is
         New_Full_Words : constant N32 := N1N2 / 64;
         Remaining_Bits : constant N32 := N1N2 mod 64;
         Start : N32 := New_Full_Words;
      begin
         if Remaining_Bits > 0 then
            declare
               Mask : constant U64 := 2 ** Natural (Remaining_Bits) - 1;
            begin
               V (New_Full_Words) := V (New_Full_Words) and Mask;
               Start := Start + 1;
            end;
         end if;

         for I in Index_N_Bits_As_Words range Start .. Index_N_Bits_As_Words'Last loop
            V (I) := 0;
         end loop;

      end Truncate;

      procedure Set_Random (Ctx : in out SHAKE.SHAKE256.Context;
                            V   :    out U64_Seq_N_Bits_As_Words)
      is
         function To_Words is new Ada.Unchecked_Conversion (Seq_N_Bits_As_Bytes_Padded,
                                                            U64_Seq_N_Bits_As_Words);

         T    : Seq_N_Bits_As_Bytes_Padded;
         Mask : constant U64 := 2 ** (Param.N mod 64) - 1;
         pragma Assert (Mask = 31   or  -- for HQC-1
                        Mask = 2047 or  -- for HQC-3
                        Mask = 137_438_953_471); -- for HQC-5
      begin
         Symmetric.XOF_Get_Bytes (Ctx, T);
         V := To_Words (T);
         V (V'Last) := V (V'Last) and Mask;
      end Set_Random;

   end Vector;

   package Parsing
   is
      function HQC_DK_PKE_From_String (DK_PKE : in Seed_Bytes) return U64_Seq_N_Bits_As_Words
        with Global => null;

      procedure HQC_EK_PKE_From_String (H      :    out U64_Seq_N_Bits_As_Words;
                                        S      :    out U64_Seq_N_Bits_As_Words;
                                        EK_PKE : in     Encapsulation_Key)
        with Global => null;

      function HQC_C_KEM_To_String (C_KEM : in Ciphertext_KEM_T) return Ciphertext
        with Global => null;

      procedure HQC_C_KEM_From_String (C_PKE :    out Ciphertext_PKE_T;
                                       Salt  :    out Salt_Bytes;
                                       CT    : in     Ciphertext)
        with Global => null;
   end Parsing;

   package body Parsing
   is
      function HQC_DK_PKE_From_String (DK_PKE : Seed_Bytes) return U64_Seq_N_Bits_As_Words
      is
         DK_XOF_Ctx : SHAKE.SHAKE256.Context;
         H          : U64_Seq_N_Bits_As_Words;
      begin
         Symmetric.XOF_Init (DK_XOF_Ctx, DK_PKE);
         Vector.Sample_Fixed_Weight1 (DK_XOF_Ctx, H, Param.OMEGA);
         pragma Unreferenced (DK_XOF_Ctx);
         return H;
      end HQC_DK_PKE_From_String;

      procedure HQC_EK_PKE_From_String (H      :    out U64_Seq_N_Bits_As_Words;
                                        S      :    out U64_Seq_N_Bits_As_Words;
                                        EK_PKE : in     Encapsulation_Key)
      is
         EK_XOF_Ctx : SHAKE.SHAKE256.Context;
         S_Padded   : Seq_N_Bits_As_Bytes_Padded;

         function To_Words is new Ada.Unchecked_Conversion (Seq_N_Bits_As_Bytes_Padded,
                                                            U64_Seq_N_Bits_As_Words);
      begin
         Symmetric.XOF_Init (EK_XOF_Ctx, EK_PKE (0 .. Param.SEED_BYTES - 1));
         Vector.Set_Random (EK_XOF_Ctx, H);
         pragma Unreferenced (EK_XOF_Ctx);

         S_Padded := (others => 0);
         S_Padded (0 .. Param.VEC_N_SIZE_BYTES - 1) := EK_PKE (Param.SEED_BYTES .. EK_PKE'Last);

         S := To_Words (S_Padded);
      end HQC_EK_PKE_From_String;

      function HQC_C_KEM_To_String (C_KEM : in Ciphertext_KEM_T) return Ciphertext
      is
         UP : constant Seq_N_Bits_As_Bytes_Padded := To_Bytes1 (C_KEM.C_PKE.U);
         VP : constant Seq_N_Bits_As_Bytes_Padded := To_Bytes1 (C_KEM.C_PKE.V);
      begin
         return UP (0 .. Param.VEC_N_SIZE_BYTES - 1) &
                VP (0 .. Param.VEC_N1N2_SIZE_BYTES - 1) &
                C_KEM.Salt;
      end HQC_C_KEM_To_String;

      procedure HQC_C_KEM_From_String (C_PKE :    out Ciphertext_PKE_T;
                                       Salt  :    out Salt_Bytes;
                                       CT    : in     Ciphertext)
      is
         function To_Words is new Ada.Unchecked_Conversion (Seq_N_Bits_As_Bytes_Padded,
                                                            U64_Seq_N_Bits_As_Words);
         UP : constant Seq_N_Bits_As_Bytes_Padded :=
           CT (0 .. Param.VEC_N_SIZE_BYTES - 1) & N_Padding;
         VP : constant Seq_N_Bits_As_Bytes_Padded :=
           CT (Param.VEC_N_SIZE_BYTES .. Param.VEC_N_SIZE_BYTES + Param.VEC_N1N2_SIZE_BYTES - 1) &
           N1N2_Padding;
      begin
         C_PKE := (U => To_Words (UP),
                   V => To_Words (VP));
         Salt := Salt_Bytes (CT (Param.VEC_N_SIZE_BYTES + Param.VEC_N1N2_SIZE_BYTES .. CT'Last));
      end HQC_C_KEM_From_String;
   end Parsing;

   package HQCCore
   is
      procedure PKE_KeyGen (EK_PKE :    out Encapsulation_Key;
                            DK_PKE :    out Seed_Bytes;
                            Seed   : in     Seed_Bytes)
        with Global => null;

      procedure PKE_Encrypt (C_PKE  :    out Ciphertext_PKE_T;
                             EK_PKE : in     Encapsulation_Key;
                             M      : in     Security_Bytes;
                             Theta  : in     Seed_Bytes)
        with Global => null;

      procedure PKE_Decrypt (M      :    out Security_Bytes;
                             DK_PKE : in     Seed_Bytes;
                             C_PKE  : in     Ciphertext_PKE_T)
        with Global => null;

   end HQCCore;

   package body HQCCore
   is
      procedure PKE_KeyGen (EK_PKE :    out Encapsulation_Key;
                            DK_PKE :    out Seed_Bytes;
                            Seed   : in     Seed_Bytes)
      is
         KeyPair_Seed : constant Bytes_64   := Symmetric.Hash_I (Seed);
         Seed_DK      : constant Seed_Bytes := Seed_Bytes (KeyPair_Seed (0  .. 31));
         Seed_EK      : constant Seed_Bytes := Seed_Bytes (KeyPair_Seed (32 .. 63));

         DK_XOF_Ctx   : SHAKE.SHAKE256.Context;
         EK_XOF_Ctx   : SHAKE.SHAKE256.Context;
         H, X, Y, S   : U64_Seq_N_Bits_As_Words;
         SP           : Seq_N_Bits_As_Bytes_Padded;
      begin
         Symmetric.XOF_Init (DK_XOF_Ctx, Seed_DK);
         Vector.Sample_Fixed_Weight1 (DK_XOF_Ctx, Y, Param.OMEGA);
         Vector.Sample_Fixed_Weight1 (DK_XOF_Ctx, X, Param.OMEGA);
         Symmetric.XOF_Init (EK_XOF_Ctx, Seed_EK);
         Vector.Set_Random (EK_XOF_Ctx, H);

         S := GF2X.Mul (Y, H);
         S := Vector.Add (X, S);

         SP := To_Bytes1 (S);

         EK_PKE := Seed_EK & SP (0 .. Param.VEC_N_SIZE_BYTES - 1);
         DK_PKE := Seed_DK;

         Dbg.Put_Line ("seed_dk:", Seed_DK);
         HQC.Dbg.New_Line;
         Dbg.Put_Line ("seed_ek:", Seed_EK);
         HQC.Dbg.New_Line;
         Dbg.Put_Line ("y:", Y, Param.VEC_N_SIZE_BYTES);
         Dbg.Put_Line ("x:", X, Param.VEC_N_SIZE_BYTES);
         Dbg.Put_Line ("h:", H, Param.VEC_N_SIZE_BYTES);
         Dbg.Put_Line ("s:", S, Param.VEC_N_SIZE_BYTES);

         pragma Unreferenced (DK_XOF_Ctx, EK_XOF_Ctx);
      end PKE_KeyGen;

      procedure PKE_Encrypt (C_PKE  :    out Ciphertext_PKE_T;
                             EK_PKE : in     Encapsulation_Key;
                             M      : in     Security_Bytes;
                             Theta  : in     Seed_Bytes)
      is
         M2 : constant Reed_Solomon.RS_Msg_Bytes := Reed_Solomon.RS_Msg_Bytes (M);
         MW : constant Reed_Solomon.RS_Msg_Words := Reed_Solomon.To_Words (M2);
         Theta_XOF_Ctx            : SHAKE.SHAKE256.Context;
         ME, H, S, R2, R1, E, Tmp : U64_Seq_N_Bits_As_Words;
      begin
         Symmetric.XOF_Init (Theta_XOF_Ctx, Theta);
         Parsing.HQC_EK_PKE_From_String (H, S, EK_PKE);

         Vector.Sample_Fixed_Weight2 (Theta_XOF_Ctx, R2, Param.OMEGA_R);
         Vector.Sample_Fixed_Weight2 (Theta_XOF_Ctx, E,  Param.OMEGA_E);
         Vector.Sample_Fixed_Weight2 (Theta_XOF_Ctx, R1, Param.OMEGA_R);

         Tmp := Vector.Add (E, GF2X.Mul (R2, S));
         Vector.Truncate (Tmp, Param.N1N2);

         --  RCC this is dodgy
         ME := Code.Encode (MW) & 0;

         C_PKE := (U => Vector.Add (R1, GF2X.Mul (R2, H)),
                   V => Vector.Add (ME, Tmp));

         Dbg.Put_Line ("h:", H, Param.VEC_N_SIZE_BYTES);
         Dbg.Put_Line ("s:", S, Param.VEC_N_SIZE_BYTES);
         Dbg.Put_Line ("r1:", R1, Param.VEC_N_SIZE_BYTES);
         Dbg.Put_Line ("r2:", R2, Param.VEC_N_SIZE_BYTES);
         Dbg.Put_Line ("e:", E, Param.VEC_N_SIZE_BYTES);
         Dbg.Put_Line ("Truncate(s.r2 + e):", Tmp, Param.VEC_N1N2_SIZE_BYTES);
         Dbg.Put_Line ("c_pke->u:", C_PKE.U, Param.VEC_N_SIZE_BYTES);
         Dbg.Put_Line ("c_pke->v:", C_PKE.V, Param.VEC_N1N2_SIZE_BYTES);

         pragma Unreferenced (Theta_XOF_Ctx);
      end PKE_Encrypt;

      procedure PKE_Decrypt (M      :    out Security_Bytes;
                             DK_PKE : in     Seed_Bytes;
                             C_PKE  : in     Ciphertext_PKE_T)
      is
         Y, Tmp1, Tmp2 : U64_Seq_N_Bits_As_Words;
         Tmp3 : Reed_Muller.CDW_Words;
      begin
         Y := Parsing.HQC_DK_PKE_From_String (DK_PKE);
         Tmp1 := GF2X.Mul (Y, C_PKE.U);
         Vector.Truncate (Tmp1, Param.N1N2);
         Tmp2 := Vector.Add (C_PKE.V, Tmp1);

         Tmp3 := Tmp2 (Reed_Muller.CDW_Index);

         Dbg.Put_Line ("c_pke.u:", C_PKE.U, Param.VEC_N_SIZE_BYTES);
         Dbg.Put_Line ("c_pke.v:", C_PKE.V, Param.VEC_N1N2_SIZE_BYTES);
         Dbg.Put_Line ("y:", Y, Param.VEC_N_SIZE_BYTES);
         Dbg.Put_Line ("Truncate(u.y):", Tmp1, Param.VEC_N1N2_SIZE_BYTES);
         Dbg.Put_Line ("v - Truncate(u.y):", Tmp2, Param.VEC_N1N2_SIZE_BYTES);

         M := Security_Bytes (Reed_Solomon.To_Bytes2 (Code.Decode (Tmp3)));

      end PKE_Decrypt;
   end HQCCore;

   --  ==================
   --  Exported API
   --  ==================

   procedure PRNG_Init (PRNG_Ctx               :    out SHAKE.SHAKE256.Context;
                        Entropy                : in     Byte_Seq;
                        Personalization_String : in     Byte_Seq)
   is
   begin
      Symmetric.PRNG_Init (PRNG_Ctx, Entropy, Personalization_String);
   end PRNG_Init;

   procedure PRNG_Get_Bytes (PRNG_Ctx : in out SHAKE.SHAKE256.Context;
                             Output   :    out Byte_Seq)
   is
   begin
      Symmetric.PRNG_Get_Bytes (PRNG_Ctx, Output);
   end PRNG_Get_Bytes;

   procedure KeyPair (Random_Seed : in     Seed_Bytes;
                      EK_KEM      :    out Encapsulation_Key;
                      DK_KEM      :    out Decapsulation_Key)
   is
      Ctx_KEM  : SHAKE.SHAKE256.Context;
      Seed_PKE : Seed_Bytes;
      Sigma    : Security_Bytes;
      EK_PKE   : Encapsulation_Key;
      DK_PKE   : Seed_Bytes;
   begin
      Symmetric.XOF_Init (Ctx_KEM, Random_Seed);
      Symmetric.XOF_Get_Bytes (Ctx_KEM, Seed_PKE);
      Symmetric.XOF_Get_Bytes (Ctx_KEM, Sigma);

      Dbg.Put_Line ("Seed_PKE:", Seed_PKE);
      HQC.Dbg.New_Line;
      Dbg.Put_Line ("Sigma:", Sigma);
      HQC.Dbg.New_Line;

      HQCCore.PKE_KeyGen (EK_PKE, DK_PKE, Seed_PKE);
      EK_KEM := EK_PKE;
      DK_KEM := EK_KEM & DK_PKE & Sigma & Random_Seed;
      pragma Unreferenced (Ctx_KEM);
   end KeyPair;

   procedure Enc (PK   : in     Encapsulation_Key;
                  M    : in     Security_Bytes;
                  Salt : in     Salt_Bytes;
                  CT   :    out Ciphertext;
                  SS   :    out Shared_Secret)
   is
      Hash_EK_KEM : constant Seed_Bytes := Symmetric.Hash_H (PK);
      K_Theta     : constant Bytes_64   := Symmetric.Hash_G (Hash_EK_KEM, M, Salt);

      C_KEM_T : Ciphertext_KEM_T;
      Theta   : Seed_Bytes;
   begin
      C_KEM_T.Salt := Salt;
      Theta := Bytes_32 (K_Theta (32 .. 63));
      HQCCore.PKE_Encrypt (C_KEM_T.C_PKE, PK, M, Theta);
      CT := Parsing.HQC_C_KEM_To_String (C_KEM_T);
      SS := Shared_Secret (K_Theta (0 .. 31));

      Dbg.Put_Line ("ek_kem:", PK);
      Dbg.New_Line;
      Dbg.Put_Line ("m:", M);
      Dbg.New_Line;
      Dbg.Put_Line ("salt:", Salt);
      Dbg.New_Line;
      Dbg.Put_Line ("H(ek_kem):", Hash_EK_KEM);
      Dbg.New_Line;
      Dbg.Put_Line ("theta:", Theta);
      Dbg.New_Line;
      Dbg.Put_Line ("c_kem:", CT);
      Dbg.New_Line;
      Dbg.Put_Line ("K:", SS);
      Dbg.New_Line;
   end Enc;

   procedure Dec (SK   : in     Decapsulation_Key;
                  CT   : in     Ciphertext;
                  SS   :    out Shared_Secret)
   is
      EK_PKE        : Encapsulation_Key;
      DK_PKE        : Seed_Bytes;
      Sigma         : Security_Bytes;
      M_Prime       : Security_Bytes;
      Hash_EK_KEM   : Seed_Bytes;
      K_Theta_Prime : Bytes_64;
      K_Bar         : Shared_Secret;
      Theta_Prime   : Seed_Bytes;
      C_KEM_T       : Ciphertext_KEM_T;
      C_KEM_Prime_T : Ciphertext_KEM_T;
      Result        : Byte;
   begin
      EK_PKE := SK (0 .. Param.CRYPTO_PUBLICKEYBYTES - 1);
      DK_PKE := Seed_Bytes (SK (Param.CRYPTO_PUBLICKEYBYTES ..
                                Param.CRYPTO_PUBLICKEYBYTES + Param.SEED_BYTES - 1));
      Sigma  := Security_Bytes (SK (Param.CRYPTO_PUBLICKEYBYTES + Param.SEED_BYTES ..
                                    Param.CRYPTO_PUBLICKEYBYTES + Param.SEED_BYTES + Param.SECURITY_BYTES - 1));

      Parsing.HQC_C_KEM_From_String (C_KEM_T.C_PKE, C_KEM_T.Salt, CT);

      HQCCore.PKE_Decrypt (M_Prime, DK_PKE, C_KEM_T.C_PKE);
      Result := 0;

      Hash_EK_KEM   := Symmetric.Hash_H (EK_PKE);
      K_Theta_Prime := Symmetric.Hash_G (Hash_EK_KEM, M_Prime, C_KEM_T.Salt);
      SS            := Shared_Secret (K_Theta_Prime (0 .. Param.SHARED_SECRET_BYTES - 1));
      Theta_Prime   := Seed_Bytes (K_Theta_Prime (Param.SHARED_SECRET_BYTES .. Param.SHARED_SECRET_BYTES + Param.SEED_BYTES - 1));

      HQCCore.PKE_Encrypt (C_KEM_Prime_T.C_PKE, EK_PKE, M_Prime, Theta_Prime);
      C_KEM_Prime_T.Salt := C_KEM_T.Salt;

      K_Bar := Shared_Secret (Symmetric.Hash_J (Hash_EK_KEM, Sigma, C_KEM_T));

      declare
         C_KEM_U_Bytes       : constant Seq_N_Bits_As_Bytes := To_Bytes1 (C_KEM_T.C_PKE.U) (Seq_N_Bits_As_Bytes'Range);
         C_KEM_Prime_U_Bytes : constant Seq_N_Bits_As_Bytes := To_Bytes1 (C_KEM_Prime_T.C_PKE.U) (Seq_N_Bits_As_Bytes'Range);
         C_KEM_V_Bytes       : constant Seq_N1N2_Bits_As_Bytes := To_Bytes1 (C_KEM_T.C_PKE.V) (Seq_N1N2_Bits_As_Bytes'Range);
         C_KEM_Prime_V_Bytes : constant Seq_N1N2_Bits_As_Bytes := To_Bytes1 (C_KEM_Prime_T.C_PKE.V) (Seq_N1N2_Bits_As_Bytes'Range);
      begin
         Result := Result or Vector.Compare (C_KEM_U_Bytes, C_KEM_Prime_U_Bytes);
         Result := Result or Vector.Compare (C_KEM_V_Bytes, C_KEM_Prime_V_Bytes);
         Result := Result or Vector.Compare (C_KEM_T.Salt, C_KEM_Prime_T.Salt);
      end;

      pragma Assert (Result = 0 or Result = 1);
      Result := Result - 1;
      pragma Assert (Result = 16#FF# or Result = 0);

      for I in SS'Range loop
         SS (I) := (SS (I) and Result) xor (K_Bar (I) and (not Result));
      end loop;

      Dbg.Put_Line ("ek_pke:", EK_PKE);
      Dbg.New_Line;
      Dbg.Put_Line ("dk_pke:", DK_PKE);
      Dbg.New_Line;
      Dbg.Put_Line ("c_kem:", CT);
      Dbg.New_Line;
      Dbg.Put_Line ("m_prime:", M_Prime);
      Dbg.New_Line;
      Dbg.Put_Line ("H(ek_kem):", Hash_EK_KEM);
      Dbg.New_Line;
      Dbg.Put_Line ("theta_prime:", Theta_Prime);
      Dbg.New_Line (2);
      Dbg.Put_Line ("# Checking Ciphertext - Begin #");
      Dbg.New_Line;
      Dbg.Put_Line ("c_kem_prime_t.c_pke.u:", C_KEM_Prime_T.C_PKE.U, Param.VEC_N_SIZE_BYTES);
      Dbg.Put_Line ("c_kem_prime_t.c_pke.v:", C_KEM_Prime_T.C_PKE.V, Param.VEC_N1N2_SIZE_BYTES);
      Dbg.Put_Line ("salt:", C_KEM_Prime_T.Salt);
      Dbg.New_Line;
      Dbg.Put_Line ("# Checking Ciphertext - End #");
      Dbg.New_Line (2);
      Dbg.Put_Line ("K_prime:", SS);
      Dbg.New_Line;
   end Dec;

end HQC;
