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
   --  Local constants and types
   --=======================================

   --  Bytes_64 type is needed for SHA3
   subtype Index_64  is I32 range 0 .. 63;
   subtype Bytes_64  is Byte_Seq (Index_64);

   subtype U8_Bit is Unsigned_8 range 0 .. 1;

   subtype Index_8   is I32 range 0 .. 7;

   --=======================================
   --  Local packages and subprograms
   --=======================================

   package Hash
   is
      function H_Msg (R : in Bytes_N; PK_Seed : in Bytes_N; PK_Root : in Bytes_N; M : in Byte_Seq) return Bytes_M
        with Global => null,
             Pre    => M'First = 0 and M'Last <= I32'Last - 1;
   end Hash;

   package body Hash
   is
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

   end Hash;

   --=======================================
   --  Exported subprograms
   --=======================================

end SLH;
