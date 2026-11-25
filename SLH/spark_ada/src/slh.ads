--  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
--  SPDX-License-Identifier: Apache-2.0

with Interfaces; use Interfaces;
package SLH
  with SPARK_Mode => On
is
   pragma Elaborate_Body (SLH);

   --==============================================
   --  Exported constants, types, and subprograms
   --
   --  These are needed by clients, or by the
   --  specifications of child packages
   --==============================================

   --  Constants common to all parameter sets
   --  from FIPS 205 section ???
   Len2 : constant := 3;
   LG_W : constant := 4;

   --  Parameters for SLH-DSA_SHA2-256s and SLG-DSA-SHAKE-256s
   N      : constant := 32;
   H      : constant := 64;
   D      : constant := 8;
   H_Tick : constant := 8;
   A      : constant := 14;
   K      : constant := 22;
   M      : constant := 47;

   PK_Bytes  : constant := 64;
   Sig_Bytes : constant := 29_792;

   ----------------------------------------------------------------------
   --  Parameter set validation
   ----------------------------------------------------------------------

   --  FIPS 205 section ??? requires that implementations shall confirm
   --  that only valid sets of parameters are chosen.  This can be
   --  encoded as an assertion, thus:
   pragma Assert (True); -- TBD

   subtype Byte is Unsigned_8;
   subtype I32  is Integer_32;
   subtype N32  is I32 range 0 .. I32'Last;

   --  Unconstrained (aka "Size Polymorphic") array of bytes
   type Byte_Seq is array (N32 range <>) of Byte;

   subtype Index_32  is I32 range 0 .. 31;
   subtype Bytes_32  is Byte_Seq (Index_32);

   subtype Index_N is I32 range 0 .. N - 1;
   subtype Bytes_N is Byte_Seq (Index_N);

   subtype Index_M is I32 range 0 .. M - 1;
   subtype Bytes_M is Byte_Seq (Index_M);

   --==============================================
   --  Exported subprograms. These subprograms
   --  form the main user-facing API for SLH
   --==============================================

   --  Input Validation Functions

   --  Main SLH API

   --  Algorithm XXX

private
   subtype U16 is Unsigned_16;
   subtype U32 is Unsigned_32;
   subtype U64 is Unsigned_64;
   subtype I64 is Integer_64;

   subtype Index_128 is I32 range 0 .. 127;
   subtype Index_256 is I32 range 0 .. 255;

end SLH;
