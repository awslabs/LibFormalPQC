--  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
--  SPDX-License-Identifier: Apache-2.0

with Ada.Command_Line; use Ada.Command_Line;
with Ada.Text_IO;      use Ada.Text_IO;
with SLH.KAT;

--  Runs the SLH KATs, writing results to stdout.
--
--    tkats hash   runs the hash function KATs. Check the
--                 results with check_hash_kats.py
--    tkats wots   runs the WOTS+ KATs. Check the results
--                 with check_wots_kats.py
--    tkats xmss   runs the XMSS KATs. Check the results
--                 with check_xmss_kats.py
--    tkats ht     runs the hypertree KATs. Check the results
--                 with check_ht_kats.py
--    tkats fors   runs the FORS KATs. Check the results
--                 with check_fors_kats.py
--    tkats slh    runs the SLH-DSA internal function KATs. Check
--                 the results with check_slh_kats.py
--    tkats acvp   runs the NIST ACVP tests read from stdin. Make
--                 the input and check the results with check_acvp.py
procedure TKATs
is
begin
   if Argument_Count = 1 and then Argument (1) = "hash" then
      SLH.KAT.Hash_KATs;
   elsif Argument_Count = 1 and then Argument (1) = "wots" then
      SLH.KAT.WOTS_KATs;
   elsif Argument_Count = 1 and then Argument (1) = "xmss" then
      SLH.KAT.XMSS_KATs;
   elsif Argument_Count = 1 and then Argument (1) = "ht" then
      SLH.KAT.HT_KATs;
   elsif Argument_Count = 1 and then Argument (1) = "fors" then
      SLH.KAT.FORS_KATs;
   elsif Argument_Count = 1 and then Argument (1) = "slh" then
      SLH.KAT.SLH_KATs;
   elsif Argument_Count = 1 and then Argument (1) = "acvp" then
      SLH.KAT.ACVP_Tests;
   else
      Put_Line (Standard_Error, "usage: tkats hash|wots|xmss|ht|fors|slh|acvp");
      Set_Exit_Status (Failure);
   end if;
end TKATs;
