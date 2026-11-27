--  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
--  SPDX-License-Identifier: Apache-2.0

with Interfaces;

--  Binding to the cycle counter in SLH/hal/hal.h, from mlkem-native.
--  Which counter is used depends on the C preprocessor symbol that
--  hal.c is compiled with; see SLH/hal/README.md
package Cycles
is
   procedure Enable_Cycle_Counter
     with Import, Convention => C, External_Name => "enable_cyclecounter";

   procedure Disable_Cycle_Counter
     with Import, Convention => C, External_Name => "disable_cyclecounter";

   function Get_Cycle_Counter return Interfaces.Unsigned_64
     with Import, Convention => C, External_Name => "get_cyclecounter";
end Cycles;
