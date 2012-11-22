-----------------------------------------------------------------------
--  Security-permissions-tests - Unit tests for Security.Permissions
--  Copyright (C) 2011 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--
--  Licensed under the Apache License, Version 2.0 (the "License");
--  you may not use this file except in compliance with the License.
--  You may obtain a copy of the License at
--
--      http://www.apache.org/licenses/LICENSE-2.0
--
--  Unless required by applicable law or agreed to in writing, software
--  distributed under the License is distributed on an "AS IS" BASIS,
--  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
--  See the License for the specific language governing permissions and
--  limitations under the License.
-----------------------------------------------------------------------
with Util.Tests;

with Util.Files;
with Util.Test_Caller;
with Util.Measures;

with Security.Contexts;
package body Security.Permissions.Tests is

   use Util.Tests;

   package Caller is new Util.Test_Caller (Test, "Security.Permissions");

   procedure Add_Tests (Suite : in Util.Tests.Access_Test_Suite) is
   begin
      Caller.Add_Test (Suite, "Test Security.Permissions.Add_Permission",
                       Test_Add_Permission'Access);
      Caller.Add_Test (Suite, "Test Security.Permissions.Get_Permission_Index",
                       Test_Add_Permission'Access);
   end Add_Tests;

   --  ------------------------------
   --  Test Add_Permission and Get_Permission_Index
   --  ------------------------------
   procedure Test_Add_Permission (T : in out Test) is
      Index1, Index2 : Permission_Index;
   begin
      Add_Permission ("test-create-permission", Index1);

      T.Assert (Index1 = Get_Permission_Index ("test-create-permission"),
                "Get_Permission_Index failed");

      Add_Permission ("test-create-permission", Index2);

      T.Assert (Index2 = Index1,
                "Add_Permission failed");

   end Test_Add_Permission;

end Security.Permissions.Tests;
