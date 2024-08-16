-----------------------------------------------------------------------
--  Security-permissions-tests - Unit tests for Security.Permissions
--  Copyright (C) 2011, 2012, 2016, 2018 Stephane Carrez
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
with Util.Test_Caller;

package body Security.Permissions.Tests is

   package Caller is new Util.Test_Caller (Test, "Security.Permissions");

   procedure Add_Tests (Suite : in Util.Tests.Access_Test_Suite) is
   begin
      Caller.Add_Test (Suite, "Test Security.Permissions.Add_Permission",
                       Test_Add_Permission'Access);
      Caller.Add_Test (Suite, "Test Security.Permissions.Get_Permission_Index",
                       Test_Add_Permission'Access);
      Caller.Add_Test (Suite, "Test Security.Permissions.Definition",
                       Test_Define_Permission'Access);
      Caller.Add_Test (Suite, "Test Security.Permissions.Get_Permission_Index (invalid name)",
                       Test_Get_Invalid_Permission'Access);
      Caller.Add_Test (Suite, "Test Security.Permissions.Add_Permission (Set)",
                       Test_Add_Permission_Set'Access);
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

   --  ------------------------------
   --  Test the permission created by the Definition package.
   --  ------------------------------
   procedure Test_Define_Permission (T : in out Test) is
      Index : Permission_Index;
   begin
      Index := Get_Permission_Index ("admin");
      T.Assert (P_Admin.Permission = Index, "Invalid permission for admin");

      Index := Get_Permission_Index ("create");
      T.Assert (P_Create.Permission = Index, "Invalid permission for create");

      Index := Get_Permission_Index ("update");
      T.Assert (P_Update.Permission = Index, "Invalid permission for update");

      Index := Get_Permission_Index ("delete");
      T.Assert (P_Delete.Permission = Index, "Invalid permission for delete");

      T.Assert (P_Admin.Permission /= P_Create.Permission, "Admin or create permission invalid");
      T.Assert (P_Admin.Permission /= P_Update.Permission, "Admin or update permission invalid");
      T.Assert (P_Admin.Permission /= P_Delete.Permission, "Admin or delete permission invalid");
      T.Assert (P_Create.Permission /= P_Update.Permission, "Create or update permission invalid");
      T.Assert (P_Create.Permission /= P_Delete.Permission, "Create or delete permission invalid");
      T.Assert (P_Update.Permission /= P_Delete.Permission, "Create or delete permission invalid");
   end Test_Define_Permission;

   --  ------------------------------
   --  Test Get_Permission on invalid permission name.
   --  ------------------------------
   procedure Test_Get_Invalid_Permission (T : in out Test) is
      Index : Permission_Index;

      pragma Unreferenced (Index);
   begin
      Index := Get_Permission_Index ("invalid");
      Util.Tests.Fail (T, "No exception raised by Get_Permission_Index for an invalid name");

   exception
      when Invalid_Name =>
         null;
   end Test_Get_Invalid_Permission;

   --  ------------------------------
   --  Test operations on the Permission_Index_Set.
   --  ------------------------------
   procedure Test_Add_Permission_Set (T : in out Test) is
      Set : Permission_Index_Set := EMPTY_SET;
   begin
      T.Assert (not Has_Permission (Set, P_Update.Permission),
                "The update permission is not in the set");
      Add_Permission (Set, P_Update.Permission);
      T.Assert (Has_Permission (Set, P_Update.Permission),
                "The update permission is in the set");
   end Test_Add_Permission_Set;

end Security.Permissions.Tests;
