-----------------------------------------------------------------------
--  Security-policies-tests - Unit tests for Security.Permissions
--  Copyright (C) 2011, 2012, 2013, 2017 Stephane Carrez
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

with Util.Files;
with Util.Test_Caller;
with Util.Measures;

with Security.Contexts;
with Security.Permissions.Tests;
with Security.Policies.URLs;

package body Security.Policies.Tests is

   use Util.Tests;

   procedure Configure_Policy (Manager : in out Security.Policies.Policy_Manager;
                               Name    : in String);

   package Caller is new Util.Test_Caller (Test, "Security.Policies");

   procedure Add_Tests (Suite : in Util.Tests.Access_Test_Suite) is
   begin

      Caller.Add_Test (Suite, "Test Security.Permissions.Create_Role",
                       Test_Create_Role'Access);
      Caller.Add_Test (Suite, "Test Security.Permissions.Has_Permission",
                       Test_Has_Permission'Access);
      Caller.Add_Test (Suite, "Test Security.Permissions.Read_Policy (empty)",
                       Test_Read_Empty_Policy'Access);

      Caller.Add_Test (Suite, "Test Security.Policies.Add_Policy",
                       Test_Get_Role_Policy'Access);
      Caller.Add_Test (Suite, "Test Security.Policies.Get_Policy",
                       Test_Get_Role_Policy'Access);
      Caller.Add_Test (Suite, "Test Security.Policies.Roles.Get_Role_Policy",
                       Test_Get_Role_Policy'Access);

      Caller.Add_Test (Suite, "Test Security.Policies.Read_Policy",
                       Test_Read_Policy'Access);
      Caller.Add_Test (Suite, "Test Security.Policies.Roles.Set_Roles",
                       Test_Set_Roles'Access);
      Caller.Add_Test (Suite, "Test Security.Policies.Roles.Set_Roles (invalid)",
                       Test_Set_Invalid_Roles'Access);
      Caller.Add_Test (Suite, "Test Security.Policies.Roles.Get_Grants",
                       Test_Grants'Access);

      --  These tests are identical but registered under different names
      --  for the test documentation.
      Caller.Add_Test (Suite, "Test Security.Contexts.Has_Permission",
                       Test_Role_Policy'Access);
      Caller.Add_Test (Suite, "Test Security.Controllers.Roles.Has_Permission",
                       Test_Role_Policy'Access);
      Caller.Add_Test (Suite, "Test Security.Permissions.Role_Policy",
                       Test_Role_Policy'Access);
      Caller.Add_Test (Suite, "Test Security.Contexts.Has_Permission (all-permission)",
                       Test_Anonymous_Permission'Access);
      Caller.Add_Test (Suite, "Test Security.Contexts.Has_Permission (auth-permission)",
                       Test_Anonymous_Permission'Access);
   end Add_Tests;

   --  ------------------------------
   --  Get the roles assigned to the user.
   --  ------------------------------
   function Get_Roles (User : in Test_Principal) return Roles.Role_Map is
   begin
      return User.Roles;
   end Get_Roles;

   --  ------------------------------
   --  Get the principal name.
   --  ------------------------------
   function Get_Name (From : in Test_Principal) return String is
   begin
      return Util.Strings.To_String (From.Name);
   end Get_Name;

   --  ------------------------------
   --  Test Create_Role and Get_Role_Name
   --  ------------------------------
   procedure Test_Create_Role (T : in out Test) is
      use Security.Policies.Roles;

      M     : Security.Policies.Roles.Role_Policy;
      Role  : Role_Type;
   begin
      M.Create_Role (Name => "admin",
                     Role => Role);
      Assert_Equals (T, "admin", M.Get_Role_Name (Role), "Invalid name");

      for I in Role + 1 .. Role_Type'Last loop
         declare
            Name : constant String := "admin-" & Role_Type'Image (I);
            Role2 : Role_Type;
         begin
            Role2 := M.Find_Role ("admin");
            T.Assert (Role2 = Role, "Find_Role returned an invalid role");

            M.Create_Role (Name => Name,
                           Role => Role2);
            Assert_Equals (T, Name, M.Get_Role_Name (Role2), "Invalid name");
         end;
      end loop;
   end Test_Create_Role;

   --  ------------------------------
   --  Test Set_Roles
   --  ------------------------------
   procedure Test_Set_Roles (T : in out Test) is
      use Security.Policies.Roles;

      M       : Security.Policies.Roles.Role_Policy;
      Admin   : Role_Type;
      Manager : Role_Type;
      Map     : Role_Map := (others => False);
   begin
      M.Create_Role (Name => "manager",
                     Role => Manager);
      M.Create_Role (Name => "admin",
                     Role => Admin);
      Assert_Equals (T, "admin", M.Get_Role_Name (Admin), "Invalid name");

      T.Assert (not Map (Admin), "The admin role must not set in the map");
      M.Set_Roles ("admin", Map);
      T.Assert (Map (Admin), "The admin role is not set in the map");
      T.Assert (not Map (Manager), "The manager role must not be set in the map");

      M.Set_Roles ("manager,admin", Map);
      T.Assert (Map (Admin), "The admin role is not set in the map");
      T.Assert (Map (Manager), "The manager role is not set in the map");

   end Test_Set_Roles;

   --  ------------------------------
   --  Test Set_Roles on an invalid role name
   --  ------------------------------
   procedure Test_Set_Invalid_Roles (T : in out Test) is
      use Security.Policies.Roles;

      M       : Security.Policies.Roles.Role_Policy;
      Map     : Role_Map := (others => False);
      pragma Unreferenced (Map);
   begin
      M.Set_Roles ("manager,admin", Map);
      T.Assert (False, "No exception was raised");

   exception
      when Security.Policies.Roles.Invalid_Name =>
         null;
   end Test_Set_Invalid_Roles;

   --  ------------------------------
   --  Test Has_Permission
   --  ------------------------------
   procedure Test_Has_Permission (T : in out Test) is
      M       : Security.Policies.Policy_Manager (1);
      Perm    : Permissions.Permission (Permissions.Tests.P_Admin.Permission);
      Context : aliased Security.Contexts.Security_Context;
   begin
      T.Assert (not M.Has_Permission (Context, Perm), "User has a non-existing permission");
   end Test_Has_Permission;

   procedure Configure_Policy (Manager : in out Security.Policies.Policy_Manager;
                               Name    : in String) is
      Dir         : constant String := "regtests/files/permissions/";
      Path        : constant String := Util.Tests.Get_Path (Dir);
      R           : constant Security.Policies.Roles.Role_Policy_Access := new Roles.Role_Policy;
      U           : constant Security.Policies.URLs.URL_Policy_Access := new URLs.URL_Policy;
   begin
      Manager.Add_Policy (R.all'Access);
      Manager.Add_Policy (U.all'Access);
      Manager.Read_Policy (Util.Files.Compose (Path, Name));
   end Configure_Policy;

   --  ------------------------------
   --  Test the Get_Policy, Get_Role_Policy and Add_Policy operations.
   --  ------------------------------
   procedure Test_Get_Role_Policy (T : in out Test) is
      use type Roles.Role_Policy_Access;

      M           : aliased Security.Policies.Policy_Manager (Max_Policies => 2);
      P           : Security.Policies.Policy_Access;
      R           : Security.Policies.Roles.Role_Policy_Access;
   begin
      P := M.Get_Policy (Security.Policies.Roles.NAME);
      T.Assert (P = null, "Get_Policy succeeded");

      R := Security.Policies.Roles.Get_Role_Policy (M);
      T.Assert (R = null, "Get_Role_Policy succeeded");

      R := new Roles.Role_Policy;
      M.Add_Policy (R.all'Access);

      P := M.Get_Policy (Security.Policies.Roles.NAME);
      T.Assert (P /= null, "Role policy not found");
      T.Assert (P.all in Roles.Role_Policy'Class, "Invalid role policy");

      R := Security.Policies.Roles.Get_Role_Policy (M);
      T.Assert (R /= null, "Get_Role_Policy should not return null");
   end Test_Get_Role_Policy;

   --  ------------------------------
   --  Test reading an empty policy file
   --  ------------------------------
   procedure Test_Read_Empty_Policy (T : in out Test) is
      M           : aliased Security.Policies.Policy_Manager (Max_Policies => 2);
      User        : aliased Test_Principal;
      Context     : aliased Security.Contexts.Security_Context;
      R           : Security.Policies.Roles.Role_Policy_Access;
   begin
      Configure_Policy (M, "empty.xml");
      Context.Set_Context (Manager   => M'Unchecked_Access,
                           Principal => User'Unchecked_Access);

      R := Security.Policies.Roles.Get_Role_Policy (M);
      declare
         Admin : Policies.Roles.Role_Type;
         pragma Unreferenced (Admin);
      begin
         Admin := R.Find_Role ("admin");
         T.Fail ("'admin' role was returned");

      exception
         when Security.Policies.Roles.Invalid_Name =>
            null;
      end;

      T.Assert (not Contexts.Has_Permission (Permissions.Tests.P_Admin.Permission),
                "Has_Permission (admin) failed for empty policy");

      T.Assert (not Contexts.Has_Permission (Permissions.Tests.P_Create.Permission),
                "Has_Permission (create) failed for empty policy");

      T.Assert (not Contexts.Has_Permission (Permissions.Tests.P_Update.Permission),
                "Has_Permission (update) failed for empty policy");

      T.Assert (not Contexts.Has_Permission (Permissions.Tests.P_Delete.Permission),
                "Has_Permission (delete) failed for empty policy");

   end Test_Read_Empty_Policy;

   --  ------------------------------
   --  Test reading policy files
   --  ------------------------------
   procedure Test_Read_Policy (T : in out Test) is
      use Security.Permissions.Tests;

      M            : aliased Security.Policies.Policy_Manager (Max_Policies => 2);
      User         : aliased Test_Principal;
      Admin        : Policies.Roles.Role_Type;
      Context      : aliased Security.Contexts.Security_Context;
      R            : Security.Policies.Roles.Role_Policy_Access;
   begin
      Configure_Policy (M, "simple-policy.xml");
      Context.Set_Context (Manager   => M'Unchecked_Access,
                           Principal => User'Unchecked_Access);

      R := Security.Policies.Roles.Get_Role_Policy (M);
      Admin := R.Find_Role ("admin");

      T.Assert (not Contexts.Has_Permission (Permission => P_Admin.Permission),
                "Permission was granted but user has no role");

      User.Roles (Admin) := True;

      T.Assert (Contexts.Has_Permission (Permission => P_Admin.Permission),
                "Permission was not granted and user has admin role");

      declare
         S : Util.Measures.Stamp;
         Result : Boolean;
      begin
         for I in 1 .. 1_000 loop
            Result := Contexts.Has_Permission (Permission => P_Admin.Permission);
         end loop;
         Util.Measures.Report (S, "Has_Permission role based", 1_000);

         T.Assert (Result, "Permission not granted");
      end;
      declare
         S : Util.Measures.Stamp;
      begin
         for I in 1 .. 1_000 loop
            declare
               URL : constant String := "/admin/list.html";
               P   : constant URLs.URL_Permission (URL'Length)
                 := URLs.URL_Permission '(Len => URL'Length, URL => URL);
            begin
               T.Assert (Contexts.Has_Permission (Permission => P),
                         "Permission not granted");
            end;
         end loop;
         Util.Measures.Report (S, "Has_Permission (cache hit)", 1_000);
      end;

   end Test_Read_Policy;

   --  ------------------------------
   --  Read the policy file <b>File</b> and perform a test on the given URI
   --  with a user having the given role.
   --  ------------------------------
   procedure Check_Policy (T         : in out Test;
                           File      : in String;
                           Role      : in String;
                           URL       : in String;
                           Anonymous : in Boolean := False;
                           Granted   : in Boolean := True) is
      M           : aliased Security.Policies.Policy_Manager (2);
      User        : aliased Test_Principal;
      Admin       : Roles.Role_Type;
      Context     : aliased Security.Contexts.Security_Context;
      R           : Security.Policies.Roles.Role_Policy_Access;
      U           : Security.Policies.URLs.URL_Policy_Access;
   begin
      Configure_Policy (M, File);

      if Anonymous then
         Context.Set_Context (Manager   => M'Unchecked_Access,
                              Principal => null);
      else
         Context.Set_Context (Manager   => M'Unchecked_Access,
                              Principal => User'Unchecked_Access);
      end if;

      R := Security.Policies.Roles.Get_Role_Policy (M);
      U := Security.Policies.URLs.Get_URL_Policy (M);
      Admin := R.Find_Role (Role);

      declare
         P   : constant URLs.URL_Permission (URL'Length)
           := URLs.URL_Permission '(Len => URL'Length, URL => URL);
      begin
         if not Anonymous then
            --  A user without the role should not have the permission.
            T.Assert (not U.Has_Permission (Context    => Context,
                                            Permission => P),
              "Permission was granted for user without role.  URL=" & URL);

            --  Set the role.
            User.Roles (Admin) := True;
         end if;

         if Granted then
            T.Assert (U.Has_Permission (Context    => Context,
                                        Permission => P),
              "Permission was not granted for user with role.  URL=" & URL);
         else
            T.Assert (not U.Has_Permission (Context    => Context,
                                            Permission => P),
              "Permission was granted for user with role.  URL=" & URL);
         end if;
      end;
   end Check_Policy;

   --  ------------------------------
   --  Test reading policy files and using the <role-permission> controller
   --  ------------------------------
   procedure Test_Role_Policy (T : in out Test) is
   begin
      T.Check_Policy (File => "policy-with-role.xml",
                      Role => "developer",
                      URL  => "/developer/user-should-have-developer-role");
      T.Check_Policy (File => "policy-with-role.xml",
                      Role => "manager",
                      URL  => "/developer/user-should-have-manager-role");
      T.Check_Policy (File => "policy-with-role.xml",
                      Role => "manager",
                      URL  => "/manager/user-should-have-manager-role");
      T.Check_Policy (File => "policy-with-role.xml",
                      Role => "admin",
                      URL  => "/manager/user-should-have-admin-role");
      T.Check_Policy (File => "policy-with-role.xml",
                      Role => "admin",
                      URL  => "/admin/user-should-have-admin-role");

      T.Check_Policy (File => "policy-with-role.xml",
                      Role => "developer",
                      URL  => "/admin/user-with-developer-role-should-not-access-admin",
                      Granted => False);
   end Test_Role_Policy;

   --  ------------------------------
   --  Test anonymous users and permissions.
   --  ------------------------------
   procedure Test_Anonymous_Permission (T : in out Test) is
   begin
      T.Check_Policy (File      => "simple-policy.xml",
                      Role      => "admin",
                      URL       => "/admin/page.html",
                      Anonymous => True,
                      Granted   => False);
      T.Check_Policy (File      => "simple-policy.xml",
                      Role      => "admin",
                      URL       => "/user/totopage.html",
                      Anonymous => True,
                      Granted   => False);

      --  Anonymous users can access the page.
      T.Check_Policy (File      => "simple-policy.xml",
                      Role      => "admin",
                      URL       => "/page.html",
                      Anonymous => True,
                      Granted   => True);
   end Test_Anonymous_Permission;

   --  ------------------------------
   --  Test the Get_Grants operation.
   --  ------------------------------
   procedure Test_Grants (T : in out Test) is
      use Security.Permissions.Tests;
      use type Security.Policies.Roles.Role_Map;

      M            : aliased Security.Policies.Policy_Manager (Max_Policies => 2);
      User         : aliased Test_Principal;
      Developer    : Policies.Roles.Role_Type;
      Manager      : Policies.Roles.Role_Type;
      Admin        : Policies.Roles.Role_Type;
      Context      : aliased Security.Contexts.Security_Context;
      R            : Security.Policies.Roles.Role_Policy_Access;
      Permission   : Security.Permissions.Permission_Index;
      Roles        : Security.Policies.Roles.Role_Map;
      Expect       : Security.Policies.Roles.Role_Map;
   begin
      Configure_Policy (M, "grants.xml");
      Context.Set_Context (Manager   => M'Unchecked_Access,
                           Principal => User'Unchecked_Access);

      R := Security.Policies.Roles.Get_Role_Policy (M);
      Developer := R.Find_Role ("developer");
      Manager := R.Find_Role ("manager");
      Admin := R.Find_Role ("admin");

      --  Check that the 'create-ticket' permission is granted to 'developer' and 'manager'
      Permission := Security.Permissions.Get_Permission_Index ("create-ticket");
      Roles := R.Get_Grants (Permission);
      Expect := (others => False);
      Expect (Developer) := True;
      Expect (Manager) := True;
      if Roles /= Expect then
         T.Fail ("The create-ticket permission is assigned to the wrong roles");
      end if;

      --  Check that the 'update-ticket' permission is granted to 'developer' and 'manager'
      Permission := Security.Permissions.Get_Permission_Index ("update-ticket");
      Roles := R.Get_Grants (Permission);
      if Roles /= Expect then
         T.Fail ("The update-ticket permission is assigned to the wrong roles");
      end if;

      --  Check that the 'delete-ticket' permission is granted to 'developer' and 'manager'
      Permission := Security.Permissions.Get_Permission_Index ("delete-ticket");
      Roles := R.Get_Grants (Permission);
      if Roles /= Expect then
         T.Fail ("The delete-ticket permission is assigned to the wrong roles");
      end if;

      --  Check that the 'add-user' permission is granted to 'admin' and 'manager'
      Permission := Security.Permissions.Get_Permission_Index ("add-user");
      Roles := R.Get_Grants (Permission);
      Expect := (others => False);
      Expect (Admin) := True;
      Expect (Manager) := True;
      if Roles /= Expect then
         T.Fail ("The add-user permission is assigned to the wrong roles");
      end if;

      --  Check that the 'remove-user' permission is granted to 'admin' and 'manager'
      Permission := Security.Permissions.Get_Permission_Index ("remove-user");
      Roles := R.Get_Grants (Permission);
      if Roles /= Expect then
         T.Fail ("The remove-user permission is assigned to the wrong roles");
      end if;

   end Test_Grants;

end Security.Policies.Tests;
