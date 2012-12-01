-----------------------------------------------------------------------
--  Security-policies-tests - Unit tests for Security.Permissions
--  Copyright (C) 2011, 2012 Stephane Carrez
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
with Security.Policies.Roles;
with Security.Permissions.Tests;
package body Security.Policies.Tests is

   use Util.Tests;

   package Caller is new Util.Test_Caller (Test, "Security.Policies");

   procedure Add_Tests (Suite : in Util.Tests.Access_Test_Suite) is
   begin

      Caller.Add_Test (Suite, "Test Security.Permissions.Create_Role",
                       Test_Create_Role'Access);
      Caller.Add_Test (Suite, "Test Security.Permissions.Has_Permission",
                       Test_Has_Permission'Access);
      Caller.Add_Test (Suite, "Test Security.Permissions.Read_Policy",
                       Test_Read_Policy'Access);
      Caller.Add_Test (Suite, "Test Security.Policies.Roles.Set_Roles",
                       Test_Set_Roles'Access);
      Caller.Add_Test (Suite, "Test Security.Policies.Roles.Set_Roles (invalid)",
                       Test_Set_Invalid_Roles'Access);

      --  These tests are identical but registered under different names
      --  for the test documentation.
      Caller.Add_Test (Suite, "Test Security.Contexts.Has_Permission",
                       Test_Role_Policy'Access);
      Caller.Add_Test (Suite, "Test Security.Controllers.Roles.Has_Permission",
                       Test_Role_Policy'Access);
      Caller.Add_Test (Suite, "Test Security.Permissions.Role_Policy",
                       Test_Role_Policy'Access);
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

      Map := (others => False);
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
   begin
      M.Set_Roles ("manager,admin", Map);
      T.Assert (False, "No exception was raised");

   exception
      when E : Security.Policies.Roles.Invalid_Name =>
         null;
   end Test_Set_Invalid_Roles;

   --  ------------------------------
   --  Test Has_Permission
   --  ------------------------------
   procedure Test_Has_Permission (T : in out Test) is
      M    : Security.Policies.Policy_Manager (1);
--        Perm : Permissions.Permission_Type;
      User : Test_Principal;
   begin
      --        T.Assert (not M.Has_Permission (User, 1), "User has a non-existing permission");
      null;
   end Test_Has_Permission;

   --  ------------------------------
   --  Test reading policy files
   --  ------------------------------
   procedure Test_Read_Policy (T : in out Test) is
      M           : aliased Security.Policies.Policy_Manager (Max_Policies => 2);
      Dir         : constant String := "regtests/files/permissions/";
      Path        : constant String := Util.Tests.Get_Path (Dir);
      User        : aliased Test_Principal;
      Admin_Perm  : Policies.Roles.Role_Type;
      Manager_Perm : Policies.Roles.Role_Type;
      Context     : aliased Security.Contexts.Security_Context;
      R            : Security.Policies.Roles.Role_Policy_Access := new Roles.Role_Policy;
   begin
      M.Add_Policy (R.all'Access);
      M.Read_Policy (Util.Files.Compose (Path, "empty.xml"));

      R.Add_Role_Type (Name   => "admin",
                       Result => Admin_Perm);
      R.Add_Role_Type (Name   => "manager",
                       Result => Manager_Perm);
      M.Read_Policy (Util.Files.Compose (Path, "simple-policy.xml"));

      User.Roles (Admin_Perm) := True;

      Context.Set_Context (Manager   => M'Unchecked_Access,
                           Principal => User'Unchecked_Access);
      declare
         use Security.Permissions.Tests;

         S : Util.Measures.Stamp;
      begin
         for I in 1 .. 1_000 loop
            declare
               URI : constant String := "/admin/home/" & Util.Strings.Image (I) & "/l.html";
               P   : constant URLs.URI_Permission (URI'Length)
                 := URLs.URI_Permission '(Len => URI'Length, URI => URI);
            begin
               T.Assert (Contexts.Has_Permission (Permission => P_Admin.Permission),
                         "Permission not granted");
            end;
         end loop;
         Util.Measures.Report (S, "Has_Permission (1000 calls, cache miss)");
      end;
      declare
         use Security.Permissions.Tests;

         S : Util.Measures.Stamp;
      begin
         for I in 1 .. 1_000 loop
            declare
               URI : constant String := "/admin/home/list.html";
               P   : constant URLs.URI_Permission (URI'Length)
                 := URLs.URI_Permission '(Len => URI'Length, URI => URI);
            begin
               T.Assert (Contexts.Has_Permission (Permission => P_Admin.Permission),
                         "Permission not granted");
            end;
         end loop;
         Util.Measures.Report (S, "Has_Permission (1000 calls, cache hit)");
      end;

   end Test_Read_Policy;

   --  ------------------------------
   --  Read the policy file <b>File</b> and perform a test on the given URI
   --  with a user having the given role.
   --  ------------------------------
   procedure Check_Policy (T     : in out Test;
                           File  : in String;
                           Role  : in String;
                           URI : in String) is
      M           : aliased Security.Policies.Policy_Manager (2);
      Dir         : constant String := "regtests/files/permissions/";
      Path        : constant String := Util.Tests.Get_Path (Dir);
      User        : aliased Test_Principal;
      Admin_Perm  : Roles.Role_Type;
      Context     : aliased Security.Contexts.Security_Context;
      R           : Security.Policies.Roles.Role_Policy_Access := new Roles.Role_Policy;
      U           : Security.Policies.URLs.URL_Policy_Access := new URLs.URL_Policy;
   begin
      M.Add_Policy (R.all'Access);
      M.Add_Policy (U.all'Access);
      M.Read_Policy (Util.Files.Compose (Path, File));

      Admin_Perm := R.Find_Role (Role);
      Context.Set_Context (Manager   => M'Unchecked_Access,
                           Principal => User'Unchecked_Access);

      declare
         P   : constant URLs.URI_Permission (URI'Length)
           := URLs.URI_Permission '(Len => URI'Length, URI => URI);
      begin
         --  A user without the role should not have the permission.
         T.Assert (not U.Has_Permission (Context    => Context'Unchecked_Access,
                                         Permission => P),
           "Permission was granted for user without role.  URI=" & URI);

         --  Set the role.
         User.Roles (Admin_Perm) := True;
         T.Assert (U.Has_Permission (Context    => Context'Unchecked_Access,
                                     Permission => P),
           "Permission was not granted for user with role.  URI=" & URI);
      end;
   end Check_Policy;

   --  ------------------------------
   --  Test reading policy files and using the <role-permission> controller
   --  ------------------------------
   procedure Test_Role_Policy (T : in out Test) is
   begin
      T.Check_Policy (File => "policy-with-role.xml",
                      Role => "developer",
                      URI  => "/developer/user-should-have-developer-role");
      T.Check_Policy (File => "policy-with-role.xml",
                      Role => "manager",
                      URI  => "/developer/user-should-have-manager-role");
      T.Check_Policy (File => "policy-with-role.xml",
                      Role => "manager",
                      URI  => "/manager/user-should-have-manager-role");
      T.Check_Policy (File => "policy-with-role.xml",
                      Role => "admin",
                      URI  => "/manager/user-should-have-admin-role");
      T.Check_Policy (File => "policy-with-role.xml",
                      Role => "admin",
                      URI  => "/admin/user-should-have-admin-role");
   end Test_Role_Policy;

end Security.Policies.Tests;
