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
package body Security.Policies.Tests is

   use Util.Tests;

   package Caller is new Util.Test_Caller (Test, "Security.Policies");

   procedure Add_Tests (Suite : in Util.Tests.Access_Test_Suite) is
   begin
      Caller.Add_Test (Suite, "Test Security.Permissions.Add_Permission",
                       Test_Add_Permission'Access);
      Caller.Add_Test (Suite, "Test Security.Permissions.Get_Permission_Index",
                       Test_Add_Permission'Access);

      Caller.Add_Test (Suite, "Test Security.Permissions.Create_Role",
                       Test_Create_Role'Access);
      Caller.Add_Test (Suite, "Test Security.Permissions.Has_Permission",
                       Test_Has_Permission'Access);
      Caller.Add_Test (Suite, "Test Security.Permissions.Read_Policy",
                       Test_Read_Policy'Access);

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
   --  Returns true if the given permission is stored in the user principal.
   --  ------------------------------
   function Has_Role (User : in Test_Principal;
                      Role : in Role_Type) return Boolean is
   begin
      return User.Roles (Role);
   end Has_Role;

   --  ------------------------------
   --  Get the principal name.
   --  ------------------------------
   function Get_Name (From : in Test_Principal) return String is
   begin
      return Util.Strings.To_String (From.Name);
   end Get_Name;

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
   --  Test Has_Permission
   --  ------------------------------
   procedure Test_Has_Permission (T : in out Test) is
      M    : Security.Permissions.Permission_Manager;
      Perm : Permission_Type;
      User : Test_Principal;
   begin
      T.Assert (not M.Has_Permission (User, 1), "User has a non-existing permission");
   end Test_Has_Permission;

   --  ------------------------------
   --  Test reading policy files
   --  ------------------------------
   procedure Test_Read_Policy (T : in out Test) is
      M           : aliased Security.Permissions.Permission_Manager;
      Dir         : constant String := "regtests/files/permissions/";
      Path        : constant String := Util.Tests.Get_Path (Dir);
      User        : aliased Test_Principal;
      Admin_Perm  : Role_Type;
      Manager_Perm : Role_Type;
      Context     : aliased Security.Contexts.Security_Context;
   begin
      M.Read_Policy (Util.Files.Compose (Path, "empty.xml"));

      M.Add_Role_Type (Name   => "admin",
                       Result => Admin_Perm);
      M.Add_Role_Type (Name   => "manager",
                       Result => Manager_Perm);
      M.Read_Policy (Util.Files.Compose (Path, "simple-policy.xml"));

      User.Roles (Admin_Perm) := True;

      Context.Set_Context (Manager   => M'Unchecked_Access,
                           Principal => User'Unchecked_Access);
      declare
         S : Util.Measures.Stamp;
      begin
         for I in 1 .. 1_000 loop
            declare
               URI : constant String := "/admin/home/" & Util.Strings.Image (I) & "/l.html";
               P   : constant URI_Permission (URI'Length)
                 := URI_Permission '(Len => URI'Length, URI => URI);
            begin
               T.Assert (M.Has_Permission (Context    => Context'Unchecked_Access,
                                           Permission => P), "Permission not granted");
            end;
         end loop;
         Util.Measures.Report (S, "Has_Permission (1000 calls, cache miss)");
      end;

      declare
         S : Util.Measures.Stamp;
      begin
         for I in 1 .. 1_000 loop
            declare
               URI : constant String := "/admin/home/list.html";
               P   : constant URI_Permission (URI'Length)
                 := URI_Permission '(Len => URI'Length, URI => URI);
            begin
               T.Assert (M.Has_Permission (Context    => Context'Unchecked_Access,
                                           Permission => P), "Permission not granted");
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
      M           : aliased Security.Permissions.Permission_Manager;
      Dir         : constant String := "regtests/files/permissions/";
      Path        : constant String := Util.Tests.Get_Path (Dir);
      User        : aliased Test_Principal;
      Admin_Perm  : Role_Type;
      Context     : aliased Security.Contexts.Security_Context;
   begin
      M.Read_Policy (Util.Files.Compose (Path, File));

      Admin_Perm := M.Find_Role (Role);

      Context.Set_Context (Manager   => M'Unchecked_Access,
                           Principal => User'Unchecked_Access);

      declare
         P   : constant URI_Permission (URI'Length)
           := URI_Permission '(Len => URI'Length, URI => URI);
      begin
         --  A user without the role should not have the permission.
         T.Assert (not M.Has_Permission (Context    => Context'Unchecked_Access,
                                         Permission => P),
           "Permission was granted for user without role.  URI=" & URI);

         --  Set the role.
         User.Roles (Admin_Perm) := True;
         T.Assert (M.Has_Permission (Context    => Context'Unchecked_Access,
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
