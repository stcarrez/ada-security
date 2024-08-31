-----------------------------------------------------------------------
--  Security-policies-tests - Unit tests for Security.Permissions
--  Copyright (C) 2011, 2012, 2013, 2017, 2022 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

with Util.Tests;
with Util.Strings;

with Security.Policies.Roles;

package Security.Policies.Tests is

   procedure Add_Tests (Suite : in Util.Tests.Access_Test_Suite);

   type Test is new Util.Tests.Test with null record;

   --  Test Create_Role and Get_Role_Name
   procedure Test_Create_Role (T : in out Test);

   --  Test Set_Roles
   procedure Test_Set_Roles (T : in out Test);

   --  Test Set_Roles on an invalid role name
   procedure Test_Set_Invalid_Roles (T : in out Test);

   --  Test the Get_Policy, Get_Role_Policy and Add_Policy operations.
   procedure Test_Get_Role_Policy (T : in out Test);

   --  Test Has_Permission
   procedure Test_Has_Permission (T : in out Test);

   --  Test reading an empty policy file
   procedure Test_Read_Empty_Policy (T : in out Test);

   --  Test reading policy files
   procedure Test_Read_Policy (T : in out Test);

   --  Test reading policy files and using the <role-permission> controller
   procedure Test_Role_Policy (T : in out Test);

   --  Test the Get_Grants operation.
   procedure Test_Grants (T : in out Test);

   --  Test anonymous users and permissions.
   procedure Test_Anonymous_Permission (T : in out Test);

      --  Read the policy file <b>File</b> and perform a test on the given URI
   --  with a user having the given role.
   procedure Check_Policy (T         : in out Test;
                           File      : in String;
                           Role      : in String;
                           URL       : in String;
                           Anonymous : in Boolean := False;
                           Granted   : in Boolean := True);

   type Test_Principal is new Principal and Roles.Role_Principal_Context with record
      Name  : Util.Strings.String_Ref;
      Roles : Security.Policies.Roles.Role_Map := (others => False);
   end record;

   --  Get the roles assigned to the user.
   overriding
   function Get_Roles (User : in Test_Principal) return Roles.Role_Map;

   --  Get the principal name.
   overriding
   function Get_Name (From : in Test_Principal) return String;

end Security.Policies.Tests;
