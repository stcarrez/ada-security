-----------------------------------------------------------------------
--  Security-permissions-tests - Unit tests for Security.Permissions
--  Copyright (C) 2011, 2012, 2016 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

with Util.Tests;

package Security.Permissions.Tests is

   package P_Admin is new Permissions.Definition ("admin");
   package P_Create is new Permissions.Definition ("create");
   package P_Update is new Permissions.Definition ("update");
   package P_Delete is new Permissions.Definition ("delete");

   procedure Add_Tests (Suite : in Util.Tests.Access_Test_Suite);

   type Test is new Util.Tests.Test with null record;

   --  Test Add_Permission and Get_Permission_Index.
   procedure Test_Add_Permission (T : in out Test);

   --  Test the permission created by the Definition package.
   procedure Test_Define_Permission (T : in out Test);

   --  Test Get_Permission on invalid permission name.
   procedure Test_Get_Invalid_Permission (T : in out Test);

   --  Test operations on the Permission_Index_Set.
   procedure Test_Add_Permission_Set (T : in out Test);

end Security.Permissions.Tests;
