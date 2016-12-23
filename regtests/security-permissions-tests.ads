-----------------------------------------------------------------------
--  Security-permissions-tests - Unit tests for Security.Permissions
--  Copyright (C) 2011, 2012, 2016 Stephane Carrez
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
