-----------------------------------------------------------------------
--  security-permissions -- Definition of permissions
--  Copyright (C) 2010, 2011, 2012, 2016 Stephane Carrez
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
private with Interfaces;

--  == Permission ==
--  The <b>Security.Permissions</b> package defines the different permissions that can be
--  checked by the access control manager.  An application should declare each permission
--  by instantiating the <tt>Definition</tt> package:
--
--    package Perm_Create_Workspace is new Security.Permissions.Definition ("create-workspace");
--
--  This declares a permission that can be represented by "<tt>create-workspace</tt>" in
--  configuration files.  In Ada, the permission is used as follows:
--
--     Perm_Create_Workspace.Permission
--
package Security.Permissions is

   Invalid_Name   : exception;

   --  Max number of permissions supported by the implementation.
   MAX_PERMISSION : constant Natural := 256;

   type Permission_Index is new Natural range 0 .. MAX_PERMISSION;

   --  Get the permission index associated with the name.
   function Get_Permission_Index (Name : in String) return Permission_Index;

   --  The permission root class.
   --  Each permission is represented by a <b>Permission_Index</b> number to provide a fast
   --  and efficient permission check.
   type Permission (Id : Permission_Index) is tagged limited null record;

   generic
      Name : String;
   package Definition is
      function Permission return Permission_Index;
      pragma Inline_Always (Permission);
   end Definition;

   --  Add the permission name and allocate a unique permission index.
   procedure Add_Permission (Name  : in String;
                             Index : out Permission_Index);

   type Permission_Index_Set is private;

   --  Check if the permission index set contains the given permission index.
   function Has_Permission (Set   : in Permission_Index_Set;
                            Index : in Permission_Index) return Boolean;

private

   --  Get the last permission index registered in the global permission map.
   function Get_Last_Permission_Index return Permission_Index;

   INDEX_SET_SIZE : constant Natural := (MAX_PERMISSION + 7) / 8;

   type Permission_Index_Set is array (1 .. INDEX_SET_SIZE) of Interfaces.Unsigned_8;

end Security.Permissions;
