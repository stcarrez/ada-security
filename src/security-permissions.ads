-----------------------------------------------------------------------
--  security-permissions -- Definition of permissions
--  Copyright (C) 2010, 2011, 2012, 2016, 2017 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
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
   MAX_PERMISSION : constant Natural := 255;

   type Permission_Index is new Natural range 0 .. MAX_PERMISSION;

   type Permission_Index_Array is array (Positive range <>) of Permission_Index;

   NONE : constant Permission_Index := Permission_Index'First;

   --  Get the permission index associated with the name.
   function Get_Permission_Index (Name : in String) return Permission_Index;

   --  Get the list of permissions whose name is given in the string with separated comma.
   function Get_Permission_Array (List : in String) return Permission_Index_Array;

   --  Get the permission name given the index.
   function Get_Name (Index : in Permission_Index) return String;

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

   --  Add the permission index to the set.
   procedure Add_Permission (Set   : in out Permission_Index_Set;
                             Index : in Permission_Index);

   --  Get the last permission index registered in the global permission map.
   function Get_Last_Permission_Index return Permission_Index;

   --  The empty set of permission indexes.
   EMPTY_SET : constant Permission_Index_Set;

private

   INDEX_SET_SIZE : constant Natural := (MAX_PERMISSION + 7) / 8;

   type Permission_Index_Set is array (0 .. INDEX_SET_SIZE - 1) of Interfaces.Unsigned_8;

   EMPTY_SET : constant Permission_Index_Set := (others => 0);

end Security.Permissions;
