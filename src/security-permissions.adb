-----------------------------------------------------------------------
--  security-permissions -- Definition of permissions
--  Copyright (C) 2010, 2011 Stephane Carrez
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

with Ada.Containers.Indefinite_Hashed_Maps;
with Ada.Strings.Hash;

with Util.Log.Loggers;

--  The <b>Security.Permissions</b> package defines the different permissions that can be
--  checked by the access control manager.
package body Security.Permissions is

   use Util.Log;

   --  ------------------------------
   --  Permission Manager
   --  ------------------------------

   --  The logger
   Log : constant Loggers.Logger := Loggers.Create ("Security.Permissions");

   --  A global map to translate a string to a permission index.
   package Permission_Maps is
     new Ada.Containers.Indefinite_Hashed_Maps (Key_Type        => String,
                                                Element_Type    => Permission_Index,
                                                Hash            => Ada.Strings.Hash,
                                                Equivalent_Keys => "=",
                                                "="             => "=");

   protected type Global_Index is
      --  Get the permission index
      function Get_Permission_Index (Name : in String) return Permission_Index;

      --  Get the last permission index registered in the global permission map.
      function Get_Last_Permission_Index return Permission_Index;

      procedure Add_Permission (Name  : in String;
                                Index : out Permission_Index);
   private
      Map        : Permission_Maps.Map;
      Next_Index : Permission_Index := Permission_Index'First;
   end Global_Index;

   protected body Global_Index is
      function Get_Permission_Index (Name : in String) return Permission_Index is
         Pos : constant Permission_Maps.Cursor := Map.Find (Name);
      begin
         if Permission_Maps.Has_Element (Pos) then
            return Permission_Maps.Element (Pos);
         else
            raise Invalid_Name with "There is no permission '" & Name & "'";
         end if;
      end Get_Permission_Index;

      --  Get the last permission index registered in the global permission map.
      function Get_Last_Permission_Index return Permission_Index is
      begin
         return Next_Index;
      end Get_Last_Permission_Index;

      procedure Add_Permission (Name  : in String;
                                Index : out Permission_Index) is
         Pos : constant Permission_Maps.Cursor := Map.Find (Name);
      begin
         if Permission_Maps.Has_Element (Pos) then
            Index := Permission_Maps.Element (Pos);
         else
            Index := Next_Index;
            Log.Debug ("Creating permission index {1} for {0}",
                       Name, Permission_Index'Image (Index));
            Map.Insert (Name, Index);
            Next_Index := Next_Index + 1;
         end if;
      end Add_Permission;

   end Global_Index;

   Permission_Indexes : Global_Index;

   --  ------------------------------
   --  Get the permission index associated with the name.
   --  ------------------------------
   function Get_Permission_Index (Name : in String) return Permission_Index is
   begin
      return Permission_Indexes.Get_Permission_Index (Name);
   end Get_Permission_Index;

   --  ------------------------------
   --  Get the last permission index registered in the global permission map.
   --  ------------------------------
   function Get_Last_Permission_Index return Permission_Index is
   begin
      return Permission_Indexes.Get_Last_Permission_Index;
   end Get_Last_Permission_Index;

   --  ------------------------------
   --  Add the permission name and allocate a unique permission index.
   --  ------------------------------
   procedure Add_Permission (Name  : in String;
                             Index : out Permission_Index) is
   begin
      Permission_Indexes.Add_Permission (Name, Index);
   end Add_Permission;

   package body Permission_ACL is
      P : Permission_Index;

      function Permission return Permission_Index is
      begin
         return P;
      end Permission;

   begin
      Add_Permission (Name => Name, Index => P);
   end Permission_ACL;

end Security.Permissions;
