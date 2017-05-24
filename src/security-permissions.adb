-----------------------------------------------------------------------
--  security-permissions -- Definition of permissions
--  Copyright (C) 2010, 2011, 2016, 2017 Stephane Carrez
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
with Util.Strings.Tokenizers;

with Util.Log.Loggers;

--  The <b>Security.Permissions</b> package defines the different permissions that can be
--  checked by the access control manager.
package body Security.Permissions is

   --  ------------------------------
   --  Permission Manager
   --  ------------------------------

   --  The logger
   Log : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("Security.Permissions");

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

      --  Get the permission name associated with the index.
      function Get_Name (Index : in Permission_Index) return String;

      procedure Add_Permission (Name  : in String;
                                Index : out Permission_Index);
   private
      Map        : Permission_Maps.Map;
      Next_Index : Permission_Index := NONE + 1;
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

      --  ------------------------------
      --  Get the last permission index registered in the global permission map.
      --  ------------------------------
      function Get_Last_Permission_Index return Permission_Index is
      begin
         return Next_Index - 1;
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
            if Next_Index = Permission_Index'Last then
               Log.Error ("Too many permission instantiated. "
                          & "Increase Security.Permissions.MAX_PERMISSION");
            else
               Next_Index := Next_Index + 1;
            end if;
         end if;
      end Add_Permission;

      --  ------------------------------
      --  Get the permission name associated with the index.
      --  ------------------------------
      function Get_Name (Index : in Permission_Index) return String is
         Iter : Permission_Maps.Cursor := Map.First;
      begin
         while Permission_Maps.Has_Element (Iter) loop
            if Permission_Maps.Element (Iter) = Index then
               return Permission_Maps.Key (Iter);
            end if;
            Permission_Maps.Next (Iter);
         end loop;
         return "";
      end Get_Name;

   end Global_Index;

   Permission_Indexes : Global_Index;

   --  ------------------------------
   --  Get the permission index associated with the name.
   --  ------------------------------
   function Get_Permission_Index (Name : in String) return Permission_Index is
   begin
      return Permission_Indexes.Get_Permission_Index (Name);
   end Get_Permission_Index;

   function Occurence (List : in String; Of_Char : in Character) return Natural is
      Count : Natural := 0;
   begin
      if List'Length > 0 then
         Count := 1;
         for C of List loop
            if C = Of_Char then
               Count := Count + 1;
            end if;
         end loop;
      end if;
      return Count;
   end Occurence;

   --  ------------------------------
   --  Get the list of permissions whose name is given in the string with separated comma.
   --  ------------------------------
   function Get_Permission_Array (List : in String) return Permission_Index_Array is
      Result : Permission_Index_Array (1 .. Occurence (List, ','));
      Count  : Natural := 0;

      procedure Process (Name : in String;
                         Done : out Boolean) is
      begin
         Done := False;
         Result (Count + 1) := Get_Permission_Index (Name);
         Count := Count + 1;

      exception
         when Invalid_Name =>
            Log.Info ("Permission {0} does not exist", Name);

      end Process;
   begin
      Util.Strings.Tokenizers.Iterate_Tokens (Content => List,
                                              Pattern => ",",
                                              Process => Process'Access,
                                              Going   => Ada.Strings.Forward);
      return Result (1 .. Count);
   end Get_Permission_Array;

   --  ------------------------------
   --  Get the permission name given the index.
   --  ------------------------------
   function Get_Name (Index : in Permission_Index) return String is
   begin
      return Permission_Indexes.Get_Name (Index);
   end Get_Name;

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

   --  ------------------------------
   --  Check if the permission index set contains the given permission index.
   --  ------------------------------
   function Has_Permission (Set   : in Permission_Index_Set;
                            Index : in Permission_Index) return Boolean is
      use Interfaces;
   begin
      return (Set (Natural (Index / 8)) and Shift_Left (1, Natural (Index mod 8))) /= 0;
   end Has_Permission;

   --  ------------------------------
   --  Add the permission index to the set.
   --  ------------------------------
   procedure Add_Permission (Set   : in out Permission_Index_Set;
                             Index : in Permission_Index) is
      use Interfaces;
      Pos : constant Natural := Natural (Index / 8);
   begin
      Set (Pos) := Set (Pos) or Shift_Left (1, Natural (Index mod 8));
   end Add_Permission;

   package body Definition is
      P : Permission_Index;

      function Permission return Permission_Index is
      begin
         return P;
      end Permission;

   begin
      Add_Permission (Name => Name, Index => P);
   end Definition;

end Security.Permissions;
