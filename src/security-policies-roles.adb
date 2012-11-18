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

with Ada.Unchecked_Deallocation;
with Ada.Containers.Indefinite_Hashed_Maps;
with Ada.Strings.Hash;

with Util.Log.Loggers;
with Util.Serialize.Mappers.Record_Mapper;

with Security.Contexts;
with Security.Controllers;
with Security.Controllers.Roles;

--  The <b>Security.Permissions</b> package defines the different permissions that can be
--  checked by the access control manager.
package body Security.Policies.Roles is

   use Util.Log;

   --  ------------------------------
   --  Permission Manager
   --  ------------------------------

   --  The logger
   Log : constant Loggers.Logger := Loggers.Create ("Security.Permissions");

   --  ------------------------------
   --  Get the role name.
   --  ------------------------------
   function Get_Role_Name (Manager : in Role_Policy;
                           Role    : in Role_Type) return String is
      use type Ada.Strings.Unbounded.String_Access;
   begin
      if Manager.Names (Role) = null then
         return "";
      else
         return Manager.Names (Role).all;
      end if;
   end Get_Role_Name;

   --  ------------------------------
   --  Find the role type associated with the role name identified by <b>Name</b>.
   --  Raises <b>Invalid_Name</b> if there is no role type.
   --  ------------------------------
   function Find_Role (Manager : in Role_Policy;
                       Name    : in String) return Role_Type is
      use type Ada.Strings.Unbounded.String_Access;
   begin
      Log.Debug ("Searching role {0}", Name);

      for I in Role_Type'First .. Manager.Next_Role loop
         exit when Manager.Names (I) = null;
         if Name = Manager.Names (I).all then
            return I;
         end if;
      end loop;

      Log.Debug ("Role {0} not found", Name);
      raise Invalid_Name;
   end Find_Role;

   --  ------------------------------
   --  Create a role
   --  ------------------------------
   procedure Create_Role (Manager : in out Role_Policy;
                          Name    : in String;
                          Role    : out Role_Type) is
   begin
      Role := Manager.Next_Role;
      Log.Info ("Role {0} is {1}", Name, Role_Type'Image (Role));

      if Manager.Next_Role = Role_Type'Last then
         Log.Error ("Too many roles allocated.  Number of roles is {0}",
                    Role_Type'Image (Role_Type'Last));
      else
         Manager.Next_Role := Manager.Next_Role + 1;
      end if;
      Manager.Names (Role) := new String '(Name);
   end Create_Role;

   --  ------------------------------
   --  Get or build a permission type for the given name.
   --  ------------------------------
   procedure Add_Role_Type (Manager   : in out Role_Policy;
                            Name      : in String;
                            Result    : out Role_Type) is
   begin
      Result := Manager.Find_Role (Name);

   exception
      when Invalid_Name =>
         Manager.Create_Role (Name, Result);
   end Add_Role_Type;

end Security.Policies.Roles;
