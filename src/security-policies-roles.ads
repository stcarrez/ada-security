-----------------------------------------------------------------------
--  security-policies-roles -- Role based policies
--  Copyright (C) 2010, 2011, 2012 Stephane Carrez
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

with Ada.Finalization;
with Ada.Strings.Unbounded;

package Security.Policies.Roles is

   --  Each role is represented by a <b>Role_Type</b> number to provide a fast
   --  and efficient role check.
   type Role_Type is new Natural range 0 .. 63;

   type Role_Type_Array is array (Positive range <>) of Role_Type;

   --  The <b>Role_Map</b> represents a set of roles which are assigned to a user.
   --  Each role is represented by a boolean in the map.  The implementation is limited
   --  to 64 roles (the number of different permissions can be higher).
   type Role_Map is array (Role_Type'Range) of Boolean;
   pragma Pack (Role_Map);


   type Role_Policy is new Policy with private;

   Invalid_Name : exception;

   --  Each permission is represented by a <b>Permission_Type</b> number to provide a fast
   --  and efficient permission check.
   type Permission_Type is new Natural range 0 .. 63;

   --  The <b>Permission_Map</b> represents a set of permissions which are granted to a user.
   --  Each permission is represented by a boolean in the map.  The implementation is limited
   --  to 64 permissions.
   type Permission_Map is array (Permission_Type'Range) of Boolean;
   pragma Pack (Permission_Map);

   --  ------------------------------
   --  Permission Manager
   --  ------------------------------
   --  The <b>Permission_Manager</b> verifies through some policy that a permission
   --  is granted to a user.

   --  Find the role type associated with the role name identified by <b>Name</b>.
   --  Raises <b>Invalid_Name</b> if there is no role type.
   function Find_Role (Manager : in Role_Policy;
                       Name    : in String) return Role_Type;

   --  Get the role name.
   function Get_Role_Name (Manager : in Role_Policy;
                           Role    : in Role_Type) return String;

   --  Create a role
   procedure Create_Role (Manager : in out Role_Policy;
                          Name    : in String;
                          Role    : out Role_Type);

   --  Get or add a role type for the given name.
   procedure Add_Role_Type (Manager   : in out Role_Policy;
                            Name      : in String;
                            Result    : out Role_Type);

private

   type Role_Name_Array is
     array (Role_Type'Range) of Ada.Strings.Unbounded.String_Access;

   type Role_Policy is new Policy with record
      Names        : Role_Name_Array;
      Next_Role    : Role_Type := Role_Type'First;
   end record;

end Security.Policies.Roles;
