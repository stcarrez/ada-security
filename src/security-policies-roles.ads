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

with Ada.Strings.Unbounded;

--  == Role Based Security Policy ==
--  The <tt>Security.Policies.Roles</tt> package implements a role based security policy.
--
--  === Policy creation ===
--  An instance of the <tt>Role_Policy</tt> must be created and registered in the policy manager.
--  Get or declare the following variables:
--
--    Manager : Security.Policies.Policy_Manager;
--    Policy  : Security.Policies.Roles.Role_Policy_Access;
--
--  Create the role policy and register it in the policy manager as follows:
--
--    Policy := new Role_Policy;
--    Manager.Add_Policy (Policy.all'Access);
--
--  === Policy Configuration ===
--  A role is represented by a name in security configuration files.  A role based permission
--  is associated with a list of roles.  The permission is granted if the user has one of these
--  roles.  When the role based policy is registered in the policy manager, the following
--  XML configuration is used:
--
--    <security-role>
--      <role-name>admin</role-name>
--    </security-role>
--    <security-role>
--      <role-name>manager</role-name>
--    </security-role>
--    <role-permission>
--      <name>create-workspace</name>
--      <role>admin</role>
--      <role>manager</role>
--    </role-permission>
--
--  This definition declares two roles: <tt>admin</tt> and <tt>manager</tt>
--  It defines a permission <b>create-workspace</b> that will be granted if the
--  user has either the <b>admin</b> or the <b>manager</b> role.
--
--  Each role is identified by a name in the configuration file.  It is represented by
--  a <tt>Role_Type</tt>.  To provide an efficient implementation, the <tt>Role_Type</tt>
--  is represented as an integer with a limit of 64 different roles.
--
--  === Assigning roles to users ===
--  A <tt>Security_Context</tt> must be associated with a set of roles before checking the
--  permission.  This is done by using the <tt>Set_Role_Context</tt> operation:
--
--     Security.Policies.Roles.Set_Role_Context (Security.Contexts.Current, "admin");
--
package Security.Policies.Roles is

   NAME : constant String := "Role-Policy";

   --  Each role is represented by a <b>Role_Type</b> number to provide a fast
   --  and efficient role check.
   type Role_Type is new Natural range 0 .. 63;
   for Role_Type'Size use 8;

   type Role_Type_Array is array (Positive range <>) of Role_Type;

   --  The <b>Role_Map</b> represents a set of roles which are assigned to a user.
   --  Each role is represented by a boolean in the map.  The implementation is limited
   --  to 64 roles (the number of different permissions can be higher).
   type Role_Map is array (Role_Type'Range) of Boolean;
   pragma Pack (Role_Map);

   --  ------------------------------
   --  Role principal context
   --  ------------------------------
   --  The <tt>Role_Principal_Context</tt> interface must be implemented by the user
   --  <tt>Principal</tt> to be able to use the role based policy.   The role based policy
   --  controller will first check that the <tt>Principal</tt> implements that interface.
   --  It uses the <tt>Get_Roles</tt> function to get the current roles assigned to the user.
   type Role_Principal_Context is limited interface;
   function Get_Roles (User : in Role_Principal_Context) return Role_Map is abstract;

   --  ------------------------------
   --  Policy context
   --  ------------------------------
   --  The <b>Role_Policy_Context</b> gives security context information that the role
   --  based policy can use to verify the permission.
   type Role_Policy_Context is new Policy_Context with record
      Roles : Role_Map;
   end record;
   type Role_Policy_Context_Access is access all Role_Policy_Context'Class;

   --  Set the roles which are assigned to the user in the security context.
   --  The role policy will use these roles to verify a permission.
   procedure Set_Role_Context (Context : in out Security.Contexts.Security_Context'Class;
                               Roles   : in Role_Map);

   --  Set the roles which are assigned to the user in the security context.
   --  The role policy will use these roles to verify a permission.
   procedure Set_Role_Context (Context : in out Security.Contexts.Security_Context'Class;
                               Roles   : in String);

   --  ------------------------------
   --  Role based policy
   --  ------------------------------
   type Role_Policy is new Policy with private;
   type Role_Policy_Access is access all Role_Policy'Class;

   Invalid_Name : exception;

   --  Get the policy name.
   overriding
   function Get_Name (From : in Role_Policy) return String;

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

   --  Set the roles specified in the <tt>Roles</tt> parameter.  Each role is represented by
   --  its name and multiple roles are separated by ','.
   --  Raises Invalid_Name if a role was not found.
   procedure Set_Roles (Manager : in Role_Policy;
                        Roles   : in String;
                        Into    : out Role_Map);

   --  Setup the XML parser to read the <b>role-permission</b> description.
   overriding
   procedure Prepare_Config (Policy : in out Role_Policy;
                             Reader : in out Util.Serialize.IO.XML.Parser);

   --  Finalize the policy manager.
   overriding
   procedure Finalize (Policy : in out Role_Policy);

   --  Get the role policy associated with the given policy manager.
   --  Returns the role policy instance or null if it was not registered in the policy manager.
   function Get_Role_Policy (Manager : in Security.Policies.Policy_Manager'Class)
                             return Role_Policy_Access;

private

   type Role_Name_Array is
     array (Role_Type'Range) of Ada.Strings.Unbounded.String_Access;

   type Role_Policy is new Policy with record
      Names        : Role_Name_Array;
      Next_Role    : Role_Type := Role_Type'First;
   end record;

   type Controller_Config is record
      Name    : Util.Beans.Objects.Object;
      Roles   : Role_Type_Array (1 .. Integer (Role_Type'Last));
      Count   : Natural := 0;
      Manager : Role_Policy_Access;
   end record;

end Security.Policies.Roles;
