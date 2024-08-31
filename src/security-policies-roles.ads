-----------------------------------------------------------------------
--  security-policies-roles -- Role based policies
--  Copyright (C) 2010, 2011, 2012, 2017, 2018 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

with Ada.Strings.Unbounded;

--  == Role Based Security Policy ==
--  The `Security.Policies.Roles` package implements a role based security policy.
--  In this policy, users are assigned one or several roles and permissions are
--  associated with roles.  A permission is granted if the user has one of the roles required
--  by the permission.
--
--  === Policy creation ===
--  An instance of the `Role_Policy` must be created and registered in the policy manager.
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
--    <policy-rules>
--      <security-role>
--        <role-name>admin</role-name>
--      </security-role>
--      <security-role>
--        <role-name>manager</role-name>
--      </security-role>
--      <role-permission>
--        <name>create-workspace</name>
--        <role>admin</role>
--        <role>manager</role>
--      </role-permission>
--      ...
--    </policy-rules>
--
--  This definition declares two roles: `admin` and `manager`
--  It defines a permission `create-workspace` that will be granted if the
--  user has either the `admin` or the `manager` role.
--
--  Each role is identified by a name in the configuration file.  It is represented by
--  a `Role_Type`.  To provide an efficient implementation, the `Role_Type`
--  is represented as an integer with a limit of 64 different roles.
--
--  === Assigning roles to users ===
--  A `Security_Context` must be associated with a set of roles before checking the
--  permission.  This is done by using the `Set_Role_Context` operation:
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

   type Role_Name_Array is array (Positive range <>) of Ada.Strings.Unbounded.String_Access;

   --  The <b>Role_Map</b> represents a set of roles which are assigned to a user.
   --  Each role is represented by a boolean in the map.  The implementation is limited
   --  to 64 roles (the number of different permissions can be higher).
   type Role_Map is array (Role_Type'Range) of Boolean;
   pragma Pack (Role_Map);

   --  Get the number of roles set in the map.
   function Get_Count (Map : in Role_Map) return Natural;

   --  Return the list of role names separated by ','.
   function To_String (List : in Role_Name_Array) return String;

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

   --  Get the roles that grant the given permission.
   function Get_Grants (Manager    : in Role_Policy;
                        Permission : in Permissions.Permission_Index) return Role_Map;

   --  Get the list of role names that are defined by the role map.
   function Get_Role_Names (Manager : in Role_Policy;
                            Map     : in Role_Map) return Role_Name_Array;

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
                             Mapper : in out Util.Serialize.Mappers.Processing);

   --  Finalize the policy manager.
   overriding
   procedure Finalize (Policy : in out Role_Policy);

   --  Get the role policy associated with the given policy manager.
   --  Returns the role policy instance or null if it was not registered in the policy manager.
   function Get_Role_Policy (Manager : in Security.Policies.Policy_Manager'Class)
                             return Role_Policy_Access;

private

   --  Array to map a permission index to a list of roles that are granted the permission.
   type Permission_Role_Array is array (Permission_Index) of Role_Map;

   type Role_Map_Name_Array is array (Role_Type'Range) of Ada.Strings.Unbounded.String_Access;

   type Role_Policy is new Policy with record
      Names     : Role_Map_Name_Array := (others => null);
      Next_Role : Role_Type := Role_Type'First;
      Name      : Util.Beans.Objects.Object;
      Roles     : Role_Type_Array (1 .. Integer (Role_Type'Last)) := (others => 0);
      Count     : Natural := 0;

      --  The Grants array indicates for each permission the list of roles
      --  that are granted the permission.  This array allows a O(1) lookup.
      --  The implementation is limited to 256 permissions and 64 roles so this array uses 2K.
      --  The default is that no role is assigned to the permission.
      Grants    : Permission_Role_Array := (others => (others => False));
   end record;

end Security.Policies.Roles;
