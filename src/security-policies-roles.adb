-----------------------------------------------------------------------
--  security-policies-roles -- Role based policies
--  Copyright (C) 2010, 2011, 2012, 2017 Stephane Carrez
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

with Util.Log.Loggers;
with Util.Serialize.Mappers.Record_Mapper;
with Util.Strings.Tokenizers;

with Security.Controllers;
with Security.Controllers.Roles;

package body Security.Policies.Roles is

   --  The logger
   Log : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("Security.Policies.Roles");

   --  ------------------------------
   --  Set the roles which are assigned to the user in the security context.
   --  The role policy will use these roles to verify a permission.
   --  ------------------------------
   procedure Set_Role_Context (Context : in out Security.Contexts.Security_Context'Class;
                               Roles   : in Role_Map) is
      Policy : constant Security.Policies.Policy_Access := Context.Get_Policy (NAME);
      Data   : Role_Policy_Context_Access;
   begin
      if Policy = null then
         Log.Error ("There is no security policy: " & NAME);
      end if;
      Data := new Role_Policy_Context;
      Data.Roles := Roles;

      Context.Set_Policy_Context (Policy, Data.all'Access);
   end Set_Role_Context;

   --  ------------------------------
   --  Set the roles which are assigned to the user in the security context.
   --  The role policy will use these roles to verify a permission.
   --  ------------------------------
   procedure Set_Role_Context (Context : in out Security.Contexts.Security_Context'Class;
                               Roles   : in String) is
      Policy : constant Security.Policies.Policy_Access := Context.Get_Policy (NAME);
      Data   : Role_Policy_Context_Access;
      Map    : Role_Map;
   begin
      if Policy = null then
         Log.Error ("There is no security policy: " & NAME);
      end if;
      Role_Policy'Class (Policy.all).Set_Roles (Roles, Map);
      Data := new Role_Policy_Context;
      Data.Roles := Map;

      Context.Set_Policy_Context (Policy, Data.all'Access);
   end Set_Role_Context;

   --  ------------------------------
   --  Get the policy name.
   --  ------------------------------
   overriding
   function Get_Name (From : in Role_Policy) return String is
      pragma Unreferenced (From);
   begin
      return NAME;
   end Get_Name;

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

   --  ------------------------------
   --  Set the roles specified in the <tt>Roles</tt> parameter.  Each role is represented by
   --  its name and multiple roles are separated by ','.
   --  Raises Invalid_Name if a role was not found.
   --  ------------------------------
   procedure Set_Roles (Manager : in Role_Policy;
                        Roles   : in String;
                        Into    : out Role_Map) is
      procedure Process (Role : in String;
                         Done : out Boolean);

      procedure Process (Role : in String;
                         Done : out Boolean) is
      begin
         Into (Manager.Find_Role (Role)) := True;
         Done := False;
      end Process;

   begin
      Into := (others => False);
      Util.Strings.Tokenizers.Iterate_Tokens (Content => Roles,
                                              Pattern => ",",
                                              Process => Process'Access,
                                              Going   => Ada.Strings.Forward);
   end Set_Roles;

   type Config_Fields is (FIELD_NAME, FIELD_ROLE, FIELD_ROLE_PERMISSION, FIELD_ROLE_NAME);

   procedure Set_Member (Into  : in out Role_Policy'Class;
                         Field : in Config_Fields;
                         Value : in Util.Beans.Objects.Object);

   --  ------------------------------
   --  Called while parsing the XML policy file when the <name>, <role> and <role-permission>
   --  XML entities are found.  Create the new permission when the complete permission definition
   --  has been parsed and save the permission in the security manager.
   --  ------------------------------
   procedure Set_Member (Into  : in out Role_Policy'Class;
                         Field : in Config_Fields;
                         Value : in Util.Beans.Objects.Object) is
      use Security.Controllers.Roles;
   begin
      case Field is
         when FIELD_NAME =>
            Into.Name := Value;

         when FIELD_ROLE =>
            declare
               Role : constant String := Util.Beans.Objects.To_String (Value);
            begin
               Into.Roles (Into.Count + 1) := Into.Find_Role (Role);
               Into.Count := Into.Count + 1;

            exception
               when Invalid_Name =>
                  raise Util.Serialize.Mappers.Field_Error with "Invalid role: " & Role;
            end;

         when FIELD_ROLE_PERMISSION =>
            if Into.Count = 0 then
               raise Util.Serialize.Mappers.Field_Error with "Missing at least one role";
            end if;
            declare
               Name : constant String := Util.Beans.Objects.To_String (Into.Name);
               Perm : constant Role_Controller_Access
                 := new Role_Controller '(Count => Into.Count,
                                          Roles => Into.Roles (1 .. Into.Count));
               Index : Permission_Index;
            begin
               Security.Permissions.Add_Permission (Name, Index);
               for I in 1 .. Into.Count loop
                  Into.Grants (Index) (Into.Roles (I)) := True;
               end loop;
               Into.Manager.Add_Permission (Name, Perm.all'Access);
               Into.Count := 0;
            end;

         when FIELD_ROLE_NAME =>
            declare
               Name : constant String := Util.Beans.Objects.To_String (Value);
               Role : Role_Type;
            begin
               Into.Add_Role_Type (Name, Role);
            end;
      end case;
   end Set_Member;

   package Config_Mapper is
     new Util.Serialize.Mappers.Record_Mapper (Element_Type        => Role_Policy'Class,
                                               Element_Type_Access => Role_Policy_Access,
                                               Fields              => Config_Fields,
                                               Set_Member          => Set_Member);

   Mapper : aliased Config_Mapper.Mapper;

   --  ------------------------------
   --  Setup the XML parser to read the <b>role-permission</b> description.
   --  ------------------------------
   procedure Prepare_Config (Policy : in out Role_Policy;
                             Reader : in out Util.Serialize.IO.XML.Parser) is
   begin
      Reader.Add_Mapping ("policy-rules", Mapper'Access);
      Reader.Add_Mapping ("module", Mapper'Access);
      Config_Mapper.Set_Context (Reader, Policy'Unchecked_Access);
   end Prepare_Config;

   --  ------------------------------
   --  Finalize the policy manager.
   --  ------------------------------
   overriding
   procedure Finalize (Policy : in out Role_Policy) is
      use type Ada.Strings.Unbounded.String_Access;
   begin
      for I in Policy.Names'Range loop
         exit when Policy.Names (I) = null;
         Ada.Strings.Unbounded.Free (Policy.Names (I));
      end loop;
   end Finalize;

   --  ------------------------------
   --  Get the role policy associated with the given policy manager.
   --  Returns the role policy instance or null if it was not registered in the policy manager.
   --  ------------------------------
   function Get_Role_Policy (Manager : in Security.Policies.Policy_Manager'Class)
                             return Role_Policy_Access is
      Policy : constant Security.Policies.Policy_Access := Manager.Get_Policy (NAME);
   begin
      if Policy = null or else not (Policy.all in Role_Policy'Class) then
         return null;
      else
         return Role_Policy'Class (Policy.all)'Access;
      end if;
   end Get_Role_Policy;

begin
   Mapper.Add_Mapping ("role-permission", FIELD_ROLE_PERMISSION);
   Mapper.Add_Mapping ("role-permission/name", FIELD_NAME);
   Mapper.Add_Mapping ("role-permission/role", FIELD_ROLE);
   Mapper.Add_Mapping ("security-role/role-name", FIELD_ROLE_NAME);
end Security.Policies.Roles;
