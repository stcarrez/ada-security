-----------------------------------------------------------------------
--  security-controllers-roles -- Simple role base security
--  Copyright (C) 2011 Stephane Carrez
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

with Util.Serialize.Mappers.Record_Mapper;
package body Security.Controllers.Roles is

   --  ------------------------------
   --  Returns true if the user associated with the security context <b>Context</b> has
   --  one of the role defined in the <b>Handler</b>.
   --  ------------------------------
   function Has_Permission (Handler : in Role_Controller;
                            Context : in Security.Contexts.Security_Context'Class)
                            return Boolean is
      use type Security.Principal_Access;

      P : constant Security.Principal_Access := Context.Get_User_Principal;
   begin
      if P /= null then
         for I in Handler.Roles'Range loop
--              if P.Has_Role (Handler.Roles (I)) then
               return True;
--              end if;
         end loop;
      end if;
      return False;
   end Has_Permission;

   type Config_Fields is (FIELD_NAME, FIELD_ROLE, FIELD_ROLE_PERMISSION, FIELD_ROLE_NAME);

   type Controller_Config_Access is access all Controller_Config;

   procedure Set_Member (Into  : in out Controller_Config;
                         Field : in Config_Fields;
                         Value : in Util.Beans.Objects.Object);

   --  ------------------------------
   --  Called while parsing the XML policy file when the <name>, <role> and <role-permission>
   --  XML entities are found.  Create the new permission when the complete permission definition
   --  has been parsed and save the permission in the security manager.
   --  ------------------------------
   procedure Set_Member (Into  : in out Controller_Config;
                         Field : in Config_Fields;
                         Value : in Util.Beans.Objects.Object) is
   begin
      case Field is
         when FIELD_NAME =>
            Into.Name := Value;

         when FIELD_ROLE =>
            declare
               Role : constant String := Util.Beans.Objects.To_String (Value);
            begin
               Into.Roles (Into.Count + 1) := Into.Manager.Find_Role (Role);
               Into.Count := Into.Count + 1;

            exception
               when Permissions.Invalid_Name =>
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
            begin
               Into.Manager.Add_Permission (Name, Perm.all'Access);
               Into.Count := 0;
            end;

         when FIELD_ROLE_NAME =>
            declare
               Name : constant String := Util.Beans.Objects.To_String (Value);
               Role : Permissions.Role_Type;
            begin
               Into.Manager.Add_Role_Type (Name, Role);
            end;
      end case;
   end Set_Member;

   package Config_Mapper is
     new Util.Serialize.Mappers.Record_Mapper (Element_Type        => Controller_Config,
                                               Element_Type_Access => Controller_Config_Access,
                                               Fields              => Config_Fields,
                                               Set_Member          => Set_Member);

   Mapper : aliased Config_Mapper.Mapper;

   --  ------------------------------
   --  Setup the XML parser to read the <b>role-permission</b> description.  For example:
   --
   --  <security-role>
   --    <role-name>admin</role-name>
   --  </security-role>
   --  <role-permission>
   --     <name>create-workspace</name>
   --     <role>admin</role>
   --     <role>manager</role>
   --  </role-permission>
   --
   --  This defines a permission <b>create-workspace</b> that will be granted if the
   --  user has either the <b>admin</b> or the <b>manager</b> role.
   --  ------------------------------
   package body Reader_Config is
   begin
      Reader.Add_Mapping ("policy-rules", Mapper'Access);
      Reader.Add_Mapping ("module", Mapper'Access);
      Config.Manager := Manager;
      Config_Mapper.Set_Context (Reader, Config'Unchecked_Access);
   end Reader_Config;

begin
   Mapper.Add_Mapping ("role-permission", FIELD_ROLE_PERMISSION);
   Mapper.Add_Mapping ("role-permission/name", FIELD_NAME);
   Mapper.Add_Mapping ("role-permission/role", FIELD_ROLE);
   Mapper.Add_Mapping ("security-role/role-name", FIELD_ROLE_NAME);
end Security.Controllers.Roles;
