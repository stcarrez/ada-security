-----------------------------------------------------------------------
--  security-controllers-roles -- Simple role base security
--  Copyright (C) 2011, 2012, 2018 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

package body Security.Controllers.Roles is

   --  ------------------------------
   --  Returns true if the user associated with the security context <b>Context</b> has
   --  one of the role defined in the <b>Handler</b>.
   --  ------------------------------
   overriding
   function Has_Permission (Handler    : in Role_Controller;
                            Context    : in Security.Contexts.Security_Context'Class;
                            Permission : in Security.Permissions.Permission'Class)
                            return Boolean is
      pragma Unreferenced (Permission);

      P     : constant Security.Principal_Access := Context.Get_User_Principal;
      Roles : Security.Policies.Roles.Role_Map;
   begin
      if P /= null then
         --  If the principal has some roles, get them.
         if P.all in Policies.Roles.Role_Principal_Context'Class then
            Roles := Policies.Roles.Role_Principal_Context'Class (P.all).Get_Roles;
         else
            return False;
         end if;

         for I in Handler.Roles'Range loop
            if Roles (Handler.Roles (I)) then
               return True;
            end if;
         end loop;
      end if;
      return False;
   end Has_Permission;

end Security.Controllers.Roles;
