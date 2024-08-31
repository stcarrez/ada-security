-----------------------------------------------------------------------
--  security-controllers-roles -- Simple role base security
--  Copyright (C) 2011, 2012 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

with Security.Contexts;
with Security.Permissions;

with Security.Policies.Roles;

package Security.Controllers.Roles is

   --  ------------------------------
   --  Security Controller
   --  ------------------------------
   --  The <b>Role_Controller</b> implements a simple role based permissions check.
   --  The permission is granted if the user has the role defined by the controller.
   type Role_Controller (Count : Positive) is limited new Controller with record
      Roles : Policies.Roles.Role_Type_Array (1 .. Count);
   end record;
   type Role_Controller_Access is access all Role_Controller'Class;

   --  Returns true if the user associated with the security context <b>Context</b> has
   --  one of the role defined in the <b>Handler</b>.
   overriding
   function Has_Permission (Handler    : in Role_Controller;
                            Context    : in Security.Contexts.Security_Context'Class;
                            Permission : in Security.Permissions.Permission'Class)
                            return Boolean;

end Security.Controllers.Roles;
