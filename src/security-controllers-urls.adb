-----------------------------------------------------------------------
--  security-controllers-urls -- URL permission controller
--  Copyright (C) 2012 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

package body Security.Controllers.URLs is

   --  ------------------------------
   --  Returns true if the user associated with the security context <b>Context</b> has
   --  the permission to access the URL defined in <b>Permission</b>.
   --  ------------------------------
   overriding
   function Has_Permission (Handler    : in URL_Controller;
                            Context    : in Security.Contexts.Security_Context'Class;
                            Permission : in Security.Permissions.Permission'Class)
                            return Boolean is
   begin
      if Permission in Security.Policies.URLs.URL_Permission'Class then
         return Handler.Manager.Has_Permission (Context,
                                                Policies.URLs.URL_Permission'Class (Permission));
      else
         return False;
      end if;
   end Has_Permission;

end Security.Controllers.URLs;
