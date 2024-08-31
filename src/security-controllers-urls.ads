-----------------------------------------------------------------------
--  security-controllers-urls -- URL permission controller
--  Copyright (C) 2012 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

with Security.Contexts;
with Security.Permissions;

with Security.Policies.URLs;

package Security.Controllers.URLs is

   --  ------------------------------
   --  Security Controller
   --  ------------------------------
   --  The <b>URL_Controller</b> implements the permission check for URL permissions.
   --  It uses the URL policy manager to verify the permission.
   type URL_Controller is limited new Controller with record
      Manager : Security.Policies.URLs.URL_Policy_Access;
   end record;
   type URL_Controller_Access is access all URL_Controller'Class;

   --  Returns true if the user associated with the security context <b>Context</b> has
   --  the permission to access the URL defined in <b>Permission</b>.
   overriding
   function Has_Permission (Handler    : in URL_Controller;
                            Context    : in Security.Contexts.Security_Context'Class;
                            Permission : in Security.Permissions.Permission'Class)
                            return Boolean;

end Security.Controllers.URLs;
