-----------------------------------------------------------------------
--  security-controllers -- Controllers to verify a security permission
--  Copyright (C) 2011, 2012 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

with Security.Contexts;
with Security.Permissions;

--  == Security Controller ==
--  The <b>Security.Controllers</b> package defines the security controller used to
--  verify that a given permission is granted.  A security controller uses the security
--  context and other controller specific and internal data to verify that the permission
--  is granted.
--
--  Security controller instances are created when the security policy rules are parsed.
--  These instances are shared across possibly several concurrent requests.
package Security.Controllers is

   Invalid_Controller : exception;

   --  ------------------------------
   --  Security Controller interface
   --  ------------------------------
   type Controller is limited interface;
   type Controller_Access is access all Controller'Class;

   --  Checks whether the permission defined by the <b>Handler</b> controller data is granted
   --  by the security context passed in <b>Context</b>.
   --  Returns true if such permission is granted.
   function Has_Permission (Handler : in Controller;
                            Context : in Security.Contexts.Security_Context'Class;
                            Permission : in Security.Permissions.Permission'Class)
                            return Boolean is abstract;

end Security.Controllers;
