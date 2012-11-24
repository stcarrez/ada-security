-----------------------------------------------------------------------
--  security-controllers -- Controllers to verify a security permission
--  Copyright (C) 2011, 2012 Stephane Carrez
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

with Security.Contexts;
with Security.Permissions;

--  == Security Controller ==
--  The <b>Security.Controllers</b> package defines the security controller used to
--  verify that a given permission is granted.  A security controller uses the security
--  context and other controller specific and internal data to verify that the permission
--  is granted.
--
--  To implement a new security controller, one must:
--
--    * Define a type that implements the <b>Controller</b> interface with the
--      <b>Has_Permission</b> operation
--    * Write a function to allocate instances of the given <b>Controller</b> type
--    * Register the function under a unique name by using <b>Register_Controller</b>
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
