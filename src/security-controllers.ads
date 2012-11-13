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
                            Context : in Security.Contexts.Security_Context'Class)
                            return Boolean is abstract;

   type Controller_Factory is not null access function return Controller_Access;

   --  To keep this implementation simple, a maximum of 32 security controller factory
   --  can be registered.  ASF provides one based on roles.  AWA provides another one
   --  based on entity ACLs.
   MAX_CONTROLLER_FACTORY : constant Positive := 32;

   --  Register in a global table the controller factory under the name <b>Name</b>.
   --  When this factory is used, the <b>Factory</b> operation will be called to
   --  create new instances of the controller.
   procedure Register_Controller (Name    : in String;
                                  Factory : in Controller_Factory);

   --  Create a security controller by using the controller factory registered under
   --  the name <b>Name</b>.
   --  Raises <b>Invalid_Controller</b> if the name is not recognized.
   function Create_Controller (Name : in String) return Controller_Access;

end Security.Controllers;
