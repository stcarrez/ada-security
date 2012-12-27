-----------------------------------------------------------------------
--  security-controllers-roles -- Simple role base security
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
