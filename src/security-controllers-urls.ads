-----------------------------------------------------------------------
--  security-controllers-urls -- URL permission controller
--  Copyright (C) 2012 Stephane Carrez
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
