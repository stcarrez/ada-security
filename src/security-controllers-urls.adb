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
