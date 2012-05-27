-----------------------------------------------------------------------
--  security-controllers-roles -- Simple role base security
--  Copyright (C) 2011 Stephane Carrez
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

with Util.Beans.Objects;
with Util.Serialize.IO.XML;

package Security.Controllers.Roles is

   --  ------------------------------
   --  Security Controller
   --  ------------------------------
   --  The <b>Role_Controller</b> implements a simple role based permissions check.
   --  The permission is granted if the user has the role defined by the controller.
   type Role_Controller (Count : Positive) is limited new Controller with record
      Roles : Permissions.Role_Type_Array (1 .. Count);
   end record;
   type Role_Controller_Access is access all Role_Controller'Class;

   --  Returns true if the user associated with the security context <b>Context</b> has
   --  one of the role defined in the <b>Handler</b>.
   function Has_Permission (Handler : in Role_Controller;
                            Context : in Security.Contexts.Security_Context'Class)
                            return Boolean;

   type Controller_Config is record
      Name    : Util.Beans.Objects.Object;
      Roles   : Permissions.Role_Type_Array (1 .. Integer (Permissions.Role_Type'Last));
      Count   : Natural := 0;
      Manager : Security.Permissions.Permission_Manager_Access;
   end record;

   --  Setup the XML parser to read the <b>role-permission</b> description.  For example:
   --
   --  <security-role>
   --    <role-name>admin</role-name>
   --  </security-role>
   --  <role-permission>
   --     <name>create-workspace</name>
   --     <role>admin</role>
   --     <role>manager</role>
   --  </role-permission>
   --
   --  This defines a permission <b>create-workspace</b> that will be granted if the
   --  user has either the <b>admin</b> or the <b>manager</b> role.
   generic
      Reader  : in out Util.Serialize.IO.XML.Parser;
      Manager : in Security.Permissions.Permission_Manager_Access;
   package Reader_Config is
      Config : aliased Controller_Config;
   end Reader_Config;

end Security.Controllers.Roles;
