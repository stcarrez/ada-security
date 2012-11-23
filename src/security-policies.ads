-----------------------------------------------------------------------
--  security-policies -- Security Policies
--  Copyright (C) 2010, 2011, 2012 Stephane Carrez
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

with Ada.Finalization;

with Util.Beans.Objects;
with Util.Beans.Objects.Vectors;
with Util.Serialize.IO.XML;

with Security.Permissions;
limited with Security.Controllers;
limited with Security.Contexts;

package Security.Policies is

   type Security_Context_Access is access all Contexts.Security_Context'Class;

   type Controller_Access is access all Security.Controllers.Controller'Class;

   type Controller_Access_Array is
     array (Permissions.Permission_Index range <>) of Controller_Access;

   type Policy_Index is new Positive;

   type Policy_Context is limited interface;
   type Policy_Context_Access is access all Policy_Context'Class;

   type Policy_Context_Array is
     array (Policy_Index range <>) of Policy_Context_Access;
   type Policy_Context_Array_Access is access Policy_Context_Array;

   --  ------------------------------
   --  Security policy
   --  ------------------------------
   type Policy is new Ada.Finalization.Limited_Controlled with private;
   type Policy_Access is access all Policy'Class;

   --  Get the policy name.
   function Get_Name (From : in Policy) return String;

   --  Get the policy index.
   function Get_Policy_Index (From : in Policy'Class) return Policy_Index;
   pragma Inline (Get_Policy_Index);

   --  Prepare the XML parser to read the policy configuration.
   procedure Prepare_Config (Pol     : in out Policy;
                             Reader  : in out Util.Serialize.IO.XML.Parser) is null;

   --  Finish reading the XML policy configuration.  The security policy implementation can use
   --  this procedure to perform any configuration setup after the configuration is parsed.
   procedure Finish_Config (Into    : in out Policy;
                            Reader  : in out Util.Serialize.IO.XML.Parser) is null;

   --  Add a permission under the given permission name and associated with the controller.
   --  To verify the permission, the controller will be called.
   procedure Add_Permission (Manager    : in out Policy;
                             Name       : in String;
                             Permission : in Controller_Access);

   Invalid_Name : exception;

   Policy_Error : exception;

   --  ------------------------------
   --  Permission Manager
   --  ------------------------------
   --  The <b>Permission_Manager</b> verifies through some policy that a permission
   --  is granted to a user.
   type Policy_Manager (Max_Policies : Policy_Index) is
     new Ada.Finalization.Limited_Controlled with private;
   type Policy_Manager_Access is access all Policy_Manager'Class;

   --  Get the policy with the name <b>Name</b> registered in the policy manager.
   --  Returns null if there is no such policy.
   function Get_Policy (Manager : in Policy_Manager;
                        Name    : in String) return Policy_Access;

   --  Add the policy to the policy manager.  After a policy is added in the manager,
   --  it can participate in the security policy.
   --  Raises Policy_Error if the policy table is full.
   procedure Add_Policy (Manager : in out Policy_Manager;
                         Policy  : in Policy_Access);

   --  Add a permission under the given permission name and associated with the controller.
   --  To verify the permission, the controller will be called.
   procedure Add_Permission (Manager    : in out Policy_Manager;
                             Name       : in String;
                             Permission : in Controller_Access);

   --  Create the policy contexts to be associated with the security context.
   function Create_Policy_Contexts (Manager : in Policy_Manager)
                                    return Policy_Context_Array_Access;

   --  Get the security controller associated with the permission index <b>Index</b>.
   --  Returns null if there is no such controller.
   function Get_Controller (Manager : in Policy_Manager'Class;
                            Index   : in Permissions.Permission_Index) return Controller_Access;
   pragma Inline_Always (Get_Controller);

   --  Read the policy file
   procedure Read_Policy (Manager : in out Policy_Manager;
                          File    : in String);

   --  Initialize the permission manager.
   overriding
   procedure Initialize (Manager : in out Policy_Manager);

   --  Finalize the permission manager.
   overriding
   procedure Finalize (Manager : in out Policy_Manager);

   --  ------------------------------
   --  Policy Configuration
   --  ------------------------------
   type Policy_Config is record
      Id          : Natural := 0;
      Permissions : Util.Beans.Objects.Vectors.Vector;
      Patterns    : Util.Beans.Objects.Vectors.Vector;
      Manager     : Policy_Manager_Access;
   end record;
   type Policy_Config_Access is access all Policy_Config;

   --  Setup the XML parser to read the <b>policy</b> description.  For example:
   --
   --  <policy id='1'>
   --     <permission>create-workspace</permission>
   --     <permission>admin</permission>
   --     <url-pattern>/workspace/create</url-pattern>
   --     <url-pattern>/workspace/setup/*</url-pattern>
   --  </policy>
   --
   --  This policy gives access to the URL that match one of the URL pattern if the
   --  security context has the permission <b>create-workspace</b> or <b>admin</b>.
   generic
      Reader  : in out Util.Serialize.IO.XML.Parser;
      Manager : in Policy_Manager_Access;
   package Reader_Config is
      Config : aliased Policy_Config;
   end Reader_Config;

private

   subtype Permission_Index is Permissions.Permission_Index;

   type Permission_Index_Array is array (Positive range <>) of Permissions.Permission_Index;

   type Controller_Access_Array_Access is access all Controller_Access_Array;

   type Policy_Access_Array is array (Policy_Index range <>) of Policy_Access;

   type Policy is new Ada.Finalization.Limited_Controlled with record
      Manager : Policy_Manager_Access;
      Index   : Policy_Index;
   end record;

   type Policy_Manager (Max_Policies : Policy_Index) is
     new Ada.Finalization.Limited_Controlled with record
      Permissions  : Controller_Access_Array_Access;
      Last_Index   : Permission_Index := Permission_Index'First;

      --  The security policies.
      Policies     : Policy_Access_Array (1 .. Max_Policies);
   end record;

end Security.Policies;
