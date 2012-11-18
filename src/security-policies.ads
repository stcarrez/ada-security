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
with Ada.Strings.Unbounded;

with Ada.Containers.Hashed_Maps;
with Ada.Containers.Vectors;

with Util.Strings;
with Util.Refs;
with Util.Beans.Objects;
with Util.Beans.Objects.Vectors;
with Util.Serialize.IO.XML;

with GNAT.Regexp;

limited with Security.Controllers;
limited with Security.Contexts;

--  == Permissions ==
--  The <b>Security.Permissions</b> package defines the different permissions that can be
--  checked by the access control manager.
--
--  === Principal ===
--  The <tt>Principal</tt> is the entity that can be authenticated.  A principal is obtained
--  after successful authentication of a user or of a system through an authorization process.
--  The OpenID or OAuth authentication processes generate such security principal.
--
--  === Permission ===
--  The <tt>Permission</tt> represents an access to a system or application resource.
--  A permission is checked by using the security manager.  The security manager uses a
--  security controller to enforce the permission.
--
package Security.Policies is

   type Policy is new Ada.Finalization.Limited_Controlled with null record;
   type Policy_Access is access all Policy'Class;

   procedure Set_Reader_Config (Pol     : in Policy;
                                Reader  : in out Util.Serialize.IO.XML.Parser) is null;

   --  Get the policy name.
   function Get_Name (From : in Policy) return String;;

   Invalid_Name : exception;

   type Security_Context_Access is access all Contexts.Security_Context'Class;

   type Controller_Access is access all Security.Controllers.Controller'Class;

   type Controller_Access_Array is array (Permission_Index range <>) of Controller_Access;

   --  Each permission is represented by a <b>Permission_Type</b> number to provide a fast
   --  and efficient permission check.
   type Permission_Type is new Natural range 0 .. 63;

   --  The <b>Permission_Map</b> represents a set of permissions which are granted to a user.
   --  Each permission is represented by a boolean in the map.  The implementation is limited
   --  to 64 permissions.
   type Permission_Map is array (Permission_Type'Range) of Boolean;
   pragma Pack (Permission_Map);

   --  ------------------------------
   --  Permission Manager
   --  ------------------------------
   --  The <b>Permission_Manager</b> verifies through some policy that a permission
   --  is granted to a user.
   type Policy_Manager is new Ada.Finalization.Limited_Controlled with private;
   type Policy_Manager_Access is access all Policy_Manager'Class;

   --  Add the policy to the policy manager.  After a policy is added in the manager,
   --  it can participate in the security policy.
   procedure Add_Policy (Manager : in out Policy_Manager;
                         Policy  : in Policy_Access);

   procedure Add_Permission (Manager    : in out Policy_Manager;
                             Name       : in String;
                             Permission : in Controller_Access);

   --  Returns True if the user has the permission to access the given URI permission.
--     function Has_Permission (Manager    : in Policy_Manager;
--                              Context    : in Security_Context_Access;
--                              Permission : in URI_Permission'Class) return Boolean;

   --  Returns True if the user has the given role permission.
--     function Has_Permission (Manager    : in Permission_Manager;
--                              User       : in Principal'Class;
--                              Permission : in Permission_Type) return Boolean;

   --  Get the security controller associated with the permission index <b>Index</b>.
   --  Returns null if there is no such controller.
   function Get_Controller (Manager : in Policy_Manager'Class;
                            Index   : in Permission_Index) return Controller_Access;
   pragma Inline_Always (Get_Controller);

   --  Grant the permission to access to the given <b>URI</b> to users having the <b>To</b>
   --  permissions.
--     procedure Grant_URI_Permission (Manager : in out Permission_Manager;
--                                     URI     : in String;
--                                     To      : in String);

   --  Grant the permission to access to the given <b>Path</b> to users having the <b>To</b>
   --  permissions.
--     procedure Grant_File_Permission (Manager : in out Permission_Manager;
--                                      Path    : in String;
--                                      To      : in String);

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

   use Util.Strings;

   type Permission_Type_Array is array (1 .. 10) of Permission_Type;

   type Permission_Index_Array is array (Positive range <>) of Permission_Index;

   --  The <b>Access_Rule</b> represents a list of permissions to verify to grant
   --  access to the resource.  To make it simple, the user must have one of the
   --  permission from the list.  Each permission will refer to a specific permission
   --  controller.
   type Access_Rule (Count : Natural) is new Util.Refs.Ref_Entity with record
      Permissions : Permission_Index_Array (1 .. Count);
   end record;
   type Access_Rule_Access is access all Access_Rule;

   package Access_Rule_Refs is
     new Util.Refs.Indefinite_References (Element_Type   => Access_Rule,
                                          Element_Access => Access_Rule_Access);
   subtype Access_Rule_Ref is Access_Rule_Refs.Ref;

   --  No rule
   --     No_Rule : constant Access_Rule := (Count => 0,
   --                                        Permissions => (others => Permission_Index'First));

   --  Find the access rule of the policy that matches the given URI.
   --  Returns the No_Rule value (disable access) if no rule is found.
   function Find_Access_Rule (Manager : in Permission_Manager;
                              URI     : in String) return Access_Rule_Ref;

   --  The <b>Policy</b> defines the access rules that are applied on a given
   --  URL, set of URLs or files.
   type Policy is record
      Id      : Natural;
      Pattern : GNAT.Regexp.Regexp;
      Rule    : Access_Rule_Ref;
   end record;

   --  The <b>Policy_Vector</b> represents the whole permission policy.  The order of
   --  policy in the list is important as policies can override each other.
   package Policy_Vector is new Ada.Containers.Vectors (Index_Type   => Positive,
                                                        Element_Type => Policy);

   package Rules_Maps is new Ada.Containers.Hashed_Maps (Key_Type        => String_Ref,
                                                         Element_Type    => Access_Rule_Ref,
                                                         Hash            => Hash,
                                                         Equivalent_Keys => Equivalent_Keys,
                                                         "="             => Access_Rule_Refs."=");

   type Rules is new Util.Refs.Ref_Entity with record
      Map : Rules_Maps.Map;
   end record;
   type Rules_Access is access all Rules;

   package Rules_Ref is new Util.Refs.References (Rules, Rules_Access);

   type Rules_Ref_Access is access Rules_Ref.Atomic_Ref;

   type Controller_Access_Array_Access is access all Controller_Access_Array;

   type Policy_Manager is new Ada.Finalization.Limited_Controlled with record
      Cache        : Rules_Ref_Access;
      Policies     : Policy_Vector.Vector;
      Permissions  : Controller_Access_Array_Access;
      Last_Index   : Permission_Index := Permission_Index'First;
   end record;

end Security.Policies;
