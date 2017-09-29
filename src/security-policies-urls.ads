-----------------------------------------------------------------------
--  security-policies-urls -- URL security policy
--  Copyright (C) 2010, 2011, 2012, 2017 Stephane Carrez
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

with Ada.Containers.Hashed_Maps;
with Ada.Containers.Vectors;

with Util.Refs;
with Util.Strings;
with Util.Serialize.Mappers;

with GNAT.Regexp;

with Security.Contexts;

--  == URL Security Policy ==
--  The <tt>Security.Policies.Urls</tt> implements a security policy intended to be used
--  in web servers.  It allows to protect an URL by defining permissions that must be granted
--  for a user to get access to the URL.  A typical example is a web server that has a set of
--  administration pages, these pages should be accessed by users having some admin permission.
--
--  === Policy creation ===
--  An instance of the <tt>URL_Policy</tt> must be created and registered in the policy manager.
--  Get or declare the following variables:
--
--    Manager : Security.Policies.Policy_Manager;
--    Policy  : Security.Policies.Urls.URL_Policy_Access;
--
--  Create the URL policy and register it in the policy manager as follows:
--
--    Policy := new URL_Policy;
--    Manager.Add_Policy (Policy.all'Access);
--
--  === Policy Configuration ===
--  Once the URL policy is registered, the policy manager can read and process the following
--  XML configuration:
--
--    <policy-rules>
--      <url-policy id='1'>
--        <permission>create-workspace</permission>
--        <permission>admin</permission>
--        <url-pattern>/workspace/create</url-pattern>
--        <url-pattern>/workspace/setup/*</url-pattern>
--      </url-policy>
--      ...
--    </policy-rules>
--
--  This policy gives access to the URL that match one of the URL pattern if the
--  security context has the permission <b>create-workspace</b> or <b>admin</b>.
--  These two permissions are checked according to another security policy.
--  The XML configuration can define several <tt>url-policy</tt>.  They are checked in
--  the order defined in the XML.  In other words, the first <tt>url-policy</tt> that matches
--  the URL is used to verify the permission.
--
--  The <tt>url-policy</tt> definition can contain several <tt>permission</tt>.
--  The first permission that is granted gives access to the URL.
--
--  === Checking for permission ===
--  To check a URL permission, you must declare a <tt>URL_Permission</tt> object with the URL.
--
--     URL    : constant String := ...;
--     Perm   : constant Policies.URLs.URL_Permission (URL'Length)
--               := URL_Permission '(Len => URI'Length, URL => URL);
--
--  Then, we can check the permission:
--
--     Result : Boolean := Security.Contexts.Has_Permission (Perm);
--
package Security.Policies.URLs is

   NAME : constant String := "URL-Policy";

   package P_URL is new Security.Permissions.Definition ("url");

   --  ------------------------------
   --  URL Permission
   --  ------------------------------
   --  Represents a permission to access a given URL.
   type URL_Permission (Len : Natural) is new Permissions.Permission (P_URL.Permission) with record
      URL : String (1 .. Len);
   end record;

   --  ------------------------------
   --  URL policy
   --  ------------------------------
   type URL_Policy is new Policy with private;
   type URL_Policy_Access is access all URL_Policy'Class;

   Invalid_Name : exception;

   --  Get the policy name.
   overriding
   function Get_Name (From : in URL_Policy) return String;

   --  Returns True if the user has the permission to access the given URI permission.
   function Has_Permission (Manager    : in URL_Policy;
                            Context    : in Contexts.Security_Context'Class;
                            Permission : in URL_Permission'Class) return Boolean;

   --  Grant the permission to access to the given <b>URI</b> to users having the <b>To</b>
   --  permissions.
   procedure Grant_URI_Permission (Manager : in out URL_Policy;
                                   URI     : in String;
                                   To      : in String);

   --  Initialize the permission manager.
   overriding
   procedure Initialize (Manager : in out URL_Policy);

   --  Finalize the permission manager.
   overriding
   procedure Finalize (Manager : in out URL_Policy);

   --  Setup the XML parser to read the <b>policy</b> description.
   overriding
   procedure Prepare_Config (Policy : in out URL_Policy;
                             Mapper : in out Util.Serialize.Mappers.Processing);

   --  Get the URL policy associated with the given policy manager.
   --  Returns the URL policy instance or null if it was not registered in the policy manager.
   function Get_URL_Policy (Manager : in Security.Policies.Policy_Manager'Class)
                            return URL_Policy_Access;

private

   use Util.Strings;

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

   --  Find the access rule of the policy that matches the given URI.
   --  Returns the No_Rule value (disable access) if no rule is found.
   function Find_Access_Rule (Manager : in URL_Policy;
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

   type URL_Policy is new Security.Policies.Policy with record
      Cache        : Rules_Ref_Access;
      Policies     : Policy_Vector.Vector;
      Id           : Natural := 0;
      Permissions  : Util.Beans.Objects.Vectors.Vector;
      Patterns     : Util.Beans.Objects.Vectors.Vector;
   end record;

end Security.Policies.URLs;
