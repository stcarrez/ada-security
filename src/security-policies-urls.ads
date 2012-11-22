-----------------------------------------------------------------------
--  security-policies-urls -- URL security policy
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

with Ada.Containers.Hashed_Maps;
with Ada.Containers.Vectors;

with Util.Refs;
with Util.Strings;
with Util.Serialize.IO.XML;

with GNAT.Regexp;

package Security.Policies.Urls is

   NAME : constant String := "URL-Policy";

   --  ------------------------------
   --  URI Permission
   --  ------------------------------
   --  Represents a permission to access a given URI.
   type URI_Permission (Len : Natural) is new Permissions.Permission with record
      URI : String (1 .. Len);
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
                            Context    : in Security_Context_Access;
                            Permission : in URI_Permission'Class) return Boolean;

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
                             Reader : in out Util.Serialize.IO.XML.Parser);

   --  Finish reading the XML policy configuration.  The security policy implementation can use
   --  this procedure to perform any configuration setup after the configuration is parsed.
   overriding
   procedure Finish_Config (Into    : in out URL_Policy;
                            Reader  : in out Util.Serialize.IO.XML.Parser);

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
   end record;

end Security.Policies.Urls;
