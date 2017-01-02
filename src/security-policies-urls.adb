-----------------------------------------------------------------------
--  security-policies-urls -- URL security policy
--  Copyright (C) 2010, 2011, 2012, 2016 Stephane Carrez
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

with Ada.Unchecked_Deallocation;

with Util.Beans.Objects;
with Util.Beans.Objects.Vectors;
with Util.Serialize.Mappers;
with Util.Serialize.Mappers.Record_Mapper;

with Security.Controllers.URLs;

package body Security.Policies.URLs is

   --  ------------------------------
   --  Get the policy name.
   --  ------------------------------
   overriding
   function Get_Name (From : in URL_Policy) return String is
      pragma Unreferenced (From);
   begin
      return NAME;
   end Get_Name;

   --  ------------------------------
   --  Returns True if the user has the permission to access the given URI permission.
   --  ------------------------------
   function Has_Permission (Manager    : in URL_Policy;
                            Context    : in Contexts.Security_Context'Class;
                            Permission : in URL_Permission'Class) return Boolean is
      Name  : constant String_Ref := To_String_Ref (Permission.URL);
      Ref   : constant Rules_Ref.Ref := Manager.Cache.Get;
      Rules : constant Rules_Access := Ref.Value;
      Pos   : constant Rules_Maps.Cursor := Rules.Map.Find (Name);
      Rule  : Access_Rule_Ref;
   begin
      --  If the rule is not in the cache, search for the access rule that
      --  matches our URI.  Update the cache.  This cache update is thread-safe
      --  as the cache map is never modified: a new cache map is installed.
      if not Rules_Maps.Has_Element (Pos) then
         declare
            New_Ref : constant Rules_Ref.Ref := Rules_Ref.Create;
         begin
            Rule := Manager.Find_Access_Rule (Permission.URL);
            New_Ref.Value.all.Map := Rules.Map;
            New_Ref.Value.all.Map.Insert (Name, Rule);
            Manager.Cache.Set (New_Ref);
         end;
      else
         Rule := Rules_Maps.Element (Pos);
      end if;

      --  Check if the user has one of the required permission.
      declare
         P       : constant Access_Rule_Access := Rule.Value;
      begin
         if P /= null then
            for I in P.Permissions'Range loop
               if Context.Has_Permission (P.Permissions (I)) then
                  return True;
               end if;
            end loop;
         end if;
      end;
      return False;
   end Has_Permission;

   --  Grant the permission to access to the given <b>URI</b> to users having the <b>To</b>
   --  permissions.
   procedure Grant_URI_Permission (Manager : in out URL_Policy;
                                   URI     : in String;
                                   To      : in String) is
   begin
      null;
   end Grant_URI_Permission;

   --  ------------------------------
   --  Policy Configuration
   --  ------------------------------

   --  ------------------------------
   --  Find the access rule of the policy that matches the given URI.
   --  Returns the No_Rule value (disable access) if no rule is found.
   --  ------------------------------
   function Find_Access_Rule (Manager : in URL_Policy;
                              URI     : in String) return Access_Rule_Ref is

      Matched : Boolean := False;
      Result  : Access_Rule_Ref;

      procedure Match (P : in Policy);

      procedure Match (P : in Policy) is
      begin
         if GNAT.Regexp.Match (URI, P.Pattern) then
            Matched := True;
            Result  := P.Rule;
         end if;
      end Match;

      Last : constant Natural := Manager.Policies.Last_Index;
   begin
      for I in 1 .. Last loop
         Manager.Policies.Query_Element (I, Match'Access);
         if Matched then
            return Result;
         end if;
      end loop;
      return Result;
   end Find_Access_Rule;

   --  ------------------------------
   --  Initialize the permission manager.
   --  ------------------------------
   overriding
   procedure Initialize (Manager : in out URL_Policy) is
   begin
      Manager.Cache := new Rules_Ref.Atomic_Ref;
      Manager.Cache.Set (Rules_Ref.Create);
   end Initialize;

   --  ------------------------------
   --  Finalize the permission manager.
   --  ------------------------------
   overriding
   procedure Finalize (Manager : in out URL_Policy) is

      procedure Free is
        new Ada.Unchecked_Deallocation (Rules_Ref.Atomic_Ref,
                                        Rules_Ref_Access);
   begin
      Free (Manager.Cache);
   end Finalize;

   type Policy_Fields is (FIELD_ID, FIELD_PERMISSION, FIELD_URL_PATTERN, FIELD_POLICY);

   procedure Set_Member (P     : in out URL_Policy'Class;
                         Field : in Policy_Fields;
                         Value : in Util.Beans.Objects.Object);

   procedure Process (Policy : in out URL_Policy'Class);

   procedure Set_Member (P     : in out URL_Policy'Class;
                         Field : in Policy_Fields;
                         Value : in Util.Beans.Objects.Object) is
   begin
      case Field is
         when FIELD_ID =>
            P.Id := Util.Beans.Objects.To_Integer (Value);

         when FIELD_PERMISSION =>
            P.Permissions.Append (Value);

         when FIELD_URL_PATTERN =>
            P.Patterns.Append (Value);

         when FIELD_POLICY =>
            Process (P);
            P.Id := 0;
            P.Permissions.Clear;
            P.Patterns.Clear;

      end case;
   end Set_Member;

   procedure Process (Policy : in out URL_Policy'Class) is
      Pol    : Security.Policies.URLs.Policy;
      Count  : constant Natural := Natural (Policy.Permissions.Length);
      Rule   : constant Access_Rule_Ref := Access_Rule_Refs.Create (new Access_Rule (Count));
      Iter   : Util.Beans.Objects.Vectors.Cursor := Policy.Permissions.First;
      Pos    : Positive := 1;
   begin
      Pol.Rule := Rule;

      --  Step 1: Initialize the list of permission index in Access_Rule from the permission names.
      while Util.Beans.Objects.Vectors.Has_Element (Iter) loop
         declare
            Perm : constant Util.Beans.Objects.Object := Util.Beans.Objects.Vectors.Element (Iter);
            Name : constant String := Util.Beans.Objects.To_String (Perm);
         begin
            Rule.Value.all.Permissions (Pos) := Permissions.Get_Permission_Index (Name);
            Pos := Pos + 1;

         exception
            when Invalid_Name =>
               raise Util.Serialize.Mappers.Field_Error with "Invalid permission: " & Name;
         end;
         Util.Beans.Objects.Vectors.Next (Iter);
      end loop;

      --  Step 2: Create one policy for each URL pattern
      Iter := Policy.Patterns.First;
      while Util.Beans.Objects.Vectors.Has_Element (Iter) loop
         declare
            Pattern : constant Util.Beans.Objects.Object
              := Util.Beans.Objects.Vectors.Element (Iter);
         begin
            Pol.Id   := Policy.Id;
            Pol.Pattern := GNAT.Regexp.Compile (Util.Beans.Objects.To_String (Pattern));
            Policy.Policies.Append (Pol);
         end;
         Util.Beans.Objects.Vectors.Next (Iter);
      end loop;
   end Process;

   package Policy_Mapper is
     new Util.Serialize.Mappers.Record_Mapper (Element_Type        => URL_Policy'Class,
                                               Element_Type_Access => URL_Policy_Access,
                                               Fields              => Policy_Fields,
                                               Set_Member          => Set_Member);

   Policy_Mapping        : aliased Policy_Mapper.Mapper;

   --  ------------------------------
   --  Setup the XML parser to read the <b>policy</b> description.
   --  ------------------------------
   overriding
   procedure Prepare_Config (Policy : in out URL_Policy;
                             Reader : in out Util.Serialize.IO.XML.Parser) is
      Perm : Security.Controllers.URLs.URL_Controller_Access;
   begin
      Reader.Add_Mapping ("policy-rules", Policy_Mapping'Access);
      Reader.Add_Mapping ("module", Policy_Mapping'Access);
      Policy_Mapper.Set_Context (Reader, Policy'Unchecked_Access);
      if not Policy.Manager.Has_Controller (P_URL.Permission) then
         Perm := new Security.Controllers.URLs.URL_Controller;
         Perm.Manager := Policy'Unchecked_Access;
         Policy.Manager.Add_Permission (Name       => "url",
                                        Permission => Perm.all'Access);
      end if;
   end Prepare_Config;

   --  ------------------------------
   --  Get the URL policy associated with the given policy manager.
   --  Returns the URL policy instance or null if it was not registered in the policy manager.
   --  ------------------------------
   function Get_URL_Policy (Manager : in Security.Policies.Policy_Manager'Class)
                            return URL_Policy_Access is
      Policy : constant Security.Policies.Policy_Access := Manager.Get_Policy (NAME);
   begin
      if Policy = null or else not (Policy.all in URL_Policy'Class) then
         return null;
      else
         return URL_Policy'Class (Policy.all)'Access;
      end if;
   end Get_URL_Policy;

begin
   Policy_Mapping.Add_Mapping ("url-policy", FIELD_POLICY);
   Policy_Mapping.Add_Mapping ("url-policy/@id", FIELD_ID);
   Policy_Mapping.Add_Mapping ("url-policy/permission", FIELD_PERMISSION);
   Policy_Mapping.Add_Mapping ("url-policy/url-pattern", FIELD_URL_PATTERN);
end Security.Policies.URLs;
