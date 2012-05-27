-----------------------------------------------------------------------
--  security-permissions -- Definition of permissions
--  Copyright (C) 2010, 2011 Stephane Carrez
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
with Ada.Containers.Indefinite_Hashed_Maps;
with Ada.Strings.Hash;

with Util.Log.Loggers;
with Util.Serialize.Mappers.Record_Mapper;

with Security.Contexts;
with Security.Controllers;
with Security.Controllers.Roles;

--  The <b>Security.Permissions</b> package defines the different permissions that can be
--  checked by the access control manager.
package body Security.Permissions is

   use Util.Log;

   --  ------------------------------
   --  Permission Manager
   --  ------------------------------

   --  The logger
   Log : constant Loggers.Logger := Loggers.Create ("Security.Permissions");

   --  A global map to translate a string to a permission index.
   package Permission_Maps is
     new Ada.Containers.Indefinite_Hashed_Maps (Key_Type        => String,
                                                Element_Type    => Permission_Index,
                                                Hash            => Ada.Strings.Hash,
                                                Equivalent_Keys => "=",
                                                "="             => "=");

   protected type Global_Index is
      --  Get the permission index
      function Get_Permission_Index (Name : in String) return Permission_Index;

      --  Get the last permission index registered in the global permission map.
      function Get_Last_Permission_Index return Permission_Index;

      procedure Add_Permission (Name  : in String;
                                Index : out Permission_Index);
   private
      Map        : Permission_Maps.Map;
      Next_Index : Permission_Index := Permission_Index'First;
   end Global_Index;

   protected body Global_Index is
      function Get_Permission_Index (Name : in String) return Permission_Index is
         Pos : constant Permission_Maps.Cursor := Map.Find (Name);
      begin
         if Permission_Maps.Has_Element (Pos) then
            return Permission_Maps.Element (Pos);
         else
            raise Invalid_Name with "There is no permission '" & Name & "'";
         end if;
      end Get_Permission_Index;

      --  Get the last permission index registered in the global permission map.
      function Get_Last_Permission_Index return Permission_Index is
      begin
         return Next_Index;
      end Get_Last_Permission_Index;

      procedure Add_Permission (Name  : in String;
                                Index : out Permission_Index) is
         Pos : constant Permission_Maps.Cursor := Map.Find (Name);
      begin
         if Permission_Maps.Has_Element (Pos) then
            Index := Permission_Maps.Element (Pos);
         else
            Index := Next_Index;
            Log.Debug ("Creating permission index {1} for {0}",
                       Name, Permission_Index'Image (Index));
            Map.Insert (Name, Index);
            Next_Index := Next_Index + 1;
         end if;
      end Add_Permission;

   end Global_Index;

   Permission_Indexes : Global_Index;

   --  ------------------------------
   --  Get the permission index associated with the name.
   --  ------------------------------
   function Get_Permission_Index (Name : in String) return Permission_Index is
   begin
      return Permission_Indexes.Get_Permission_Index (Name);
   end Get_Permission_Index;

   --  ------------------------------
   --  Get the last permission index registered in the global permission map.
   --  ------------------------------
   function Get_Last_Permission_Index return Permission_Index is
   begin
      return Permission_Indexes.Get_Last_Permission_Index;
   end Get_Last_Permission_Index;

   --  ------------------------------
   --  Add the permission name and allocate a unique permission index.
   --  ------------------------------
   procedure Add_Permission (Name  : in String;
                             Index : out Permission_Index) is
   begin
      Permission_Indexes.Add_Permission (Name, Index);
   end Add_Permission;

   --  ------------------------------
   --  Find the access rule of the policy that matches the given URI.
   --  Returns the No_Rule value (disable access) if no rule is found.
   --  ------------------------------
   function Find_Access_Rule (Manager : in Permission_Manager;
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

   procedure Add_Permission (Manager    : in out Permission_Manager;
                             Name       : in String;
                             Permission : in Controller_Access) is
      Index : Permission_Index;
   begin
      Log.Info ("Adding permission {0}", Name);

      Add_Permission (Name, Index);
      if Index >= Manager.Last_Index then
         declare
            Count : constant Permission_Index := Index + 32;
            Perms : constant Controller_Access_Array_Access
              := new Controller_Access_Array (0 .. Count);
         begin
            if Manager.Permissions /= null then
               Perms (Manager.Permissions'Range) := Manager.Permissions.all;
            end if;
            Manager.Permissions := Perms;
            Manager.Last_Index := Count;
         end;
      end if;
      Manager.Permissions (Index) := Permission;
   end Add_Permission;

   --  ------------------------------
   --  Returns True if the user has the permission to access the given URI permission.
   --  ------------------------------
   function Has_Permission (Manager    : in Permission_Manager;
                            Context    : in Security_Context_Access;
                            Permission : in URI_Permission'Class) return Boolean is
      Name  : constant String_Ref := To_String_Ref (Permission.URI);
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
            Rule := Manager.Find_Access_Rule (Permission.URI);
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
         Granted : Boolean;
      begin
         if P /= null then
            for I in P.Permissions'Range loop
               Context.Has_Permission (P.Permissions (I), Granted);
               if Granted then
                  return True;
               end if;
            end loop;
         end if;
      end;
      return False;
   end Has_Permission;

   --  ------------------------------
   --  Returns True if the user has the given role permission.
   --  ------------------------------
   function Has_Permission (Manager    : in Permission_Manager;
                            User       : in Principal'Class;
                            Permission : in Permission_Type) return Boolean is
      pragma Unreferenced (Manager);
   begin
      --        return User.Has_Permission (Permission);
      return False;
   end Has_Permission;

   --  ------------------------------
   --  Get the security controller associated with the permission index <b>Index</b>.
   --  Returns null if there is no such controller.
   --  ------------------------------
   function Get_Controller (Manager : in Permission_Manager'Class;
                            Index   : in Permission_Index) return Controller_Access is
   begin
      if Index >= Manager.Last_Index then
         return null;
      else
         return Manager.Permissions (Index);
      end if;
   end Get_Controller;

   --  ------------------------------
   --  Get the role name.
   --  ------------------------------
   function Get_Role_Name (Manager : in Permission_Manager;
                           Role    : in Role_Type) return String is
      use type Ada.Strings.Unbounded.String_Access;
   begin
      if Manager.Names (Role) = null then
         return "";
      else
         return Manager.Names (Role).all;
      end if;
   end Get_Role_Name;

   --  ------------------------------
   --  Find the role type associated with the role name identified by <b>Name</b>.
   --  Raises <b>Invalid_Name</b> if there is no role type.
   --  ------------------------------
   function Find_Role (Manager : in Permission_Manager;
                       Name    : in String) return Role_Type is
      use type Ada.Strings.Unbounded.String_Access;
   begin
      Log.Debug ("Searching role {0}", Name);

      for I in Role_Type'First .. Manager.Next_Role loop
         exit when Manager.Names (I) = null;
         if Name = Manager.Names (I).all then
            return I;
         end if;
      end loop;

      Log.Debug ("Role {0} not found", Name);
      raise Invalid_Name;
   end Find_Role;

   --  ------------------------------
   --  Create a role
   --  ------------------------------
   procedure Create_Role (Manager : in out Permission_Manager;
                          Name    : in String;
                          Role    : out Role_Type) is
   begin
      Role := Manager.Next_Role;
      Log.Info ("Role {0} is {1}", Name, Role_Type'Image (Role));

      if Manager.Next_Role = Role_Type'Last then
         Log.Error ("Too many roles allocated.  Number of roles is {0}",
                    Role_Type'Image (Role_Type'Last));
      else
         Manager.Next_Role := Manager.Next_Role + 1;
      end if;
      Manager.Names (Role) := new String '(Name);
   end Create_Role;

   --  Grant the permission to access to the given <b>URI</b> to users having the <b>To</b>
   --  permissions.
   procedure Grant_URI_Permission (Manager : in out Permission_Manager;
                                   URI     : in String;
                                   To      : in String) is
   begin
      null;
   end Grant_URI_Permission;

   --  Grant the permission to access to the given <b>Path</b> to users having the <b>To</b>
   --  permissions.
   procedure Grant_File_Permission (Manager : in out Permission_Manager;
                                    Path    : in String;
                                    To      : in String) is
   begin
      null;
   end Grant_File_Permission;

   --  ------------------------------
   --  Get or build a permission type for the given name.
   --  ------------------------------
   procedure Add_Role_Type (Manager   : in out Permission_Manager;
                            Name      : in String;
                            Result    : out Role_Type) is
   begin
      Result := Manager.Find_Role (Name);

   exception
      when Invalid_Name =>
         Manager.Create_Role (Name, Result);
   end Add_Role_Type;

   type Policy_Fields is (FIELD_ID, FIELD_PERMISSION, FIELD_URL_PATTERN, FIELD_POLICY);

   procedure Set_Member (P     : in out Policy_Config;
                         Field : in Policy_Fields;
                         Value : in Util.Beans.Objects.Object);

   procedure Process (Policy : in Policy_Config);

   procedure Set_Member (P     : in out Policy_Config;
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

   procedure Process (Policy : in Policy_Config) is
      Pol    : Security.Permissions.Policy;
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
            Rule.Value.all.Permissions (Pos) := Get_Permission_Index (Name);
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
            Policy.Manager.Policies.Append (Pol);
         end;
         Util.Beans.Objects.Vectors.Next (Iter);
      end loop;
   end Process;

   package Policy_Mapper is
     new Util.Serialize.Mappers.Record_Mapper (Element_Type        => Policy_Config,
                                               Element_Type_Access => Policy_Config_Access,
                                               Fields              => Policy_Fields,
                                               Set_Member          => Set_Member);

   Policy_Mapping        : aliased Policy_Mapper.Mapper;

   --  ------------------------------
   --  Setup the XML parser to read the servlet and mapping rules <b>context-param</b>,
   --  <b>filter-mapping</b> and <b>servlet-mapping</b>.
   --  ------------------------------
   package body Reader_Config is
   begin
      Reader.Add_Mapping ("policy-rules", Policy_Mapping'Access);
      Reader.Add_Mapping ("module", Policy_Mapping'Access);
      Config.Manager := Manager;
      Policy_Mapper.Set_Context (Reader, Config'Unchecked_Access);
   end Reader_Config;

   --  ------------------------------
   --  Read the policy file
   --  ------------------------------
   procedure Read_Policy (Manager : in out Permission_Manager;
                          File    : in String) is

      use Util;

      Reader : Util.Serialize.IO.XML.Parser;

      package Policy_Config is
        new Reader_Config (Reader, Manager'Unchecked_Access);
      package Role_Config is
        new Security.Controllers.Roles.Reader_Config (Reader, Manager'Unchecked_Access);
      pragma Warnings (Off, Policy_Config);
      pragma Warnings (Off, Role_Config);
   begin
      Log.Info ("Reading policy file {0}", File);

      Reader.Parse (File);

   end Read_Policy;

   --  ------------------------------
   --  Initialize the permission manager.
   --  ------------------------------
   overriding
   procedure Initialize (Manager : in out Permission_Manager) is
   begin
      Manager.Cache := new Rules_Ref.Atomic_Ref;
      Manager.Cache.Set (Rules_Ref.Create);
   end Initialize;

   --  ------------------------------
   --  Finalize the permission manager.
   --  ------------------------------
   overriding
   procedure Finalize (Manager : in out Permission_Manager) is
      use Ada.Strings.Unbounded;
      use Security.Controllers;

      procedure Free is
        new Ada.Unchecked_Deallocation (Rules_Ref.Atomic_Ref,
                                        Rules_Ref_Access);
      procedure Free is
        new Ada.Unchecked_Deallocation (Security.Controllers.Controller'Class,
                                        Security.Controllers.Controller_Access);
      procedure Free is
        new Ada.Unchecked_Deallocation (Controller_Access_Array,
                                        Controller_Access_Array_Access);

   begin
      Free (Manager.Cache);
      for I in Manager.Names'Range loop
         exit when Manager.Names (I) = null;
         Ada.Strings.Unbounded.Free (Manager.Names (I));
      end loop;

      if Manager.Permissions /= null then
         for I in Manager.Permissions.all'Range loop
            exit when Manager.Permissions (I) = null;

            --  SCz 2011-12-03: GNAT 2011 reports a compilation error:
            --  'missing "with" clause on package "Security.Controllers"'
            --  if we use the 'Security.Controller_Access' type, even if this "with" clause exist.
            --  gcc 4.4.3 under Ubuntu does not have this issue.
            --  We use the 'Security.Controllers.Controller_Access' type to avoid the compiler bug
            --  but we have to use a temporary variable and do some type conversion...
            declare
               P : Security.Controllers.Controller_Access := Manager.Permissions (I).all'Access;
            begin
               Free (P);
               Manager.Permissions (I) := null;
            end;
         end loop;
         Free (Manager.Permissions);
      end if;
   end Finalize;

   package body Permission_ACL is
      P : Permission_Index;

      function Permission return Permission_Index is
      begin
         return P;
      end Permission;

   begin
      Add_Permission (Name => Name, Index => P);
   end Permission_ACL;

   --  ------------------------------
   --  EL function to check if the given permission name is granted by the current
   --  security context.
   --  ------------------------------
   function Has_Permission (Value : in Util.Beans.Objects.Object)
                            return Util.Beans.Objects.Object is
      Name   : constant String := Util.Beans.Objects.To_String (Value);
   begin
      if Security.Contexts.Has_Permission (Name) then
         return Util.Beans.Objects.To_Object (True);
      else
         return Util.Beans.Objects.To_Object (False);
      end if;
   end Has_Permission;

   --  ------------------------------
   --  Register a set of functions in the namespace
   --  xmlns:fn="http://code.google.com/p/ada-asf/auth"
   --  Functions:
   --    hasPermission(NAME)   --  Returns True if the permission NAME is granted
   --  ------------------------------
--   procedure Set_Functions (Mapper : in out EL.Functions.Function_Mapper'Class) is
--   begin
--      Mapper.Set_Function (Name      => HAS_PERMISSION_FN,
--                           Namespace => AUTH_NAMESPACE_URI,
--                           Func      => Has_Permission'Access);
--   end Set_Functions;

begin
   Policy_Mapping.Add_Mapping ("policy", FIELD_POLICY);
   Policy_Mapping.Add_Mapping ("policy/@id", FIELD_ID);
   Policy_Mapping.Add_Mapping ("policy/permission", FIELD_PERMISSION);
   Policy_Mapping.Add_Mapping ("policy/url-pattern", FIELD_URL_PATTERN);
end Security.Permissions;
