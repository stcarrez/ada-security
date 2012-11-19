-----------------------------------------------------------------------
--  security-contexts -- Context to provide security information and verify permissions
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

with Ada.Task_Attributes;

with Security.Controllers;
package body Security.Contexts is

   package Task_Context is new Ada.Task_Attributes
     (Security_Context_Access, null);

   --  ------------------------------
   --  Get the application associated with the current service operation.
   --  ------------------------------
   function Get_User_Principal (Context : in Security_Context'Class)
                                return Security.Principal_Access is
   begin
      return Context.Principal;
   end Get_User_Principal;

   --  ------------------------------
   --  Get the permission manager.
   --  ------------------------------
   function Get_Permission_Manager (Context : in Security_Context'Class)
                                    return Security.Permissions.Permission_Manager_Access is
   begin
      return Context.Manager;
   end Get_Permission_Manager;

   --  ------------------------------
   --  Check if the permission identified by <b>Permission</b> is allowed according to
   --  the current security context.  The result is cached in the security context and
   --  returned in <b>Result</b>.
   --  ------------------------------
   procedure Has_Permission (Context    : in out Security_Context;
                             Permission : in Security.Permissions.Permission_Index;
                             Result     : out Boolean) is
      use type Security.Permissions.Controller_Access;
      use type Security.Permissions.Permission_Manager_Access;
   begin
      if Context.Manager = null then
         Result := False;
         return;
      end if;
      declare
         C : constant Permissions.Controller_Access := Context.Manager.Get_Controller (Permission);
      begin
         if C = null then
            Result := False;
         else
            --              Result := C.Has_Permission (Context);
            Result := False;
         end if;
      end;
   end Has_Permission;

   --  ------------------------------
   --  Check if the permission identified by <b>Permission</b> is allowed according to
   --  the current security context.  The result is cached in the security context and
   --  returned in <b>Result</b>.
   --  ------------------------------
   procedure Has_Permission (Context    : in out Security_Context;
                             Permission : in String;
                             Result     : out Boolean) is
      Index : constant Permissions.Permission_Index
        := Permissions.Get_Permission_Index (Permission);
   begin
      Security_Context'Class (Context).Has_Permission (Index, Result);
   end Has_Permission;

   --  ------------------------------
   --  Initializes the service context.  By creating the <b>Security_Context</b> variable,
   --  the instance will be associated with the current task attribute.  If the current task
   --  already has a security context, the new security context is installed, the old one
   --  being kept.
   --  ------------------------------
   overriding
   procedure Initialize (Context : in out Security_Context) is
   begin
      Context.Previous := Task_Context.Value;
      Task_Context.Set_Value (Context'Unchecked_Access);
   end Initialize;

   --  ------------------------------
   --  Finalize the security context releases any object.  The previous security context is
   --  restored to the current task attribute.
   --  ------------------------------
   overriding
   procedure Finalize (Context : in out Security_Context) is
   begin
      Task_Context.Set_Value (Context.Previous);
   end Finalize;

   --  ------------------------------
   --  Add a context information represented by <b>Value</b> under the name identified by
   --  <b>Name</b> in the security context <b>Context</b>.
   --  ------------------------------
   procedure Add_Context (Context   : in out Security_Context;
                          Name      : in String;
                          Value     : in String) is
   begin
      Context.Context.Include (Key      => Name,
                               New_Item => Value);
   end Add_Context;

   --  ------------------------------
   --  Get the context information registered under the name <b>Name</b> in the security
   --  context <b>Context</b>.
   --  Raises <b>Invalid_Context</b> if there is no such information.
   --  ------------------------------
   function Get_Context (Context  : in Security_Context;
                         Name     : in String) return String is
      Pos : constant Util.Strings.Maps.Cursor := Context.Context.Find (Name);
   begin
      if Util.Strings.Maps.Has_Element (Pos) then
         return Util.Strings.Maps.Element (Pos);
      else
         raise Invalid_Context;
      end if;
   end Get_Context;

   --  ------------------------------
   --  Returns True if a context information was registered under the name <b>Name</b>.
   --  ------------------------------
   function Has_Context (Context : in Security_Context;
                         Name    : in String) return Boolean is
      use type Util.Strings.Maps.Cursor;
   begin
      return Context.Context.Find (Name) /= Util.Strings.Maps.No_Element;
   end Has_Context;

   --  ------------------------------
   --  Set the current application and user context.
   --  ------------------------------
   procedure Set_Context (Context   : in out Security_Context;
                          Manager   : in Security.Permissions.Permission_Manager_Access;
                          Principal : in Security.Principal_Access) is
   begin
      Context.Manager   := Manager;
      Context.Principal := Principal;
   end Set_Context;

   --  ------------------------------
   --  Get the current security context.
   --  Returns null if the current thread is not associated with any security context.
   --  ------------------------------
   function Current return Security_Context_Access is
   begin
      return Task_Context.Value;
   end Current;

   --  ------------------------------
   --  Check if the permission identified by <b>Permission</b> is allowed according to
   --  the current security context.  The result is cached in the security context and
   --  returned in <b>Result</b>.
   --  ------------------------------
   function Has_Permission (Permission : in Permissions.Permission_Index) return Boolean is
      Result  : Boolean;
      Context : constant Security_Context_Access := Current;
   begin
      if Context = null then
         return False;
      else
         Context.Has_Permission (Permission, Result);
         return Result;
      end if;
   end Has_Permission;

   --  ------------------------------
   --  Check if the permission identified by <b>Permission</b> is allowed according to
   --  the current security context.  The result is cached in the security context and
   --  returned in <b>Result</b>.
   --  ------------------------------
   function Has_Permission (Permission : in String) return Boolean is
      Result  : Boolean;
      Context : constant Security_Context_Access := Current;
   begin
      if Context = null then
         return False;
      else
         Context.Has_Permission (Permission, Result);
         return Result;
      end if;
   end Has_Permission;

end Security.Contexts;
