-----------------------------------------------------------------------
--  security-contexts -- Context to provide security information and verify permissions
--  Copyright (C) 2011, 2012 Stephane Carrez
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
with Ada.Unchecked_Deallocation;

package body Security.Contexts is

   use type Security.Policies.Policy_Context_Array_Access;
   use type Security.Policies.Policy_Access;
   use type Security.Policies.Policy_Context_Access;

   package Task_Context is new Ada.Task_Attributes
     (Security_Context_Access, null);

   procedure Free is
      new Ada.Unchecked_Deallocation (Object => Security.Policies.Policy_Context'Class,
                                      Name   => Security.Policies.Policy_Context_Access);

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
                                    return Security.Policies.Policy_Manager_Access is
   begin
      return Context.Manager;
   end Get_Permission_Manager;

   --  ------------------------------
   --  Get the policy with the name <b>Name</b> registered in the policy manager.
   --  Returns null if there is no such policy.
   --  ------------------------------
   function Get_Policy (Context : in Security_Context'Class;
                        Name    : in String) return Security.Policies.Policy_Access is
      use type Security.Policies.Policy_Manager_Access;
   begin
      if Context.Manager = null then
         return null;
      else
         return Context.Manager.Get_Policy (Name);
      end if;
   end Get_Policy;

   --  ------------------------------
   --  Check if the permission identified by <b>Permission</b> is allowed according to
   --  the current security context.  The result is cached in the security context and
   --  returned in <b>Result</b>.
   --  ------------------------------
   procedure Has_Permission (Context    : in out Security_Context;
                             Permission : in Security.Permissions.Permission_Index;
                             Result     : out Boolean) is
      use type Security.Policies.Policy_Manager_Access;
   begin
      if Context.Manager = null then
         Result := False;
         return;
      end if;
      declare
         Perm : Security.Permissions.Permission (Permission);
      begin
         Result := Context.Manager.Has_Permission (Context, Perm);
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
   --  Check if the permission identified by <b>Permission</b> is allowed according to
   --  the current security context.  The result is cached in the security context and
   --  returned in <b>Result</b>.
   --  ------------------------------
   procedure Has_Permission (Context    : in out Security_Context;
                             Permission : in Security.Permissions.Permission'Class;
                             Result     : out Boolean) is
      use type Security.Policies.Policy_Manager_Access;
   begin
      if Context.Manager = null then
         Result := False;
         return;
      end if;
      Result := Context.Manager.Has_Permission (Context, Permission);
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

      procedure Free is
        new Ada.Unchecked_Deallocation (Object => Security.Policies.Policy_Context_Array,
                                        Name   => Security.Policies.Policy_Context_Array_Access);
   begin
      Task_Context.Set_Value (Context.Previous);
      if Context.Contexts /= null then
         for I in Context.Contexts'Range loop
            Free (Context.Contexts (I));
         end loop;
         Free (Context.Contexts);
      end if;
   end Finalize;

   --  ------------------------------
   --  Set a policy context information represented by <b>Value</b> and associated with
   --  the policy index <b>Policy</b>.
   --  ------------------------------
   procedure Set_Policy_Context (Context   : in out Security_Context;
                                 Policy    : in Security.Policies.Policy_Access;
                                 Value     : in Security.Policies.Policy_Context_Access) is
   begin
      if Context.Contexts = null then
         Context.Contexts := Context.Manager.Create_Policy_Contexts;
      end if;
      Free (Context.Contexts (Policy.Get_Policy_Index));
      Context.Contexts (Policy.Get_Policy_Index) := Value;
   end Set_Policy_Context;

   --  ------------------------------
   --  Get the policy context information registered for the given security policy in the security
   --  context <b>Context</b>.
   --  Raises <b>Invalid_Context</b> if there is no such information.
   --  Raises <b>Invalid_Policy</b> if the policy was not set.
   --  ------------------------------
   function Get_Policy_Context (Context  : in Security_Context;
                                Policy   : in Security.Policies.Policy_Access)
                                return Security.Policies.Policy_Context_Access is
      Result : Security.Policies.Policy_Context_Access;
   begin
      if Policy = null then
         raise Invalid_Policy;
      end if;
      if Context.Contexts = null then
         raise Invalid_Context;
      end if;
      Result := Context.Contexts (Policy.Get_Policy_Index);
      return Result;
   end Get_Policy_Context;

   --  ------------------------------
   --  Returns True if a context information was registered for the security policy.
   --  ------------------------------
   function Has_Policy_Context (Context : in Security_Context;
                                Policy  : in Security.Policies.Policy_Access) return Boolean is
   begin
      return Policy /= null and then Context.Contexts /= null
        and then Context.Contexts (Policy.Get_Policy_Index) /= null;
   end Has_Policy_Context;

   --  ------------------------------
   --  Set the current application and user context.
   --  ------------------------------
   procedure Set_Context (Context   : in out Security_Context;
                          Manager   : in Security.Policies.Policy_Manager_Access;
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

   --  ------------------------------
   --  Check if the permission identified by <b>Permission</b> is allowed according to
   --  the current security context.
   --  ------------------------------
   function Has_Permission (Permission : in Permissions.Permission'Class) return Boolean is
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
