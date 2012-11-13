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

with Ada.Finalization;

with Util.Strings.Maps;
with Security.Permissions;

--  == Security Context ==
--  The security context provides contextual information for a security controller to
--  verify that a permission is granted.
--  This security context is used as follows:
--
--    * An instance of the security context is declared within a function/procedure as
--      a local variable
--
--    * This instance will be associated with the current thread through a task attribute
--
--    * The security context is populated with information to identify the current user,
--      his roles, permissions and other information that could be used by security controllers
--
--    * To verify a permission, the current security context is retrieved and the
--      <b>Has_Permission</b> operation is called,
--
--    * The <b>Has_Permission</b> will first look in a small cache stored in the security context.
--
--    * When not present in the cache, it will use the security manager to find the
--      security controller associated with the permission to verify
--
--    * The security controller will be called with the security context to check the permission.
--      The whole job of checking the permission is done by the security controller.
--      The security controller retrieves information from the security context to decide
--      whether the permission is granted or not.
--
--    * The result produced by the security controller is then saved in the local cache.
--
package Security.Contexts is

   Invalid_Context : exception;

   type Security_Context is new Ada.Finalization.Limited_Controlled with private;
   type Security_Context_Access is access all Security_Context'Class;

   --  Get the application associated with the current service operation.
   function Get_User_Principal (Context : in Security_Context'Class)
                                return Security.Permissions.Principal_Access;
   pragma Inline_Always (Get_User_Principal);

   --  Get the permission manager.
   function Get_Permission_Manager (Context : in Security_Context'Class)
                                    return Security.Permissions.Permission_Manager_Access;
   pragma Inline_Always (Get_Permission_Manager);

   --  Check if the permission identified by <b>Permission</b> is allowed according to
   --  the current security context.  The result is cached in the security context and
   --  returned in <b>Result</b>.
   procedure Has_Permission (Context    : in out Security_Context;
                             Permission : in Security.Permissions.Permission_Index;
                             Result     : out Boolean);

   --  Check if the permission identified by <b>Permission</b> is allowed according to
   --  the current security context.  The result is cached in the security context and
   --  returned in <b>Result</b>.
   procedure Has_Permission (Context    : in out Security_Context;
                             Permission : in String;
                             Result     : out Boolean);

   --  Initializes the service context.  By creating the <b>Security_Context</b> variable,
   --  the instance will be associated with the current task attribute.  If the current task
   --  already has a security context, the new security context is installed, the old one
   --  being kept.
   overriding
   procedure Initialize (Context : in out Security_Context);

   --  Finalize the security context releases any object.  The previous security context is
   --  restored to the current task attribute.
   overriding
   procedure Finalize (Context : in out Security_Context);

   --  Set the current application and user context.
   procedure Set_Context (Context   : in out Security_Context;
                          Manager   : in Security.Permissions.Permission_Manager_Access;
                          Principal : in Security.Permissions.Principal_Access);

   --  Add a context information represented by <b>Value</b> under the name identified by
   --  <b>Name</b> in the security context <b>Context</b>.
   procedure Add_Context (Context   : in out Security_Context;
                          Name      : in String;
                          Value     : in String);

   --  Get the context information registered under the name <b>Name</b> in the security
   --  context <b>Context</b>.
   --  Raises <b>Invalid_Context</b> if there is no such information.
   function Get_Context (Context  : in Security_Context;
                         Name     : in String) return String;

   --  Returns True if a context information was registered under the name <b>Name</b>.
   function Has_Context (Context : in Security_Context;
                         Name    : in String) return Boolean;

   --  Get the current security context.
   --  Returns null if the current thread is not associated with any security context.
   function Current return Security_Context_Access;
   pragma Inline_Always (Current);

   --  Check if the permission identified by <b>Permission</b> is allowed according to
   --  the current security context.  The result is cached in the security context and
   --  returned in <b>Result</b>.
   function Has_Permission (Permission : in Security.Permissions.Permission_Index) return Boolean;

   --  Check if the permission identified by <b>Permission</b> is allowed according to
   --  the current security context.  The result is cached in the security context and
   --  returned in <b>Result</b>.
   function Has_Permission (Permission : in String) return Boolean;

private

   type Permission_Cache is record
      Perm   : Security.Permissions.Permission_Type;
      Result : Boolean;
   end record;

   type Security_Context is new Ada.Finalization.Limited_Controlled with record
      Previous    : Security_Context_Access := null;
      Manager     : Security.Permissions.Permission_Manager_Access := null;
      Principal   : Security.Permissions.Principal_Access := null;
      Context     : Util.Strings.Maps.Map;
   end record;

end Security.Contexts;
