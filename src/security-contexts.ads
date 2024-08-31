-----------------------------------------------------------------------
--  security-contexts -- Context to provide security information and verify permissions
--  Copyright (C) 2011, 2012 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

with Ada.Finalization;

with Security.Permissions;
with Security.Policies;

--  == Security Context ==
--  The security context provides contextual information for a security controller to
--  verify that a permission is granted.
--  This security context is used as follows:
--
--    * An instance of the security context is declared within a function/procedure as
--      a local variable.  This instance will be associated internally with the current thread
--      through a task attribute.
--    * The security context is populated with information to identify the current user,
--      his roles, permissions and other information that could be used by security controllers.
--    * To verify a permission, the current security context is retrieved and the
--      <b>Has_Permission</b> operation is called.  This operation will use the security manager
--      to find the security controller associated with the permission to verify.
--    * The security controller will be called with the security context to check the permission.
--      The whole job of checking the permission is done by the security controller or its
--      associated policy manager.  The security controller retrieves information from the
--      security context to decide whether the permission is granted or not.
--
--  For example the security context is declared as follows:
--
--    Context : Security.Contexts.Security_Context;
--
--  A security policy and a principal must be set in the security context.  The security policy
--  defines the rules that govern the security and the principal identifies the current user.
--
--    Context.Set_Context (Policy_Manager, P);
--
--  A permission is checked by using the <tt>Has_Permission</tt> operation:
--
--    if Security.Contexts.Has_Permission (Perm_Create_Workspace.Permission) then
--      -- Granted
--    else
--      -- Denied
--    end if;
--
package Security.Contexts is

   Invalid_Context : exception;
   Invalid_Policy  : exception;

   type Security_Context is new Ada.Finalization.Limited_Controlled with private;
   type Security_Context_Access is access all Security_Context'Class;

   --  Get the application associated with the current service operation.
   function Get_User_Principal (Context : in Security_Context'Class)
                                return Security.Principal_Access;
   pragma Inline_Always (Get_User_Principal);

   --  Get the permission manager.
   function Get_Permission_Manager (Context : in Security_Context'Class)
                                    return Security.Policies.Policy_Manager_Access;
   pragma Inline_Always (Get_Permission_Manager);

   --  Get the policy with the name <b>Name</b> registered in the policy manager.
   --  Returns null if there is no such policy.
   function Get_Policy (Context : in Security_Context'Class;
                        Name    : in String) return Security.Policies.Policy_Access;

   --  Check if the permission identified by <b>Permission</b> is allowed according to
   --  the current security context.
   --  Returns True if the permission is granted.
   function Has_Permission (Context    : in Security_Context;
                            Permission : in Security.Permissions.Permission_Index) return Boolean;

   --  Check if the permission identified by <b>Permission</b> is allowed according to
   --  the current security context.
   --  Returns True if the permission is granted.
   function Has_Permission (Context    : in Security_Context;
                            Permission : in String) return Boolean;

   --  Check if the permission identified by <b>Permission</b> is allowed according to
   --  the current security context.
   --  Returns True if the permission is granted.
   function Has_Permission (Context    : in Security_Context;
                            Permission : in Security.Permissions.Permission'Class) return Boolean;

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
                          Manager   : in Security.Policies.Policy_Manager_Access;
                          Principal : in Security.Principal_Access);

   --  Set a policy context information represented by <b>Value</b> and associated with
   --  the <b>Policy</b>.
   procedure Set_Policy_Context (Context   : in out Security_Context;
                                 Policy    : in Security.Policies.Policy_Access;
                                 Value     : in Security.Policies.Policy_Context_Access);

   --  Get the policy context information registered for the given security policy in the security
   --  context <b>Context</b>.
   --  Raises <b>Invalid_Context</b> if there is no such information.
   --  Raises <b>Invalid_Policy</b> if the policy was not set.
   function Get_Policy_Context (Context  : in Security_Context;
                                Policy   : in Security.Policies.Policy_Access)
                                return Security.Policies.Policy_Context_Access;

   --  Returns True if a context information was registered for the security policy.
   function Has_Policy_Context (Context : in Security_Context;
                                Policy  : in Security.Policies.Policy_Access) return Boolean;

   --  Get the current security context.
   --  Returns null if the current thread is not associated with any security context.
   function Current return Security_Context_Access;
   pragma Inline_Always (Current);

   --  Check if the permission identified by <b>Permission</b> is allowed according to
   --  the current security context.
   function Has_Permission (Permission : in Security.Permissions.Permission_Index) return Boolean;

   --  Check if the permission identified by <b>Permission</b> is allowed according to
   --  the current security context.
   function Has_Permission (Permission : in String) return Boolean;

   --  Check if the permission identified by <b>Permission</b> is allowed according to
   --  the current security context.
   function Has_Permission (Permission : in Security.Permissions.Permission'Class) return Boolean;

private

   type Security_Context is new Ada.Finalization.Limited_Controlled with record
      Previous    : Security_Context_Access := null;
      Manager     : Security.Policies.Policy_Manager_Access := null;
      Principal   : Security.Principal_Access := null;
      Contexts    : Security.Policies.Policy_Context_Array_Access := null;
   end record;

end Security.Contexts;
