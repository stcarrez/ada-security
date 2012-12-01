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

with Ada.Unchecked_Deallocation;

with Util.Log.Loggers;

with Security.Controllers;
with Security.Contexts;

package body Security.Policies is

   --  The logger
   Log : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("Security.Policies");

   procedure Free is
     new Ada.Unchecked_Deallocation (Security.Controllers.Controller'Class,
                                     Controller_Access);

   --  ------------------------------
   --  Get the policy index.
   --  ------------------------------
   function Get_Policy_Index (From : in Policy'Class) return Policy_Index is
   begin
      return From.Index;
   end Get_Policy_Index;

   --  ------------------------------
   --  Add a permission under the given permission name and associated with the controller.
   --  To verify the permission, the controller will be called.
   --  ------------------------------
   procedure Add_Permission (Manager    : in out Policy;
                             Name       : in String;
                             Permission : in Controller_Access) is
   begin
      Manager.Manager.Add_Permission (Name, Permission);
   end Add_Permission;

   --  ------------------------------
   --  Get the policy with the name <b>Name</b> registered in the policy manager.
   --  Returns null if there is no such policy.
   --  ------------------------------
   function Get_Policy (Manager : in Policy_Manager;
                        Name    : in String) return Policy_Access is
   begin
      for I in Manager.Policies'Range loop
         if Manager.Policies (I) = null then
            return null;
         elsif Manager.Policies (I).Get_Name = Name then
            return Manager.Policies (I);
         end if;
      end loop;
      return null;
   end Get_Policy;

   --  ------------------------------
   --  Add the policy to the policy manager.  After a policy is added in the manager,
   --  it can participate in the security policy.
   --  Raises Policy_Error if the policy table is full.
   --  ------------------------------
   procedure Add_Policy (Manager : in out Policy_Manager;
                         Policy  : in Policy_Access) is
      Name : constant String := Policy.Get_Name;
   begin
      Log.Info ("Adding policy {0}", Name);

      for I in Manager.Policies'Range loop
         if Manager.Policies (I) = null then
            Manager.Policies (I) := Policy;
            Policy.Manager := Manager'Unchecked_Access;
            Policy.Index   := I;
            return;
         end if;
      end loop;
      Log.Error ("Policy table is full, increase policy manager table to {0} to add policy {1}",
                 Policy_Index'Image (Manager.Max_Policies + 1), Name);
      raise Policy_Error;
   end Add_Policy;

   --  ------------------------------
   --  Add a permission under the given permission name and associated with the controller.
   --  To verify the permission, the controller will be called.
   --  ------------------------------
   procedure Add_Permission (Manager    : in out Policy_Manager;
                             Name       : in String;
                             Permission : in Controller_Access) is
      use type Permissions.Permission_Index;

      Index : Permission_Index;
   begin
      Log.Info ("Adding permission {0}", Name);

      Permissions.Add_Permission (Name, Index);
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

      --  If the permission has a controller, release it.
      if Manager.Permissions (Index) /= null then
         Log.Warn ("Permission {0} is redefined", Name);
         Free (Manager.Permissions (Index));
      end if;

      Manager.Permissions (Index) := Permission;
   end Add_Permission;

   --  ------------------------------
   --  Checks whether the permission defined by the <b>Permission</b> is granted
   --  for the security context passed in <b>Context</b>.
   --  Returns true if such permission is granted.
   --  ------------------------------
   function Has_Permission (Manager    : in Policy_Manager;
                            Context    : in Security.Contexts.Security_Context'Class;
                            Permission : in Security.Permissions.Permission'Class)
                            return Boolean is
      use type Permissions.Permission_Index;
   begin
      if Permission.Id >= Manager.Last_Index then
         return False;
      end if;
      declare
         C : constant Controller_Access := Manager.Permissions (Permission.Id);
      begin
         if C = null then
            return False;
         else
            return C.Has_Permission (Context, Permission);
         end if;
      end;
   end Has_Permission;

   --  ------------------------------
   --  Create the policy contexts to be associated with the security context.
   --  ------------------------------
   function Create_Policy_Contexts (Manager : in Policy_Manager)
                                    return Policy_Context_Array_Access is
   begin
      return new Policy_Context_Array (1 .. Manager.Max_Policies);
   end Create_Policy_Contexts;

   --  Read the policy file
   procedure Read_Policy (Manager : in out Policy_Manager;
                          File    : in String) is

      use Util;

      Reader : Util.Serialize.IO.XML.Parser;

      package Policy_Config is
        new Reader_Config (Reader, Manager'Unchecked_Access);
      pragma Warnings (Off, Policy_Config);
   begin
      Log.Info ("Reading policy file {0}", File);

      --  Prepare the reader to parse the policy configuration.
      for I in Manager.Policies'Range loop
         exit when Manager.Policies (I) = null;
         Manager.Policies (I).Prepare_Config (Reader);
      end loop;

      --  Read the configuration file.
      Reader.Parse (File);

      --  Finish the policy configuration.
      for I in Manager.Policies'Range loop
         exit when Manager.Policies (I) = null;
         Manager.Policies (I).Finish_Config (Reader);
      end loop;

   end Read_Policy;

   --  ------------------------------
   --  Initialize the policy manager.
   --  ------------------------------
   overriding
   procedure Initialize (Manager : in out Policy_Manager) is
   begin
      null;
   end Initialize;

   --  ------------------------------
   --  Finalize the policy manager.
   --  ------------------------------
   overriding
   procedure Finalize (Manager : in out Policy_Manager) is
      procedure Free is
        new Ada.Unchecked_Deallocation (Controller_Access_Array,
                                        Controller_Access_Array_Access);
      procedure Free is
        new Ada.Unchecked_Deallocation (Policy'Class,
                                        Policy_Access);

   begin
      --  Release the security controllers.
      if Manager.Permissions /= null then
         for I in Manager.Permissions.all'Range loop
            if Manager.Permissions (I) /= null then
               --  SCz 2011-12-03: GNAT 2011 reports a compilation error:
               --  'missing "with" clause on package "Security.Controllers"'
               --  if we use the 'Security.Controller_Access' type, even if this "with"
               --  clause exist.
               --  gcc 4.4.3 under Ubuntu does not have this issue.
               --  We use the 'Security.Controllers.Controller_Access' type to avoid the compiler
               --  bug but we have to use a temporary variable and do some type conversion...
               declare
                  P : Controller_Access := Manager.Permissions (I).all'Access;
               begin
                  Free (P);
                  Manager.Permissions (I) := null;
               end;
            end if;
         end loop;
         Free (Manager.Permissions);
      end if;

      --  Release the policy instances.
      for I in Manager.Policies'Range loop
         exit when Manager.Policies (I) = null;
         Free (Manager.Policies (I));
      end loop;

   end Finalize;

end Security.Policies;
