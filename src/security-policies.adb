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

with Util.Log.Loggers;
with Util.Strings;
with Util.Refs;
with Util.Beans.Objects;
with Util.Beans.Objects.Vectors;
with Util.Serialize.IO.XML;

with GNAT.Regexp;

with Security.Permissions;

package body Security.Policies is

   --  The logger
   Log : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("Security.Policies");

   --  Get the policy name.
   function Get_Name (From : in Policy) return String is
   begin
      return "";
   end Get_Name;

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
   --  Permission Manager
   --  ------------------------------

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
            return;
         end if;
      end loop;
      Log.Error ("Policy table is full, increase policy manager table to {0} to add policy {1}",
                 Positive'Image (Manager.Max_Policies + 1), Name);
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
      Manager.Permissions (Index) := Permission;
   end Add_Permission;

   --  Get the security controller associated with the permission index <b>Index</b>.
   --  Returns null if there is no such controller.
   function Get_Controller (Manager : in Policy_Manager'Class;
                            Index   : in Permissions.Permission_Index) return Controller_Access is
      use type Permissions.Permission_Index;
   begin
      if Index >= Manager.Last_Index then
         return null;
      else
         return Manager.Permissions (Index);
      end if;
   end Get_Controller;

   --  Read the policy file
   procedure Read_Policy (Manager : in out Policy_Manager;
                          File    : in String) is

      use Util;

      Reader : Util.Serialize.IO.XML.Parser;

      package Policy_Config is
        new Reader_Config (Reader, Manager'Unchecked_Access);
--        package Role_Config is
--          new Security.Controllers.Roles.Reader_Config (Reader, Manager'Unchecked_Access);
      pragma Warnings (Off, Policy_Config);
--        pragma Warnings (Off, Role_Config);
   begin
      Log.Info ("Reading policy file {0}", File);

      --  Prepare the reader to parse the policy configuration.
      for I in Manager.Policies'Range loop
         exit when Manager.Policies (I) = null;
         Manager.Policies (I).Set_Reader_Config (Reader);
      end loop;

      --  Read the configuration file.
      Reader.Parse (File);

   end Read_Policy;

   --  Initialize the permission manager.
   overriding
   procedure Initialize (Manager : in out Policy_Manager) is
   begin
      null;
   end Initialize;

   --  Finalize the permission manager.
   overriding
   procedure Finalize (Manager : in out Policy_Manager) is
   begin
      null;
   end Finalize;

end Security.Policies;
