-----------------------------------------------------------------------
--  security-permissions -- Definition of permissions
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

--  The <b>Security.Permissions</b> package defines the different permissions that can be
--  checked by the access control manager.
package Security.Permissions is

   Invalid_Name : exception;

   type Permission_Index is new Natural;

   --  Get the permission index associated with the name.
   function Get_Permission_Index (Name : in String) return Permission_Index;

   --  Get the last permission index registered in the global permission map.
   function Get_Last_Permission_Index return Permission_Index;

   --  Add the permission name and allocate a unique permission index.
   procedure Add_Permission (Name  : in String;
                             Index : out Permission_Index);


   --  The permission root class.
   --  Each permission is represented by a <b>Permission_Index</b> number to provide a fast
   --  and efficient permission check.
   type Permission (Id : Permission_Index) is tagged limited null record;

   generic
      Name : String;
   package Permission_ACL is
      function Permission return Permission_Index;
      pragma Inline_Always (Permission);
   end Permission_ACL;

end Security.Permissions;
