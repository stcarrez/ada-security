-----------------------------------------------------------------------
--  security -- Security
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

--  == Introduction ==
--  The <tt>Security</tt> package provides security frameworks that allows
--  an application to use OpenID or OAuth security frameworks.  This security
--  framework was first developed within the Ada Server Faces project.
--  This package defines abstractions that are close or similar to Java
--  security package.
--
--  @include security-permissions.ads
--  @include security-openid.ads
--  @include security-oauth.ads
--  @include security-contexts.ads
--  @include security-controllers.ads
package Security is

   --  ------------------------------
   --  Principal
   --  ------------------------------
   type Principal is limited interface;
   type Principal_Access is access all Principal'Class;
--
--     --  Returns true if the given role is stored in the user principal.
--     function Has_Role (User : in Principal;
--                        Role : in Role_Type) return Boolean is abstract;

   --  Get the principal name.
   function Get_Name (From : in Principal) return String is abstract;

end Security;
