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
--  The <tt>Security</tt> package provides a security framework that allows
--  an application to use OpenID or OAuth security frameworks.  This security
--  framework was first developed within the Ada Server Faces project.
--  This package defines abstractions that are close or similar to Java
--  security package.
--
--  === Principal ===
--  The <tt>Principal</tt> is the entity that can be authenticated.  A principal is obtained
--  after successful authentication of a user or of a system through an authorization process.
--  The OpenID or OAuth authentication processes generate such security principal.
--
--  === Permission ===
--  The <tt>Permission</tt> represents an access to a system or application resource.
--  A permission is checked by using the security manager.  The security manager uses a
--  security controller to enforce the permission.
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

   --  Get the principal name.
   function Get_Name (From : in Principal) return String is abstract;

end Security;
