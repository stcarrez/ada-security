-----------------------------------------------------------------------
--  security -- Security
--  Copyright (C) 2010, 2011, 2012, 2015, 2017, 2018, 2019 Stephane Carrez
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

--  = Security =
--  The `Security` package provides a security framework that allows
--  an application to use OpenID or OAuth security frameworks.  This security
--  framework was first developed within the Ada Server Faces project.
--  It was moved to a separate project so that it can easyly be used with AWS.
--  This package defines abstractions that are close or similar to Java
--  security package.
--
--  The security framework uses the following abstractions:
--
--  * **Policy and policy manager**:
--    The `Policy` defines and implements the set of security rules that specify how to
--    protect the system or resources.  The `Policy_Manager` maintains the security policies.
--
--  * **Principal**:
--    The `Principal` is the entity that can be authenticated.  A principal is obtained
--    after successful authentication of a user or of a system through an authorization process.
--    The OpenID or OAuth authentication processes generate such security principal.
--
--  * **Permission**:
--    The `Permission` represents an access to a system or application resource.
--    A permission is checked by using the security policy manager.  The policy manager uses a
--    security controller to enforce the permission.
--
--  The `Security_Context` holds the contextual information that the security controller
--  can use to verify the permission.  The security context is associated with a principal and
--  a set of policy context.
--
--  == Overview ==
--  An application will create a security policy manager and register one or several security
--  policies (yellow).  The framework defines a simple role based security policy and an URL
--  security policy intended to provide security in web applications.  The security policy manager
--  reads some security policy configuration file which allows the security policies to configure
--  and create the security controllers.  These controllers will enforce the security according
--  to the application security rules.  All these components are built only once when
--  an application starts.
--
--  A user is authenticated through an authentication system which creates a `Principal`
--  instance that identifies the user (green).  The security framework provides two authentication
--  systems: OpenID and OAuth 2.0 OpenID Connect.
--
--  [images/ModelOverview.png]
--
--  When a permission must be enforced, a security context is created and linked to the
--  `Principal` instance (blue).  Additional security policy context can be added depending
--  on the application context.  To check the permission, the security policy manager is called
--  and it will ask a security controller to verify the permission.
--
--  The framework allows an application to plug its own security policy, its own policy context,
--  its own principal and authentication mechanism.
--
--  @include security-permissions.ads
--
--  == Principal ==
--  A principal is created by using either the [Security_Auth OpenID],
--  the [Security_OAuth OAuth] or another authentication mechanism.  The authentication produces
--  an object that must implement the `Principal` interface.  For example:
--
--    P : Security.Auth.Principal_Access := Security.Auth.Create_Principal (Auth);
--
--  or
--
--    P : Security.OAuth.Clients.Access_Token_Access := Security.OAuth.Clients.Create_Access_Token
--
--  The principal is then stored in a security context.
--
--  @include security-contexts.ads
--
package Security is

   pragma Preelaborate;

   --  ------------------------------
   --  Principal
   --  ------------------------------
   type Principal is limited interface;
   type Principal_Access is access all Principal'Class;

   --  Get the principal name.
   function Get_Name (From : in Principal) return String is abstract;

end Security;
