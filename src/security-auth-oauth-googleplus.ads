-----------------------------------------------------------------------
--  security-auth-oauth-googleplus -- Google+ OAuth based authentication
--  Copyright (C) 2013 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

with Security.OAuth.Clients;

--  === Google+ ===
--  The Google+ authentication is based on OAuth 2.0 and the OpenID Connect Basic Client Profile.
--
--  See https://developers.google.com/accounts/docs/OAuth2Login
package Security.Auth.OAuth.Googleplus is

   --  ------------------------------
   --  OAuth Manager
   --  ------------------------------
   --  The <b>Manager</b> provides the core operations for the OAuth authorization process.
   type Manager is new Security.Auth.OAuth.Manager with private;

   --  Verify the OAuth access token and retrieve information about the user.
   overriding
   procedure Verify_Access_Token (Realm   : in Manager;
                                  Assoc   : in Association;
                                  Request : in Parameters'Class;
                                  Token   : in Security.OAuth.Clients.Access_Token_Access;
                                  Result  : in out Authentication);

private

   type Manager is new Security.Auth.OAuth.Manager with null record;

end Security.Auth.OAuth.Googleplus;
