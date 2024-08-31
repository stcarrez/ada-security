-----------------------------------------------------------------------
--  security-auth-oauth-github -- Github OAuth based authentication
--  Copyright (C) 2013, 2014, 2020 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

with Security.OAuth.Clients;
package Security.Auth.OAuth.Github is

   --  ------------------------------
   --  OAuth Manager
   --  ------------------------------
   --  The <b>Manager</b> provides the core operations for the OAuth authorization process.
   type Manager is new Security.Auth.OAuth.Manager with null record;

   --  Verify the OAuth access token and retrieve information about the user.
   overriding
   procedure Verify_Access_Token (Realm   : in Manager;
                                  Assoc   : in Association;
                                  Request : in Parameters'Class;
                                  Token   : in Security.OAuth.Clients.Access_Token_Access;
                                  Result  : in out Authentication);

end Security.Auth.OAuth.Github;
