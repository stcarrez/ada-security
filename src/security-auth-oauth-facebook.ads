-----------------------------------------------------------------------
--  security-auth-oauth-facebook -- Facebook OAuth based authentication
--  Copyright (C) 2013, 2014 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

with Security.OAuth.Clients;
package Security.Auth.OAuth.Facebook is

   --  ------------------------------
   --  OAuth Manager
   --  ------------------------------
   --  The <b>Manager</b> provides the core operations for the OAuth authorization process.
   type Manager is new Security.Auth.OAuth.Manager with private;

   --  Initialize the authentication realm.
   overriding
   procedure Initialize (Realm     : in out Manager;
                         Params    : in Parameters'Class;
                         Provider  : in String := PROVIDER_OPENID);

   --  Verify the OAuth access token and retrieve information about the user.
   overriding
   procedure Verify_Access_Token (Realm   : in Manager;
                                  Assoc   : in Association;
                                  Request : in Parameters'Class;
                                  Token   : in Security.OAuth.Clients.Access_Token_Access;
                                  Result  : in out Authentication);

private

   type Manager is new Security.Auth.OAuth.Manager with record
      App_Access_Token : Ada.Strings.Unbounded.Unbounded_String;
   end record;

end Security.Auth.OAuth.Facebook;
