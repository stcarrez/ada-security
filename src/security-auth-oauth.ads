-----------------------------------------------------------------------
--  security-auth-oauth -- OAuth based authentication
--  Copyright (C) 2013, 2020 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

with Security.OAuth.Clients;
private package Security.Auth.OAuth is

   --  ------------------------------
   --  OAuth Manager
   --  ------------------------------
   --  The <b>Manager</b> provides the core operations for the OAuth authorization process.
   type Manager is abstract new Security.Auth.Manager with private;

   --  Initialize the authentication realm.
   overriding
   procedure Initialize (Realm     : in out Manager;
                         Params    : in Parameters'Class;
                         Provider  : in String := PROVIDER_OPENID);

   --  Discover the OpenID provider that must be used to authenticate the user.
   --  The <b>Name</b> can be an URL or an alias that identifies the provider.
   --  A cached OpenID provider can be returned.
   --  Read the XRDS document from the URI and initialize the OpenID provider end point.
   --  (See OpenID Section 7.3 Discovery)
   overriding
   procedure Discover (Realm  : in out Manager;
                       Name   : in String;
                       Result : out End_Point);

   --  Associate the application (relying party) with the OpenID provider.
   --  The association can be cached.
   --  (See OpenID Section 8 Establishing Associations)
   overriding
   procedure Associate (Realm  : in out Manager;
                        OP     : in End_Point;
                        Result : out Association);

   --  Get the authentication URL to which the user must be redirected for authentication
   --  by the authentication server.
   overriding
   function Get_Authentication_URL (Realm : in Manager;
                                    OP    : in End_Point;
                                    Assoc : in Association) return String;

   --  Verify the authentication result
   overriding
   procedure Verify (Realm   : in out Manager;
                     Assoc   : in Association;
                     Request : in Parameters'Class;
                     Result  : out Authentication);

   --  Verify the OAuth access token and retrieve information about the user.
   procedure Verify_Access_Token (Realm   : in Manager;
                                  Assoc   : in Association;
                                  Request : in Parameters'Class;
                                  Token   : in Security.OAuth.Clients.Access_Token_Access;
                                  Result  : in out Authentication) is abstract;

private

   type Manager is abstract new Security.Auth.Manager with record
      Return_To : Unbounded_String;
      Realm     : Unbounded_String;
      Scope     : Unbounded_String;
      Issuer    : Unbounded_String;
      App       : Security.OAuth.Clients.Application;
   end record;

end Security.Auth.OAuth;
