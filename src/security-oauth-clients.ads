-----------------------------------------------------------------------
--  security-oauth -- OAuth Security
--  Copyright (C) 2012, 2013, 2016, 2017, 2018 Stephane Carrez
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
with Ada.Strings.Unbounded;

--  = OAuth2 Client =
--  The `Security.OAuth.Clients` package implements the client OAuth 2.0 authorization.
--
--  == Application setup ==
--  For an OAuth2 client application to authenticate, it must be registered on the server
--  and the server provides the following information:
--
--  * **client_id**: the client identifier is a unique string that identifies the application.
--  * **client_secret** the client secret is a secret shared between the server and the
--    client application.  The client secret is optional.
--
--  The `Security.OAuth.Clients.Application` tagged record is the primary type that
--  allows to perform one of the OAuth 2.0 authorization flows.  It is necessary to
--  declare an `Application` instance and register the **client_id**, the **client_secret**
--  and the authorisation URLs to connect to the server.
--
--    App : Security.OAuth.Clients.Application;
--    ...
--       App.Set_Application_Identifier ("app-identifier");
--       App.Set_Application_Secret ("app-secret");
--       App.Set_Provider_URL ("https://graph.facebook.com/oauth/access_token");
--
--
--  == Resource Owner Password Credentials Grant ==
--  The RFC 6749: 4.3.  Resource Owner Password Credentials Grant allows to authorize an
--  application by using the user's name and password.  This is the simplest OAuth flow
--  but because it requires to know the user's name and password, it is not recommended and
--  not supported by several servers.  To use this authorization, the application will use
--  the `Request_Token` procedure and will give the user's name, password and the scope
--  of permissions.  When the authorization succeeds, a `Grant_Type` token object is returned.
--
--    Token  : Security.OAuth.Clients.Grant_Type;
--    ...
--      App.Request_Token ("admin", "admin", "scope", Token);
--
--  == Refreshing an access token ==
--  An access token has an expiration date and a new access token must be asked by using the
--  refresh token.  When the access token has expired, the grant token object can be refreshed
--  to retrieve a new access token by using the `Refresh_Token` procedure.  The scope of
--  permissions can also be passsed.
--
--     App.Refresh_Token ("scope", Token);
--
package Security.OAuth.Clients is

   --  Note: OAuth 1.0 could be implemented but since it's being deprecated it's not worth doing it.

   --  ------------------------------
   --  Access Token
   --  ------------------------------
   --  Access tokens are credentials used to access protected resources.
   --  The access token is represented as a <b>Principal</b>.  This is an opaque
   --  value for an application.
   type Access_Token (Len : Natural) is new Security.Principal with private;
   type Access_Token_Access is access all Access_Token'Class;

   --  Get the principal name.  This is the OAuth access token.
   function Get_Name (From : in Access_Token) return String;

   type OpenID_Token (Len, Id_Len, Refresh_Len : Natural) is new Access_Token with private;
   type OpenID_Token_Access is access all OpenID_Token'Class;

   --  Get the id_token that was returned by the authentication process.
   function Get_Id_Token (From : in OpenID_Token) return String;

   --  Generate a random nonce with at last the number of random bits.
   --  The number of bits is rounded up to a multiple of 32.
   --  The random bits are then converted to base64url in the returned string.
   function Create_Nonce (Bits : in Positive := 256) return String;

   type Grant_Type is new Security.Principal with private;

   --  Get the principal name.  This is the OAuth access token.
   function Get_Name (From : in Grant_Type) return String;

   --  Get the Authorization header to be used for accessing a protected resource.
   --  (See RFC 6749 7.  Accessing Protected Resources)
   function Get_Authorization (From : in Grant_Type) return String;

   --  ------------------------------
   --  Application
   --  ------------------------------
   --  The <b>Application</b> holds the necessary information to let a user
   --  grant access to its protected resources on the resource server.  It contains
   --  information that allows the OAuth authorization server to identify the
   --  application (client id and secret key).
   type Application is new Security.OAuth.Application with private;

   --  Set the OAuth authorization server URI that the application must use
   --  to exchange the OAuth code into an access token.
   procedure Set_Provider_URI (App : in out Application;
                               URI : in String);

   --  OAuth 2.0 Section 4.1.1  Authorization Request

   --  Build a unique opaque value used to prevent cross-site request forgery.
   --  The <b>Nonce</b> parameters is an optional but recommended unique value
   --  used only once.  The state value will be returned back by the OAuth provider.
   --  This protects the <tt>client_id</tt> and <tt>redirect_uri</tt> parameters.
   function Get_State (App   : in Application;
                       Nonce : in String) return String;

   --  Get the authenticate parameters to build the URI to redirect the user to
   --  the OAuth authorization form.
   function Get_Auth_Params (App : in Application;
                             State : in String;
                             Scope : in String := "") return String;

   --  OAuth 2.0 Section 4.1.2  Authorization Response

   --  Verify that the <b>State</b> opaque value was created by the <b>Get_State</b>
   --  operation with the given client and redirect URL.
   function Is_Valid_State (App   : in Application;
                            Nonce : in String;
                            State : in String) return Boolean;


   --  OAuth 2.0 Section 4.1.3.  Access Token Request
   --            Section 4.1.4.  Access Token Response

   --  Exchange the OAuth code into an access token.
   function Request_Access_Token (App  : in Application;
                                  Code : in String) return Access_Token_Access;

   --  Get a request token with username and password.
   --  RFC 6749: 4.3.  Resource Owner Password Credentials Grant
   procedure Request_Token (App      : in Application;
                            Username : in String;
                            Password : in String;
                            Scope    : in String;
                            Token    : in out Grant_Type'Class);

   --  Refresh the access token.
   --  RFC 6749: 6.  Refreshing an Access Token
   procedure Refresh_Token (App      : in Application;
                            Scope    : in String;
                            Token    : in out Grant_Type'Class);

   --  Create the access token
   function Create_Access_Token (App      : in Application;
                                 Token    : in String;
                                 Refresh  : in String;
                                 Id_Token : in String;
                                 Expires  : in Natural) return Access_Token_Access;

private

   type Access_Token (Len : Natural) is new Security.Principal with record
      Access_Id : String (1 .. Len);
   end record;

   type OpenID_Token (Len, Id_Len, Refresh_Len : Natural) is new Access_Token (Len) with record
      Id_Token      : String (1 .. Id_Len);
      Refresh_Token : String (1 .. Refresh_Len);
   end record;

   type Application is new Security.OAuth.Application with record
      Request_URI : Ada.Strings.Unbounded.Unbounded_String;
   end record;

   type Grant_Type is new Security.Principal with record
      Access_Token  : Ada.Strings.Unbounded.Unbounded_String;
      Refresh_Token : Ada.Strings.Unbounded.Unbounded_String;
      Id_Token      : Ada.Strings.Unbounded.Unbounded_String;
   end record;

end Security.OAuth.Clients;
