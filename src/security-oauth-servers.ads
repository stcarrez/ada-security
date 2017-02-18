-----------------------------------------------------------------------
--  security-oauth-servers -- OAuth Server Authentication Support
--  Copyright (C) 2016, 2017 Stephane Carrez
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
with Ada.Calendar;
with Ada.Finalization;
with Ada.Strings.Hash;
with Ada.Containers.Indefinite_Hashed_Maps;

with Util.Strings;

with Security.Auth;
with Security.Permissions;

--  == OAuth Server ==
--  OAuth server side is provided by the <tt>Security.OAuth.Servers</tt> package.
--  This package allows to implement the authorization framework described in RFC 6749
--  The OAuth 2.0 Authorization Framework.
--
--  The authorization method produce a <tt>Grant_Type</tt> object that contains the result
--  of the grant (successful or denied).  It is the responsibility of the caller to format
--  the result in JSON/XML and return it to the client.
--
--  Three important operations are defined for the OAuth 2.0 framework.
--
--  <tt>Authorize</tt> is used to obtain an authorization request.  This operation is
--  optional in the OAuth 2.0 framework since some authorization method directly return
--  the access token.  This operation is used by the "Authorization Code Grant" and the
--  "Implicit Grant".
--
--  <tt>Token</tt> is used to get the access token and optional refresh token.
--
--  <tt>Authenticate</tt> is used for the API request to verify the access token
--  and authenticate the API call.

--  Several grant types are supported.
--
--  === Application Manager ===
--  The application manager maintains the repository of applications which are known by
--  the server and which can request authorization.  Each application is identified by
--  a client identifier (represented by the <tt>client_id</tt> request parameter).
--  The application defines the authorization methods which are allowed as well as
--  the parameters to control and drive the authorization.  This includes the redirection
--  URI, the application secret, the expiration delay for the access token.
--
--  The application manager is implemented by the application server and it must
--  implement the <tt>Application_Manager</tt> interface with the <tt>Find_Application</tt>
--  method.  The <tt>Find_Application</tt> is one of the first call made during the
--  authenticate and token generation phases.
--
--  === Resource Owner Password Credentials Grant ===
--  The password grant is one of the easiest grant method to understand but it is also one
--  of the less secure.  In this grant method, the username and user password are passed in
--  the request parameter together with the application client identifier.  The realm verifies
--  the username and password and when they are correct it generates the access token with
--  an optional refresh token.
--
--    Realm : Security.OAuth.Servers.Auth_Manager;
--    Grant : Security.OAuth.Servers.Grant_Type;
--
--      Realm.Authorize (Params, Grant);
--
--  === Accessing Protected Resources ===
--  When accessing a protected resource, the API implementation will use the
--  <tt>Authenticate</tt> operation to verify the access token and get a security principal.
--  The security principal will identifies the resource owner as well as the application
--  that is doing the call.
--
--     Realm : Security.OAuth.Servers.Auth_Manager;
--     Auth  : Security.Principal_Access;
--     Token : String := ...;
--
--       Realm.Authenticate (Token, Auth);
--
--  When a security principal is returned, the access token was validated and the
--  request is granted for the application.
--
package Security.OAuth.Servers is

   Invalid_Application : exception;

   type Application is new Security.OAuth.Application with private;

   --  Check if the application has the given permission.
   function Has_Permission (App        : in Application;
                            Permission : in Security.Permissions.Permission_Index) return Boolean;

   --  Define the status of the grant.
   type Grant_Status is (Invalid_Grant, Expired_Grant, Revoked_Grant,
                         Stealed_Grant, Valid_Grant);

   --  Define the grant type.
   type Grant_Kind is (No_Grant, Access_Grant, Code_Grant,
                       Implicit_Grant, Password_Grant, Credential_Grant,
                       Extension_Grant);

   --  The <tt>Grant_Type</tt> holds the results of the authorization.
   --  When the grant is refused, the type holds information about the refusal.
   type Grant_Type is record
      --  The request grant type.
      Request : Grant_Kind := No_Grant;

      --  The response status.
      Status  : Grant_Status := Invalid_Grant;

      --  When success, the token to return.
      Token   : Ada.Strings.Unbounded.Unbounded_String;

      --  When success, the token expiration date.
      Expires : Ada.Calendar.Time;

      --  When success, the authentication principal.
      Auth    : Security.Principal_Access;

      --  When error, the type of error to return.
      Error   : Util.Strings.Name_Access;
   end record;

   type Application_Manager is limited interface;
   type Application_Manager_Access is access all Application_Manager'Class;

   --  Find the application that correspond to the given client id.
   --  The <tt>Invalid_Application</tt> exception should be raised if there is no such application.
   function Find_Application (Realm     : in Application_Manager;
                              Client_Id : in String) return Application'Class is abstract;

   type Realm_Manager is limited interface;
   type Realm_Manager_Access is access all Realm_Manager'Class;

   --  Authenticate the token and find the associated authentication principal.
   --  The access token has been verified and the token represents the identifier
   --  of the Tuple (client_id, user, session) that describes the authentication.
   --  The <tt>Authenticate</tt> procedure should look in its database (internal
   --  or external) to find the authentication principal that was granted for
   --  the token Tuple.  When the token was not found (because it was revoked),
   --  the procedure should return a null principal.  If the authentication
   --  principal can be cached, the <tt>Cacheable</tt> value should be set.
   --  In that case, the access token and authentication  principal are inserted
   --  in a cache.
   procedure Authenticate (Realm     : in out Realm_Manager;
                           Token     : in String;
                           Auth      : out Principal_Access;
                           Cacheable : out Boolean) is abstract;

   --  Create an auth token string that identifies the given principal.  The returned
   --  token will be used by <tt>Authenticate</tt> to retrieve back the principal.  The
   --  returned token does not need to be signed.  It will be inserted in the public part
   --  of the returned access token.
   function Authorize (Realm : in Realm_Manager;
                       App   : in Application'Class;
                       Scope : in String;
                       Auth  : in Principal_Access) return String is abstract;

   procedure Verify (Realm    : in out Realm_Manager;
                     Username : in String;
                     Password : in String;
                     Auth     : out Principal_Access) is abstract;

   procedure Verify (Realm : in out Realm_Manager;
                     Token : in String;
                     Auth  : out Principal_Access) is abstract;

   procedure Revoke (Realm : in out Realm_Manager;
                     Auth  : in Principal_Access) is abstract;

   type Auth_Manager is tagged limited private;
   type Auth_Manager_Access is access all Auth_Manager'Class;

   --  Set the auth private key.
   procedure Set_Private_Key (Manager : in out Auth_Manager;
                              Key     : in String);

   --  Set the application manager to use and and applications.
   procedure Set_Application_Manager (Manager    : in out Auth_Manager;
                                      Repository : in Application_Manager_Access);

   --  Set the realm manager to authentify users.
   procedure Set_Realm_Manager (Manager : in out Auth_Manager;
                                Realm   : in Realm_Manager_Access);

   --  Authorize the access to the protected resource by the application and for the
   --  given principal.  The resource owner has been verified and is represented by the
   --  <tt>Auth</tt> principal.  Extract from the request parameters represented by
   --  <tt>Params</tt> the application client id, the scope and the expected response type.
   --  Handle the "Authorization Code Grant" and "Implicit Grant" defined in RFC 6749.
   procedure Authorize (Realm   : in out Auth_Manager;
                        Params  : in Security.Auth.Parameters'Class;
                        Auth    : in Security.Principal_Access;
                        Grant   : out Grant_Type);

   procedure Token (Realm   : in out Auth_Manager;
                    Params  : in Security.Auth.Parameters'Class;
                    Grant   : out Grant_Type);

   --  Make the access token from the authorization code that was created by the
   --  <tt>Authorize</tt> operation.  Verify the client application, the redirect uri, the
   --  client secret and the validity of the authorization code.  Extract from the
   --  authorization code the auth principal that was used for the grant and make the
   --  access token.
   procedure Token_From_Code (Realm   : in out Auth_Manager;
                              App     : in Application'Class;
                              Params  : in Security.Auth.Parameters'Class;
                              Grant   : out Grant_Type);

   procedure Authorize_Code (Realm   : in out Auth_Manager;
                             App     : in Application'Class;
                             Params  : in Security.Auth.Parameters'Class;
                             Auth    : in Security.Principal_Access;
                             Grant   : out Grant_Type);

   procedure Authorize_Token (Realm   : in out Auth_Manager;
                              App     : in Application'Class;
                              Params  : in Security.Auth.Parameters'Class;
                              Auth    : in Security.Principal_Access;
                              Grant   : out Grant_Type);

   --  Make the access token from the resource owner password credentials.  The username,
   --  password and scope are extracted from the request and they are verified through the
   --  <tt>Verify</tt> procedure to obtain an associated principal.  When successful, the
   --  principal describes the authorization and it is used to forge the access token.
   --  This operation implements the RFC 6749: 4.3.  Resource Owner Password Credentials Grant.
   procedure Token_From_Password (Realm   : in out Auth_Manager;
                                  App     : in Application'Class;
                                  Params  : in Security.Auth.Parameters'Class;
                                  Grant   : out Grant_Type);

   --  RFC 6749: 5.  Issuing an Access Token
   procedure Create_Token (Realm  : in Auth_Manager;
                           Ident  : in String;
                           Grant  : in out Grant_Type);

   --  Authenticate the access token and get a security principal that identifies the app/user.
   --  See RFC 6749, 7.  Accessing Protected Resources.
   --  The access token is first searched in the cache.  If it was found, it means the access
   --  token was already verified in the past, it is granted and associated with a principal.
   --  Otherwise, we have to verify the token signature first, then the expiration date and
   --  we extract from the token public part the auth identification.  The <tt>Authenticate</tt>
   --  operation is then called to obtain the principal from the auth identification.
   --  When access token is invalid or authentification cannot be verified, a null principal
   --  is returned.  The <tt>Grant</tt> data will hold the result of the grant with the reason
   --  of failures (if any).
   procedure Authenticate (Realm : in out Auth_Manager;
                           Token : in String;
                           Grant : out Grant_Type);

   procedure Revoke (Realm     : in out Auth_Manager;
                     Token     : in String);

private

   use Ada.Strings.Unbounded;

   function Format_Expire (Expire : in Ada.Calendar.Time) return String;

   type Application is new Security.OAuth.Application with record
      Expire_Timeout : Duration := 3600.0;
      Permissions    : Security.Permissions.Permission_Index_Set := Security.Permissions.EMPTY_SET;
   end record;

   type Cache_Entry is record
      Expire : Ada.Calendar.Time;
      Auth   : Principal_Access;
   end record;

   package Cache_Map is
     new Ada.Containers.Indefinite_Hashed_Maps (Key_Type        => String,
                                                Element_Type    => Cache_Entry,
                                                Hash            => Ada.Strings.Hash,
                                                Equivalent_Keys => "=",
                                                "="             => "=");

   --  The access token cache is used to speed up the access token verification
   --  when a request to a protected resource is made.
   protected type Token_Cache is

      procedure Authenticate (Token : in String;
                              Grant : in out Grant_Type);

      procedure Insert (Token     : in String;
                        Expire    : in Ada.Calendar.Time;
                        Principal : in Principal_Access);

      procedure Remove (Token : in String);

      procedure Timeout;

   private
      Entries : Cache_Map.Map;
   end Token_Cache;

   type Auth_Manager is new Ada.Finalization.Limited_Controlled with record
      --  The repository of applications.
      Repository  : Application_Manager_Access;

      --  The realm for user authentication.
      Realm       : Realm_Manager_Access;

      --  The server private key used by the HMAC signature.
      Private_Key : Ada.Strings.Unbounded.Unbounded_String;

      --  The access token cache.
      Cache       : Token_Cache;

      --  The expiration time for the generated authorization code.
      Expire_Code : Duration := 300.0;
   end record;

   --  The <tt>Token_Validity</tt> record provides information about a token to find out
   --  the different components it is made of and verify its validity.  The <tt>Validate</tt>
   --  procedure is in charge of checking the components and verifying the HMAC signature.
   --  The token has the following format:
   --  <expiration>.<client_id>.<auth-ident>.hmac(<public>.<private-key>)
   type Token_Validity is record
      Status       : Grant_Status := Invalid_Grant;
      Ident_Start  : Natural := 0;
      Ident_End    : Natural := 0;
      Expire       : Ada.Calendar.Time;
   end record;

   function Validate (Realm     : in Auth_Manager;
                      Client_Id : in String;
                      Token     : in String) return Token_Validity;

end Security.OAuth.Servers;
