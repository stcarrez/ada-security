-----------------------------------------------------------------------
--  security-oauth -- OAuth Security
--  Copyright (C) 2012, 2016, 2017, 2018, 2019 Stephane Carrez
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

--  = OAuth =
--  The <b>Security.OAuth</b> package defines and implements the OAuth 2.0 authorization
--  framework as defined by the IETF working group in RFC 6749:
--  The OAuth 2.0 Authorization Framework.
--
--  @include security-oauth-clients.ads
--  @include security-oauth-servers.ads
package Security.OAuth is

   --  OAuth 2.0: Section 10.2.2. Initial Registry Contents
   --  RFC 6749: 11.2.2.  Initial Registry Contents
   CLIENT_ID         : constant String := "client_id";
   CLIENT_SECRET     : constant String := "client_secret";
   RESPONSE_TYPE     : constant String := "response_type";
   REDIRECT_URI      : constant String := "redirect_uri";
   SCOPE             : constant String := "scope";
   STATE             : constant String := "state";
   CODE              : constant String := "code";
   ERROR_DESCRIPTION : constant String := "error_description";
   ERROR_URI         : constant String := "error_uri";
   GRANT_TYPE        : constant String := "grant_type";
   ACCESS_TOKEN      : constant String := "access_token";
   TOKEN_TYPE        : constant String := "token_type";
   EXPIRES_IN        : constant String := "expires_in";
   USERNAME          : constant String := "username";
   PASSWORD          : constant String := "password";
   REFRESH_TOKEN     : constant String := "refresh_token";

   --  RFC 6749: 5.2.  Error Response
   INVALID_REQUEST        : aliased constant String := "invalid_request";
   INVALID_CLIENT         : aliased constant String := "invalid_client";
   INVALID_GRANT          : aliased constant String := "invalid_grant";
   UNAUTHORIZED_CLIENT    : aliased constant String := "unauthorized_client";
   UNSUPPORTED_GRANT_TYPE : aliased constant String := "unsupported_grant_type";
   INVALID_SCOPE          : aliased constant String := "invalid_scope";

   --  RFC 6749: 4.1.2.1.  Error Response
   ACCESS_DENIED             : aliased constant String := "access_denied";
   UNSUPPORTED_RESPONSE_TYPE : aliased constant String := "unsupported_response_type";
   SERVER_ERROR              : aliased constant String := "server_error";
   TEMPORARILY_UNAVAILABLE   : aliased constant String := "temporarily_unavailable";

   type Client_Authentication_Type is (AUTH_NONE, AUTH_BASIC);

   --  ------------------------------
   --  Application
   --  ------------------------------
   --  The <b>Application</b> holds the necessary information to let a user
   --  grant access to its protected resources on the resource server.  It contains
   --  information that allows the OAuth authorization server to identify the
   --  application (client id and secret key).
   type Application is tagged private;

   --  Get the application identifier.
   function Get_Application_Identifier (App : in Application) return String;

   --  Set the application identifier used by the OAuth authorization server
   --  to identify the application (for example, the App ID in Facebook).
   procedure Set_Application_Identifier (App    : in out Application;
                                         Client : in String);

   --  Set the application secret defined in the OAuth authorization server
   --  for the application (for example, the App Secret in Facebook).
   procedure Set_Application_Secret (App    : in out Application;
                                     Secret : in String);

   --  Set the redirection callback that will be used to redirect the user
   --  back to the application after the OAuth authorization is finished.
   procedure Set_Application_Callback (App : in out Application;
                                       URI : in String);

   --  Set the client authentication method used when doing OAuth calls for this application.
   --  See RFC 6749, 2.3.  Client Authentication
   procedure Set_Client_Authentication (App    : in out Application;
                                        Method : in Client_Authentication_Type);

private

   type Application is tagged record
      Client_Id   : Ada.Strings.Unbounded.Unbounded_String;
      Secret      : Ada.Strings.Unbounded.Unbounded_String;
      Callback    : Ada.Strings.Unbounded.Unbounded_String;
      Client_Auth : Client_Authentication_Type := AUTH_NONE;
   end record;

end Security.OAuth;
