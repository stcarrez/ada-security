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

--  The <b>Security.OAuth.Clients</b> package implements the client OAuth 2.0 authorization.
--
--  Note: OAuth 1.0 could be implemented but since it's being deprecated it's not worth doing it.
package Security.OAuth.Clients is

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
