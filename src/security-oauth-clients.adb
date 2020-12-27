-----------------------------------------------------------------------
--  security-oauth-clients -- OAuth Client Security
--  Copyright (C) 2012, 2013, 2017, 2018, 2020 Stephane Carrez
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
with Ada.Exceptions;
with Util.Log.Loggers;
with Util.Strings;
with Util.Beans.Objects;
with Util.Http.Clients;
with Util.Properties.JSON;
with Util.Properties.Form;
with Util.Encoders.HMAC.SHA1;
with Security.Random;

package body Security.OAuth.Clients is

   use Ada.Strings.Unbounded;

   Log : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("Security.OAuth.Clients");

   procedure Do_Request_Token (URI  : in String;
                               Data : in Util.Http.Clients.Form_Data'Class;
                               Cred : in out Grant_Type'Class);

   function Get_Expires (Props : in Util.Properties.Manager) return Natural;

   --  ------------------------------
   --  Access Token
   --  ------------------------------

   Random_Generator : Security.Random.Generator;

   --  ------------------------------
   --  Generate a random nonce with at last the number of random bits.
   --  The number of bits is rounded up to a multiple of 32.
   --  The random bits are then converted to base64url in the returned string.
   --  ------------------------------
   function Create_Nonce (Bits : in Positive := 256) return String is
   begin
      --  Generate the random sequence.
      return Random_Generator.Generate (Bits);
   end Create_Nonce;

   --  ------------------------------
   --  Get the principal name.  This is the OAuth access token.
   --  ------------------------------
   function Get_Name (From : in Access_Token) return String is
   begin
      return From.Access_Id;
   end Get_Name;

   --  ------------------------------
   --  Get the id_token that was returned by the authentication process.
   --  ------------------------------
   function Get_Id_Token (From : in OpenID_Token) return String is
   begin
      return From.Id_Token;
   end Get_Id_Token;

   --  ------------------------------
   --  Get the principal name.  This is the OAuth access token.
   --  ------------------------------
   function Get_Name (From : in Grant_Type) return String is
   begin
      return To_String (From.Access_Token);
   end Get_Name;

   --  ------------------------------
   --  Get the Authorization header to be used for accessing a protected resource.
   --  (See RFC 6749 7.  Accessing Protected Resources)
   --  ------------------------------
   function Get_Authorization (From : in Grant_Type) return String is
   begin
      return "Bearer " & To_String (From.Access_Token);
   end Get_Authorization;

   --  ------------------------------
   --  Set the OAuth authorization server URI that the application must use
   --  to exchange the OAuth code into an access token.
   --  ------------------------------
   procedure Set_Provider_URI (App : in out Application;
                               URI : in String) is
   begin
      App.Request_URI := Ada.Strings.Unbounded.To_Unbounded_String (URI);
   end Set_Provider_URI;

   --  ------------------------------
   --  Build a unique opaque value used to prevent cross-site request forgery.
   --  The <b>Nonce</b> parameters is an optional but recommended unique value
   --  used only once.  The state value will be returned back by the OAuth provider.
   --  This protects the <tt>client_id</tt> and <tt>redirect_uri</tt> parameters.
   --  ------------------------------
   function Get_State (App   : in Application;
                       Nonce : in String) return String is
      Data : constant String := Nonce & To_String (App.Client_Id) & To_String (App.Callback);
      Hmac : String := Util.Encoders.HMAC.SHA1.Sign_Base64 (Key  => To_String (App.Secret),
                                                            Data => Data,
                                                            URL  => True);
   begin
      --  Avoid the '=' at end of HMAC since it could be replaced by %C20 which is annoying...
      Hmac (Hmac'Last) := '.';
      return Hmac;
   end Get_State;

   --  ------------------------------
   --  Get the authenticate parameters to build the URI to redirect the user to
   --  the OAuth authorization form.
   --  ------------------------------
   function Get_Auth_Params (App : in Application;
                             State : in String;
                             Scope : in String := "") return String is
   begin
      return Security.OAuth.CLIENT_ID
        & "=" & Ada.Strings.Unbounded.To_String (App.Client_Id)
        & "&"
        & Security.OAuth.REDIRECT_URI
        & "=" & Ada.Strings.Unbounded.To_String (App.Callback)
        & "&"
        & Security.OAuth.SCOPE
        & "=" & Scope
        & "&"
        & Security.OAuth.STATE
        & "=" & State;
   end Get_Auth_Params;

   --  ------------------------------
   --  Verify that the <b>State</b> opaque value was created by the <b>Get_State</b>
   --  operation with the given client and redirect URL.
   --  ------------------------------
   function Is_Valid_State (App   : in Application;
                            Nonce : in String;
                            State : in String) return Boolean is
      Hmac : constant String := Application'Class (App).Get_State (Nonce);
   begin
      return Hmac = State;
   end Is_Valid_State;

   function Get_Expires (Props : in Util.Properties.Manager) return Natural is
      Value : Util.Beans.Objects.Object;
   begin
      Value := Props.Get_Value ("expires_in");
      if Util.Beans.Objects.Is_Null (Value) then
         Value := Props.Get_Value ("refresh_token_expires_in");
         if Util.Beans.Objects.Is_Null (Value) then
            return 3600;
         end if;
      end if;
      return Util.Beans.Objects.To_Integer (Value);
   end Get_Expires;

   --  ------------------------------
   --  Exchange the OAuth code into an access token.
   --  ------------------------------
   function Request_Access_Token (App  : in Application;
                                  Code : in String) return Access_Token_Access is
      Client   : Util.Http.Clients.Client;
      Response : Util.Http.Clients.Response;

      Data : constant String
        := Security.OAuth.GRANT_TYPE & "=authorization_code"
          & "&"
        & Security.OAuth.CODE & "=" & Code
        & "&"
        & Security.OAuth.REDIRECT_URI & "=" & Ada.Strings.Unbounded.To_String (App.Callback)
        & "&"
        & Security.OAuth.CLIENT_ID & "=" & Ada.Strings.Unbounded.To_String (App.Client_Id)
        & "&"
        & Security.OAuth.CLIENT_SECRET & "=" & Ada.Strings.Unbounded.To_String (App.Secret);
      URI : constant String := Ada.Strings.Unbounded.To_String (App.Request_URI);
   begin
      Log.Info ("Getting access token from {0}", URI);
      begin
         Client.Post (URL   => URI,
                      Data  => Data,
                      Reply => Response);
         if Response.Get_Status /= Util.Http.SC_OK then
            Log.Warn ("Cannot get access token from {0}: status is {1} Body {2}",
                      URI, Natural'Image (Response.Get_Status), Response.Get_Body);
            return null;
         end if;

      exception
            --  Handle a Program_Error exception that could be raised by AWS when SSL
            --  is not supported.  Emit a log error so that we can trouble this kins of
            --  problem more easily.
         when E : Program_Error =>
            Log.Error ("Cannot get access token from {0}: program error: {1}",
                       URI, Ada.Exceptions.Exception_Message (E));
            raise;
      end;

      --  Decode the response.
      declare
         Content      : constant String := Response.Get_Body;
         Content_Type : constant String := Response.Get_Header ("Content-Type");
         Pos          : Natural := Util.Strings.Index (Content_Type, ';');
         Last         : Natural;
         Expires      : Natural;
      begin
         if Pos = 0 then
            Pos := Content_Type'Last;
         else
            Pos := Pos - 1;
         end if;
         Log.Debug ("Content type: {0}", Content_Type);
         Log.Debug ("Data: {0}", Content);

         --  Facebook sends the access token as a 'text/plain' content.
         if Content_Type (Content_Type'First .. Pos) = "text/plain" then
            Pos := Util.Strings.Index (Content, '=');
            if Pos = 0 then
               Log.Error ("Invalid access token response: '{0}'", Content);
               return null;
            end if;
            if Content (Content'First .. Pos) /= "access_token=" then
               Log.Error ("The 'access_token' parameter is missing in response: '{0}'", Content);
               return null;
            end if;
            Last := Util.Strings.Index (Content, '&', Pos + 1);
            if Last = 0 then
               Log.Error ("Invalid 'access_token' parameter: '{0}'", Content);
               return null;
            end if;
            if Content (Last .. Last + 8) /= "&expires=" then
               Log.Error ("Invalid 'expires' parameter: '{0}'", Content);
               return null;
            end if;
            Expires := Natural'Value (Content (Last + 9 .. Content'Last));
            return Application'Class (App).Create_Access_Token (Content (Pos + 1 .. Last - 1),
                                                                "", "",
                                                                Expires);

         elsif Content_Type (Content_Type'First .. Pos) = "application/json" then
            declare
               P : Util.Properties.Manager;
            begin
               Util.Properties.JSON.Parse_JSON (P, Content);
               Expires := Get_Expires (P);
               return Application'Class (App).Create_Access_Token (P.Get ("access_token"),
                                                                   P.Get ("refresh_token", ""),
                                                                   P.Get ("id_token", ""),
                                                                   Expires);
            end;

         elsif Content_Type (Content_Type'First .. Pos) = "application/x-www-form-urlencoded" then
            declare
               P : Util.Properties.Manager;
            begin
               Util.Properties.Form.Parse_Form (P, Content);
               Expires := Get_Expires (P);
               return Application'Class (App).Create_Access_Token (P.Get ("access_token"),
                                                                   P.Get ("refresh_token", ""),
                                                                   P.Get ("id_token", ""),
                                                                   Expires);
            end;

         else
            Log.Error ("Content type {0} not supported for access token response", Content_Type);
            Log.Error ("Response: {0}", Content);
            return null;
         end if;
      end;
   end Request_Access_Token;

   --  ------------------------------
   --  Exchange the OAuth code into an access token.
   --  ------------------------------
   procedure Do_Request_Token (URI  : in String;
                               Data : in Util.Http.Clients.Form_Data'Class;
                               Cred : in out Grant_Type'Class) is
      Client   : Util.Http.Clients.Client;
      Response : Util.Http.Clients.Response;
   begin
      Log.Info ("Getting access token from {0}", URI);
      Client.Post (URL   => URI,
                   Data  => Data,
                   Reply => Response);
      if Response.Get_Status /= Util.Http.SC_OK then
         Log.Warn ("Cannot get access token from {0}: status is {1} Body {2}",
                   URI, Natural'Image (Response.Get_Status), Response.Get_Body);
         return;
      end if;

      --  Decode the response.
      declare
         Content      : constant String := Response.Get_Body;
         Content_Type : constant String := Response.Get_Header ("Content-Type");
         Pos          : Natural := Util.Strings.Index (Content_Type, ';');
         Last         : Natural;
      begin
         if Pos = 0 then
            Pos := Content_Type'Last;
         else
            Pos := Pos - 1;
         end if;
         Log.Debug ("Content type: {0}", Content_Type);
         Log.Debug ("Data: {0}", Content);

         --  Facebook sends the access token as a 'text/plain' content.
         if Content_Type (Content_Type'First .. Pos) = "text/plain" then
            Pos := Util.Strings.Index (Content, '=');
            if Pos = 0 then
               Log.Error ("Invalid access token response: '{0}'", Content);
               return;
            end if;
            if Content (Content'First .. Pos) /= "access_token=" then
               Log.Error ("The 'access_token' parameter is missing in response: '{0}'", Content);
               return;
            end if;
            Last := Util.Strings.Index (Content, '&', Pos + 1);
            if Last = 0 then
               Log.Error ("Invalid 'access_token' parameter: '{0}'", Content);
               return;
            end if;
            if Content (Last .. Last + 8) /= "&expires=" then
               Log.Error ("Invalid 'expires' parameter: '{0}'", Content);
               return;
            end if;
            Cred.Expires := Natural'Value (Content (Last + 9 .. Content'Last));
            Cred.Access_Token := To_Unbounded_String (Content (Pos + 1 .. Last - 1));

         elsif Content_Type (Content_Type'First .. Pos) = "application/json" then
            declare
               P : Util.Properties.Manager;
            begin
               Util.Properties.JSON.Parse_JSON (P, Content);
               Cred.Expires := Natural'Value (P.Get ("expires_in"));
               Cred.Access_Token := P.Get ("access_token");
               Cred.Refresh_Token := To_Unbounded_String (P.Get ("refresh_token", ""));
               Cred.Id_Token := To_Unbounded_String (P.Get ("id_token", ""));
            end;
         else
            Log.Error ("Content type {0} not supported for access token response", Content_Type);
            Log.Error ("Response: {0}", Content);
            return;
         end if;
      end;
   exception
         --  Handle a Program_Error exception that could be raised by AWS when SSL
         --  is not supported.  Emit a log error so that we can trouble this kins of
         --  problem more easily.
      when E : Program_Error =>
         Log.Error ("Cannot get access token from {0}: program error: {1}",
                    URI, Ada.Exceptions.Exception_Message (E));
         raise;
   end Do_Request_Token;

   --  ------------------------------
   --  Get a request token with username and password.
   --  RFC 6749: 4.3.  Resource Owner Password Credentials Grant
   --  ------------------------------
   procedure Request_Token (App      : in Application;
                            Username : in String;
                            Password : in String;
                            Scope    : in String;
                            Token    : in out Grant_Type'Class) is
      URI  : constant String := Ada.Strings.Unbounded.To_String (App.Request_URI);
      Form : Util.Http.Clients.Form_Data;
   begin
      Log.Info ("Getting access token from {0} - resource owner password", URI);
      Form.Initialize (Size => 1024);
      Form.Write_Attribute (Security.OAuth.GRANT_TYPE, "password");
      Form.Write_Attribute (Security.OAuth.CLIENT_ID, App.Client_Id);
      Form.Write_Attribute (Security.OAuth.CLIENT_SECRET, App.Secret);
      Form.Write_Attribute (Security.OAuth.USERNAME, Username);
      Form.Write_Attribute (Security.OAuth.PASSWORD, Password);
      Form.Write_Attribute (Security.OAuth.SCOPE, Scope);
      Do_Request_Token (URI, Form, Token);
   end Request_Token;

   --  ------------------------------
   --  Refresh the access token.
   --  RFC 6749: 6.  Refreshing an Access Token
   --  ------------------------------
   procedure Refresh_Token (App      : in Application;
                            Scope    : in String;
                            Token    : in out Grant_Type'Class) is
      URI    : constant String := Ada.Strings.Unbounded.To_String (App.Request_URI);
      Form   : Util.Http.Clients.Form_Data;
   begin
      Log.Info ("Refresh access token from {0}", URI);
      Form.Initialize (Size => 1024);
      Form.Write_Attribute (Security.OAuth.GRANT_TYPE, "refresh_token");
      Form.Write_Attribute (Security.OAuth.REFRESH_TOKEN, Token.Refresh_Token);
      Form.Write_Attribute (Security.OAuth.CLIENT_ID, App.Client_Id);
      Form.Write_Attribute (Security.OAuth.SCOPE, Scope);
      Form.Write_Attribute (Security.OAuth.CLIENT_SECRET, App.Secret);
      Do_Request_Token (URI, Form, Token);
   end Refresh_Token;

   --  ------------------------------
   --  Create the access token
   --  ------------------------------
   function Create_Access_Token (App      : in Application;
                                 Token    : in String;
                                 Refresh  : in String;
                                 Id_Token : in String;
                                 Expires  : in Natural) return Access_Token_Access is
      pragma Unreferenced (App, Expires);

   begin
      if Id_Token'Length > 0 then
         declare
            Result : constant OpenID_Token_Access
              := new OpenID_Token '(Len         => Token'Length,
                                    Id_Len      => Id_Token'Length,
                                    Refresh_Len => Refresh'Length,
                                    Access_Id   => Token,
                                    Id_Token    => Id_Token,
                                    Refresh_Token => Refresh);
         begin
            return Result.all'Access;
         end;
      else
         return new Access_Token '(Len => Token'Length,
                                   Access_Id => Token);
      end if;
   end Create_Access_Token;

end Security.OAuth.Clients;
