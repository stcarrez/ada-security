-----------------------------------------------------------------------
--  security-oauth -- OAuth Security
--  Copyright (C) 2012, 2013 Stephane Carrez
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
with Util.Log.Loggers;
with Util.Strings;
with Util.Http.Clients;
with Util.Properties.JSON;
with Util.Encoders.HMAC.SHA1;
with Security.Random;

package body Security.OAuth.Clients is

   Log : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("Security.OAuth.Clients");

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
      use Ada.Strings.Unbounded;

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
      return Security.OAuth.Client_Id
        & "=" & Ada.Strings.Unbounded.To_String (App.Client_Id)
        & "&"
        & Security.OAuth.Redirect_Uri
        & "=" & Ada.Strings.Unbounded.To_String (App.Callback)
        & "&"
        & Security.OAuth.Scope
        & "=" & Scope
        & "&"
        & Security.OAuth.State
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

   --  ------------------------------
   --  Exchange the OAuth code into an access token.
   --  ------------------------------
   function Request_Access_Token (App  : in Application;
                                  Code : in String) return Access_Token_Access is
      Client   : Util.Http.Clients.Client;
      Response : Util.Http.Clients.Response;

      Data : constant String
        := Security.OAuth.Grant_Type & "=authorization_code"
          & "&"
        & Security.OAuth.Code & "=" & Code
        & "&"
        & Security.OAuth.Redirect_Uri & "=" & Ada.Strings.Unbounded.To_String (App.Callback)
        & "&"
        & Security.OAuth.Client_Id & "=" & Ada.Strings.Unbounded.To_String (App.Client_Id)
        & "&"
        & Security.OAuth.Client_Secret & "=" & Ada.Strings.Unbounded.To_String (App.Secret);
      URI : constant String := Ada.Strings.Unbounded.To_String (App.Request_URI);
   begin
      Log.Info ("Getting access token from {0}", URI);
      Client.Post (URL   => URI,
                   Data  => Data,
                   Reply => Response);
      if Response.Get_Status /= Util.Http.SC_OK then
         Log.Warn ("Cannot get access token from {0}: status is {1} Body {2}",
                   URI, Natural'Image (Response.Get_Status), Response.Get_Body);
         return null;
      end if;

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
               Expires := Natural'Value (P.Get ("expires_in"));
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
