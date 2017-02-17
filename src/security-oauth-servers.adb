-----------------------------------------------------------------------
--  security-oauth-servers -- OAuth Server Authentication Support
--  Copyright (C) 2016 Stephane Carrez
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
with Ada.Calendar.Conversions;
with Interfaces.C;

with Util.Log.Loggers;
with Util.Encoders.Base64;
with Util.Encoders.HMAC.SHA1;

package body Security.OAuth.Servers is

   use type Ada.Calendar.Time;

   Log : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("Security.OAuth.Servers");

   --  ------------------------------
   --  Check if the application has the given permission.
   --  ------------------------------
   function Has_Permission (App        : in Application;
                            Permission : in Permissions.Permission_Index) return Boolean is
   begin
      return Security.Permissions.Has_Permission (App.Permissions, Permission);
   end Has_Permission;

   protected body Token_Cache is

      procedure Authenticate (Token : in String;
                              Grant : in out Grant_Type) is
         Pos : Cache_Map.Cursor := Entries.Find (Token);
      begin
         if Cache_Map.Has_Element (Pos) then
            if Grant.Expires < Ada.Calendar.Clock then
               Entries.Delete (Pos);
               Grant.Status := Expired_Grant;
            else
               Grant.Auth    := Cache_Map.Element (Pos).Auth;
               Grant.Expires := Cache_Map.Element (Pos).Expire;
               Grant.Status  := Valid_Grant;
            end if;
         else
            Grant.Status := Invalid_Grant;
         end if;
      end Authenticate;

      procedure Insert (Token     : in String;
                        Expire    : in Ada.Calendar.Time;
                        Principal : in Principal_Access) is
      begin
         Entries.Insert (Token, Cache_Entry '(Expire, Principal));
      end Insert;

      procedure Remove (Token : in String) is
      begin
         null;
      end Remove;

      procedure Timeout is
      begin
         null;
      end Timeout;

   end Token_Cache;

   --  ------------------------------
   --  Set the auth private key.
   --  ------------------------------
   procedure Set_Private_Key (Manager : in out Auth_Manager;
                              Key     : in String) is
   begin
      Manager.Private_Key := To_Unbounded_String (Key);
   end Set_Private_Key;

   --  ------------------------------
   --  Set the application manager to use and and applications.
   --  ------------------------------
   procedure Set_Application_Manager (Manager    : in out Auth_Manager;
                                      Repository : in Application_Manager_Access) is
   begin
      Manager.Repository := Repository;
   end Set_Application_Manager;

   --  ------------------------------
   --  Set the realm manager to authentify users.
   --  ------------------------------
   procedure Set_Realm_Manager (Manager : in out Auth_Manager;
                                Realm   : in Realm_Manager_Access) is
   begin
      Manager.Realm := Realm;
   end Set_Realm_Manager;

   --  ------------------------------
   --  Authorize the access to the protected resource by the application and for the
   --  given principal.  The resource owner has been verified and is represented by the
   --  <tt>Auth</tt> principal.  Extract from the request parameters represented by
   --  <tt>Params</tt> the application client id, the scope and the expected response type.
   --  Handle the "Authorization Code Grant" and "Implicit Grant" defined in RFC 6749.
   --  ------------------------------
   procedure Authorize (Realm   : in out Auth_Manager;
                        Params  : in Security.Auth.Parameters'Class;
                        Auth    : in Security.Principal_Access;
                        Grant   : out Grant_Type) is
      Method    : constant String := Params.Get_Parameter (Security.OAuth.RESPONSE_TYPE);
      Client_Id : constant String := Params.Get_Parameter (Security.OAuth.CLIENT_ID);
   begin
      if Client_Id'Length = 0 then
         Grant.Status := Invalid_Grant;
         Grant.Error  := INVALID_REQUEST'Access;
         return;
      end if;
      declare
         App : constant Application'Class := Realm.Repository.Find_Application (Client_Id);
      begin
         if Method = "code" then
            Realm.Authorize_Code (App, Params, Auth, Grant);
         elsif Method = "token" then
            Realm.Authorize_Token (App, Params, Auth, Grant);
         else
            Grant.Status := Invalid_Grant;
            Grant.Error := UNSUPPORTED_RESPONSE_TYPE'Access;
         end if;
      end;

   exception
      when Invalid_Application =>
         Log.Warn ("Invalid client_id {0}", Client_Id);
         Grant.Status := Invalid_Grant;
         Grant.Error  := INVALID_CLIENT'Access;
         return;

      when E : others =>
         Log.Error ("Error while doing authorization for client_id " & Client_Id, E);
         Grant.Status := Invalid_Grant;
         Grant.Error  := SERVER_ERROR'Access;

   end Authorize;

   --
   --  client_id, callback_uri, secret_id -> application
   procedure Token (Realm   : in out Auth_Manager;
                    Params  : in Security.Auth.Parameters'Class;
                    Grant   : out Grant_Type) is
      Method    : constant String := Params.Get_Parameter (Security.OAuth.GRANT_TYPE);
      Client_Id : constant String := Params.Get_Parameter (Security.OAuth.CLIENT_ID);
   begin
      if Client_Id'Length = 0 then
         Grant.Status := Invalid_Grant;
         Grant.Error := INVALID_REQUEST'Access;
         return;
      end if;
      declare
         App : constant Application'Class := Realm.Repository.Find_Application (Client_Id);
      begin
         if Method = "authorization_code" then
            Realm.Token_From_Code (App, Params, Grant);
         elsif Method = "password" then
            Realm.Token_From_Password (App, Params, Grant);
         elsif Method = "refresh_token" then
            Grant.Error := UNSUPPORTED_GRANT_TYPE'Access;
         elsif Method = "client_credentials" then
            Grant.Error := UNSUPPORTED_GRANT_TYPE'Access;
         else
            Grant.Error := UNSUPPORTED_GRANT_TYPE'Access;
            Log.Warn ("Grant type {0} is not supported", Method);
         end if;
      end;

   exception
      when Invalid_Application =>
         Log.Warn ("Invalid client_id {0}", Client_Id);
         Grant.Status := Invalid_Grant;
         Grant.Error  := INVALID_CLIENT'Access;
         return;
   end Token;

   --  ------------------------------
   --  Format the expiration date to a compact string.  The date is transformed to a Unix
   --  date and encoded in LEB128 + base64url.
   --  ------------------------------
   function Format_Expire (Expire : in Ada.Calendar.Time) return String is
      T : constant Interfaces.C.Long := Ada.Calendar.Conversions.To_Unix_Time (Expire);
   begin
      return Util.Encoders.Base64.Encode (Interfaces.Unsigned_64 (T));
   end Format_Expire;

   --  ------------------------------
   --  Decode the expiration date that was extracted from the token.
   --  ------------------------------
   function Parse_Expire (Expire : in String) return Ada.Calendar.Time is
      V : constant Interfaces.Unsigned_64 := Util.Encoders.Base64.Decode (Expire);
   begin
      return Ada.Calendar.Conversions.To_Ada_Time (Interfaces.C.Long (V));
   end Parse_Expire;

   --  Implement the RFC 6749: 4.1.1.  Authorization Request for the authorization code grant.
   procedure Authorize_Code (Realm   : in out Auth_Manager;
                             App     : in Application'Class;
                             Params  : in Security.Auth.Parameters'Class;
                             Auth    : in Security.Principal_Access;
                             Grant   : out Grant_Type) is
      Callback  : constant String := Params.Get_Parameter (Security.OAuth.REDIRECT_URI);
      Scope     : constant String := Params.Get_Parameter (Security.OAuth.SCOPE);
   begin
      Grant.Request := Code_Grant;
      Grant.Status  := Invalid_Grant;
      if Auth = null then
         Log.Info ("Authorization is denied");
         Grant.Error := ACCESS_DENIED'Access;

      elsif App.Callback /= Callback then
         Log.Info ("Invalid application callback");
         Grant.Error := UNAUTHORIZED_CLIENT'Access;

      else
         --  Manager'Class (Realm).Authorize (Auth, Scope);
         Grant.Expires := Ada.Calendar.Clock + Realm.Expire_Code;
         Grant.Status  := Valid_Grant;
         Grant.Auth    := Auth;
         Realm.Create_Token (Realm.Realm.Authorize (App, Scope, Auth), Grant);
      end if;
   end Authorize_Code;

   --  Implement the RFC 6749: 4.2.1.  Authorization Request for the implicit grant.
   procedure Authorize_Token (Realm   : in out Auth_Manager;
                              App     : in Application'Class;
                              Params  : in Security.Auth.Parameters'Class;
                              Auth    : in Security.Principal_Access;
                              Grant   : out Grant_Type) is
      Callback  : constant String := Params.Get_Parameter (Security.OAuth.REDIRECT_URI);
      Scope     : constant String := Params.Get_Parameter (Security.OAuth.SCOPE);
   begin
      Grant.Request := Implicit_Grant;
      Grant.Status  := Invalid_Grant;
      if Auth = null then
         Log.Info ("Authorization is denied");
         Grant.Error := ACCESS_DENIED'Access;

      elsif App.Callback /= Callback then
         Log.Info ("Invalid application callback");
         Grant.Error := UNAUTHORIZED_CLIENT'Access;

      else
         Grant.Expires := Ada.Calendar.Clock + App.Expire_Timeout;
         Grant.Status  := Valid_Grant;
         Grant.Auth    := Auth;
         Realm.Create_Token (Realm.Realm.Authorize (App, Scope, Grant.Auth), Grant);
      end if;
   end Authorize_Token;

   --  Make the access token from the authorization code that was created by the
   --  <tt>Authorize</tt> operation.  Verify the client application, the redirect uri, the
   --  client secret and the validity of the authorization code.  Extract from the
   --  authorization code the auth principal that was used for the grant and make the
   --  access token.
   procedure Token_From_Code (Realm   : in out Auth_Manager;
                              App     : in Application'Class;
                              Params  : in Security.Auth.Parameters'Class;
                              Grant   : out Grant_Type) is
      Code      : constant String := Params.Get_Parameter (Security.OAuth.CODE);
      Callback  : constant String := Params.Get_Parameter (Security.OAuth.REDIRECT_URI);
      Secret    : constant String := Params.Get_Parameter (Security.OAuth.CLIENT_SECRET);
      Token     : Token_Validity;
   begin
      Grant.Request := Code_Grant;
      Grant.Status  := Invalid_Grant;
      if Code'Length = 0 then
         Log.Info ("Missing authorization code request parameter");
         Grant.Error := INVALID_REQUEST'Access;

      elsif App.Secret /= Secret then
         Log.Info ("Invalid application secret");
         Grant.Error := UNAUTHORIZED_CLIENT'Access;

      elsif App.Callback /= Callback then
         Log.Info ("Invalid application callback");
         Grant.Error := UNAUTHORIZED_CLIENT'Access;

      else
         Token := Realm.Validate (To_String (App.Client_Id), Code);
         Grant.Status := Token.Status;
         if Token.Status /= Valid_Grant then
            Log.Info ("Invalid authorization code {0}", Code);
            Grant.Error := ACCESS_DENIED'Access;
         else
            --  Verify the identification token and get the principal.
            Realm.Realm.Verify (Code (Token.Ident_Start .. Token.Ident_End), Grant.Auth);
            if Grant.Auth = null then
               Log.Info ("Access denied for authorization code {0}", Code);
               Grant.Error := ACCESS_DENIED'Access;
            else
               --  Extract user/session ident from code.
               Grant.Expires := Ada.Calendar.Clock + App.Expire_Timeout;
               Grant.Error   := null;
               Realm.Create_Token (Realm.Realm.Authorize (App, Scope, Grant.Auth), Grant);
            end if;
         end if;
      end if;
   end Token_From_Code;

   --  ------------------------------
   --  Make the access token from the resource owner password credentials.  The username,
   --  password and scope are extracted from the request and they are verified through the
   --  <tt>Verify</tt> procedure to obtain an associated principal.  When successful, the
   --  principal describes the authorization and it is used to forge the access token.
   --  This operation implements the RFC 6749: 4.3.  Resource Owner Password Credentials Grant.
   --  ------------------------------
   procedure Token_From_Password (Realm   : in out Auth_Manager;
                                  App     : in Application'Class;
                                  Params  : in Security.Auth.Parameters'Class;
                                  Grant   : out Grant_Type) is
      Username  : constant String := Params.Get_Parameter (Security.OAuth.USERNAME);
      Password  : constant String := Params.Get_Parameter (Security.OAuth.PASSWORD);
      Scope     : constant String := Params.Get_Parameter (Security.OAuth.SCOPE);
   begin
      Grant.Request := Password_Grant;
      Grant.Status  := Invalid_Grant;
      if Username'Length = 0 then
         Log.Info ("Missing username request parameter");
         Grant.Error := INVALID_REQUEST'Access;

      elsif Password'Length = 0 then
         Log.Info ("Missing password request parameter");
         Grant.Error := INVALID_REQUEST'Access;
      else
         --  Verify the username and password to get the principal.
         Realm.Realm.Verify (Username, Password, Grant.Auth);
         if Grant.Auth = null then
            Log.Info ("Access denied for {0}", Username);
            Grant.Error := ACCESS_DENIED'Access;
         else
            Grant.Status  := Valid_Grant;
            Grant.Expires := Ada.Calendar.Clock + App.Expire_Timeout;
            Grant.Error   := null;
            Realm.Create_Token (Realm.Realm.Authorize (App, Scope, Grant.Auth), Grant);
         end if;
      end if;
   end Token_From_Password;

   --  Forge an access token
   --  RFC 6749: 5.  Issuing an Access Token
   procedure Create_Token (Realm  : in Auth_Manager;
                           Ident  : in String;
                           Grant  : in out Grant_Type) is
      Exp   : constant String := Format_Expire (Grant.Expires);
      Data  : constant String := Exp & "." & Ident;
      Hmac  : constant String
        := Util.Encoders.HMAC.SHA1.Sign_Base64 (Key  => To_String (Realm.Private_Key),
                                                Data => Data,
                                                URL  => True);
   begin
      Grant.Token := Ada.Strings.Unbounded.To_Unbounded_String (Data & "." & Hmac);
   end Create_Token;

   --  Validate the token by checking that it is well formed, it has not expired
   --  and the HMAC-SHA1 signature is valid.  Return the set of information to allow
   --  the extraction of the auth identification from the token public part.
   function Validate (Realm     : in Auth_Manager;
                      Client_Id : in String;
                      Token     : in String) return Token_Validity is
      Pos1   : constant Natural := Util.Strings.Index (Token, '.');
      Pos2   : constant Natural := Util.Strings.Rindex (Token, '.');
      Result : Token_Validity := (Status => Invalid_Grant, others => <>);
   begin
      --  Verify the access token validity.
      if Pos1 = 0 or Pos2 = 0 or Pos1 = Pos2 then
         Log.Info ("Authenticate bad formed access token {0}", Token);
         return Result;
      end if;

      --  Build the HMAC signature with the private key.
      declare
         Hmac : constant String
           := Util.Encoders.HMAC.SHA1.Sign_Base64 (Key  => To_String (Realm.Private_Key),
                                                   Data => Token (Token'First .. Pos2 - 1),
                                                   URL  => True);
      begin
         --  Check the HMAC signature part.
         if Token (Pos2 + 1 .. Token'Last) /= Hmac then
            Log.Info ("Bad signature for access token {0}", Token);
            return Result;
         end if;

         --  Signature is valid we can check the token expiration date.
         Result.Expire := Parse_Expire (Token (Token'First .. Pos1 - 1));
         if Result.Expire < Ada.Calendar.Clock then
            Log.Info ("Token {0} has expired", Token);
            Result.Status := Expired_Grant;
            return Result;
         end if;

         Result.Ident_Start := Pos1 + 1;
         Result.Ident_End   := Pos2 - 1;

         --  When an identifier is passed, verify it.
         if Client_Id'Length > 0 then
            Result.Ident_Start := Util.Strings.Index (Token, '.', Pos1 + 1);
            if Result.Ident_Start = 0
              or else Client_Id /= Token (Pos1 + 1 .. Result.Ident_Start - 1)
            then
               Log.Info ("Token {0} was stealed for another application", Token);
               Result.Status := Stealed_Grant;
               return Result;
            end if;
         end if;

         --  The access token is valid.
         Result.Status := Valid_Grant;
         return Result;
      end;

   exception
      when E : others =>
         --  No exception should ever be raised because we verify the signature first.
         Log.Error ("Token " & Token & " raised an exception", E);
         Result.Status := Invalid_Grant;
         return Result;

   end Validate;

   --  ------------------------------
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
   --  ------------------------------
   procedure Authenticate (Realm  : in out Auth_Manager;
                           Token  : in String;
                           Grant  : out Grant_Type) is
      Cacheable : Boolean;
      Check     : Token_Validity;
   begin
      Grant.Request := Access_Grant;
      Grant.Status  := Invalid_Grant;
      Realm.Cache.Authenticate (Token, Grant);
      if Grant.Auth /= null then
         Log.Debug ("Authenticate access token {0} succeeded from cache", Token);
         return;
      end if;

      Check := Realm.Validate ("", Token);
      Grant.Status := Check.Status;
      if Check.Status = Expired_Grant then
         Log.Info ("Access token {0} has expired", Token);

      elsif Check.Status /= Valid_Grant then
         Log.Info ("Access token {0} is invalid", Token);

      else
         --  The access token is valid, well formed and has not expired.
         --  Get the associated principal (the only possibility it could fail is
         --  that it was revoked).
         Realm.Realm.Authenticate (Token (Check.Ident_Start .. Check.Ident_End),
                                   Grant.Auth, Cacheable);
         if Grant.Auth = null then
            Log.Info ("Access token {0} was revoked", Token);
            Grant.Status := Revoked_Grant;

            --  We are allowed to keep the token in the cache, insert it.
         elsif Cacheable then
            Realm.Cache.Insert (Token, Check.Expire, Grant.Auth);
            Log.Debug ("Access token {0} is granted and inserted in the cache", Token);

         else
            Log.Debug ("Access token {0} is granted", Token);
         end if;
      end if;
   end Authenticate;

   procedure Revoke (Realm     : in out Auth_Manager;
                     Token     : in String) is
      Check     : Token_Validity;
      Auth      : Principal_Access;
      Cacheable : Boolean;
   begin
      Check := Realm.Validate ("", Token);
      if Check.Status = Valid_Grant then

         --  The access token is valid, well formed and has not expired.
         --  Get the associated principal (the only possibility it could fail is
         --  that it was revoked).
         Realm.Realm.Authenticate (Token (Check.Ident_Start .. Check.Ident_End),
                                   Auth, Cacheable);
         if Auth /= null then
            Realm.Cache.Remove (Token);
            Realm.Realm.Revoke (Auth);
         end if;
      end if;
   end Revoke;

end Security.OAuth.Servers;
