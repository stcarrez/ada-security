-----------------------------------------------------------------------
--  security-auth-oauth -- OAuth based authentication
--  Copyright (C) 2013 Stephane Carrez
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
with Security.OAuth.Clients;
package body Security.Auth.OAuth is

   Log : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("Security.Auth.OAuth");

   --  ------------------------------
   --  OAuth Manager
   --  ------------------------------
   --  The <b>Manager</b> provides the core operations for the OAuth authorization process.

   --  Initialize the authentication realm.
   overriding
   procedure Initialize (Realm     : in out Manager;
                         Params    : in Parameters'Class;
                         Provider  : in String := PROVIDER_OPENID) is
   begin
      Realm.App.Set_Application_Identifier (Params.Get_Parameter (Provider & ".client_id"));
      Realm.App.Set_Application_Secret (Params.Get_Parameter (Provider & ".secret"));
      Realm.App.Set_Application_Callback (Params.Get_Parameter (Provider & ".callback_url"));
      Realm.App.Set_Provider_URI (Params.Get_Parameter (Provider & ".request_url"));
      Realm.Realm := To_Unbounded_String (Params.Get_Parameter (Provider & ".realm"));
      Realm.Scope := To_Unbounded_String (Params.Get_Parameter (Provider & ".scope"));
   end Initialize;

   --  Discover the OpenID provider that must be used to authenticate the user.
   --  The <b>Name</b> can be an URL or an alias that identifies the provider.
   --  A cached OpenID provider can be returned.
   --  Read the XRDS document from the URI and initialize the OpenID provider end point.
   --  (See OpenID Section 7.3 Discovery)
   overriding
   procedure Discover (Realm  : in out Manager;
                       Name   : in String;
                       Result : out End_Point) is
   begin
      Result.URL := To_Unbounded_String (Name);
   end Discover;

   --  Associate the application (relying party) with the OpenID provider.
   --  The association can be cached.
   --  (See OpenID Section 8 Establishing Associations)
   overriding
   procedure Associate (Realm  : in out Manager;
                        OP     : in End_Point;
                        Result : out Association) is
   begin
      null;
   end Associate;

   overriding
   function Get_Authentication_URL (Realm : in Manager;
                                    OP    : in End_Point;
                                    Assoc : in Association) return String is
      Result : Unbounded_String := OP.URL;
      State  : constant String := Realm.App.Get_State (To_String (Assoc.Assoc_Handle));
      Params : constant String := Realm.App.Get_Auth_Params (State, To_String (Realm.Scope));
   begin
      if Index (Result, "?") > 0 then
         Append (Result, "&");
      else
         Append (Result, "?");
      end if;
      Append (Result, Params);

      Log.Debug ("Params = {0}", Params);
      return To_String (Result);
   end Get_Authentication_URL;

   --  Verify the authentication result
   overriding
   procedure Verify (Realm   : in out Manager;
                     Assoc   : in Association;
                     Request : in Parameters'Class;
                     Result  : out Authentication) is
      State : constant String := Request.Get_Parameter (Security.OAuth.State);
      Code  : constant String := Request.Get_Parameter (Security.OAuth.Code);
      Error : constant String := Request.Get_Parameter (Security.OAuth.Error_Description);
   begin
      if Error'Length /= 0 then
         Set_Result (Result, CANCEL, "Authentication refused: " & Error);
         return;
      end if;

      --  First, verify that the state parameter matches our internal state.
      if not Realm.App.Is_Valid_State (To_String (Assoc.Assoc_Handle), State) then
         Set_Result (Result, INVALID_SIGNATURE, "invalid OAuth state parameter");
         return;
      end if;

      --  Get the access token from the authorization code.
      declare
         use type Security.OAuth.Clients.Access_Token_Access;

         Acc : constant Security.OAuth.Clients.Access_Token_Access
           := Realm.App.Request_Access_Token (Code);
      begin
         if Acc = null then
            Set_Result (Result, INVALID_SIGNATURE, "cannot change the code to an access_token");
            return;
         end if;

         --  Last step, verify the access token and get the user identity.
         Manager'Class (Realm).Verify_Access_Token (Assoc, Request, Acc, Result);
      end;

   end Verify;

end Security.Auth.OAuth;
