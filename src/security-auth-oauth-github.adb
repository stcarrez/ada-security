-----------------------------------------------------------------------
--  security-auth-oauth-github -- Github OAuth based authentication
--  Copyright (C) 2020 Stephane Carrez
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
with Util.Http.Clients;
with Util.Properties.JSON;
package body Security.Auth.OAuth.Github is

   use Util.Log;

   Log : constant Loggers.Logger := Util.Log.Loggers.Create ("Security.Auth.OAuth.Github");

   --  ------------------------------
   --  Verify the OAuth access token and retrieve information about the user.
   --  ------------------------------
   overriding
   procedure Verify_Access_Token (Realm   : in Manager;
                                  Assoc   : in Association;
                                  Request : in Parameters'Class;
                                  Token   : in Security.OAuth.Clients.Access_Token_Access;
                                  Result  : in out Authentication) is
      pragma Unreferenced (Request);

      URI      : constant String := "https://api.github.com/user";
      Http     : Util.Http.Clients.Client;
      Reply    : Util.Http.Clients.Response;
      Props    : Util.Properties.Manager;
   begin
      Http.Add_Header ("Authorization", "token " & Token.Get_Name);
      Http.Get (URI, Reply);
      if Reply.Get_Status /= Util.Http.SC_OK then
         Log.Warn ("Cannot retrieve Github user information");
         Set_Result (Result, INVALID_SIGNATURE, "invalid access token");
         return;
      end if;

      Util.Properties.JSON.Parse_JSON (Props, Reply.Get_Body);

      Result.Identity := Realm.Issuer;
      Append (Result.Identity, "/");
      Append (Result.Identity, String '(Props.Get ("id")));
      Result.Claimed_Id := Result.Identity;
      Result.First_Name := To_Unbounded_String (Props.Get ("name"));
      Result.Full_Name := To_Unbounded_String (Props.Get ("name"));

      --  The email is optional and depends on the scope.
      Result.Email := To_Unbounded_String (Props.Get ("email"));
      Set_Result (Result, AUTHENTICATED, "authenticated");
   end Verify_Access_Token;

end Security.Auth.OAuth.Github;
