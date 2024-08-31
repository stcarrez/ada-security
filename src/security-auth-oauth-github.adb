-----------------------------------------------------------------------
--  security-auth-oauth-github -- Github OAuth based authentication
--  Copyright (C) 2020, 2021 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
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
      pragma Unreferenced (Assoc, Request);

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
