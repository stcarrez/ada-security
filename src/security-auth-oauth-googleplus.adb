-----------------------------------------------------------------------
--  security-auth-oauth-googleplus -- Google+ OAuth based authentication
--  Copyright (C) 2013, 2020 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

with Util.Log.Loggers;
with Security.OAuth.JWT;
package body Security.Auth.OAuth.Googleplus is

   use Util.Log;

   Log : constant Loggers.Logger := Util.Log.Loggers.Create ("Security.Auth.OAuth.Googleplus");

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
   begin
      --  The token returned by Google+ must contain an id_token.
      if not (Token.all in Security.OAuth.Clients.OpenID_Token'Class) then
         Log.Warn ("Invalid token instance created: missing the id_token");
         Set_Result (Result, INVALID_SIGNATURE, "invalid access token returned");
         return;
      end if;

      --  The id_token is a JWT token that must be decoded and verified.
      --  See https://developers.google.com/accounts/docs/OAuth2Login#validatingtoken
      --  It contains information to identify the user.
      declare
         T : constant Security.OAuth.Clients.OpenID_Token_Access :=
           Security.OAuth.Clients.OpenID_Token'Class (Token.all)'Access;
         Info : constant Security.OAuth.JWT.Token := Security.OAuth.JWT.Decode (T.Get_Id_Token);
      begin
         --  Verify that the JWT token concerns our application.
         if Security.OAuth.JWT.Get_Audience (Info) /= Realm.App.Get_Application_Identifier then
            Set_Result (Result, INVALID_SIGNATURE,
                        "the access token was granted for another application");
            return;

            --  Verify that the issuer is Google+
         elsif Security.OAuth.JWT.Get_Issuer (Info) /= Realm.Issuer then
            Set_Result (Result, INVALID_SIGNATURE,
                        "the access token was not generated by the expected authority");
            return;

            --  Verify that the nonce we received matches our nonce.
         elsif Security.OAuth.JWT.Get_Claim (Info, "nonce") /= Assoc.Nonce then
            Set_Result (Result, INVALID_SIGNATURE,
                        "the access token was not generated with the expected nonce");
            return;

         end if;
         Result.Identity := To_Unbounded_String ("https://accounts.google.com/");
         Append (Result.Identity, Security.OAuth.JWT.Get_Subject (Info));
         Result.Claimed_Id := Result.Identity;

         --  The email is optional and depends on the scope.
         Result.Email := To_Unbounded_String (Security.OAuth.JWT.Get_Claim (Info, "email", ""));
         Set_Result (Result, AUTHENTICATED, "authenticated");
      end;
   end Verify_Access_Token;

end Security.Auth.OAuth.Googleplus;
