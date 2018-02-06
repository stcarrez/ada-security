-----------------------------------------------------------------------
--  Security-oauth-servers-tests - Unit tests for server side OAuth
--  Copyright (C) 2017, 2018 Stephane Carrez
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
with Util.Test_Caller;

with Security.Auth.Tests;
with Security.OAuth.File_Registry;
package body Security.OAuth.Servers.Tests is

   use Auth.Tests;
   use File_Registry;

   package Caller is new Util.Test_Caller (Test, "Security.OAuth.Servers");

   procedure Add_Tests (Suite : in Util.Tests.Access_Test_Suite) is
   begin
      Caller.Add_Test (Suite, "Test Security.OAuth.Servers.Find_Application",
                       Test_Application_Manager'Access);
      Caller.Add_Test (Suite, "Test Security.OAuth.Servers.Verify",
                       Test_User_Verify'Access);
      Caller.Add_Test (Suite, "Test Security.OAuth.Servers.Token",
                       Test_Token_Password'Access);
      Caller.Add_Test (Suite, "Test Security.OAuth.Servers.Authenticate",
                       Test_Bad_Token'Access);
      Caller.Add_Test (Suite, "Test Security.OAuth.File_Registry.Load",
                       Test_Load_Registry'Access);
   end Add_Tests;

   --  ------------------------------
   --  Test the application manager.
   --  ------------------------------
   procedure Test_Application_Manager (T : in out Test) is
      Manager : File_Application_Manager;
      App     : Application;
   begin
      App.Set_Application_Identifier ("my-app-id");
      App.Set_Application_Secret ("my-secret");
      App.Set_Application_Callback ("my-callback");
      Manager.Add_Application (App);

      --  Check that we can find our application.
      declare
         A : constant Application'Class := Manager.Find_Application ("my-app-id");
      begin
         Util.Tests.Assert_Equals (T, "my-app-id", A.Get_Application_Identifier,
                                   "Invalid application returned by Find");
      end;

      --  Check that an exception is raised for an invalid client ID.
      begin
         declare
            A : constant Application'Class := Manager.Find_Application ("unkown-app-id");
         begin
            Util.Tests.Fail (T, "Found the application " & A.Get_Application_Identifier);
         end;

      exception
         when Invalid_Application =>
            null;
      end;
   end Test_Application_Manager;

   --  ------------------------------
   --  Test the user registration and verification.
   --  ------------------------------
   procedure Test_User_Verify (T : in out Test) is
      Manager : File_Realm_Manager;
      Auth    : Principal_Access;
   begin
      Manager.Add_User ("Gandalf", "Mithrandir");
      Manager.Verify ("Gandalf", "mithrandir", Auth);
      T.Assert (Auth = null, "Verify password should fail with an invalid password");

      Manager.Verify ("Sauron", "Mithrandir", Auth);
      T.Assert (Auth = null, "Verify password should fail with an invalid user");

      Manager.Verify ("Gandalf", "Mithrandir", Auth);
      T.Assert (Auth /= null, "Verify password operation failed for a good user/password");
   end Test_User_Verify;

   --  ------------------------------
   --  Test the token operation that produces an access token from user/password.
   --  RFC 6749: Section 4.3.  Resource Owner Password Credentials Grant
   --  ------------------------------
   procedure Test_Token_Password (T : in out Test) is
      use type Util.Strings.Name_Access;

      Apps       : aliased File_Application_Manager;
      Realm      : aliased File_Realm_Manager;
      Manager    : Auth_Manager;
      App        : Application;
      Grant      : Grant_Type;
      Auth_Grant : Grant_Type;
      Params     : Test_Parameters;
   begin
      --  Add one test application.
      App.Set_Application_Identifier ("my-app-id");
      App.Set_Application_Secret ("my-secret");
      App.Set_Application_Callback ("my-callback");
      Apps.Add_Application (App);

      --  Add one test user.
      Realm.Add_User ("Gandalf", "Mithrandir");

      --  Configure the auth manager.
      Manager.Set_Application_Manager (Apps'Unchecked_Access);
      Manager.Set_Realm_Manager (Realm'Unchecked_Access);
      Manager.Set_Private_Key ("server-private-key-no-so-secure");

      Manager.Token (Params, Grant);
      T.Assert (Grant.Status = Invalid_Grant, "Expecting Invalid_Grant when client_id is missing");

      Params.Set_Parameter (Security.OAuth.CLIENT_ID, "");
      Manager.Token (Params, Grant);
      T.Assert (Grant.Status = Invalid_Grant, "Expecting Invalid_Grant when client_id is empty");

      Params.Set_Parameter (Security.OAuth.CLIENT_ID, "unkown-app");
      Manager.Token (Params, Grant);
      T.Assert (Grant.Status = Invalid_Grant, "Expecting Invalid_Grant when client_id is invalid");

      Params.Set_Parameter (Security.OAuth.CLIENT_ID, "my-app-id");
      Params.Set_Parameter (Security.OAuth.GRANT_TYPE, "");
      Manager.Token (Params, Grant);
      T.Assert (Grant.Status = Invalid_Grant,
                "Expecting Invalid_Grant when client_id is empty");

      Params.Set_Parameter (Security.OAuth.GRANT_TYPE, "password");
      Manager.Token (Params, Grant);
      T.Assert (Grant.Request = Password_Grant,
                "Expecting Password_Grant for the grant request");
      T.Assert (Grant.Status = Invalid_Grant,
                "Expecting Invalid_Grant when the user/password is missing");

      Params.Set_Parameter (Security.OAuth.USERNAME, "Gandalf");
      Manager.Token (Params, Grant);
      T.Assert (Grant.Request = Password_Grant,
                "Expecting Password_Grant for the grant request");
      T.Assert (Grant.Status = Invalid_Grant,
                "Expecting Invalid_Grant when the password is missing");

      Params.Set_Parameter (Security.OAuth.PASSWORD, "test");
      Manager.Token (Params, Grant);
      T.Assert (Grant.Request = Password_Grant,
                "Expecting Password_Grant for the grant request");
      T.Assert (Grant.Status = Invalid_Grant,
                "Expecting Invalid_Grant when the password is invalid");

      Params.Set_Parameter (Security.OAuth.PASSWORD, "Mithrandir");
      Manager.Token (Params, Grant);
      T.Assert (Grant.Request = Password_Grant,
                "Expecting Password_Grant for the grant request");
      T.Assert (Grant.Status = Invalid_Grant,
                "Expecting Invalid_Grant when the client_secret is invalid");

      Params.Set_Parameter (Security.OAuth.CLIENT_SECRET, "my-secret");
      Manager.Token (Params, Grant);
      T.Assert (Grant.Request = Password_Grant,
                "Expecting Password_Grant for the grant request");
      T.Assert (Grant.Status = Valid_Grant,
                "Expecting Valid_Grant when the user/password are correct");
      T.Assert (Grant.Error = null, "Expecting null error");
      T.Assert (Length (Grant.Token) > 20,
                "Expecting a token with some reasonable size");
      T.Assert (Grant.Auth /= null,
                "Expecting a non null auth principal");
      Util.Tests.Assert_Equals (T, "Gandalf", Grant.Auth.Get_Name,
                                "Invalid user name in the principal");

      --  Verify the access token.
      for I in 1 .. 5 loop
         Manager.Authenticate (To_String (Grant.Token), Auth_Grant);
         T.Assert (Auth_Grant.Request = Access_Grant,
                   "Expecting Access_Grant for the authenticate");
         T.Assert (Auth_Grant.Status = Valid_Grant,
                   "Expecting Valid_Grant when the access token is checked");
         T.Assert (Auth_Grant.Error = null, "Expecting null error for access_token");
         T.Assert (Auth_Grant.Auth = Grant.Auth, "Expecting valid auth principal");
      end loop;

      --  Verify the modified access token.
      Manager.Authenticate (To_String (Grant.Token) & "x", Auth_Grant);
      T.Assert (Auth_Grant.Status = Invalid_Grant,
                "Expecting Invalid_Grant for the authenticate");

      Manager.Revoke (To_String (Grant.Token));

      --  Verify the access is now denied.
      for I in 1 .. 5 loop
         Manager.Authenticate (To_String (Grant.Token), Auth_Grant);
         T.Assert (Auth_Grant.Status = Revoked_Grant,
                   "Expecting Revoked_Grant for the authenticate");
      end loop;

      --  Change application token expiration time to 1 second.
      App.Expire_Timeout := 1.0;
      Apps.Add_Application (App);

      --  Make the access token.
      Manager.Token (Params, Grant);
      T.Assert (Grant.Status = Valid_Grant,
                "Expecting Valid_Grant when the user/password are correct");

      --  Verify the access token.
      for I in 1 .. 5 loop
         Manager.Authenticate (To_String (Grant.Token), Auth_Grant);
         T.Assert (Auth_Grant.Request = Access_Grant,
                   "Expecting Access_Grant for the authenticate");
         T.Assert (Auth_Grant.Status = Valid_Grant,
                   "Expecting Valid_Grant when the access token is checked");
         T.Assert (Auth_Grant.Error = null,
                   "Expecting null error for access_token");
         T.Assert (Auth_Grant.Auth = Grant.Auth,
                   "Expecting valid auth principal");
      end loop;

      --  Wait for the token to expire.
      delay 2.0;
      for I in 1 .. 5 loop
         Manager.Authenticate (To_String (Grant.Token), Auth_Grant);
         T.Assert (Auth_Grant.Status = Expired_Grant,
                   "Expecting Expired when the access token is checked");
      end loop;

   end Test_Token_Password;

   --  ------------------------------
   --  Test the access token validation with invalid tokens (bad formed).
   --  ------------------------------
   procedure Test_Bad_Token (T : in out Test) is
      Manager    : Auth_Manager;
      Auth_Grant : Grant_Type;
   begin
      Manager.Authenticate ("x", Auth_Grant);
      T.Assert (Auth_Grant.Status = Invalid_Grant,
                "Expecting Invalid_Grant for badly formed token");
      Manager.Authenticate (".", Auth_Grant);
      T.Assert (Auth_Grant.Status = Invalid_Grant,
                "Expecting Invalid_Grant for badly formed token");
      Manager.Authenticate ("..", Auth_Grant);
      T.Assert (Auth_Grant.Status = Invalid_Grant,
                "Expecting Invalid_Grant for badly formed token");
      Manager.Authenticate ("a..", Auth_Grant);
      T.Assert (Auth_Grant.Status = Invalid_Grant,
                "Expecting Invalid_Grant for badly formed token");
      Manager.Authenticate ("..b", Auth_Grant);
      T.Assert (Auth_Grant.Status = Invalid_Grant,
                "Expecting Invalid_Grant for badly formed token");
      Manager.Authenticate ("a..b", Auth_Grant);
      T.Assert (Auth_Grant.Status = Invalid_Grant,
                "Expecting Invalid_Grant for badly formed token");
   end Test_Bad_Token;

   --  ------------------------------
   --  Test the loading configuration files for the File_Registry.
   --  ------------------------------
   procedure Test_Load_Registry (T : in out Test) is
      Apps       : aliased File_Application_Manager;
      Realm      : aliased File_Realm_Manager;
      Manager    : Auth_Manager;
      Grant      : Grant_Type;
      Auth_Grant : Grant_Type;
      Params     : Test_Parameters;
   begin
      Apps.Load (Util.Tests.Get_Path ("regtests/files/user_apps.properties"), "apps");
      Realm.Load (Util.Tests.Get_Path ("regtests/files/user_apps.properties"), "users");

      --  Configure the auth manager.
      Manager.Set_Application_Manager (Apps'Unchecked_Access);
      Manager.Set_Realm_Manager (Realm'Unchecked_Access);
      Manager.Set_Private_Key ("server-private-key-no-so-secure");
      Params.Set_Parameter (Security.OAuth.CLIENT_ID, "app-id-1");
      Params.Set_Parameter (Security.OAuth.CLIENT_SECRET, "app-secret-1");
      Params.Set_Parameter (Security.OAuth.GRANT_TYPE, "password");
      Params.Set_Parameter (Security.OAuth.USERNAME, "joe");
      Params.Set_Parameter (Security.OAuth.PASSWORD, "test");
      Manager.Token (Params, Grant);
      T.Assert (Grant.Request = Password_Grant,
                "Expecting Password_Grant for the grant request");
      T.Assert (Grant.Status = Valid_Grant,
                "Expecting Valid_Grant when the user/password are correct");
   end Test_Load_Registry;

end Security.OAuth.Servers.Tests;
