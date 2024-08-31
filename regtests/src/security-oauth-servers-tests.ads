-----------------------------------------------------------------------
--  Security-oauth-servers-tests - Unit tests for server side OAuth
--  Copyright (C) 2017, 2018 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

with Util.Tests;

package Security.OAuth.Servers.Tests is

   procedure Add_Tests (Suite : in Util.Tests.Access_Test_Suite);

   type Test is new Util.Tests.Test with null record;

   --  Test the application manager.
   procedure Test_Application_Manager (T : in out Test);

   --  Test the user registration and verification.
   procedure Test_User_Verify (T : in out Test);

   --  Test the token operation that produces an access token from user/password.
   --  RFC 6749: Section 4.3.  Resource Owner Password Credentials Grant
   procedure Test_Token_Password (T : in out Test);

   --  Test the access token validation with invalid tokens (bad formed).
   procedure Test_Bad_Token (T : in out Test);

   --  Test the loading configuration files for the File_Registry.
   procedure Test_Load_Registry (T : in out Test);

end Security.OAuth.Servers.Tests;
