-----------------------------------------------------------------------
--  Security-oauth-servers-tests - Unit tests for server side OAuth
--  Copyright (C) 2017 Stephane Carrez
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

end Security.OAuth.Servers.Tests;
