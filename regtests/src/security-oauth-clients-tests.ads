-----------------------------------------------------------------------
--  Security-oauth-clients-tests - Unit tests for OAuth
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

with Util.Tests;

package Security.OAuth.Clients.Tests is

   procedure Add_Tests (Suite : in Util.Tests.Access_Test_Suite);

   type Test is new Util.Tests.Test with null record;

   --  Test Create_Nonce operation.
   procedure Test_Create_Nonce (T : in out Test);

   --  Test the Get_State operation.
   procedure Test_Get_State (T : in out Test);

   --  Test the Is_Valid_State operation.
   procedure Test_Is_Valid_State (T : in out Test);

   --  Test the Get_Auth_Params operation.
   procedure Test_Get_Auth_Params (T : in out Test);

end Security.OAuth.Clients.Tests;
