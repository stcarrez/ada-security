-----------------------------------------------------------------------
--  Security-oauth-clients-tests - Unit tests for OAuth
--  Copyright (C) 2013 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
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
