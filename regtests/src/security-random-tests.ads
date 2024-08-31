-----------------------------------------------------------------------
--  security-random-tests - Tests for random package
--  Copyright (C) 2017, 2022 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

with Util.Tests;
package Security.Random.Tests is

   procedure Add_Tests (Suite : in Util.Tests.Access_Test_Suite);

   type Test is new Util.Tests.Test with null record;

   procedure Test_Generate (T : in out Test);

   procedure Test_Generate_String (T : in out Test);

end Security.Random.Tests;
