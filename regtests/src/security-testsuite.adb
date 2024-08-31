-----------------------------------------------------------------------
--  Security testsuite - Ada Security Test suite
--  Copyright (C) 2011, 2012, 2013, 2017 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
with Security.Auth.Tests;
with Security.Permissions.Tests;
with Security.Policies.Tests;
with Security.OAuth.JWT.Tests;
with Security.OAuth.Clients.Tests;
with Security.OAuth.Servers.Tests;
with Security.Random.Tests;
package body Security.Testsuite is

   Tests : aliased Util.Tests.Test_Suite;

   function Suite return Util.Tests.Access_Test_Suite is
      Ret : constant Util.Tests.Access_Test_Suite := Tests'Access;
   begin
      Security.Random.Tests.Add_Tests (Ret);
      Security.OAuth.JWT.Tests.Add_Tests (Ret);
      Security.Auth.Tests.Add_Tests (Ret);
      Security.Permissions.Tests.Add_Tests (Ret);
      Security.Policies.Tests.Add_Tests (Ret);
      Security.OAuth.Clients.Tests.Add_Tests (Ret);
      Security.OAuth.Servers.Tests.Add_Tests (Ret);
      return Ret;
   end Suite;

end Security.Testsuite;
