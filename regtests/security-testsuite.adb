-----------------------------------------------------------------------
--  Security testsuite - Ada Security Test suite
--  Copyright (C) 2011, 2012, 2013, 2017 Stephane Carrez
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
with Security.Auth.Tests;
with Security.Permissions.Tests;
with Security.Policies.Tests;
with Security.OAuth.JWT.Tests;
with Security.OAuth.Clients.Tests;
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
      return Ret;
   end Suite;

end Security.Testsuite;
