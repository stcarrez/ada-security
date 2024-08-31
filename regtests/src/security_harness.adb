-----------------------------------------------------------------------
--  Security -- Unit tests for the Ada Security
--  Copyright (C) 2012 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

with Util.Tests;
with Security.Testsuite;
procedure Security_Harness is

   procedure Harness is new Util.Tests.Harness (Security.Testsuite.Suite);

begin
   Harness ("security-tests.xml");
end Security_Harness;
