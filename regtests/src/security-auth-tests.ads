-----------------------------------------------------------------------
--  security-openid - Tests for OpenID
--  Copyright (C) 2009, 2010, 2011, 2012, 2013 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

with Util.Strings.Maps;
with Util.Tests;
package Security.Auth.Tests is

   use Ada.Strings.Unbounded;

   procedure Add_Tests (Suite : in Util.Tests.Access_Test_Suite);

   type Test is new Util.Tests.Test with null record;

   procedure Test_Discovery (T : in out Test);

   procedure Test_Verify_Signature (T : in out Test);

   type Test_Parameters is new Security.Auth.Parameters with record
      Params : Util.Strings.Maps.Map;
   end record;

   overriding
   function Get_Parameter (Params : in Test_Parameters;
                           Name   : in String) return String;

   procedure Set_Parameter (Params : in out Test_Parameters;
                            Name   : in String;
                            Value  : in String);

end Security.Auth.Tests;
