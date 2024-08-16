-----------------------------------------------------------------------
--  security-openid - Tests for OpenID
--  Copyright (C) 2009, 2010, 2011, 2012, 2013 Stephane Carrez
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
