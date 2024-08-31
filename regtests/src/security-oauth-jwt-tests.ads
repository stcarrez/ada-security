-----------------------------------------------------------------------
--  Security-oayth-jwt-tests - Unit tests for JSON Web Token
--  Copyright (C) 2013 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

with Util.Tests;

package Security.OAuth.JWT.Tests is

   procedure Add_Tests (Suite : in Util.Tests.Access_Test_Suite);

   type Test is new Util.Tests.Test with null record;

   --  Test Decode operation with errors.
   procedure Test_Decode_Error (T : in out Test);

   generic
      with function Get (From : in Token) return String;
      Value : String;
   procedure Test_Operation (T : in out Test);

   generic
      with function Get (From : in Token) return Ada.Calendar.Time;
      Value : String;
   procedure Test_Time_Operation (T : in out Test);

end Security.OAuth.JWT.Tests;
