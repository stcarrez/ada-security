-----------------------------------------------------------------------
--  security-random-tests - Tests for random package
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

with Ada.Strings.Unbounded;

with Util.Test_Caller;
package body Security.Random.Tests is

   use Util.Tests;

   package Caller is new Util.Test_Caller (Test, "Security.Random");

   procedure Add_Tests (Suite : in Util.Tests.Access_Test_Suite) is
   begin
      Caller.Add_Test (Suite, "Test Security.Random.Generate",
                       Test_Generate'Access);
   end Add_Tests;

   --  ------------------------------
   --  Test Yadis discovery using static files
   --  ------------------------------
   procedure Test_Generate (T : in out Test) is
      use Ada.Strings.Unbounded;

      G   : Generator;
      Max : constant Ada.Streams.Stream_Element_Offset := 10;
   begin
      for I in 1 .. Max loop
         declare
            use type Ada.Streams.Stream_Element;
            S : Ada.Streams.Stream_Element_Array (1 .. I)
              := (others => 0);
            Rand : Ada.Strings.Unbounded.Unbounded_String;
         begin
            --  Try 5 times to fill the array with random patterns and make sure
            --  we don't get any 0.
            for Retry in 1 .. 5 loop
               G.Generate (S);
               exit when (for all R of S => R /= 0);
            end loop;
            T.Assert ((for all R of S => R /= 0), "Generator failed to initialize all bytes");

            G.Generate (Positive (I), Rand);
            T.Assert (Length (Rand) > 0, "Generator failed to produce a base64url sequence");
         end;
      end loop;
   end Test_Generate;

end Security.Random.Tests;
