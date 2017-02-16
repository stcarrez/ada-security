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
with Ada.Text_IO;
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
      G   : Generator;
      Max : constant Ada.Streams.Stream_Element_Offset := 10;
   begin
      for I in 1 .. Max loop
         declare
            use type Ada.Streams.Stream_Element;
            S : Ada.Streams.Stream_Element_Array (1 .. I)
              := (others => 0);
            Z : Boolean := False;
         begin
            G.Generate (S);
            for J in S'Range loop
               if S (J) = 0 then
                  Z := True;
               end if;
            end loop;
            T.Assert (Z = False, "Generator failed to initialize all bytes");
         end;
      end loop;
   end Test_Generate;

end Security.Random.Tests;
