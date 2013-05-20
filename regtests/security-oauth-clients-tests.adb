-----------------------------------------------------------------------
--  Security-oauth-clients-tests - Unit tests for OAuth
--  Copyright (C) 2013 Stephane Carrez
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

with Util.Test_Caller;
with Util.Measures;
with Util.Strings.Sets;

package body Security.OAuth.Clients.Tests is

   package Caller is new Util.Test_Caller (Test, "Security.OAuth.Clients");

   procedure Add_Tests (Suite : in Util.Tests.Access_Test_Suite) is
   begin
      Caller.Add_Test (Suite, "Test Security.OAuth.Clients.Create_Nonce",
                       Test_Create_Nonce'Access);
   end Add_Tests;

   --  ------------------------------
   --  Test Create_Nonce operation.
   --  ------------------------------
   procedure Test_Create_Nonce (T : in out Test) is
      Nonces : Util.Strings.Sets.Set;
   begin
      for I in 1 .. 1_000 loop
         for I in 32 .. 734 loop
            declare
               S : constant String := Create_Nonce (I * 3);
            begin
               T.Assert (not Nonces.Contains (S), "Nonce was not unique: " & S);
               Nonces.Include (S);
            end;
         end loop;
      end loop;
      declare
         S : Util.Measures.Stamp;
      begin
         for I in 1 .. 1_000 loop
            declare
               Nonce : constant String := Create_Nonce (128);
               pragma Unreferenced (Nonce);
            begin
               null;
            end;
         end loop;
         Util.Measures.Report (S, "128 bits nonce generation (1000 calls)");
      end;
   end Test_Create_Nonce;

end Security.OAuth.Clients.Tests;
