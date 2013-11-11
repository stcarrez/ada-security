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
with Ada.Strings.Fixed;
with Util.Test_Caller;
with Util.Measures;
with Util.Strings.Sets;

package body Security.OAuth.Clients.Tests is

   package Caller is new Util.Test_Caller (Test, "Security.OAuth.Clients");

   procedure Add_Tests (Suite : in Util.Tests.Access_Test_Suite) is
   begin
      Caller.Add_Test (Suite, "Test Security.OAuth.Clients.Create_Nonce",
                       Test_Create_Nonce'Access);
      Caller.Add_Test (Suite, "Test Security.OAuth.Clients.Get_State",
                       Test_Get_State'Access);
      Caller.Add_Test (Suite, "Test Security.OAuth.Clients.Is_Valid_State",
                       Test_Is_Valid_State'Access);
      Caller.Add_Test (Suite, "Test Security.OAuth.Clients.Get_Auth_Params",
                       Test_Get_Auth_Params'Access);
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
         Util.Measures.Report (S, "128 bits nonce generation", 1_000);
      end;
   end Test_Create_Nonce;

   --  ------------------------------
   --  Test the Get_State operation.
   --  ------------------------------
   procedure Test_Get_State (T : in out Test) is
      App   : Application;
      Nonce : constant String := Create_Nonce (128);
   begin
      App.Set_Application_Identifier ("test");
      Util.Tests.Assert_Equals (T, "test", App.Get_Application_Identifier, "Invalid application");

      App.Set_Application_Secret ("my-secret");
      App.Set_Application_Callback ("my-callback");
      App.Set_Provider_URI ("http://my-provider");

      declare
         State : constant String := App.Get_State (Nonce);
      begin
         T.Assert (State'Length > 25, "State is too small: " & State);
         T.Assert (Ada.Strings.Fixed.Index (State, Nonce) = 0,
                   "The state must not contain the nonce");

         --  Calling Get_State with the same nonce should produce the same result.
         Util.Tests.Assert_Equals (T, State, App.Get_State (Nonce), "Invalid state");

         App.Set_Application_Secret ("second-secret");
         declare
            State2 : constant String := App.Get_State (Nonce);
         begin
            T.Assert (State /= State2,
                      "Changing the application key should produce a different state");
         end;

         --  Restore the secret and change the callback.
         App.Set_Application_Secret ("my-secret");
         App.Set_Application_Callback ("my-callback2");
         declare
            State2 : constant String := App.Get_State (Nonce);
         begin
            T.Assert (State /= State2,
                      "Changing the application callback should produce a different state");
         end;

         --  Restore the callback and change the client Id.
         App.Set_Application_Callback ("my-callback");
         App.Set_Application_Identifier ("test2");
         declare
            State2 : constant String := App.Get_State (Nonce);
         begin
            T.Assert (State /= State2,
                      "Changing the application identifier should produce a different state");
         end;
      end;
   end Test_Get_State;

   --  ------------------------------
   --  Test the Is_Valid_State operation.
   --  ------------------------------
   procedure Test_Is_Valid_State (T : in out Test) is
      App   : Application;
   begin
      App.Set_Application_Identifier ("test");
      Util.Tests.Assert_Equals (T, "test", App.Get_Application_Identifier, "Invalid application");

      App.Set_Application_Secret ("my-secret");
      App.Set_Application_Callback ("my-callback");
      App.Set_Provider_URI ("http://my-provider");

      for I in 1 .. 100 loop
         declare
            Nonce : constant String := Create_Nonce (128);
            State : constant String := App.Get_State (Nonce);
         begin
            T.Assert (State'Length > 25, "State is too small: " & State);
            T.Assert (App.Is_Valid_State (Nonce, State), "Invalid state: " & State);
            T.Assert (not App.Is_Valid_State ("", State), "State was valid with invalid nonce");
            T.Assert (not App.Is_Valid_State (State, State), "State must be invalid");
            T.Assert (not App.Is_Valid_State (Nonce, State & "d"), "State must be invalid");
         end;
      end loop;
   end Test_Is_Valid_State;

   --  Test the Get_Auth_Params operation.
   procedure Test_Get_Auth_Params (T : in out Test) is
      App   : Application;
   begin
      App.Set_Application_Identifier ("test");
      Util.Tests.Assert_Equals (T, "test", App.Get_Application_Identifier, "Invalid application");

      App.Set_Application_Secret ("my-secret");
      App.Set_Application_Callback ("my-callback");
      App.Set_Provider_URI ("http://my-provider");
      declare
         P : constant String := App.Get_Auth_Params ("the-state", "the-scope");
      begin
         Util.Tests.Assert_Equals (T, "client_id=test&redirect_uri=my-callback&"
                                   & "scope=the-scope&state=the-state", P,
                                   "Invalid auth params");
      end;
   end Test_Get_Auth_Params;

end Security.OAuth.Clients.Tests;
