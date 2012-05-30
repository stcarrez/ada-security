-----------------------------------------------------------------------
--  security-openid - Tests for OpenID
--  Copyright (C) 2009, 2010, 2011, 2012 Stephane Carrez
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

with Util.Http.Mockups;
with Util.Http.Clients.Mockups;

with Util.Test_Caller;
with Ada.Text_IO;
package body Security.Openid.Tests is

   use Util.Tests;

   package Caller is new Util.Test_Caller (Test, "Security.Openid");

   procedure Check_Discovery (T    : in out Test;
                              Name : in String;
                              URI  : in String);

   procedure Add_Tests (Suite : in Util.Tests.Access_Test_Suite) is
   begin
      Caller.Add_Test (Suite, "Test Security.OpenID.Discover",
                       Test_Discovery'Access);
      Caller.Add_Test (Suite, "Test Security.OpenID.Verify_Signature",
                       Test_Verify_Signature'Access);
   end Add_Tests;

   overriding
   function Get_Parameter (Params : in Test_Parameters;
                           Name   : in String) return String is
   begin
      if Params.Params.Contains (Name) then
         return Params.Params.Element (Name);
      else
         return "";
      end if;
   end Get_Parameter;

   procedure Set_Parameter (Params : in out Test_Parameters;
                            Name   : in String;
                            Value  : in String) is
   begin
      Params.Params.Include (Name, Value);
   end Set_Parameter;

   procedure Check_Discovery (T    : in out Test;
                              Name : in String;
                              URI  : in String) is
      pragma Unreferenced (URI, T);

      M      : Manager;
      Dir    : constant String := "regtests/files/discover/";
      Path   : constant String := Util.Tests.Get_Path (Dir);
      Result : End_Point;
   begin
      Util.Http.Clients.Mockups.Register;
      Util.Http.Clients.Mockups.Set_File (Path & Name & ".xrds");
      M.Discover (Name   => Name,
                  Result => Result);
      Ada.Text_IO.Put_Line ("Result: " & To_String (Result));
   end Check_Discovery;

   --  ------------------------------
   --  Test Yadis discovery using static files
   --  ------------------------------
   procedure Test_Discovery (T : in out Test) is
   begin
      Check_Discovery (T, "google", "https://www.google.com/accounts/o8/ud");
      Check_Discovery (T, "yahoo", "https://open.login.yahooapis.com/openid/op/auth");
      Check_Discovery (T, "claimid", "");
      Check_Discovery (T, "livejournal", "");
      Check_Discovery (T, "myopenid", "");
      Check_Discovery (T, "myspace", "");
      Check_Discovery (T, "orange", "");
      Check_Discovery (T, "verisign", "");
      Check_Discovery (T, "steamcommunity", "");
   end Test_Discovery;

   --  ------------------------------
   --  Test the OpenID verify signature process
   --  ------------------------------
   procedure Test_Verify_Signature (T : in out Test) is
      Assoc  : Association;
      Req    : Test_Parameters;
      M      : Manager;
      Result : Authentication;
   begin
      M.Return_To := To_Unbounded_String ("http://localhost/openId");

      --  Below is a part of the authentication process on Google OpenId.
      --  In theory, you cannot use the following information to authenticate again...
      Assoc.Session_Type := To_Unbounded_String ("no-encryption");
      Assoc.Assoc_Type   := To_Unbounded_String ("HMAC-SHA1");
      Assoc.Assoc_Handle := To_Unbounded_String ("AOQobUdTfNDRSgJLi_0mQQnCCstOsefQadOiW9LNSp4JFO815iHCHsRk");
      Assoc.Mac_Key      := To_Unbounded_String ("NGFpR6vWfe7O8YIhhnXQMjL0goI=");

      Req.Set_Parameter ("openid.ns", "http://specs.openid.net/auth/2.0");
      Req.Set_Parameter ("openid.mode", "id_res");
      Req.Set_Parameter ("openid.op_endpoint", "https://www.google.com/accounts/o8/ud");
      Req.Set_Parameter ("openid.response_nonce", "2011-04-26T20:08:22ZJ_neiVqR0e1wZw");
      Req.Set_Parameter ("openid.return_to", "http://localhost/openId");
      Req.Set_Parameter ("openid.assoc_handle", "AOQobUdTfNDRSgJLi_0mQQnCCstOsefQadOiW9LNSp4JFO815iHCHsRk");
      Req.Set_Parameter ("openid.signed", "op_endpoint,claimed_id,identity,return_to,response_nonce,assoc_handle,ns.ext1,ext1.mode,ext1.type.firstname,ext1.value.firstname,ext1.type.email,ext1.value.email,ext1.type.language,ext1.value.language,ext1.type.lastname,ext1.value.lastname");
      Req.Set_Parameter ("openid.sig", "pV8cmScjrmgKvFn2F6Wxh/qBiIE=");
      Req.Set_Parameter ("openid.identity", "https://www.google.com/accounts/o8/id?id=AItOawm4O6C695XlWrS7MUWC-_V_R2zC-Ol993E");
      Req.Set_Parameter ("openid.claimed_id", "https://www.google.com/accounts/o8/id?id=AItOawm4O6C695XlWrS7MUWC-_V_R2zC-Ol993E");
      Req.Set_Parameter ("openid.ns.ext1", "http://openid.net/srv/ax/1.0");
      Req.Set_Parameter ("openid.ext1.mode", "fetch_response");
      Req.Set_Parameter ("openid.ext1.type.firstname", "http://axschema.org/namePerson/first");
      Req.Set_Parameter ("openid.ext1.value.firstname", "Stephane");
      Req.Set_Parameter ("openid.ext1.type.email", "http://axschema.org/contact/email");
      Req.Set_Parameter ("openid.ext1.value.email", "stephane.carrez@gmail.com");
      Req.Set_Parameter ("openid.ext1.type.language", "http://axschema.org/pref/language");
      Req.Set_Parameter ("openid.ext1.value.language", "fr");
      Req.Set_Parameter ("openid.ext1.type.lastname", "http://axschema.org/namePerson/last");
      Req.Set_Parameter ("openid.ext1.value.lastname", "Carrez");

      M.Verify (Assoc, Req, Result);

      --  If the verification is succeeds, the signature is correct, we should be authenticated.
      T.Assert (Get_Status (Result) = AUTHENTICATED, "Authentication status is not authenticated");
      Assert_Equals (T, "stephane.carrez@gmail.com", Get_Email (Result), "Invalid email");
   end Test_Verify_Signature;

end Security.Openid.Tests;
