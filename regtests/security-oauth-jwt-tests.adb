-----------------------------------------------------------------------
--  Security-oayth-jwt-tests - Unit tests for JSON Web Token
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
with Ada.Calendar.Formatting;

with Util.Test_Caller;

package body Security.OAuth.JWT.Tests is

   package Caller is new Util.Test_Caller (Test, "Security.OAuth.JWT");

   --  A JWT token returned by Google+.
   K : constant String := "eyJhbGciOiJSUzI1NiIsImtpZCI6IjVmOTBlMWExMGE4YzgwZWJhZWNmYzM4NzBjZDl"
     & "lMGVhMGI3ZDVmZGMifQ.eyJpc3MiOiJhY2NvdW50cy5nb29nbGUuY29tIiwiYXRfaGFzaCI6Im9Ka19EYnFvb1"
     & "FVc0FhY3k2cnkxeHciLCJhdWQiOiI4NzI2NTU5OTQwMTQuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJz"
     & "dWIiOiIxMDgzNjA3MDMwOTk3MDg5Nzg4NzAiLCJlbWFpbF92ZXJpZmllZCI6InRydWUiLCJhenAiOiI4NzI2NT"
     & "U5OTQwMTQuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJlbWFpbCI6InN0ZXBoYW5lLmNhcnJlekBnbWFp"
     & "bC5jb20iLCJpYXQiOjEzNjg5NjgyMzMsImV4cCI6MTM2ODk3MjEzM30.UL1qp2wmleV-ED2A_hlqgDLIGgJB3f"
     & "_N7fiz1CgttJcwbmMVwhag3ox2WE9C1KwXhrjwT8eigZ0WkDys5WO1dYs2G1QbDZPnsYYMyHK9XpycaDMEKtVZ"
     & "C4C6DkB1SrBHbN0Tv6ExWpszzp1JEL8nZnHd3T_AA3paqONnkvQw_yo";

   procedure Test_Operation (T : in out Test) is
      R : Token;
   begin
      R := Decode (K);
      Util.Tests.Assert_Equals (T, Value, Get (R), "Extraction failed");
   end Test_Operation;

   procedure Test_Time_Operation (T : in out Test) is
      R : Token;
   begin
      R := Decode (K);
      Util.Tests.Assert_Equals (T, Value, Ada.Calendar.Formatting.Image (Get (R)),
                                "Extraction failed");
   end Test_Time_Operation;

   procedure Test_Get_Issuer is
     new Test_Operation (Get_Issuer, "accounts.google.com");
   procedure Test_Get_Audience is
     new Test_Operation (Get_Audience, "872655994014.apps.googleusercontent.com");
   procedure Test_Get_Subject is
     new Test_Operation (Get_Subject, "108360703099708978870");
   procedure Test_Get_Authorized_Presenters is
     new Test_Operation (Get_Authorized_Presenters, "872655994014.apps.googleusercontent.com");
   procedure Test_Get_Expiration is
     new Test_Time_Operation (Get_Expiration, "2013-05-19 14:02:13");
   procedure Test_Get_Issued_At is
     new Test_Time_Operation (Get_Issued_At, "2013-05-19 12:57:13");

   procedure Add_Tests (Suite : in Util.Tests.Access_Test_Suite) is
   begin
      Caller.Add_Test (Suite, "Test Security.OAuth.JWT.Decode",
                       Test_Get_Issuer'Access);
      Caller.Add_Test (Suite, "Test Security.OAuth.JWT.Get_Issuer",
                       Test_Get_Issuer'Access);
      Caller.Add_Test (Suite, "Test Security.OAuth.JWT.Get_Audience",
                       Test_Get_Audience'Access);
      Caller.Add_Test (Suite, "Test Security.OAuth.JWT.Get_Subject",
                       Test_Get_Subject'Access);
      Caller.Add_Test (Suite, "Test Security.OAuth.JWT.Get_Authorized_Presenters",
                       Test_Get_Authorized_Presenters'Access);
      Caller.Add_Test (Suite, "Test Security.OAuth.JWT.Get_Expiration",
                       Test_Get_Expiration'Access);
      Caller.Add_Test (Suite, "Test Security.OAuth.JWT.Get_Authentication_Time",
                       Test_Get_Issued_At'Access);
      Caller.Add_Test (Suite, "Test Security.OAuth.JWT.Decode (error)",
                       Test_Decode_Error'Access);

   end Add_Tests;

   --  ------------------------------
   --  Test Decode operation with errors.
   --  ------------------------------
   procedure Test_Decode_Error (T : in out Test) is
      K : constant String := "eyJhbxGciOiJSUzI1NiIsImtpZCI6IjVmOTBlMWExMGE4YzgwZWJhZWNmYzM4NzBjZDl"
        & "lMGVhMGI3ZDVmZGMifQ.eyJpc3xMiOiJhY2NvdW50cy5nb29nbGUuY29tIiwiYXRfaGFzaCI6Im9Ka19EYnFvb1"
        & "FVc0FhY3k2cnkxeHciLCJhdWQiOiI4NzI2NTU5OTQwMTQuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJz"
        & "dWIiOiIxMDgzNjA3MDMwOTk3MDg5Nzg4NzAiLCJlbWFpbF92ZXJpZmllZCI6InRydWUiLCJhenAiOiI4NzI2NT"
        & "U5OTQwMTQuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJlbWFpbCI6InN0ZXBoYW5lLmNhcnJlekBnbWFp"
        & "bC5jb20iLCJpYXQiOjEzNjg5NjgyMzMsImV4cCI6MTM2ODk3MjEzM30.UL1qp2wmleV-ED2A_hlqgDLIGgJB3f"
        & "_N7fiz1CgttJcwbmMVwhag3ox2WE9C1KwXhrjwT8eigZ0WkDys5WO1dYs2G1QbDZPnsYYMyHK9XpycaDMEKtVZ"
        & "C4C6DkB1SrBHbN0Tv6ExWpszzp1JEL8nZnHd3T_AA3paqONnkvQw_yx";
      R : Token;
   begin
      R := Decode (K);
      T.Fail ("No exception raised");
      T.Assert (False, "Bad");

   exception
      when Invalid_Token =>
         null;
   end Test_Decode_Error;

end Security.OAuth.JWT.Tests;
