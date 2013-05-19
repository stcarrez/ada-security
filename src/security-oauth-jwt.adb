-----------------------------------------------------------------------
--  security-oauth-jwt -- OAuth Java Web Token
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

with Ada.Calendar.Conversions;
with Interfaces.C;

with Util.Encoders;
with Util.Strings;
with Util.Serialize.IO;
with Util.Properties.JSON;
with Util.Log.Loggers;
package body Security.OAuth.JWT is

   Log : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("Security.OAuth.JWT");

   function Get_Time (From : in Util.Properties.Manager;
                      Name : in String) return Ada.Calendar.Time;

   --  Decode the part using base64url and parse the JSON content into the property manager.
   procedure Decode_Part (Into : in out Util.Properties.Manager;
                          Name : in String;
                          Data : in String);

   function Get_Time (From : in Util.Properties.Manager;
                      Name : in String) return Ada.Calendar.Time is
      Value : constant String := From.Get (Name);
   begin
      return Ada.Calendar.Conversions.To_Ada_Time (Interfaces.C.long'Value (Value));
   end Get_Time;

   --  ------------------------------
   --  Get the issuer claim from the token (the "iss" claim).
   --  ------------------------------
   function Get_Issuer (From : in Token) return String is
   begin
      return From.Claims.Get ("iss");
   end Get_Issuer;

   --  ------------------------------
   --  Get the subject claim from the token (the "sub" claim).
   --  ------------------------------
   function Get_Subject (From : in Token) return String is
   begin
      return From.Claims.Get ("sub");
   end Get_Subject;

   --  ------------------------------
   --  Get the audience claim from the token (the "aud" claim).
   --  ------------------------------
   function Get_Audience (From : in Token) return String is
   begin
      return From.Claims.Get ("aud");
   end Get_Audience;

   --  ------------------------------
   --  Get the expiration claim from the token (the "exp" claim).
   --  ------------------------------
   function Get_Expiration (From : in Token) return Ada.Calendar.Time is
   begin
      return Get_Time (From.Claims, "exp");
   end Get_Expiration;

   --  ------------------------------
   --  Get the not before claim from the token (the "nbf" claim).
   --  ------------------------------
   function Get_Not_Before (From : in Token) return Ada.Calendar.Time is
   begin
      return Get_Time (From.Claims, "nbf");
   end Get_Not_Before;

   --  ------------------------------
   --  Get the issued at claim from the token (the "iat" claim).
   --  ------------------------------
   function Get_Issued_At (From : in Token) return Ada.Calendar.Time is
   begin
      return Get_Time (From.Claims, "iat");
   end Get_Issued_At;

   --  ------------------------------
   --  Get the authentication time claim from the token (the "auth_time" claim).
   --  ------------------------------
   function Get_Authentication_Time (From : in Token) return Ada.Calendar.Time is
   begin
      return Get_Time (From.Claims, "auth_time");
   end Get_Authentication_Time;

   --  ------------------------------
   --  Get the JWT ID claim from the token (the "jti" claim).
   --  ------------------------------
   function Get_JWT_ID (From : in Token) return String is
   begin
      return From.Claims.Get ("jti");
   end Get_JWT_ID;

   --  ------------------------------
   --  Get the authorized clients claim from the token (the "azp" claim).
   --  ------------------------------
   function Get_Authorized_Presenters (From : in Token) return String is
   begin
      return From.Claims.Get ("azp");
   end Get_Authorized_Presenters;

   --  ------------------------------
   --  Get the claim with the given name from the token.
   --  ------------------------------
   function Get_Claim (From : in Token;
                       Name : in String) return String is
   begin
      return From.Claims.Get (Name);
   end Get_Claim;

   --  ------------------------------
   --  Decode the part using base64url and parse the JSON content into the property manager.
   --  ------------------------------
   procedure Decode_Part (Into : in out Util.Properties.Manager;
                          Name : in String;
                          Data : in String) is
      Decoder : constant Util.Encoders.Encoder := Util.Encoders.Create (Util.Encoders.BASE_64_URL);
      Content : constant String := Decoder.Decode (Data);
   begin
      Log.Debug ("Decoding {0}: {1}", Name, Content);

      Util.Properties.JSON.Parse_JSON (Into, Content);
   end Decode_Part;

   --  ------------------------------
   --  Decode a string representing an encoded JWT token according to the JWT specification:
   --
   --    Section 7.  Rules for Creating and Validating a JWT
   --
   --  The JWT token is composed of 3 parts encoded in Base64url and separated by '.' .
   --  The first part represents the header, the second part the claims and the last part
   --  the signature.  The <tt>Decode</tt> operation splits the parts, decodes them,
   --  parses the JSON content represented by the header and the claims.
   --  The <tt>Decode</tt> operation does not verify the signature (yet!).
   --
   --  Return the decoded token or raise an exception.
   --  ------------------------------
   function Decode (Content : in String) return Token is
      Pos1   : constant Natural := Util.Strings.Index (Content, '.');
      Pos2   : Natural;
      Result : Token;
   begin
      if Pos1 = 0 then
         Log.Error ("Invalid JWT token: missing '.' separator. JWT: {0}", Content);
         raise Invalid_Token with "Missing header separator";
      end if;
      Pos2 := Util.Strings.Index (Content, '.', Pos1 + 1);
      if Pos2 = 0 then
         Log.Error ("Invalid JWT token: missing second '.' separator. JWT: {0}", Content);
         raise Invalid_Token with "Missing signature separator";
      end if;
      Decode_Part (Result.Header, "header", Content (Content'First .. Pos1 - 1));
      Decode_Part (Result.Claims, "claims", Content (Pos1 + 1 .. Pos2 - 1));
      return Result;

   exception
      when Util.Serialize.IO.Parse_Error =>
         raise Invalid_Token with "Invalid JSON content";
   end Decode;

end Security.OAuth.JWT;
