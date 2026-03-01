-----------------------------------------------------------------------
--  security-oauth-jwt -- OAuth JSON Web Token
--  Copyright (C) 2013, 2017, 2026 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

with Ada.Calendar.Conversions;
with Interfaces.C;

with Util.Encoders;
with Util.Strings;
with Util.Serialize.IO;
with Util.Properties.JSON;
with Util.Log.Loggers;
with Util.Beans.Objects;
package body Security.OAuth.JWT is

   use Interfaces;

   Log : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("Security.OAuth.JWT");

   function Get_Time (From : in Util.Properties.Manager;
                      Name : in String) return Ada.Calendar.Time;

   function To_Value (Date : in Ada.Calendar.Time) return Util.Properties.Value is
      Nsec : constant Unsigned_64
        := Unsigned_64 (Ada.Calendar.Conversions.To_Unix_Nano_Time (Date));
      Time : constant Long_Long_Integer := Long_Long_Integer (Nsec / 1_000_000);
   begin
      return Util.Beans.Objects.To_Object (Time);
   end To_Value;

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
   function Get_Claim (From    : in Token;
                       Name    : in String;
                       Default : in String := "") return String is
   begin
      return From.Claims.Get (Name, Default);
   end Get_Claim;

   --  ------------------------------
   --  Get the given name from the token header.
   --  ------------------------------
   function Get_Header (From    : in Token;
                        Name    : in String;
                        Default : in String := "") return String is
   begin
      return From.Header.Get (Name, Default);
   end Get_Header;

   --  ------------------------------
   --  Decode the part using base64url and parse the JSON content into the property manager.
   --  ------------------------------
   procedure Decode_Part (Into : in out Util.Properties.Manager;
                          Name : in String;
                          Data : in String) is
      Decoder : constant Util.Encoders.Decoder := Util.Encoders.Create (Util.Encoders.BASE_64_URL);
      Content : constant String := Decoder.Decode (Data);
   begin
      Log.Debug ("Decoding {0}: {1}", Name, Content);

      Util.Properties.JSON.Parse_JSON (Into, Content);
   end Decode_Part;

   --  ------------------------------
   --  Decode a string representing an encoded JWT token according to the JWT specification:
   --
   --    Section 7.  Creating and Validating JWTs
   --
   --  The JWT token is composed of 3 parts encoded in Base64url and separated by '.' .
   --  The first part represents the header, the second part the claims and the last part
   --  the signature.  The `Decode` operation splits the parts, decodes them,
   --  parses the JSON content represented by the header and the claims.
   --  The `Decode` operation does not verify the signature (yet!).
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

   --  ------------------------------
   --  Set the issuer claim from the token (the "iss" claim).
   --  ------------------------------
   procedure Set_Issuer (Into : in out Token; Issuer : in String) is
   begin
      Into.Claims.Set ("iss", Issuer);
   end Set_Issuer;

   --  ------------------------------
   --  Set the subject claim from the token (the "sub" claim).
   --  ------------------------------
   procedure Set_Subject (Into : in out Token; Subject : in String) is
   begin
      Into.Claims.Set ("sub", Subject);
   end Set_Subject;

   --  ------------------------------
   --  Set the audience claim from the token (the "aud" claim).
   --  ------------------------------
   procedure Set_Audience (Into : in out Token; Audience : in String) is
   begin
      Into.Claims.Set ("aud", Audience);
   end Set_Audience;

   --  ------------------------------
   --  Set the expiration claim from the token (the "exp" claim).
   --  ------------------------------
   procedure Set_Expiration (Into       : in out Token;
                             Expiration : in Ada.Calendar.Time;
                             Header     : in Boolean := False) is
      Value : constant Util.Properties.Value := To_Value (Expiration);
   begin
      if Header then
         Into.Header.Set_Value ("exp", Value);
      else
         Into.Claims.Set_Value ("exp", Value);
      end if;
   end Set_Expiration;

   --  ------------------------------
   --  Set the not before claim from the token (the "nbf" claim).
   --  ------------------------------
   procedure Set_Not_Before (Into : in out Token; Date : in Ada.Calendar.Time) is
   begin
      Into.Claims.Set_Value ("nbf", To_Value (Date));
   end Set_Not_Before;

   --  ------------------------------
   --  Set the issued at claim from the token (the "iat" claim).
   --  This is the time when the JWT was issued.
   --  ------------------------------
   procedure Set_Issued_At (Into   : in out Token;
                            Date   : in Ada.Calendar.Time;
                            Header : in Boolean := False) is
      Value : constant Util.Properties.Value := To_Value (Date);
   begin
      if Header then
         Into.Header.Set_Value ("iat", Value);
      else
         Into.Claims.Set_Value ("iat", Value);
      end if;
   end Set_Issued_At;

   --  ------------------------------
   --  Set the authentication time claim from the token (the "auth_time" claim).
   --  ------------------------------
   procedure Set_Authentication_Time (Into : in out Token; Date : in Ada.Calendar.Time) is
   begin
      Into.Claims.Set_Value ("auth_time", To_Value (Date));
   end Set_Authentication_Time;

   --  ------------------------------
   --  Set the JWT ID claim from the token (the "jti" claim).
   --  ------------------------------
   procedure Set_JWT_ID (Into : in out Token; Jti : in String) is
   begin
      Into.Claims.Set ("jti", Jti);
   end Set_JWT_ID;

   --  ------------------------------
   --  Set the authorized clients claim from the token (the "azp" claim).
   --  ------------------------------
   procedure Set_Authorized_Presenters (Into : in out Token; Azp : in String) is
   begin
      Into.Claims.Set ("azp", Azp);
   end Set_Authorized_Presenters;

   --  ------------------------------
   --  Set the Key ID header from the token (the "kid" header).
   --  ------------------------------
   procedure Set_Key_ID (Into : in out Token; Kid : in String) is
   begin
      Into.Header.Set ("kid", Kid);
   end Set_Key_ID;

   --  ------------------------------
   --  Set the JWT issued at and expiration from the current time and valid for
   --  the given duration.
   --  ------------------------------
   procedure Set_Validity (Into   : in out Token;
                           Value  : in Duration;
                           Header : in Boolean := False) is
      use type Ada.Calendar.Time;
      Now : constant Ada.Calendar.Time := Ada.Calendar.Clock;
   begin
      Set_Issued_At (Into, Now, Header);
      Set_Expiration (Into, Now + Value, Header);
   end Set_Validity;

end Security.OAuth.JWT;
