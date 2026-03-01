-----------------------------------------------------------------------
--  security-oauth-jwt -- OAuth JSON Web Token
--  Copyright (C) 2013-2026 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

with Ada.Calendar;
with Util.Properties;

--  === JSON Web Token ===
--  JSON Web Token (JWT) is a compact URL-safe means of representing claims to be transferred
--  between two parties.  A JWT token is returned by an authorization server.  It contains
--  useful information that allows to verify the authentication and identify the user.
--
--  The `Security.OAuth.JWT` package implements the decoding and encoding part of JWT defined in:
--  JSON Web Token (JWT), RFC 7519.
--
--  A list of pre-defined ID tokens are returned in the JWT token claims and used for
--  the OpenID Connect.  This is specified in
--  OpenID Connect Basic Client Profile 1.0 - draft 26,
--  http://openid.net/specs/openid-connect-basic-1_0.html
--
--  To extract a JWT token, you can use the following steps:
--
--     Token : constant Security.OAuth.JWT
--        := Security.OAuth.JWT.Decode (Jwt_Token);
--
--  and you can access one of the JWT fields by using the `Get_<Field>` functions:
--
--     Issuer : constant String
--        := Security.OAuth.JWT.Get_Issuer (Token);
--     Claim  : constant String
--        := Security.OAuth.JWT.Get_Claim (Token, "name");
--
--  @include security-oauth-jwt-hs256.ads
package Security.OAuth.JWT is

   --  Exception raised if the encoded token is invalid or cannot be decoded.
   Invalid_Token : exception;

   type Token is private;

   --  Get the issuer claim from the token (the "iss" claim).
   function Get_Issuer (From : in Token) return String;

   --  Get the subject claim from the token (the "sub" claim).
   function Get_Subject (From : in Token) return String;

   --  Get the audience claim from the token (the "aud" claim).
   function Get_Audience (From : in Token) return String;

   --  Get the expiration claim from the token (the "exp" claim).
   function Get_Expiration (From : in Token) return Ada.Calendar.Time;

   --  Get the not before claim from the token (the "nbf" claim).
   function Get_Not_Before (From : in Token) return Ada.Calendar.Time;

   --  Get the issued at claim from the token (the "iat" claim).
   --  This is the time when the JWT was issued.
   function Get_Issued_At (From : in Token) return Ada.Calendar.Time;

   --  Get the authentication time claim from the token (the "auth_time" claim).
   function Get_Authentication_Time (From : in Token) return Ada.Calendar.Time;

   --  Get the JWT ID claim from the token (the "jti" claim).
   function Get_JWT_ID (From : in Token) return String;

   --  Get the authorized clients claim from the token (the "azp" claim).
   function Get_Authorized_Presenters (From : in Token) return String;

   --  Get the claim with the given name from the token.
   function Get_Claim (From    : in Token;
                       Name    : in String;
                       Default : in String := "") return String;

   --  Get the given name from the token header.
   function Get_Header (From    : in Token;
                        Name    : in String;
                        Default : in String := "") return String;

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
   function Decode (Content : in String) return Token;

   --  Set the issuer claim from the token (the "iss" claim).
   procedure Set_Issuer (Into : in out Token; Issuer : in String);

   --  Set the subject claim from the token (the "sub" claim).
   procedure Set_Subject (Into : in out Token; Subject : in String);

   --  Set the audience claim from the token (the "aud" claim).
   procedure Set_Audience (Into : in out Token; Audience : in String);

   --  Set the expiration claim from the token (the "exp" claim).
   procedure Set_Expiration (Into       : in out Token;
                             Expiration : in Ada.Calendar.Time;
                             Header     : in Boolean := False);

   --  Set the not before claim from the token (the "nbf" claim).
   procedure Set_Not_Before (Into : in out Token; Date : in Ada.Calendar.Time);

   --  Set the issued at claim from the token (the "iat" claim).
   --  This is the time when the JWT was issued.
   procedure Set_Issued_At (Into   : in out Token;
                            Date   : in Ada.Calendar.Time;
                            Header : in Boolean := False);

   --  Set the authentication time claim from the token (the "auth_time" claim).
   procedure Set_Authentication_Time (Into : in out Token; Date : in Ada.Calendar.Time);

   --  Set the JWT ID claim from the token (the "jti" claim).
   procedure Set_JWT_ID (Into : in out Token; Jti : in String);

   --  Set the authorized clients claim from the token (the "azp" claim).
   procedure Set_Authorized_Presenters (Into : in out Token; Azp : in String);

   --  Set the Key ID header from the token (the "kid" header).
   procedure Set_Key_ID (Into : in out Token; Kid : in String);

   --  Set the JWT issued at and expiration from the current time and valid for
   --  the given duration.
   procedure Set_Validity (Into   : in out Token;
                           Value  : in Duration;
                           Header : in Boolean := False);

private

   type Claims is new Util.Properties.Manager with null record;

   type Token is record
      Header : Util.Properties.Manager;
      Claims : Util.Properties.Manager;
   end record;

end Security.OAuth.JWT;
