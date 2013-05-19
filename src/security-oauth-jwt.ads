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

with Ada.Calendar;
with Util.Properties;

--  === JSON Web Token ===
--  JSON Web Token (JWT) is a compact URL-safe means of representing claims to be transferred
--  between two parties.  A JWT token is returned by an authorization server.  It contains
--  useful information that allows to verify the authentication and identify the user.
--
--  The <tt>Security.OAuth.JWT</tt> package implements the decoding part of JWT defined in:
--  JSON Web Token (JWT), http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-07
--
--  A list of pre-defined ID tokens are returned in the JWT token claims and used for
--  the OpenID Connect.  This is specified in
--  OpenID Connect Basic Client Profile 1.0 - draft 26,
--  http://openid.net/specs/openid-connect-basic-1_0.html
--
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
   function Get_Claim (From : in Token;
                       Name : in String) return String;

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
   function Decode (Content : in String) return Token;

private

   type Claims is new Util.Properties.Manager with null record;

   type Token is record
      Header : Util.Properties.Manager;
      Claims : Util.Properties.Manager;
   end record;

end Security.OAuth.JWT;
