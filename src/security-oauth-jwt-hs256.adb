-----------------------------------------------------------------------
--  security-oauth-jwt-hs256 -- OAuth JSON Web Token signed with HS256
--  Copyright (C) 2026 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

with Util.Properties;
with Util.Encoders;
with Util.Encoders.HMAC.SHA256;
with Util.Streams.Texts;
with Util.Serialize.IO.JSON;

package body Security.OAuth.JWT.HS256 is

   function To_JSON (Prop : in Util.Properties.Manager) return String is
      Buffer : aliased Util.Streams.Texts.Print_Stream;
      Output : Util.Serialize.IO.JSON.Output_Stream;
      procedure To_JSON (Name : in String;
                         Item : in Util.Properties.Value) is
      begin
         Output.Write_Entity (Name, Item);
      end To_JSON;
   begin
      Buffer.Initialize (Size => 10000);
      Output.Initialize (Buffer'Unchecked_Access);
      Output.Start_Document;
      Output.Start_Entity ("");
      Prop.Iterate (To_JSON'Access);
      Output.End_Entity ("");
      Output.End_Document;
      return Util.Streams.Texts.To_String (Buffer);
   end To_JSON;

   --  ------------------------------
   --  Sign the JWT token with the HS256 algorithm and the given secret.
   --  The JWT type is set to `JWT` and the algorithm set to `HS256`.
   --  ------------------------------
   function Sign (From : in out Token; Secret : in String) return String is
      E : constant Util.Encoders.Encoder := Util.Encoders.Create ("base64url");
      function To_Base64 (Part : in String) return String is
         B : constant String := E.Encode (Part);
      begin
         if B'Length <= 2 or else B (B'Last) /= '=' then
            return B;
         elsif B (B'Last - 1) = '=' then
            return B (B'First .. B'Last - 2);
         else
            return B (B'First .. B'Last - 1);
         end if;
      end To_Base64;
   begin
      From.Header.Set ("alg", "HS256");
      From.Header.Set ("typ", "JWT");
      declare
         Hdr        : constant String := To_JSON (From.Header);
         Claims     : constant String := To_JSON (From.Claims);
         Hdr_B64    : constant String := To_Base64 (Hdr);
         Claims_B64 : constant String := To_Base64 (Claims);
         To_Sign    : constant String := Hdr_B64 & "." & Claims_B64;
         Signature  : constant String
           := Util.Encoders.HMAC.SHA256.Sign_Base64 (Secret, To_Sign, True);
      begin
         return To_Sign & "." & Signature;
      end;
   end Sign;

end Security.OAuth.JWT.HS256;
