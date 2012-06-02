-----------------------------------------------------------------------
--  security-oauth -- OAuth Security
--  Copyright (C) 2012 Stephane Carrez
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
with Ada.Numerics.Discrete_Random;
with Interfaces;
with Ada.Streams;

with Util.Encoders.HMAC.SHA1;

--  The <b>Security.OAuth.Clients</b> package implements the client OAuth 2.0 authorization.
--
--  Note: OAuth 1.0 could be implemented but since it's being deprecated it's not worth doing it.
package body Security.OAuth.Clients is

   --  ------------------------------
   --  Access Token
   --  ------------------------------

   package Id_Random is new Ada.Numerics.Discrete_Random (Interfaces.Unsigned_32);

   protected type Random is

      procedure Generate (Into : out Ada.Streams.Stream_Element_Array);

   private
      --  Random number generator used for ID generation.
      Random       : Id_Random.Generator;

      --  Number of 32-bit random numbers used for the ID generation.
      Id_Size      : Ada.Streams.Stream_Element_Offset := 8;
   end Random;

   protected body Random is

      procedure Generate (Into : out Ada.Streams.Stream_Element_Array) is
         use Ada.Streams;
         use Interfaces;
      begin
         --  Generate the random sequence.
         for I in 0 .. Id_Size - 1 loop
            declare
               Value : constant Unsigned_32 := Id_Random.Random (Random);
            begin
               Into (4 * I)     := Stream_Element (Value and 16#0FF#);
               Into (4 * I + 1) := Stream_Element (Shift_Right (Value, 8) and 16#0FF#);
               Into (4 * I + 2) := Stream_Element (Shift_Right (Value, 16) and 16#0FF#);
               Into (4 * I + 3) := Stream_Element (Shift_Right (Value, 24) and 16#0FF#);
            end;
         end loop;
      end Generate;

   end Random;

   --  ------------------------------
   --  Returns true if the given role is stored in the user principal.
   --  ------------------------------
   function Has_Role (User : in Access_Token;
                      Role : in Permissions.Role_Type) return Boolean is
      pragma Unreferenced (User, Role);
   begin
      return False;
   end Has_Role;

   --  ------------------------------
   --  Get the principal name.  This is the OAuth access token.
   --  ------------------------------
   function Get_Name (From : in Access_Token) return String is
   begin
      return From.Access_Id;
   end Get_Name;

   --  ------------------------------
   --  Set the application identifier used by the OAuth authorization server
   --  to identify the application (for example, the App ID in Facebook).
   --  ------------------------------
   procedure Set_Application_Identifier (App    : in out Application;
                                         Client : in String) is
      use Ada.Strings.Unbounded;
   begin
      App.Client_Id := To_Unbounded_String (Client);
      App.Protect   := App.Client_Id & App.Callback;
   end Set_Application_Identifier;

   --  ------------------------------
   --  Set the application secret defined in the OAuth authorization server
   --  for the application (for example, the App Secret in Facebook).
   --  ------------------------------
   procedure Set_Application_Secret (App    : in out Application;
                                     Secret : in String) is
   begin
      App.Secret := Ada.Strings.Unbounded.To_Unbounded_String (Secret);
      App.Key    := App.Secret;
   end Set_Application_Secret;

   --  ------------------------------
   --  Set the redirection callback that will be used to redirect the user
   --  back to the application after the OAuth authorization is finished.
   --  ------------------------------
   procedure Set_Application_Callback (App : in out Application;
                                       URI : in String) is
      use Ada.Strings.Unbounded;
   begin
      App.Callback := To_Unbounded_String (URI);
      App.Protect  := App.Client_Id & App.Callback;
   end Set_Application_Callback;

   --  ------------------------------
   --  Set the OAuth authorization server URI that the application must use
   --  to exchange the OAuth code into an access token.
   --  ------------------------------
   procedure Set_Provider_URI (App : in out Application;
                               URI : in String) is
   begin
      App.Request_URI := Ada.Strings.Unbounded.To_Unbounded_String (URI);
   end Set_Provider_URI;

   --  ------------------------------
   --  Build a unique opaque value used to prevent cross-site request forgery.
   --  The <b>Nonce</b> parameters is an optional but recommended unique value
   --  used only once.  The state value will be returned back by the OAuth provider.
   --  This protects the <tt>client_id</tt> and <tt>redirect_uri</tt> parameters.
   --  ------------------------------
   function Get_State (App   : in Application;
                       Nonce : in String) return String is
      use Ada.Strings.Unbounded;

      Data : constant String := Nonce & To_String (App.Protect);
   begin
      return Util.Encoders.HMAC.SHA1.Sign_Base64 (Key  => To_String (App.Key),
                                                  Data => Data);
   end Get_State;

   --  ------------------------------
   --  Verify that the <b>State</b> opaque value was created by the <b>Get_State</b>
   --  operation with the given client and redirect URL.
   --  ------------------------------
   function Is_Valid_State (App   : in Application;
                            Nonce : in String;
                            State : in String) return Boolean is
      use Ada.Strings.Unbounded;

      Data : constant String := Nonce & To_String (App.Protect);
      Hmac : constant String := Util.Encoders.HMAC.SHA1.Sign_Base64 (Key  => To_String (App.Key),
                                                                     Data => Data);
   begin
      return Hmac = State;
   end Is_Valid_State;

   --  ------------------------------
   --  Exchange the OAuth code into an access token.
   --  ------------------------------
   function Request_Access_Token (App  : in Application;
                                  Code : in String) return Access_Token_Access is
   begin
      return null;
   end Request_Access_Token;

   --  ------------------------------
   --  Create the access token
   --  ------------------------------
   function Create_Access_Token (App     : in Application;
                                 Token   : in String;
                                 Expires : in Natural) return Access_Token_Access is
      pragma Unreferenced (App, Expires);
   begin
      return new Access_Token '(Len => Token'Length,
                                Access_Id => Token);
   end Create_Access_Token;

end Security.OAuth.Clients;
