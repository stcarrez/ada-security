-----------------------------------------------------------------------
--  security-oauth-file_registry -- File Based Application and Realm
--  Copyright (C) 2017 Stephane Carrez
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
with Ada.Strings.Hash;
with Ada.Containers.Indefinite_Hashed_Maps;

with Util.Strings;

with Security.OAuth.Servers;
private with Util.Strings.Maps;
private with Security.Random;
package Security.OAuth.File_Registry is

   type File_Principal is new Security.Principal with private;
   type File_Principal_Access is access all File_Principal'Class;

   --  Get the principal name.
   overriding
   function Get_Name (From : in File_Principal) return String;

   type File_Application_Manager is new Servers.Application_Manager with private;

   --  Find the application that correspond to the given client id.
   --  The <tt>Invalid_Application</tt> exception should be raised if there is no such application.
   overriding
   function Find_Application (Realm     : in File_Application_Manager;
                              Client_Id : in String) return Servers.Application'Class;

   --  Add the application to the application repository.
   procedure Add_Application (Realm : in out File_Application_Manager;
                              App   : in Servers.Application);

   type File_Realm_Manager is limited new Servers.Realm_Manager with private;

   --  Authenticate the token and find the associated authentication principal.
   --  The access token has been verified and the token represents the identifier
   --  of the Tuple (client_id, user, session) that describes the authentication.
   --  The <tt>Authenticate</tt> procedure should look in its database (internal
   --  or external) to find the authentication principal that was granted for
   --  the token Tuple.  When the token was not found (because it was revoked),
   --  the procedure should return a null principal.  If the authentication
   --  principal can be cached, the <tt>Cacheable</tt> value should be set.
   --  In that case, the access token and authentication  principal are inserted
   --  in a cache.
   overriding
   procedure Authenticate (Realm     : in out File_Realm_Manager;
                           Token     : in String;
                           Auth      : out Principal_Access;
                           Cacheable : out Boolean);

   --  Create an auth token string that identifies the given principal.  The returned
   --  token will be used by <tt>Authenticate</tt> to retrieve back the principal.  The
   --  returned token does not need to be signed.  It will be inserted in the public part
   --  of the returned access token.
   overriding
   function Authorize (Realm : in File_Realm_Manager;
                       App   : in Servers.Application'Class;
                       Scope : in String;
                       Auth  : in Principal_Access) return String;

   overriding
   procedure Verify (Realm    : in out File_Realm_Manager;
                     Username : in String;
                     Password : in String;
                     Auth     : out Principal_Access);

   overriding
   procedure Verify (Realm : in out File_Realm_Manager;
                     Token : in String;
                     Auth  : out Principal_Access);

   overriding
   procedure Revoke (Realm : in out File_Realm_Manager;
                     Auth  : in Principal_Access);

   --  Crypt the password using the given salt and return the string composed with
   --  the salt in clear text and the crypted password.
   function Crypt_Password (Realm    : in File_Realm_Manager;
                            Salt     : in String;
                            Password : in String) return String;

   --  Add a username with the associated password.
   procedure Add_User (Realm    : in out File_Realm_Manager;
                       Username : in String;
                       Password : in String);

private

   use Ada.Strings.Unbounded;

   package Application_Maps is
     new Ada.Containers.Indefinite_Hashed_Maps (Key_Type        => String,
                                                Element_Type    => Servers.Application,
                                                Hash            => Ada.Strings.Hash,
                                                Equivalent_Keys => "=",
                                                "="             => Servers."=");

   package Token_Maps is
     new Ada.Containers.Indefinite_Hashed_Maps (Key_Type        => String,
                                                Element_Type    => File_Principal_Access,
                                                Hash            => Ada.Strings.Hash,
                                                Equivalent_Keys => "=",
                                                "="             => "=");

   package User_Maps renames Util.Strings.Maps;

   type File_Principal is new Security.Principal with record
      Token : Ada.Strings.Unbounded.Unbounded_String;
      Name  : Ada.Strings.Unbounded.Unbounded_String;
   end record;

   type File_Application_Manager is new Servers.Application_Manager with record
      Applications : Application_Maps.Map;
   end record;

   type File_Realm_Manager is limited new Servers.Realm_Manager with record
      Users      : User_Maps.Map;
      Tokens     : Token_Maps.Map;
      Random     : Security.Random.Generator;
      Token_Bits : Positive := 256;
   end record;

end Security.OAuth.File_Registry;
