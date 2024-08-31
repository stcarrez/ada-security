-----------------------------------------------------------------------
--  security-oauth-file_registry -- File Based Application and Realm
--  Copyright (C) 2017, 2018 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
with Ada.Strings.Unbounded;
with Ada.Strings.Hash;
with Ada.Containers.Indefinite_Hashed_Maps;

with Util.Strings;
with Util.Properties;

with Security.OAuth.Servers;
with Security.Permissions;
private with Util.Strings.Maps;
private with Security.Random;
package Security.OAuth.File_Registry is

   type File_Principal is new Servers.Principal with private;
   type File_Principal_Access is access all File_Principal'Class;

   --  Get the principal name.
   overriding
   function Get_Name (From : in File_Principal) return String;

   --  Check if the permission was granted.
   overriding
   function Has_Permission (Auth       : in File_Principal;
                            Permission : in Security.Permissions.Permission_Index)
                            return Boolean;

   type File_Application_Manager is new Servers.Application_Manager with private;

   --  Find the application that correspond to the given client id.
   --  The <tt>Invalid_Application</tt> exception should be raised if there is no such application.
   overriding
   function Find_Application (Realm     : in File_Application_Manager;
                              Client_Id : in String) return Servers.Application'Class;

   --  Add the application to the application repository.
   procedure Add_Application (Realm : in out File_Application_Manager;
                              App   : in Servers.Application);

   --  Load from the properties the definition of applications.  The list of applications
   --  is controlled by the property <prefix>.list which contains a comma separated list of
   --  application names or ids.  The application definition are represented by properties
   --  of the form:
   --    <prefix>.<app>.client_id
   --    <prefix>.<app>.client_secret
   --    <prefix>.<app>.callback_url
   procedure Load (Realm  : in out File_Application_Manager;
                   Props  : in Util.Properties.Manager'Class;
                   Prefix : in String);

   procedure Load (Realm  : in out File_Application_Manager;
                   Path   : in String;
                   Prefix : in String);

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
                           Auth      : out Servers.Principal_Access;
                           Cacheable : out Boolean);

   --  Create an auth token string that identifies the given principal.  The returned
   --  token will be used by <tt>Authenticate</tt> to retrieve back the principal.  The
   --  returned token does not need to be signed.  It will be inserted in the public part
   --  of the returned access token.
   overriding
   function Authorize (Realm : in File_Realm_Manager;
                       App   : in Servers.Application'Class;
                       Scope : in String;
                       Auth  : in Servers.Principal_Access) return String;

   overriding
   procedure Verify (Realm    : in out File_Realm_Manager;
                     Username : in String;
                     Password : in String;
                     Auth     : out Servers.Principal_Access);

   overriding
   procedure Verify (Realm : in out File_Realm_Manager;
                     Token : in String;
                     Auth  : out Servers.Principal_Access);

   overriding
   procedure Revoke (Realm : in out File_Realm_Manager;
                     Auth  : in Servers.Principal_Access);

   --  Crypt the password using the given salt and return the string composed with
   --  the salt in clear text and the crypted password.
   function Crypt_Password (Realm    : in File_Realm_Manager;
                            Salt     : in String;
                            Password : in String) return String;

   --  Load from the properties the definition of users.  The list of users
   --  is controlled by the property <prefix>.list which contains a comma separated list of
   --  users names or ids.  The user definition are represented by properties
   --  of the form:
   --    <prefix>.<user>.username
   --    <prefix>.<user>.password
   --    <prefix>.<user>.salt
   --  When a 'salt' property is defined, it is assumed that the password is encrypted using
   --  the salt and SHA1 and base64url. Otherwise, the password is in clear text.
   procedure Load (Realm  : in out File_Realm_Manager;
                   Props  : in Util.Properties.Manager'Class;
                   Prefix : in String);

   procedure Load (Realm  : in out File_Realm_Manager;
                   Path   : in String;
                   Prefix : in String);

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

   type File_Principal is new Servers.Principal with record
      Token : Ada.Strings.Unbounded.Unbounded_String;
      Name  : Ada.Strings.Unbounded.Unbounded_String;
      Perms : Security.Permissions.Permission_Index_Set := Security.Permissions.EMPTY_SET;
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
