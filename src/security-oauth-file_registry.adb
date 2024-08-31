-----------------------------------------------------------------------
--  security-oauth-file_registry -- File Based Application and Realm
--  Copyright (C) 2017 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
with Util.Encoders.HMAC.SHA1;
with Util.Log.Loggers;

package body Security.OAuth.File_Registry is

   Log : constant Util.Log.Loggers.Logger
     := Util.Log.Loggers.Create ("Security.OAuth.File_Registry");

   --  ------------------------------
   --  Get the principal name.
   --  ------------------------------
   overriding
   function Get_Name (From : in File_Principal) return String is
   begin
      return To_String (From.Name);
   end Get_Name;

   --  ------------------------------
   --  Check if the permission was granted.
   --  ------------------------------
   overriding
   function Has_Permission (Auth       : in File_Principal;
                            Permission : in Security.Permissions.Permission_Index)
                            return Boolean is
   begin
      return Security.Permissions.Has_Permission (Auth.Perms, Permission);
   end Has_Permission;

   --  ------------------------------
   --  Find the application that correspond to the given client id.
   --  The <tt>Invalid_Application</tt> exception should be raised if there is no such application.
   --  ------------------------------
   overriding
   function Find_Application (Realm     : in File_Application_Manager;
                              Client_Id : in String) return Servers.Application'Class is
      Pos : constant Application_Maps.Cursor := Realm.Applications.Find (Client_Id);
   begin
      if not Application_Maps.Has_Element (Pos) then
         raise Servers.Invalid_Application;
      end if;
      return Application_Maps.Element (Pos);
   end Find_Application;

   --  ------------------------------
   --  Add the application to the application repository.
   --  ------------------------------
   procedure Add_Application (Realm : in out File_Application_Manager;
                              App   : in Servers.Application) is
   begin
      Realm.Applications.Include (App.Get_Application_Identifier, App);
   end Add_Application;

   --  ------------------------------
   --  Load from the properties the definition of applications.  The list of applications
   --  is controlled by the property <prefix>.list which contains a comma separated list of
   --  application names or ids.  The application definition are represented by properties
   --  of the form:
   --    <prefix>.<app>.client_id
   --    <prefix>.<app>.client_secret
   --    <prefix>.<app>.callback_url
   --  ------------------------------
   procedure Load (Realm  : in out File_Application_Manager;
                   Props  : in Util.Properties.Manager'Class;
                   Prefix : in String) is
      procedure Configure (Basename : in String);

      procedure Configure (Basename : in String) is
         App : Servers.Application;
      begin
         App.Set_Application_Identifier (Props.Get (Basename & ".client_id"));
         App.Set_Application_Secret (Props.Get (Basename & ".client_secret"));
         App.Set_Application_Callback (Props.Get (Basename & ".callback_url", ""));
         Realm.Add_Application (App);
      end Configure;

      List  : constant String := Props.Get (Prefix & ".list");
      First : Natural := List'First;
      Last  : Natural;
      Count : Natural := 0;
   begin
      Log.Info ("Loading application with prefix {0}", Prefix);
      while First <= List'Last loop
         Last := Util.Strings.Index (Source => List, Char => ',', From => First);
         if Last = 0 then
            Last := List'Last;
         else
            Last := Last - 1;
         end if;
         begin
            Configure (Prefix & "." & List (First .. Last));
            Count := Count + 1;
         exception
            when others =>
               Log.Error ("Invalid application definition {0}",
                          Prefix & "." & List (First .. Last));
         end;
         First := Last + 2;
      end loop;
      Log.Info ("Loaded {0} applications", Util.Strings.Image (Count));
   end Load;

   procedure Load (Realm  : in out File_Application_Manager;
                   Path   : in String;
                   Prefix : in String) is
      Props : Util.Properties.Manager;
   begin
      Log.Info ("Loading application with prefix {0} from {1}", Prefix, Path);
      Props.Load_Properties (Path);
      Realm.Load (Props, Prefix);
   end Load;

   --  ------------------------------
   --  Load from the properties the definition of users.  The list of users
   --  is controlled by the property <prefix>.list which contains a comma separated list of
   --  users names or ids.  The user definition are represented by properties
   --  of the form:
   --    <prefix>.<user>.username
   --    <prefix>.<user>.password
   --    <prefix>.<user>.salt
   --  When a 'salt' property is defined, it is assumed that the password is encrypted using
   --  the salt and SHA1 and base64url. Otherwise, the password is in clear text.
   --  ------------------------------
   procedure Load (Realm  : in out File_Realm_Manager;
                   Props  : in Util.Properties.Manager'Class;
                   Prefix : in String) is
      procedure Configure (Basename : in String);

      procedure Configure (Basename : in String) is
         Username : constant String := Props.Get (Basename & ".username");
         Password : constant String := Props.Get (Basename & ".password");
         Salt     : constant String := Props.Get (Basename & ".salt", "");
      begin
         if Salt'Length = 0 then
            Realm.Add_User (Username, Password);
         else
            Realm.Users.Include (Username, Salt & " " & Password);
         end if;
      end Configure;

      List  : constant String := Props.Get (Prefix & ".list");
      First : Natural := List'First;
      Last  : Natural;
      Count : Natural := 0;
   begin
      Log.Info ("Loading users with prefix {0}", Prefix);
      while First <= List'Last loop
         Last := Util.Strings.Index (Source => List, Char => ',', From => First);
         if Last = 0 then
            Last := List'Last;
         else
            Last := Last - 1;
         end if;
         begin
            Configure (Prefix & "." & List (First .. Last));
            Count := Count + 1;
         exception
            when others =>
               Log.Error ("Invalid user definition {0}",
                          Prefix & "." & List (First .. Last));
         end;
         First := Last + 2;
      end loop;
      Log.Info ("Loaded {0} users", Util.Strings.Image (Count));
   end Load;

   procedure Load (Realm  : in out File_Realm_Manager;
                   Path   : in String;
                   Prefix : in String) is
      Props : Util.Properties.Manager;
   begin
      Log.Info ("Loading users with prefix {0} from {1}", Prefix, Path);
      Props.Load_Properties (Path);
      Realm.Load (Props, Prefix);
   end Load;

   --  ------------------------------
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
   --  ------------------------------
   overriding
   procedure Authenticate (Realm     : in out File_Realm_Manager;
                           Token     : in String;
                           Auth      : out Servers.Principal_Access;
                           Cacheable : out Boolean) is
      Pos : constant Token_Maps.Cursor := Realm.Tokens.Find (Token);
   begin
      if Token_Maps.Has_Element (Pos) then
         Auth := Token_Maps.Element (Pos).all'Access;
      else
         Auth := null;
      end if;
      Cacheable := True;
   end Authenticate;

   --  ------------------------------
   --  Create an auth token string that identifies the given principal.  The returned
   --  token will be used by <tt>Authenticate</tt> to retrieve back the principal.  The
   --  returned token does not need to be signed.  It will be inserted in the public part
   --  of the returned access token.
   --  ------------------------------
   overriding
   function Authorize (Realm : in File_Realm_Manager;
                       App   : in Servers.Application'Class;
                       Scope : in String;
                       Auth  : in Servers.Principal_Access) return String is
      pragma Unreferenced (Realm, App);
      File_Auth : constant File_Principal_Access := File_Principal (Auth.all)'Access;
   begin
      for P of Security.Permissions.Get_Permission_Array (Scope) loop
         Security.Permissions.Add_Permission (File_Auth.Perms, P);
      end loop;
      return To_String (File_Principal (Auth.all).Token);
   end Authorize;

   overriding
   procedure Verify (Realm    : in out File_Realm_Manager;
                     Username : in String;
                     Password : in String;
                     Auth     : out Servers.Principal_Access) is
      Result : File_Principal_Access;
      Pos    : constant User_Maps.Cursor := Realm.Users.Find (Username);
   begin
      if not User_Maps.Has_Element (Pos) then
         Log.Info ("Verify user {0} - unknown user", Username);
         Auth := null;
         return;
      end if;

      --  Verify that the crypt password with the recorded salt are the same.
      declare
         Expect : constant String := User_Maps.Element (Pos);
         Hash   : constant String := Realm.Crypt_Password (Expect, Password);
      begin
         if Hash /= Expect then
            Log.Info ("Verify user {0} - invalid password", Username);
            Auth := null;
            return;
         end if;
      end;

      --  Generate a random token and make the principal to record it.
      declare
         Token : constant String := Realm.Random.Generate (Realm.Token_Bits);
      begin
         Result := new File_Principal;
         Ada.Strings.Unbounded.Append (Result.Token, Token);
         Ada.Strings.Unbounded.Append (Result.Name, Username);
         Realm.Tokens.Insert (Token, Result);
      end;
      Log.Info ("Verify user {0} - grant access", Username);
      Auth := Result.all'Access;
   end Verify;

   overriding
   procedure Verify (Realm : in out File_Realm_Manager;
                     Token : in String;
                     Auth  : out Servers.Principal_Access) is
      pragma Unreferenced (Realm);
   begin
      Log.Info ("Verify token {0}: refused", Token);
      Auth := null;
   end Verify;

   overriding
   procedure Revoke (Realm : in out File_Realm_Manager;
                     Auth  : in Servers.Principal_Access) is
      use type Servers.Principal_Access;
   begin
      if Auth /= null and then Auth.all in File_Principal'Class then
         Realm.Tokens.Delete (To_String (File_Principal (Auth.all).Token));
      end if;
   end Revoke;

   --  ------------------------------
   --  Crypt the password using the given salt and return the string composed with
   --  the salt in clear text and the crypted password.
   --  ------------------------------
   function Crypt_Password (Realm    : in File_Realm_Manager;
                            Salt     : in String;
                            Password : in String) return String is
      pragma Unreferenced (Realm);

      Pos : Natural := Util.Strings.Index (Salt, ' ');
   begin
      if Pos = 0 then
         Pos := Salt'Last;
      else
         Pos := Pos - 1;
      end if;
      return Salt (Salt'First .. Pos) & " "
         & Util.Encoders.HMAC.SHA1.Sign_Base64 (Key  => Salt (Salt'First .. Pos),
                                                Data => Password,
                                                URL  => True);
   end Crypt_Password;

   --  ------------------------------
   --  Add a username with the associated password.
   --  ------------------------------
   procedure Add_User (Realm    : in out File_Realm_Manager;
                       Username : in String;
                       Password : in String) is
      Salt : constant String := Realm.Random.Generate (Realm.Token_Bits);
   begin
      Realm.Users.Include (Username, Realm.Crypt_Password (Salt, Password));
   end Add_User;

end Security.OAuth.File_Registry;
