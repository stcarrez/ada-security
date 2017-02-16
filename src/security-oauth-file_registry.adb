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
with Util.Strings;

package body Security.OAuth.File_Registry is

   --  ------------------------------
   --  Get the principal name.
   --  ------------------------------
   overriding
   function Get_Name (From : in File_Principal) return String is
   begin
      return To_String (From.Name);
   end Get_Name;

   --  ------------------------------
   --  Find the application that correspond to the given client id.
   --  The <tt>Invalid_Application</tt> exception should be raised if there is no such application.
   --  ------------------------------
   overriding
   function Find_Application (Realm     : in File_Application_Manager;
                              Client_Id : in String) return Servers.Application'Class is
      Pos : Application_Maps.Cursor := Realm.Applications.Find (Client_Id);
   begin
      if not Application_Maps.Has_Element (Pos) then
         raise Servers.Invalid_Application;
      end if;
      return Application_Maps.Element (Pos);
   end Find_Application;

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
                           Auth      : out Principal_Access;
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
                       Auth  : in Principal_Access) return String is
   begin
      return To_String (File_Principal (Auth.all).Token);
   end Authorize;

   overriding
   procedure Verify (Realm    : in out File_Realm_Manager;
                     Username : in String;
                     Password : in String;
                     Auth     : out Principal_Access) is
      Result : File_Principal_Access;
      Pos    : constant User_Maps.Cursor := Realm.Users.Find (Username);
   begin
      if not User_Maps.Has_Element (Pos) then
         Auth := null;
         return;
      end if;
      if Password /= User_Maps.Element (Pos) then
         Auth := null;
         return;
      end if;
      Result := new File_Principal;
      Realm.Tokens.Insert (To_String (Result.Token), Result);
      Auth := Result.all'Access;
   end Verify;

   overriding
   procedure Verify (Realm : in out File_Realm_Manager;
                     Token : in String;
                     Auth  : out Principal_Access) is
   begin
      null;
   end Verify;

   overriding
   procedure Revoke (Realm : in out File_Realm_Manager;
                     Auth  : in Principal_Access) is
   begin
      if Auth /= null and then Auth.all in File_Principal'Class then
         Realm.Tokens.Delete (To_String (File_Principal (Auth.all).Token));
      end if;
   end Revoke;

end Security.OAuth.File_Registry;
