-----------------------------------------------------------------------
--  security-openid -- OpenID 2.0 Support
--  Copyright (C) 2009, 2010, 2011, 2012, 2013 Stephane Carrez
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

with Util.Log.Loggers;

with Security.Auth.OpenID;
with Security.Auth.OAuth.Facebook;
package body Security.Auth is

   Log : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("Security.Auth");

   --  ------------------------------
   --  Get the provider.
   --  ------------------------------
   function Get_Provider (Assoc : in Association) return String is
   begin
      return To_String (Assoc.Provider);
   end Get_Provider;

   --  ------------------------------
   --  Get the email address
   --  ------------------------------
   function Get_Email (Auth : in Authentication) return String is
   begin
      return To_String (Auth.Email);
   end Get_Email;

   --  ------------------------------
   --  Get the user first name.
   --  ------------------------------
   function Get_First_Name (Auth : in Authentication) return String is
   begin
      return To_String (Auth.First_Name);
   end Get_First_Name;

   --  ------------------------------
   --  Get the user last name.
   --  ------------------------------
   function Get_Last_Name (Auth : in Authentication) return String is
   begin
      return To_String (Auth.Last_Name);
   end Get_Last_Name;

   --  ------------------------------
   --  Get the user full name.
   --  ------------------------------
   function Get_Full_Name (Auth : in Authentication) return String is
   begin
      return To_String (Auth.Full_Name);
   end Get_Full_Name;

   --  ------------------------------
   --  Get the user identity.
   --  ------------------------------
   function Get_Identity (Auth : in Authentication) return String is
   begin
      return To_String (Auth.Identity);
   end Get_Identity;

   --  ------------------------------
   --  Get the user claimed identity.
   --  ------------------------------
   function Get_Claimed_Id (Auth : in Authentication) return String is
   begin
      return To_String (Auth.Claimed_Id);
   end Get_Claimed_Id;

   --  ------------------------------
   --  Get the user language.
   --  ------------------------------
   function Get_Language (Auth : in Authentication) return String is
   begin
      return To_String (Auth.Language);
   end Get_Language;

   --  ------------------------------
   --  Get the user country.
   --  ------------------------------
   function Get_Country (Auth : in Authentication) return String is
   begin
      return To_String (Auth.Country);
   end Get_Country;

   --  ------------------------------
   --  Get the result of the authentication.
   --  ------------------------------
   function Get_Status (Auth : in Authentication) return Auth_Result is
   begin
      return Auth.Status;
   end Get_Status;

   --  ------------------------------
   --  Default principal
   --  ------------------------------

   --  ------------------------------
   --  Get the principal name.
   --  ------------------------------
   function Get_Name (From : in Principal) return String is
   begin
      return Get_First_Name (From.Auth) & " " & Get_Last_Name (From.Auth);
   end Get_Name;

   --  ------------------------------
   --  Get the user email address.
   --  ------------------------------
   function Get_Email (From : in Principal) return String is
   begin
      return Get_Email (From.Auth);
   end Get_Email;

   --  ------------------------------
   --  Get the authentication data.
   --  ------------------------------
   function Get_Authentication (From : in Principal) return Authentication is
   begin
      return From.Auth;
   end Get_Authentication;

   --  ------------------------------
   --  Create a principal with the given authentication results.
   --  ------------------------------
   function Create_Principal (Auth : in Authentication) return Principal_Access is
      P : constant Principal_Access := new Principal;
   begin
      P.Auth := Auth;
      return P;
   end Create_Principal;

   --  ------------------------------
   --  Initialize the OpenID realm.
   --  ------------------------------
   procedure Initialize (Realm  : in out Manager;
                         Params : in Parameters'Class;
                         Name   : in String := PROVIDER_OPENID) is
      Provider : constant String := Params.Get_Parameter ("auth.provider." & Name);
      Impl     : Manager_Access;
   begin
      if Provider = PROVIDER_OPENID then
         Impl := new Security.Auth.OpenID.Manager;

      elsif Provider = PROVIDER_FACEBOOK then
         Impl := new Security.Auth.OAuth.Facebook.Manager;

      else
         Log.Error ("Authentication provider {0} not recognized", Provider);
         raise Service_Error with "Authentication provider not supported";
      end if;
      Realm.Delegate := Impl;
      Impl.Initialize (Params, Name);
      Realm.Provider := To_Unbounded_String (Name);
   end Initialize;

   --  ------------------------------
   --  Discover the OpenID provider that must be used to authenticate the user.
   --  The <b>Name</b> can be an URL or an alias that identifies the provider.
   --  A cached OpenID provider can be returned.
   --  (See OpenID Section 7.3 Discovery)
   --  ------------------------------
   procedure Discover (Realm  : in out Manager;
                       Name   : in String;
                       Result : out End_Point) is
   begin
      if Realm.Delegate /= null then
         Realm.Delegate.Discover (Name, Result);
      else
--           Result.URL := Realm.Realm;
         Result.Alias := To_Unbounded_String ("");
      end if;
   end Discover;

   --  ------------------------------
   --  Associate the application (relying party) with the OpenID provider.
   --  The association can be cached.
   --  (See OpenID Section 8 Establishing Associations)
   --  ------------------------------
   procedure Associate (Realm  : in out Manager;
                        OP     : in End_Point;
                        Result : out Association) is
   begin
      Result.Provider := Realm.Provider;
      if Realm.Delegate /= null then
         Realm.Delegate.Associate (OP, Result);
      end if;
   end Associate;

   --  ------------------------------
   --  Get the authentication URL to which the user must be redirected for authentication
   --  by the authentication server.
   --  ------------------------------
   function Get_Authentication_URL (Realm : in Manager;
                                    OP    : in End_Point;
                                    Assoc : in Association) return String is
   begin
      if Realm.Delegate /= null then
         return Realm.Delegate.Get_Authentication_URL (OP, Assoc);
      else
         return To_String (OP.URL);
      end if;
   end Get_Authentication_URL;

   procedure Set_Result (Result  : in out Authentication;
                         Status  : in Auth_Result;
                         Message : in String) is
   begin
      if Status /= AUTHENTICATED then
         Log.Error ("OpenID verification failed: {0}", Message);
      else
         Log.Info ("OpenID verification: {0}", Message);
      end if;
      Result.Status := Status;
   end Set_Result;

   --  ------------------------------
   --  Verify the authentication result
   --  ------------------------------
   procedure Verify (Realm   : in out Manager;
                     Assoc   : in Association;
                     Request : in Parameters'Class;
                     Result  : out Authentication) is
   begin
      if Realm.Delegate /= null then
         Realm.Delegate.Verify (Assoc, Request, Result);
      else
         Set_Result (Result, SETUP_NEEDED, "Setup is needed");
      end if;
   end Verify;

   function To_String (OP : End_Point) return String is
   begin
      return "openid://" & To_String (OP.URL);
   end To_String;

   function To_String (Assoc : Association) return String is
   begin
      return "session_type=" & To_String (Assoc.Session_Type)
        & "&assoc_type=" & To_String (Assoc.Assoc_Type)
        & "&assoc_handle=" & To_String (Assoc.Assoc_Handle)
        & "&mac_key=" & To_String (Assoc.Mac_Key);
   end To_String;

end Security.Auth;
