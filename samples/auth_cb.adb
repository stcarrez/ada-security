-----------------------------------------------------------------------
--  auth_cb -- Authentication callback examples
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
with Ada.Strings.Fixed;

with AWS.Session;
with AWS.Messages;
with AWS.Templates;
with AWS.Services.Web_Block.Registry;

with Util.Log.Loggers;
package body Auth_CB is

   --  The logger
   Log : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("Auth_CB");

   --  Name of the session attribute which holds information about the active authentication.
   OPENID_ASSOC_ATTRIBUTE : constant String := "openid-assoc";

   USER_INFO_ATTRIBUTE    : constant String := "user-info";

   Null_Association : Security.Auth.Association;
   Null_Auth        : Security.Auth.Authentication;

   package Auth_Session is
     new AWS.Session.Generic_Data (Security.Auth.Association, Null_Association);

   package User_Session is
     new AWS.Session.Generic_Data (Security.Auth.Authentication, Null_Auth);

   overriding
   function Get_Parameter (Params : in Auth_Config;
                           Name   : in String) return String is
   begin
      if Params.Exists (Name) then
         return Params.Get (Name);
      else
         return "";
      end if;
   end Get_Parameter;

   function Get_Auth_Name (Request : in AWS.Status.Data) return String is
      URI  : constant String := AWS.Status.URI (Request);
      Pos  : constant Natural := Ada.Strings.Fixed.Index (URI, "/", Ada.Strings.Backward);
   begin
      if Pos = 0 then
         return "";
      else
         Log.Info ("OpenID authentication with {0}", URI);
         return URI (Pos + 1 .. URI'Last);
      end if;
   end Get_Auth_Name;

   --  ------------------------------
   --  Implement the first step of authentication: discover the OpenID (if any) provider,
   --  create the authorization request and redirect the user to the authorization server.
   --  Some authorization data is saved in the session for the verify process.
   --  ------------------------------
   function Get_Authorization (Request : in AWS.Status.Data) return AWS.Response.Data is
      Name     : constant String := Get_Auth_Name (Request);
      Provider : constant String := Config.Get_Parameter ("auth.provider." & Name);
      URL      : constant String := Config.Get_Parameter ("auth.url." & Name);
      Mgr      : Security.Auth.Manager;
      OP       : Security.Auth.End_Point;
      Assoc    : Security.Auth.Association;
   begin
      if URL'Length = 0 or Provider'Length = 0 then
         return AWS.Response.URL (Location => "/login.html");
      end if;

      Mgr.Initialize (Config, Provider);

      --  Yadis discovery (get the XRDS file).  This step does nothing for OAuth.
      Mgr.Discover (URL, OP);

      --  Associate to the OpenID provider and get an end-point with a key.
      Mgr.Associate (OP, Assoc);

      --  Save the association in the HTTP session and
      --  redirect the user to the OpenID provider.
      declare
         Auth_URL : constant String := Mgr.Get_Authentication_URL (OP, Assoc);
         SID      : constant AWS.Session.Id := AWS.Status.Session (Request);
      begin
         Log.Info ("Redirect to auth URL: {0}", Auth_URL);

         Auth_Session.Set (SID, OPENID_ASSOC_ATTRIBUTE, Assoc);
         return AWS.Response.URL (Location => Auth_URL);
      end;
   end Get_Authorization;

   --  ------------------------------
   --  Second step of authentication: verify the authorization response.  The authorization
   --  data saved in the session is extracted and checked against the response.  If it matches
   --  the response is verified to check if the authentication succeeded or not.
   --  The user is then redirected to the success page.
   --  ------------------------------
   function Verify_Authorization (Request : in AWS.Status.Data) return AWS.Response.Data is

      use type Security.Auth.Auth_Result;

      --  Give access to the request parameters.
      type Auth_Params is limited new Security.Auth.Parameters with null record;

      overriding
      function Get_Parameter (Params : in Auth_Params;
                              Name   : in String) return String;

      overriding
      function Get_Parameter (Params : in Auth_Params;
                              Name   : in String) return String is
         pragma Unreferenced (Params);
      begin
         return AWS.Status.Parameter (Request, Name);
      end Get_Parameter;

      Mgr        : Security.Auth.Manager;
      Assoc      : Security.Auth.Association;
      Credential : Security.Auth.Authentication;
      Params     : Auth_Params;
      SID        : constant AWS.Session.Id := AWS.Status.Session (Request);
   begin
      Log.Info ("Verify openid authentication");

      if not AWS.Session.Exist (SID, OPENID_ASSOC_ATTRIBUTE) then
         Log.Warn ("Session has expired during OpenID authentication process");
         return AWS.Response.Build ("text/html", "Session has expired", AWS.Messages.S403);
      end if;

      Assoc := Auth_Session.Get (SID, OPENID_ASSOC_ATTRIBUTE);

      --  Cleanup the session and drop the association end point.
      AWS.Session.Remove (SID, OPENID_ASSOC_ATTRIBUTE);

      Mgr.Initialize (Provider => Security.Auth.Get_Provider (Assoc),
                      Params   => Config);

      --  Verify that what we receive through the callback matches the association key.
      Mgr.Verify (Assoc, Params, Credential);
      if Security.Auth.Get_Status (Credential) /= Security.Auth.AUTHENTICATED then
         Log.Info ("Authentication has failed");
         return AWS.Response.Build ("text/html", "Authentication failed", AWS.Messages.S403);
      end if;

      Log.Info ("Authentication succeeded for {0}", Security.Auth.Get_Email (Credential));

      Log.Info ("Claimed id: {0}", Security.Auth.Get_Claimed_Id (Credential));
      Log.Info ("Email:      {0}", Security.Auth.Get_Email (Credential));
      Log.Info ("Name:       {0}", Security.Auth.Get_Full_Name (Credential));

      --  Save the user information in the session (for the purpose of this demo).
      User_Session.Set (SID, USER_INFO_ATTRIBUTE, Credential);

      declare
         URL  : constant String := Config.Get_Parameter ("openid.success_url");
      begin
         Log.Info ("Redirect user to success URL: {0}", URL);

         return AWS.Response.URL (Location => URL);
      end;
   end Verify_Authorization;

   function User_Info (Request : in AWS.Status.Data) return AWS.Response.Data is
      URI        : constant String := AWS.Status.URI (Request);
      SID        : constant AWS.Session.Id := AWS.Status.Session (Request);
      Credential : Security.Auth.Authentication;
      Set        : AWS.Templates.Translate_Set;
   begin
      if AWS.Session.Exist (SID, USER_INFO_ATTRIBUTE) then
         Credential := User_Session.Get (SID, USER_INFO_ATTRIBUTE);
         AWS.Templates.Insert (Set,
           AWS.Templates.Assoc ("ID",
             Security.Auth.Get_Claimed_Id (Credential)));
         AWS.Templates.Insert (Set, AWS.Templates.Assoc ("EMAIL",
           Security.Auth.Get_Email (Credential)));
         AWS.Templates.Insert (Set, AWS.Templates.Assoc ("NAME",
           Security.Auth.Get_Full_Name (Credential)));
      end if;
      return AWS.Services.Web_Block.Registry.Build ("success", Request, Set);
   end User_Info;

end Auth_CB;
