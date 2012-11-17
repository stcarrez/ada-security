-----------------------------------------------------------------------
--  security-openid -- Open ID 2.0 Support
--  Copyright (C) 2009, 2010, 2011, 2012 Stephane Carrez
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
with Ada.Calendar;
with Ada.Finalization;

--  == OpenID ==
--  The <b>Security.Openid</b> package implements an authentication framework based
--  on OpenID 2.0.
--
--  See OpenID Authentication 2.0 - Final
--  http://openid.net/specs/openid-authentication-2_0.html
--
--  The authentication process is the following:
--
--    * The <b>Initialize</b> procedure is called to configure the OpenID realm and set the
--      OpenID return callback CB.
--    * The <b>Discover</b> procedure is called to retrieve from the OpenID provider the XRDS
--      stream and identify the provider.  An <b>End_Point</b> is returned.
--    * The <b>Associate</b> procedure is called to make the association with the <b>End_Point</b>.
--      The <b>Association</b> record holds session, and authentication.
--    * The <b>Get_Authentication_URL</b> builds the provider OpenID authentication
--      URL for the association.
--    * The application should redirected the user to the authentication URL.
--    * The OpenID provider authenticate the user and redirects the user to the callback CB.
--    * The association is decoded from the callback parameter.
--    * The <b>Verify</b> procedure is called with the association to check the result and
--      obtain the authentication results.
--
--  There are basically two steps that an application must implement.
--
--  [http://ada-security.googlecode.com/svn/wiki/OpenID.png]
--
--  == Discovery: creating the authentication URL ==
--  The first step is to create an authentication URL to which the user must be redirected.
--  In this step, we have to create an OpenId manager, discover the OpenID provider,
--  do the association and get an <b>End_Point</b>.
--
--    Mgr   : Openid.Manager;
--    OP    : Openid.End_Point;
--    Assoc : constant Association_Access := new Association;
--
--  The
--
--    Server.Initialize (Mgr);
--    Mgr.Discover (Provider, OP);  --  Yadis discovery (get the XRDS file).
--    Mgr.Associate (OP, Assoc.all);--  Associate and get an end-point with a key.
--
--  After this first step, you must manage to save the association in the HTTP session.
--  Then you must redirect to the authentication URL that is obtained by using:
--
--    Auth_URL : constant String := Mgr.Get_Authentication_URL (OP, Assoc.all);
--
--  == Verify: acknowledge the authentication in the callback URL ==
--  The second step is done when the user has finished the authentication successfully or not.
--  For this step, the application must get back the association that was saved in the session.
--  It must also prepare a parameters object that allows the OpenID framework to get the
--  URI parameters from the return callback.
--
--    Mgr     : Openid.Manager;
--    Assoc   : Association_Access := ...;  --  Get the association saved in the session.
--    Auth    : Openid.Authentication;
--    Params  : Auth_Params;
--
--  The OpenID manager must be initialized and the <b>Verify</b> procedure is called with
--  the association, parameters and the authentication result.  The <b>Get_Status</b> function
--  must be used to check that the authentication succeeded.
--
--    Server.Initialize (Mgr);
--    Mgr.Verify (Assoc.all, Params, Auth);
--    if Openid.Get_Status (Auth) /= Openid.AUTHENTICATED then ...  -- Failure.
--
--
--
package Security.Openid is

   Invalid_End_Point : exception;

   Service_Error     : exception;

   type Parameters is limited interface;

   function Get_Parameter (Params : in Parameters;
                           Name   : in String) return String is abstract;

   --  ------------------------------
   --  OpenID provider
   --  ------------------------------
   --  The <b>End_Point</b> represents the OpenID provider that will authenticate
   --  the user.
   type End_Point is private;

   function To_String (OP : End_Point) return String;

   --  ------------------------------
   --  Association
   --  ------------------------------
   --  The OpenID association contains the shared secret between the relying party
   --  and the OpenID provider.  The association can be cached and reused to authenticate
   --  different users using the same OpenID provider.  The association also has an
   --  expiration date.
   type Association is private;

   --  Dump the association as a string (for debugging purposes)
   function To_String (Assoc : Association) return String;

   type Auth_Result is (AUTHENTICATED, CANCEL, SETUP_NEEDED, UNKNOWN, INVALID_SIGNATURE);

   --  ------------------------------
   --  OpenID provider
   --  ------------------------------
   --
   type Authentication is private;

   --  Get the email address
   function Get_Email (Auth : in Authentication) return String;

   --  Get the user first name.
   function Get_First_Name (Auth : in Authentication) return String;

   --  Get the user last name.
   function Get_Last_Name (Auth : in Authentication) return String;

   --  Get the user full name.
   function Get_Full_Name (Auth : in Authentication) return String;

   --  Get the user identity.
   function Get_Identity (Auth : in Authentication) return String;

   --  Get the user claimed identity.
   function Get_Claimed_Id (Auth : in Authentication) return String;

   --  Get the user language.
   function Get_Language (Auth : in Authentication) return String;

   --  Get the user country.
   function Get_Country (Auth : in Authentication) return String;

   --  Get the result of the authentication.
   function Get_Status (Auth : in Authentication) return Auth_Result;

   --  ------------------------------
   --  OpenID Default principal
   --  ------------------------------
   type Principal is new Security.Principal with private;
   type Principal_Access is access all Principal'Class;

   --  Get the principal name.
   function Get_Name (From : in Principal) return String;

   --  Get the user email address.
   function Get_Email (From : in Principal) return String;

   --  Get the authentication data.
   function Get_Authentication (From : in Principal) return Authentication;

   --  Create a principal with the given authentication results.
   function Create_Principal (Auth : in Authentication) return Principal_Access;

   --  ------------------------------
   --  OpenID Manager
   --  ------------------------------
   --  The <b>Manager</b> provides the core operations for the OpenID process.
   type Manager is tagged limited private;

   --  Initialize the OpenID realm.
   procedure Initialize (Realm     : in out Manager;
                         Name      : in String;
                         Return_To : in String);

   --  Discover the OpenID provider that must be used to authenticate the user.
   --  The <b>Name</b> can be an URL or an alias that identifies the provider.
   --  A cached OpenID provider can be returned.
   --  (See OpenID Section 7.3 Discovery)
   procedure Discover (Realm  : in out Manager;
                       Name   : in String;
                       Result : out End_Point);

   --  Associate the application (relying party) with the OpenID provider.
   --  The association can be cached.
   --  (See OpenID Section 8 Establishing Associations)
   procedure Associate (Realm  : in out Manager;
                        OP     : in End_Point;
                        Result : out Association);

   function Get_Authentication_URL (Realm : in Manager;
                                    OP    : in End_Point;
                                    Assoc : in Association) return String;

   --  Verify the authentication result
   procedure Verify (Realm   : in out Manager;
                     Assoc   : in Association;
                     Request : in Parameters'Class;
                     Result  : out Authentication);

   --  Verify the authentication result
   procedure Verify_Discovered (Realm   : in out Manager;
                                Assoc   : in Association;
                                Request : in Parameters'Class;
                                Result  : out Authentication);

   --  Verify the signature part of the result
   procedure Verify_Signature (Realm   : in Manager;
                               Assoc   : in Association;
                               Request : in Parameters'Class;
                               Result  : in out Authentication);

   --  Read the XRDS document from the URI and initialize the OpenID provider end point.
   procedure Discover_XRDS (Realm  : in out Manager;
                            URI    : in String;
                            Result : out End_Point);

   --  Extract from the XRDS content the OpenID provider URI.
   --  The default implementation is very basic as it returns the first <URI>
   --  available in the stream without validating the XRDS document.
   --  Raises the <b>Invalid_End_Point</b> exception if the URI cannot be found.
   procedure Extract_XRDS (Realm   : in out Manager;
                           Content : in String;
                           Result  : out End_Point);

private

   use Ada.Strings.Unbounded;

   type Association is record
      Session_Type : Unbounded_String;
      Assoc_Type   : Unbounded_String;
      Assoc_Handle : Unbounded_String;
      Mac_Key      : Unbounded_String;
      Expired      : Ada.Calendar.Time;
   end record;

   type Authentication is record
      Status     : Auth_Result;
      Identity   : Unbounded_String;
      Claimed_Id : Unbounded_String;
      Email      : Unbounded_String;
      Full_Name  : Unbounded_String;
      First_Name : Unbounded_String;
      Last_Name  : Unbounded_String;
      Language   : Unbounded_String;
      Country    : Unbounded_String;
      Gender     : Unbounded_String;
      Timezone   : Unbounded_String;
      Nickname   : Unbounded_String;
   end record;

   type End_Point is record
      URL        : Unbounded_String;
      Alias      : Unbounded_String;
      Expired    : Ada.Calendar.Time;
   end record;

   type Manager is new Ada.Finalization.Limited_Controlled with record
      Realm     : Unbounded_String;
      Return_To : Unbounded_String;
   end record;

   type Principal is new Security.Principal with record
      Auth : Authentication;
   end record;

end Security.Openid;
