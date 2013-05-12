-----------------------------------------------------------------------
--  security-openid -- OpenID 2.0 Support
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

--  == OpenID ==
--  The <b>Security.OpenID</b> package implements an authentication framework based
--  on OpenID 2.0.
--
--  See OpenID Authentication 2.0 - Final
--  http://openid.net/specs/openid-authentication-2_0.html
--
--  There are basically two steps that an application must implement:
--
--    * <b>Discovery</b>: to resolve and use the OpenID provider and redirect the user to the
--      provider authentication form.
--    * <b>Verify</b>: to decode the authentication and check its result.
--
--  [http://ada-security.googlecode.com/svn/wiki/OpenID.png]
--
--  The authentication process is the following:
--
--    * The application should redirect the user to the authentication URL.
--    * The OpenID provider authenticate the user and redirects the user to the callback CB.
--    * The association is decoded from the callback parameter.
--    * The <b>Verify</b> procedure is called with the association to check the result and
--      obtain the authentication results.
--
--  === Initialization ===
--  The initialization process must be done before each two steps (discovery and verify).
--  The OpenID manager must be declared and configured.
--
--    Mgr   : Security.OpenID.Manager;
--
--  For the configuration, the <b>Initialize</b> procedure is called to configure
--  the OpenID realm and set the OpenID return callback URL.  The return callback
--  must be a valid URL that is based on the realm.  Example:
--
--    Mgr.Initialize (Name      => "http://app.site.com/auth",
--                    Return_To => "http://app.site.com/auth/verify");
--
--  After this initialization, the OpenID manager can be used in the authentication process.
--
--  === Discovery: creating the authentication URL ===
--  The first step is to create an authentication URL to which the user must be redirected.
--  In this step, we have to create an OpenID manager, discover the OpenID provider,
--  do the association and get an <b>End_Point</b>.  The OpenID provider is specified as an
--  URL, below is an example for Google OpenID:
--
--    Provider : constant String := "https://www.google.com/accounts/o8/id";
--    OP       : Security.OpenID.End_Point;
--    Assoc    : constant Security.OpenID.Association_Access := new Security.OpenID.Association;
--
--  The following steps are performed:
--
--    * The <b>Discover</b> procedure is called to retrieve from the OpenID provider the XRDS
--      stream and identify the provider.  An <b>End_Point</b> is returned in <tt>OP</tt>.
--    * The <b>Associate</b> procedure is called to make the association with the <b>End_Point</b>.
--      The <b>Association</b> record holds session, and authentication.
--
--    Mgr.Discover (Provider, OP);  --  Yadis discovery (get the XRDS file).
--    Mgr.Associate (OP, Assoc.all);--  Associate and get an end-point with a key.
--
--  After this first step, you must manage to save the association in the HTTP session.
--  Then you must redirect to the authentication URL that is obtained by using:
--
--    Auth_URL : constant String := Mgr.Get_Authentication_URL (OP, Assoc.all);
--
--  === Verify: acknowledge the authentication in the callback URL ===
--  The second step is done when the user has finished the authentication successfully or not.
--  For this step, the application must get back the association that was saved in the session.
--  It must also prepare a parameters object that allows the OpenID framework to get the
--  URI parameters from the return callback.
--
--    Assoc   : Association_Access := ...;  --  Get the association saved in the session.
--    Auth    : OpenID.Authentication;
--    Params  : Auth_Params;
--
--  The OpenID manager must be initialized and the <b>Verify</b> procedure is called with
--  the association, parameters and the authentication result.  The <b>Get_Status</b> function
--  must be used to check that the authentication succeeded.
--
--    Mgr.Verify (Assoc.all, Params, Auth);
--    if Security.OpenID.Get_Status (Auth) = Security.OpenID.AUTHENTICATED then ...  -- Success.
--
--  === Principal creation ===
--  After the user is successfully authenticated, a user principal can be created and saved in
--  the session.  The user principal can then be used to assign permissions to that user and
--  enforce the application permissions using the security policy manger.
--
--    P : Security.OpenID.Principal_Access := Security.OpenID.Create_Principal (Auth);
--
private package Security.Auth.OpenID is

   --  ------------------------------
   --  OpenID Manager
   --  ------------------------------
   --  The <b>Manager</b> provides the core operations for the OpenID process.
   type Manager is new Security.Auth.Manager with private;

   --  Initialize the authentication realm.
   overriding
   procedure Initialize (Realm     : in out Manager;
                         Params    : in Parameters'Class;
                         Provider  : in String := PROVIDER_OPENID);

   --  Discover the OpenID provider that must be used to authenticate the user.
   --  The <b>Name</b> can be an URL or an alias that identifies the provider.
   --  A cached OpenID provider can be returned.
   --  Read the XRDS document from the URI and initialize the OpenID provider end point.
   --  (See OpenID Section 7.3 Discovery)
   overriding
   procedure Discover (Realm  : in out Manager;
                       Name   : in String;
                       Result : out End_Point);

   --  Associate the application (relying party) with the OpenID provider.
   --  The association can be cached.
   --  (See OpenID Section 8 Establishing Associations)
   overriding
   procedure Associate (Realm  : in out Manager;
                        OP     : in End_Point;
                        Result : out Association);

   overriding
   function Get_Authentication_URL (Realm : in Manager;
                                    OP    : in End_Point;
                                    Assoc : in Association) return String;

   --  Verify the authentication result
   overriding
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

   --  Extract from the XRDS content the OpenID provider URI.
   --  The default implementation is very basic as it returns the first <URI>
   --  available in the stream without validating the XRDS document.
   --  Raises the <b>Invalid_End_Point</b> exception if the URI cannot be found.
   procedure Extract_XRDS (Realm   : in out Manager;
                           Content : in String;
                           Result  : out End_Point);

private

   type Manager is new Security.Auth.Manager with record
      Return_To : Unbounded_String;
      Realm     : Unbounded_String;
   end record;

end Security.Auth.OpenID;
