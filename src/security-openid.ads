-----------------------------------------------------------------------
--  security-openid -- OpenID 2.0 Support
--  Copyright (C) 2009, 2010, 2011, 2012, 2015 Stephane Carrez
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
with Security.Auth;

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
package Security.OpenID is

   pragma Obsolescent ("Use the Security.Auth package instead");

   Invalid_End_Point : exception;

   Service_Error     : exception;

   subtype Parameters is Security.Auth.Parameters;

   --  ------------------------------
   --  OpenID provider
   --  ------------------------------
   --  The <b>End_Point</b> represents the OpenID provider that will authenticate
   --  the user.
   subtype End_Point is Security.Auth.End_Point;

   --  ------------------------------
   --  Association
   --  ------------------------------
   --  The OpenID association contains the shared secret between the relying party
   --  and the OpenID provider.  The association can be cached and reused to authenticate
   --  different users using the same OpenID provider.  The association also has an
   --  expiration date.
   subtype Association is Security.Auth.End_Point;

   subtype Auth_Result is Security.Auth.Auth_Result;

   --  ------------------------------
   --  OpenID provider
   --  ------------------------------
   --
   subtype Authentication is Security.Auth.Authentication;

   --  ------------------------------
   --  OpenID Default principal
   --  ------------------------------
   subtype Principal is Security.Auth.Principal;
   subtype Principal_Access is Security.Auth.Principal_Access;

   --  ------------------------------
   --  OpenID Manager
   --  ------------------------------
   --  The <b>Manager</b> provides the core operations for the OpenID process.
   subtype Manager is Security.Auth.Manager;

   --  Initialize the OpenID realm.
   procedure Initialize (Realm     : in out Manager;
                         Name      : in String;
                         Return_To : in String);

end Security.OpenID;
