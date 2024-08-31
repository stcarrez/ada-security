-----------------------------------------------------------------------
--  security-auth -- Authentication Support
--  Copyright (C) 2009 - 2020, 2022 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
with Ada.Strings.Unbounded;
with Ada.Calendar;
with Ada.Finalization;

--  = Authentication =
--  The `Security.Auth` package implements an authentication framework that is
--  suitable for OpenID 2.0, OAuth 2.0 and later for OpenID Connect.  It allows an application
--  to authenticate users using an external authorization server such as Google, Facebook,
--  Google +, Twitter and others.
--
--  See OpenID Authentication 2.0 - Final
--  https://openid.net/specs/openid-authentication-2_0.html
--
--  See OpenID Connect Core 1.0
--  https://openid.net/specs/openid-connect-core-1_0.html
--
--  See Facebook API: The Login Flow for Web (without JavaScript SDK)
--  https://developers.facebook.com/docs/facebook-login/login-flow-for-web-no-jssdk/
--
--  Despite their subtle differences, all these authentication frameworks share almost
--  a common flow.  The API provided by `Security.Auth` defines an abstraction suitable
--  for all these frameworks.
--
--  There are basically two steps that an application must implement:
--
--    * `Discovery`: to resolve and use the OpenID provider and redirect the user to the
--      provider authentication form.
--    * `Verify`: to decode the authentication and check its result.
--
--  [[images/OpenID.png]]
--
--  The authentication process is the following:
--
--    * The application should redirect the user to the authentication URL.
--    * The OpenID provider authenticate the user and redirects the user to the callback CB.
--    * The association is decoded from the callback parameter.
--    * The `Verify` procedure is called with the association to check the result and
--      obtain the authentication results.
--
--  == Initialization ==
--  The initialization process must be done before each two steps (discovery and verify).
--  The Authentication manager must be declared and configured.
--
--    Mgr   : Security.Auth.Manager;
--
--  For the configuration, the <b>Initialize</b> procedure is called to configure
--  the Auth realm and set the authentication return callback URL.  The return callback
--  must be a valid URL that is based on the realm.  Example:
--
--    Mgr.Initialize (Name      => "http://app.site.com/auth",
--                    Return_To => "http://app.site.com/auth/verify",
--                    Realm     => "openid");
--
--  After this initialization, the authentication manager can be used in the authentication
--  process.
--
--  @include security-auth-openid.ads
--  @include security-auth-oauth-googleplus.ads
--
--  == Discovery: creating the authentication URL ==
--  The first step is to create an authentication URL to which the user must be redirected.
--  In this step, we have to create an OpenID manager, discover the OpenID provider,
--  do the association and get an <b>End_Point</b>.  The OpenID provider is specified as an
--  URL, below is an example for Google OpenID:
--
--    Provider : constant String := "https://www.google.com/accounts/o8/id";
--    OP       : Security.Auth.End_Point;
--    Assoc    : constant Security.Auth.Association_Access := new Security.Auth.Association;
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
--  == Verify: acknowledge the authentication in the callback URL ==
--  The second step is done when the user has finished the authentication successfully or not.
--  For this step, the application must get back the association that was saved in the session.
--  It must also prepare a parameters object that allows the OpenID framework to get the
--  URI parameters from the return callback.
--
--    Assoc      : Association_Access := ...;  --  Get the association saved in the session.
--    Credential : Security.Auth.Authentication;
--    Params     : Auth_Params;
--
--  The auth manager must be initialized and the <b>Verify</b> procedure is called with
--  the association, parameters and the authentication result.  The <b>Get_Status</b> function
--  must be used to check that the authentication succeeded.
--
--    Mgr.Verify (Assoc.all, Params, Credential);
--    if Security.Auth.Get_Status (Credential) = Security.Auth.AUTHENTICATED then ...  -- Success.
--
--  == Principal creation ==
--  After the user is successfully authenticated, a user principal can be created and saved in
--  the session.  The user principal can then be used to assign permissions to that user and
--  enforce the application permissions using the security policy manger.
--
--    P : Security.Auth.Principal_Access := Security.Auth.Create_Principal (Credential);
--
package Security.Auth is

   --  Use an authentication server implementing OpenID 2.0.
   PROVIDER_OPENID   : constant String := "openid";

   --  Use the Facebook OAuth 2.0 - draft 12 authentication server.
   PROVIDER_FACEBOOK : constant String := "facebook";

   --  Use the Google+ OpenID Connect Basic Client
   PROVIDER_GOOGLE_PLUS : constant String := "google-plus";

   --  Use the Yahoo! OpenID Connect Basic Client
   PROVIDER_YAHOO : constant String := "yahoo";

   --  Use the GitHub OpenID Connect Basic Client
   PROVIDER_GITHUB : constant String := "github";

   Invalid_End_Point : exception;

   Service_Error     : exception;

   type Parameters is limited interface;

   function Get_Parameter (Params : in Parameters;
                           Name   : in String) return String is abstract;

   --  ------------------------------
   --  Auth provider
   --  ------------------------------
   --  The <b>End_Point</b> represents the authentication provider that will authenticate
   --  the user.
   type End_Point is private;

   function To_String (OP : End_Point) return String;

   --  ------------------------------
   --  Association
   --  ------------------------------
   --  The association contains the shared secret between the relying party
   --  and the authentication provider.  The association can be cached and reused to authenticate
   --  different users using the same authentication provider.  The association also has an
   --  expiration date.
   type Association is private;

   --  Get the provider.
   function Get_Provider (Assoc : in Association) return String;

   --  Dump the association as a string (for debugging purposes)
   function To_String (Assoc : Association) return String;

   type Auth_Result is (AUTHENTICATED, CANCEL, SETUP_NEEDED, UNKNOWN, INVALID_SIGNATURE);

   --  ------------------------------
   --  Authentication result
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
   --  Default principal
   --  ------------------------------
   type Principal is new Security.Principal with private;
   type Principal_Access is access all Principal'Class;

   --  Get the principal name.
   overriding
   function Get_Name (From : in Principal) return String;

   --  Get the user email address.
   function Get_Email (From : in Principal) return String;

   --  Get the authentication data.
   function Get_Authentication (From : in Principal) return Authentication;

   --  Create a principal with the given authentication results.
   function Create_Principal (Auth : in Authentication) return Principal_Access;

   --  ------------------------------
   --  Authentication Manager
   --  ------------------------------
   --  The <b>Manager</b> provides the core operations for the authentication process.
   type Manager is tagged limited private;
   type Manager_Access is access all Manager'Class;

   --  Initialize the authentication realm.
   procedure Initialize (Realm  : in out Manager;
                         Params : in Parameters'Class;
                         Name   : in String := PROVIDER_OPENID);
   procedure Initialize (Realm   : in out Manager;
                         Params  : in Parameters'Class;
                         Factory : not null
                         access function (Name : in String) return Manager_Access;
                         Name    : in String := PROVIDER_OPENID);

   --  Discover the authentication provider that must be used to authenticate the user.
   --  The <b>Name</b> can be an URL or an alias that identifies the provider.
   --  A cached OpenID provider can be returned.  The discover step may do nothing for
   --  authentication providers based on OAuth.
   --  (See OpenID Section 7.3 Discovery)
   procedure Discover (Realm  : in out Manager;
                       Name   : in String;
                       Result : out End_Point);

   --  Associate the application (relying party) with the authentication provider.
   --  The association can be cached.
   --  (See OpenID Section 8 Establishing Associations)
   procedure Associate (Realm  : in out Manager;
                        OP     : in End_Point;
                        Result : out Association);

   --  Get the authentication URL to which the user must be redirected for authentication
   --  by the authentication server.
   function Get_Authentication_URL (Realm : in Manager;
                                    OP    : in End_Point;
                                    Assoc : in Association) return String;

   --  Verify the authentication result
   procedure Verify (Realm   : in out Manager;
                     Assoc   : in Association;
                     Request : in Parameters'Class;
                     Result  : out Authentication);

   --  Default factory used by `Initialize`.  It supports OpenID, Google, Facebook.
   function Default_Factory (Provider : in String) return Manager_Access;

   type Factory_Access is not
     null access function (Provider : in String) return Manager_Access;

   --  Set the default factory to use.
   procedure Set_Default_Factory (Factory : in Factory_Access);

private

   use Ada.Strings.Unbounded;

   type Association is record
      Provider     : Unbounded_String;
      Session_Type : Unbounded_String;
      Assoc_Type   : Unbounded_String;
      Assoc_Handle : Unbounded_String;
      Mac_Key      : Unbounded_String;
      Expired      : Ada.Calendar.Time;
      Nonce        : Unbounded_String;
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
      Provider  : Unbounded_String;
      Delegate  : Manager_Access;
   end record;

   overriding
   procedure Finalize (Realm : in out Manager);

   type Principal is new Security.Principal with record
      Auth : Authentication;
   end record;

   procedure Set_Result (Result  : in out Authentication;
                         Status  : in Auth_Result;
                         Message : in String);

end Security.Auth;
