-----------------------------------------------------------------------
--  security-openid -- OpenID 2.0 Support
--  Copyright (C) 2009, 2010, 2011, 2012, 2018 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

--  == OpenID Configuration ==
--  The Open ID provider needs the following configuration parameters:
--
--    openid.realm          The OpenID realm parameter passed in the authentication URL.
--    openid.callback_url   The OpenID return_to parameter.
--
private package Security.Auth.OpenID is

   --  ------------------------------
   --  OpenID Manager
   --  ------------------------------
   --  The <b>Manager</b> provides the core operations for the OpenID process.
   type Manager is new Security.Auth.Manager with private;

   --  Initialize the OpenID authentication realm.  Get the <tt>openid.realm</tt>
   --  and <tt>openid.callback_url</tt> parameters to configure the realm.
   overriding
   procedure Initialize (Realm  : in out Manager;
                         Params : in Parameters'Class;
                         Name   : in String := PROVIDER_OPENID);

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

   --  Get the authentication URL to which the user must be redirected for authentication
   --  by the authentication server.
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
