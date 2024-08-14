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

with AWS.Response;
with AWS.Status;
with Util.Properties;
with Security.Auth;
package Auth_CB is

   --  Implement the first step of authentication: discover the OpenID (if any) provider,
   --  create the authorization request and redirect the user to the authorization server.
   --  Some authorization data is saved in the session for the verify process.
   --  The authorization provider is defined according to the base URI which is configured
   --  by the <tt>Auth_Config</tt> properties.  The following names are recognized:
   --
   --    google yahoo orange facebook
   --
   --  Each authorization provider has its own set of configuration parameter which defines
   --  what implementation to use (OpenID or OAuth) and how to configure and connect
   --  to the server.  The google, yahoo and orange map to the <tt>openid</tt> implementation.
   --  The facebook maps to the <tt>facebook</tt> implementation (based on OAuth).

   function Get_Authorization (Request : in AWS.Status.Data) return AWS.Response.Data;

   --  Second step of authentication: verify the authorization response.  The authorization
   --  data saved in the session is extracted and checked against the response.  If it matches
   --  the response is verified to check if the authentication succeeded or not.
   --  The user is then redirected to the success page.
   function Verify_Authorization (Request : in AWS.Status.Data) return AWS.Response.Data;

   --  Display information about the current user.
   function User_Info (Request : in AWS.Status.Data) return AWS.Response.Data;

   type Auth_Config is new Util.Properties.Manager and Security.Auth.Parameters with null record;

   overriding
   function Get_Parameter (Params : in Auth_Config;
                           Name   : in String) return String;

   Config : Auth_Config;

end Auth_CB;
