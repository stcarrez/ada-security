-----------------------------------------------------------------------
--  security-oauth -- OAuth Security
--  Copyright (C) 2012 Stephane Carrez
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

--  The <b>Security.OAuth</b> package defines and implements the OAuth 2.0 authorization
--  framework as defined by the IETF working group.
--  See http://tools.ietf.org/html/draft-ietf-oauth-v2-26
package Security.OAuth is

   --  OAuth 2.0: Section 10.2.2. Initial Registry Contents
   Client_Id         : constant String := "client_id";
   Client_Secret     : constant String := "client_secret";
   Response_Type     : constant String := "response_type";
   Redirect_Uri      : constant String := "redirect_uri";
   Scope             : constant String := "scope";
   State             : constant String := "state";
   Code              : constant String := "code";
   Error_Description : constant String := "error_description";
   Error_Uri         : constant String := "error_uri";
   Grant_Type        : constant String := "grant_type";
   Access_Token      : constant String := "access_token";
   Token_Type        : constant String := "token_type";
   Expires_In        : constant String := "expires_in";
   Username          : constant String := "username";
   Password          : constant String := "password";
   Refresh_Token     : constant String := "refresh_token";

end Security.OAuth;
