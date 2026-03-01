-----------------------------------------------------------------------
--  security-oauth-jwt-hs256 -- OAuth JSON Web Token signed with HS256
--  Copyright (C) 2026 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

package Security.OAuth.JWT.HS256 is

   --  Sign the JWT token with the HS256 algorithm and the given secret.
   --  The JWT type is set to `JWT` and the algorithm set to `HS256`.
   function Sign (From   : in out Token;
                  Secret : in String) return String;

end Security.OAuth.JWT.HS256;
