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
with Ada.Strings.Fixed;
with Ada.Text_IO;

with Util.Http.Clients;
with Util.Strings;
with Util.Encoders;
with Util.Log.Loggers;
with Util.Encoders.SHA1;
with Util.Encoders.HMAC.SHA1;
package body Security.OpenID is

   use Ada.Strings.Fixed;
   use Util.Log;

   Log : constant Util.Log.Loggers.Logger := Loggers.Create ("Security.OpenID");

   --  ------------------------------
   --  Initialize the OpenID realm.
   --  ------------------------------
   procedure Initialize (Realm     : in out Manager;
                         Name      : in String;
                         Return_To : in String) is
   begin
      null;
   end Initialize;

end Security.OpenID;
