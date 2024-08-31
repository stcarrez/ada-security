-----------------------------------------------------------------------
--  security-oauth -- OAuth Security
--  Copyright (C) 2017, 2018 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
package body Security.OAuth is

   use Ada.Strings.Unbounded;

   --  ------------------------------
   --  Get the application identifier.
   --  ------------------------------
   function Get_Application_Identifier (App : in Application) return String is
   begin
      return To_String (App.Client_Id);
   end Get_Application_Identifier;

   --  ------------------------------
   --  Set the application identifier used by the OAuth authorization server
   --  to identify the application (for example, the App ID in Facebook).
   --  ------------------------------
   procedure Set_Application_Identifier (App    : in out Application;
                                         Client : in String) is
   begin
      App.Client_Id := To_Unbounded_String (Client);
   end Set_Application_Identifier;

   --  ------------------------------
   --  Set the application secret defined in the OAuth authorization server
   --  for the application (for example, the App Secret in Facebook).
   --  ------------------------------
   procedure Set_Application_Secret (App    : in out Application;
                                     Secret : in String) is
   begin
      App.Secret := To_Unbounded_String (Secret);
   end Set_Application_Secret;

   --  ------------------------------
   --  Set the redirection callback that will be used to redirect the user
   --  back to the application after the OAuth authorization is finished.
   --  ------------------------------
   procedure Set_Application_Callback (App : in out Application;
                                       URI : in String) is
   begin
      App.Callback := To_Unbounded_String (URI);
   end Set_Application_Callback;

   --  ------------------------------
   --  Set the client authentication method used when doing OAuth calls for this application.
   --  See RFC 6749, 2.3.  Client Authentication
   --  ------------------------------
   procedure Set_Client_Authentication (App    : in out Application;
                                        Method : in Client_Authentication_Type) is
   begin
      App.Client_Auth := Method;
   end Set_Client_Authentication;

end Security.OAuth;
