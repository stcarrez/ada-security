-----------------------------------------------------------------------
--  auth_cb -- Authentication callback examples
--  Copyright (C) 2013, 2020 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
with Util.Properties;
with Util.Log.Loggers;
with Util.Http.Clients.AWS;

with AWS.Config;
with AWS.Config.Set;
with AWS.Server;
with AWS.Services.Dispatchers.URI;
with AWS.Services.Page_Server;
with AWS.Services.Web_Block.Registry;
with AWS.Net.SSL;

with Auth_CB;

procedure Auth_Demo is

   Log    : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("Auth_Demo");

   Dispatcher : AWS.Services.Dispatchers.URI.Handler;
   WS         : AWS.Server.HTTP;
   Config     : AWS.Config.Object;
begin
   if not AWS.Net.SSL.Is_Supported then
      Log.Error ("SSL is not supported by AWS.");
      Log.Error ("SSL is required for the OpenID connector to connect to OpenID providers.");
      Log.Error ("Please, rebuild AWS with SSL support.");
      return;
   end if;

   --  Get the authentication provider configuration.  We use the Util.Properties and some
   --  java like property file.  Other configuration implementation are possible.
   Auth_CB.Config.Load_Properties ("samples.properties");
   Util.Log.Loggers.Initialize (Util.Properties.Manager (Auth_CB.Config));

   --  Setup the HTTP client implementation to use AWS.
   Util.Http.Clients.AWS.Register;

   --  Setup AWS dispatchers.
   AWS.Services.Dispatchers.URI.Register (Dispatcher, "/atlas/auth/auth",
                                          Auth_CB.Get_Authorization'Access,
                                          Prefix => True);
   AWS.Services.Dispatchers.URI.Register (Dispatcher, "/verify",
                                          Auth_CB.Verify_Authorization'Access);
   AWS.Services.Dispatchers.URI.Register (Dispatcher, "/atlas",
                                          AWS.Services.Page_Server.Callback'Access,
                                          Prefix => True);
   AWS.Services.Dispatchers.URI.Register (Dispatcher, "/success",
                                          Auth_CB.User_Info'Access);
   AWS.Services.Web_Block.Registry.Register ("success", "samples/web/success.thtml", null);

   --  Configure AWS.
   Config := AWS.Config.Get_Current;
   AWS.Config.Set.Session (Config, True);
   AWS.Config.Set.Session_Name (Config, "AUTH_DEMO");
   AWS.Config.Set.Reuse_Address (Config, True);
   AWS.Config.Set.WWW_Root (Config, "samples/web");

   AWS.Server.Start (WS, Dispatcher => Dispatcher, Config => Config);

   Log.Info ("Connect you browser to: http://localhost:8080/atlas/login.html");
   Log.Info ("Press 'q' key to stop the server.");

   AWS.Server.Wait (AWS.Server.Q_Key_Pressed);

   Log.Info ("Shutting down server...");
   AWS.Server.Shutdown (WS);
end Auth_Demo;
