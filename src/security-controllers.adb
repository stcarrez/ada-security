-----------------------------------------------------------------------
--  security-controllers -- Controllers to verify a security permission
--  Copyright (C) 2011 Stephane Carrez
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

with Util.Log.Loggers;

package body Security.Controllers is

   use Util.Log;

   --  The logger
   Log : constant Loggers.Logger := Loggers.Create ("Security.Controllers");

   type Factory_Entry (Len : Positive) is record
      Name    : String (1 .. Len);
      Factory : Controller_Factory;
   end record;
   type Factory_Entry_Access is access all Factory_Entry;

   type Factory_Entry_Array is array (1 .. MAX_CONTROLLER_FACTORY) of Factory_Entry_Access;

   Factories : Factory_Entry_Array := (others => null);

   --  ------------------------------
   --  Register in a global table the controller factory under the name <b>Name</b>.
   --  When this factory is used, the <b>Factory</b> operation will be called to
   --  create new instances of the controller.
   --  ------------------------------
   procedure Register_Controller (Name    : in String;
                                  Factory : in Controller_Factory) is
   begin
      Log.Info ("Register security controller factory {0}", Name);
      for I in Factories'Range loop
         if Factories (I) = null then
            Factories (I) := new Factory_Entry '(Len     => Name'Length,
                                                 Name    => Name,
                                                 Factory => Factory);
            return;
         end if;
      end loop;
      Log.Error ("Maximum number of security factories is reached: {0}",
                 Positive'Image (MAX_CONTROLLER_FACTORY));
      raise Program_Error
        with "Too many security controller factory. Increase MAX_CONTROLLER_FACTORY.";
   end Register_Controller;

   --  ------------------------------
   --  Create a security controller by using the controller factory registered under
   --  the name <b>Name</b>.
   --  Raises <b>Invalid_Controller</b> if the name is not recognized.
   --  ------------------------------
   function Create_Controller (Name : in String) return Controller_Access is
   begin
      Log.Debug ("Creating security controller {0}", Name);

      for I in Factories'Range loop
         exit when Factories (I) = null;
         if Factories (I).Name = Name then
            return Factories (I).Factory.all;
         end if;
      end loop;

      Log.Error ("Security controller factory {0} not found", Name);
      raise Invalid_Controller;
   end Create_Controller;

end Security.Controllers;
