-----------------------------------------------------------------------
--  security-auth-oauth-facebook -- Facebook OAuth based authentication
--  Copyright (C) 2013, 2014 Stephane Carrez
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

with Util.Beans.Objects;
with Util.Beans.Objects.Time;
with Util.Serialize.Mappers.Record_Mapper;
with Util.Http.Rest;
package body Security.Auth.OAuth.Facebook is

   --
   TIME_SHIFT : constant Duration := 12 * 3600.0;

   type Token_Info_Field_Type is (FIELD_APP_ID, FIELD_IS_VALID,
                                  FIELD_EXPIRES, FIELD_ISSUED_AT,
                                  FIELD_USER_ID, FIELD_EMAIL, FIELD_FIRST_NAME,
                                  FIELD_LAST_NAME, FIELD_NAME, FIELD_LOCALE, FIELD_GENDER);

   type Token_Info is record
      App_Id     : Ada.Strings.Unbounded.Unbounded_String;
      Is_Valid   : Boolean := False;
      Expires    : Ada.Calendar.Time;
      Issued     : Ada.Calendar.Time;
      User_Id    : Ada.Strings.Unbounded.Unbounded_String;
      Email      : Ada.Strings.Unbounded.Unbounded_String;
      Name       : Ada.Strings.Unbounded.Unbounded_String;
      First_Name : Ada.Strings.Unbounded.Unbounded_String;
      Last_Name  : Ada.Strings.Unbounded.Unbounded_String;
      Locale     : Ada.Strings.Unbounded.Unbounded_String;
      Gender     : Ada.Strings.Unbounded.Unbounded_String;
   end record;
   type Token_Info_Access is access all Token_Info;

   procedure Set_Member (Into  : in out Token_Info;
                         Field : in Token_Info_Field_Type;
                         Value : in Util.Beans.Objects.Object);

   procedure Set_Member (Into  : in out Token_Info;
                         Field : in Token_Info_Field_Type;
                         Value : in Util.Beans.Objects.Object) is
   begin
      case Field is
         when FIELD_APP_ID =>
            Into.App_Id := Util.Beans.Objects.To_Unbounded_String (Value);

         when FIELD_IS_VALID =>
            Into.Is_Valid := Util.Beans.Objects.To_Boolean (Value);

         when FIELD_EXPIRES =>
            Into.Expires := Util.Beans.Objects.Time.To_Time (Value);

         when FIELD_ISSUED_AT =>
            Into.Issued := Util.Beans.Objects.Time.To_Time (Value);

         when FIELD_USER_ID =>
            Into.User_Id := Util.Beans.Objects.To_Unbounded_String (Value);

         when FIELD_EMAIL =>
            Into.Email := Util.Beans.Objects.To_Unbounded_String (Value);

         when FIELD_NAME =>
            Into.Name := Util.Beans.Objects.To_Unbounded_String (Value);

         when FIELD_FIRST_NAME =>
            Into.First_Name := Util.Beans.Objects.To_Unbounded_String (Value);

         when FIELD_LAST_NAME =>
            Into.Last_Name := Util.Beans.Objects.To_Unbounded_String (Value);

         when FIELD_LOCALE =>
            Into.Locale := Util.Beans.Objects.To_Unbounded_String (Value);

         when FIELD_GENDER =>
            Into.Gender := Util.Beans.Objects.To_Unbounded_String (Value);

      end case;
   end Set_Member;

   package Token_Info_Mapper is
      new Util.Serialize.Mappers.Record_Mapper (Element_Type        => Token_Info,
                                                Element_Type_Access => Token_Info_Access,
                                                Fields              => Token_Info_Field_Type,
                                                Set_Member          => Set_Member);

   procedure Get_Token_Info is
     new Util.Http.Rest.Rest_Get (Element_Mapper => Token_Info_Mapper);

   Token_Info_Map : aliased Token_Info_Mapper.Mapper;

   --  ------------------------------
   --  Initialize the authentication realm.
   --  ------------------------------
   overriding
   procedure Initialize (Realm     : in out Manager;
                         Params    : in Parameters'Class;
                         Provider  : in String := PROVIDER_OPENID) is
      Client : constant String := Params.Get_Parameter (Provider & ".client_id");
      Secret : constant String := Params.Get_Parameter (Provider & ".secret");
   begin
      Security.Auth.OAuth.Manager (Realm).Initialize (Params, Provider);
      Realm.App_Access_Token := To_Unbounded_String (Client & "|" & Secret);
   end Initialize;

   --  ------------------------------
   --  Verify the OAuth access token and retrieve information about the user.
   --  ------------------------------
   overriding
   procedure Verify_Access_Token (Realm   : in Manager;
                                  Assoc   : in Association;
                                  Request : in Parameters'Class;
                                  Token   : in Security.OAuth.Clients.Access_Token_Access;
                                  Result  : in out Authentication) is
      pragma Unreferenced (Assoc, Request);
      use type Ada.Calendar.Time;

      T    : constant String := Token.Get_Name;
      Info : aliased Token_Info;
      Now  : constant Ada.Calendar.Time := Ada.Calendar.Clock;
   begin
      Get_Token_Info ("https://graph.facebook.com/debug_token?access_token="
                      & To_String (Realm.App_Access_Token)
                      & "&input_token=" & T,
                      Token_Info_Map'Access,
                      "/data",
                      Info'Unchecked_Access);
      if not Info.Is_Valid then
         Set_Result (Result, INVALID_SIGNATURE, "invalid access token returned");

      elsif Info.Issued + TIME_SHIFT < Now then
         Set_Result (Result, INVALID_SIGNATURE, "the access token issued more than 1 hour ago");

      elsif Info.Expires + TIME_SHIFT < Now then
         Set_Result (Result, INVALID_SIGNATURE, "the access token has expired");

      elsif Length (Info.User_Id) = 0 then
         Set_Result (Result, INVALID_SIGNATURE, "the access token refers to an empty user_id");

      elsif Info.App_Id /= Realm.App.Get_Application_Identifier then
         Set_Result (Result, INVALID_SIGNATURE,
                     "the access token was granted for another application");

      else
         Result.Identity := To_Unbounded_String ("https://graph.facebook.com/");
         Append (Result.Identity, Info.User_Id);
         Result.Claimed_Id := Result.Identity;

         Get_Token_Info ("https://graph.facebook.com/" & To_String (Info.User_Id)
                           & "?access_token=" & T,
                         Token_Info_Map'Access,
                         "",
                         Info'Unchecked_Access);

         Result.Email      := Info.Email;
         Result.Full_Name  := Info.Name;
         Result.First_Name := Info.First_Name;
         Result.Last_Name  := Info.Last_Name;
         Result.Language   := Info.Locale;
         Result.Gender     := Info.Gender;
         Set_Result (Result, AUTHENTICATED, "authenticated");
      end if;
   end Verify_Access_Token;

begin
   Token_Info_Map.Add_Mapping ("app_id", FIELD_APP_ID);
   Token_Info_Map.Add_Mapping ("expires_at", FIELD_EXPIRES);
   Token_Info_Map.Add_Mapping ("issued_at", FIELD_ISSUED_AT);
   Token_Info_Map.Add_Mapping ("is_valid", FIELD_IS_VALID);
   Token_Info_Map.Add_Mapping ("user_id", FIELD_USER_ID);
   Token_Info_Map.Add_Mapping ("email", FIELD_EMAIL);
   Token_Info_Map.Add_Mapping ("name", FIELD_NAME);
   Token_Info_Map.Add_Mapping ("first_name", FIELD_FIRST_NAME);
   Token_Info_Map.Add_Mapping ("last_name", FIELD_LAST_NAME);
   Token_Info_Map.Add_Mapping ("locale", FIELD_LOCALE);
   Token_Info_Map.Add_Mapping ("gender", FIELD_GENDER);
end Security.Auth.OAuth.Facebook;
