with Ada.Text_IO;
with Ada.Calendar;
with Ada.Strings.Unbounded;
with GNAT.Command_Line;

with Util.Log.Loggers;
with Security.OAuth.JWT.HS256;
procedure JWT is

   use Util.Log.Loggers;
   use Ada.Strings.Unbounded;
   use GNAT.Command_Line;

   Log         : constant Logger := Util.Log.Loggers.Create ("JWT");
   Token       : Security.OAuth.JWT.Token;
   Validity    : Natural := 3600;
begin
   loop
      case Getopt ("h i: k: d: s:") is
         when ASCII.NUL =>
            exit;

         when 'k' =>
            Security.OAuth.JWT.Set_Key_ID (Token, Parameter);

         when 'i' =>
            Security.OAuth.JWT.Set_Issuer (Token, Parameter);

         when 'd' =>
            Validity := Natural'Value (Parameter);

         when 's' =>
            Security.OAuth.JWT.Set_Subject (Token, Parameter);

         when others =>
            raise GNAT.Command_Line.Invalid_Switch;
      end case;
   end loop;
   Security.OAuth.JWT.Set_Validity (Token, Duration (Validity), True);
   loop
      declare
         Pattern : constant String := Get_Argument;
      begin
         exit when Pattern = "";

         Ada.Text_IO.Put_Line (Security.OAuth.JWT.HS256.Sign (Token, Pattern));
      end;
   end loop;

exception
   when GNAT.Command_Line.Invalid_Switch =>
      Log.Error ("Usage: jwt -k <kid> -i <issuer> -s <subject> -d <number> secret");
end JWT;
