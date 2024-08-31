-----------------------------------------------------------------------
--  security-random -- Random numbers for nonce, secret keys, token generation
--  Copyright (C) 2017, 2023 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
with Ada.Streams;
with Ada.Finalization;
with Ada.Strings.Unbounded;
private with Ada.Numerics.Discrete_Random;
private with Interfaces;

--  == Random Generator ==
--  The <tt>Security.Random</tt> package defines the <tt>Generator</tt> tagged type
--  which provides operations to generate random tokens intended to be used for
--  a nonce, access token, salt or other purposes.  The generator is intended to be
--  used in multi-task environments as it implements the low level random generation
--  within a protected type.  The generator defines a <tt>Generate</tt> operation
--  that returns either a binary random array or the base64url encoding of the
--  binary array.
package Security.Random is

   type Generator is limited new Ada.Finalization.Limited_Controlled with private;

   --  Initialize the random generator.
   overriding
   procedure Initialize (Gen : in out Generator);

   --  Fill the array with pseudo-random numbers.
   procedure Generate (Gen  : in out Generator;
                       Into : out Ada.Streams.Stream_Element_Array);
   procedure Generate (Gen  : in out Generator;
                       Into : out String);

   --  Generate a random sequence of bits and convert the result
   --  into a string in base64url.
   function Generate (Gen  : in out Generator'Class;
                      Bits : in Positive) return String;

   --  Generate a random sequence of bits, convert the result
   --  into a string in base64url and append it to the buffer.
   procedure Generate (Gen  : in out Generator'Class;
                       Bits : in Positive;
                       Into : in out Ada.Strings.Unbounded.Unbounded_String);

private

   package Id_Random is new Ada.Numerics.Discrete_Random (Interfaces.Unsigned_32);

   --  Protected type to allow using the random generator by several tasks.
   protected type Raw_Generator is

      procedure Generate (Into : out Ada.Streams.Stream_Element_Array);

      procedure Reset;
   private
      --  Random number generator used for ID generation.
      Rand  : Id_Random.Generator;
   end Raw_Generator;

   type Generator is limited new Ada.Finalization.Limited_Controlled with record
      Rand : Raw_Generator;
   end record;

end Security.Random;
