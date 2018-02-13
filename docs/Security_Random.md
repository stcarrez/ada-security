## Random Generator
The <tt>Security.Random</tt> package defines the <tt>Generator</tt> tagged type
which provides operations to generate random tokens intended to be used for
a nonce, access token, salt or other purposes.  The generator is intended to be
used in multi-task environments as it implements the low level random generation
within a protected type.  The generator defines a <tt>Generate</tt> operation
that returns either a binary random array or the base64url encoding of the
binary array.

