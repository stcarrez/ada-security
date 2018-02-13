### JSON Web Token
JSON Web Token (JWT) is a compact URL-safe means of representing claims to be transferred
between two parties.  A JWT token is returned by an authorization server.  It contains
useful information that allows to verify the authentication and identify the user.

The <tt>Security.OAuth.JWT</tt> package implements the decoding part of JWT defined in:
JSON Web Token (JWT), http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-07

A list of pre-defined ID tokens are returned in the JWT token claims and used for
the OpenID Connect.  This is specified in
OpenID Connect Basic Client Profile 1.0 - draft 26,
http://openid.net/specs/openid-connect-basic-1_0.html


