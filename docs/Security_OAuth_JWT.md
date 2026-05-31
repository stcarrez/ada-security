### JSON Web Token
JSON Web Token (JWT) is a compact URL-safe means of representing claims to be transferred
between two parties.  A JWT token is returned by an authorization server.  It contains
useful information that allows to verify the authentication and identify the user.

The `Security.OAuth.JWT` package implements the decoding and encoding part of JWT defined in:
JSON Web Token (JWT), [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519).

A list of pre-defined ID tokens are returned in the JWT token claims and used for
the OpenID Connect.  This is specified in
OpenID Connect Basic Client Profile 1.0 - draft 26,
http://openid.net/specs/openid-connect-basic-1_0.html

To extract a JWT token, you can use the following steps:

```Ada
 Token : constant Security.OAuth.JWT
    := Security.OAuth.JWT.Decode (Jwt_Token);
```

and you can access one of the JWT fields by using the `Get_<Field>` functions:

```Ada
 Issuer : constant String
    := Security.OAuth.JWT.Get_Issuer (Token);
 Claim  : constant String
    := Security.OAuth.JWT.Get_Claim (Token, "name");
```


