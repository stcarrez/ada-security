## OAuth Server
OAuth server side is provided by the <tt>Security.OAuth.Servers</tt> package.
This package allows to implement the authorization framework described in RFC 6749
"The OAuth 2.0 Authorization Framework".

The authorization method produces a <tt>Grant_Type</tt> object that contains the result
of the grant (successful or denied).  It is the responsibility of the caller to format
the result in JSON/XML and return it to the client.

Three important operations are defined for the OAuth 2.0 framework.  They will be used
in the following order:

<tt>Authorize</tt> is used to obtain an authorization request.  This operation is
optional in the OAuth 2.0 framework since some authorization method directly return
the access token.  This operation is used by the "Authorization Code Grant" and the
"Implicit Grant".

<tt>Token</tt> is used to get the access token and optional refresh token.  Each time it
is called, a new token is generated.

<tt>Authenticate</tt> is used for the API request to verify the access token
and authenticate the API call.  This operation can be called several times with the same
token until the token is revoked or it has expired.

Several grant types are supported.

### Application Manager
The application manager maintains the repository of applications which are known by
the server and which can request authorization.  Each application is identified by
a client identifier (represented by the <tt>client_id</tt> request parameter).
The application defines the authorization methods which are allowed as well as
the parameters to control and drive the authorization.  This includes the redirection
URI, the application secret, the expiration delay for the access token.

The application manager is implemented by the application server and it must
implement the <tt>Application_Manager</tt> interface with the <tt>Find_Application</tt>
method.  The <tt>Find_Application</tt> is one of the first call made during the
authenticate and token generation phases.

### Resource Owner Password Credentials Grant
The password grant is one of the easiest grant method to understand but it is also one
of the less secure.  In this grant method, the username and user password are passed in
the request parameter together with the application client identifier.  The realm verifies
the username and password and when they are correct it generates the access token with
an optional refresh token.  The realm also returns in the grant the user principal that
identifies the user.

```Ada
  Realm : Security.OAuth.Servers.Auth_Manager;
  Grant : Security.OAuth.Servers.Grant_Type;
    Realm.Token (Params, Grant);

```

### Accessing Protected Resources
When accessing a protected resource, the API implementation will use the
<tt>Authenticate</tt> operation to verify the access token and get a security principal.
The security principal will identify the resource owner as well as the application
that is doing the call.

```Ada
   Realm : Security.OAuth.Servers.Auth_Manager;
   Grant : Security.OAuth.Servers.Grant_Type;
   Token : String := ...;
     Realm.Authenticate (Token, Grant);

```

When a security principal is returned, the access token was validated and the
request is granted for the application.


