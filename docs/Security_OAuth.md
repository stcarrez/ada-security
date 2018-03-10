# OAuth
The <b>Security.OAuth</b> package defines and implements the OAuth 2.0 authorization
framework as defined by the IETF working group.
See http://tools.ietf.org/html/draft-ietf-oauth-v2-26

# OAuth2 Client
The `Security.OAuth.Clients` package implements the client OAuth 2.0 authorization.

## Application setup
For an OAuth2 client application to authenticate, it must be registered on the server
and the server provides the following information:

* **client_id**: the client identifier is a unique string that identifies the application.
* **client_secret** the client secret is a secret shared between the server and the client application.  The client secret is optional.

The `Security.OAuth.Clients.Application` tagged record is the primary type that
allows to perform one of the OAuth 2.0 authorization flows.  It is necessary to
declare an `Application` instance and register the **client_id**, the **client_secret**
and the authorisation URLs to connect to the server.

```Ada
App : Security.OAuth.Clients.Application;
...
   App.Set_Application_Identifier ("app-identifier");
   App.Set_Application_Secret ("app-secret");
   App.Set_Provider_URL ("https://graph.facebook.com/oauth/access_token");

```

## Resource Owner Password Credentials Grant
The RFC 6749: 4.3.  Resource Owner Password Credentials Grant allows to authorize an
application by using the user's name and password.  This is the simplest OAuth flow
but because it requires to know the user's name and password, it is not recommended and
not supported by several servers.  To use this authorization, the application will use
the `Request_Token` procedure and will give the user's name, password and the scope
of permissions.  When the authorization succeeds, a `Grant_Type` token object is returned.

```Ada
Token  : Security.OAuth.Clients.Grant_Type;
...
  App.Request_Token ("admin", "admin", "scope", Token);
```

## Refreshing an access token
An access token has an expiration date and a new access token must be asked by using the
refresh token.  When the access token has expired, the grant token object can be refreshed
to retrieve a new access token by using the `Refresh_Token` procedure.  The scope of
permissions can also be passsed.

```Ada
 App.Refresh_Token ("scope", Token);
```

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



