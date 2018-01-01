# Ada Security Library

[![Build Status](https://img.shields.io/jenkins/s/http/jenkins.vacs.fr/Ada-Security.svg)](http://jenkins.vacs.fr/job/Ada-Security/)
[![Test Status](https://img.shields.io/jenkins/t/http/jenkins.vacs.fr/Ada-Security.svg)](http://jenkins.vacs.fr/job/Ada-Security/)
[![Download](https://img.shields.io/badge/download-1.1.2-brightgreen.svg)](http://download.vacs.fr/ada-security/ada-security-1.1.2.tar.gz)
[![License](http://img.shields.io/badge/license-APACHE2-blue.svg)](LICENSE)
![Commits](https://img.shields.io/github/commits-since/stcarrez/ada-security/1.1.2.svg)

Ada Security provides a security framework which allows applications to define
and enforce security policies. This framework allows users to authenticate by using
[OpenID Authentication 2.0](http://openid.net/specs/openid-authentication-2_0.html)
as well as [OAuth 2.0](http://oauth.net/2/) protocol.
It allows a web application to integrate easily with Yahoo!, Facebook and
Google+ authentication systems.
The Ada05 library includes:

* An OpenID client authentication,
* An OAuth 2.0 client authentication,
* An OpenID Connect authentication framework,
* An OAuth 2.0 server authentication framework,
* A policy based security framework to protect the resources

![Ada Security Overview](https://github.com/stcarrez/ada-security/wiki/images/AdaSecurity.jpg)

# Build

To use Ada Security library, configure as follows:
```
   ./configure
   make
```
The unit tests are built and executed with:
```
   make test
```
For the installation, use the following command:
```
   make install
```
The package provides a simple AWS server that illustrates the OpenID and OpenConnect
authentication.  Build it as follows:
```
   gnatmake -Psamples
```
Before launching the demo server, you must update the 'samples.properties' file
and change the lines that contain PUT-HERE-YOUR-FACEBOOK-xxx and
PUT-HERE-GOOGLE-xxx with your client ID and client secrets.  These two changes
are required by the OAuth and OpenID Connect framework only.
Then, run the server:
```
   bin/auth_demo
```
and redirect your browser to:
```
   http://localhost:8080/atlas/login.html
```
# Documentation

The Ada Security sources as well as a wiki documentation is provided on:

- [Overview](https://github.com/stcarrez/ada-security/wiki)
- [Security Overview](https://github.com/stcarrez/ada-security/wiki/Security)
- [Security Policies](https://github.com/stcarrez/ada-security/wiki/Security_Policies)
- [Security Authorization](https://github.com/stcarrez/ada-security/wiki/Security_Auth)
- [Security OAuth Client](https://github.com/stcarrez/ada-security/wiki/Security_OAuth)
- [Security OAuth Server](https://github.com/stcarrez/ada-security/wiki/Security_OAuth_Servers)

# Other Documentation

The OAuth literature is quite complete on the Internet and there are several good tutorials and
documentation.
- [Facebook Login](https://developers.facebook.com/docs/facebook-login/manually-build-a-login-flow)
- [Using OAuth 2.0 to Access Google APIs](https://developers.google.com/identity/protocols/OAuth2)
- [Yahoo OAuth 2.0 Guide](https://developer.yahoo.com/oauth2/guide/)
- [Salesforce OAuth 2.0 Guide](https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/intro_understanding_authentication.htm)
(this is a good guide if you want to learn)

# References

- [RFC 6749: The OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
- [RFC 6750: The OAuth 2.0 Authorization Framework: Bearer Token Usage](https://tools.ietf.org/html/rfc6750)
- [RFC 6819: OAuth 2.0 Threat Model and Security Considerations](https://tools.ietf.org/html/rfc6819)
- [OpenID Connect Core 1.0](http://openid.net/specs/openid-connect-core-1_0.html)
