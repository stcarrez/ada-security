# Ada Security Library

[![Alire](https://img.shields.io/endpoint?url=https://alire.ada.dev/badges/security.json)](https://alire.ada.dev/crates/security)
[![Build Status](https://img.shields.io/endpoint?url=https://porion.vacs.fr/porion/api/v1/projects/ada-security/badges/build.json)](https://porion.vacs.fr/porion/projects/view/ada-security/summary)
[![Test Status](https://img.shields.io/endpoint?url=https://porion.vacs.fr/porion/api/v1/projects/ada-security/badges/tests.json)](https://porion.vacs.fr/porion/projects/view/ada-securit/xunits)
[![Coverage](https://img.shields.io/endpoint?url=https://porion.vacs.fr/porion/api/v1/projects/ada-security/badges/coverage.json)](https://porion.vacs.fr/porion/projects/view/ada-security/summary)
[![Documentation Status](https://readthedocs.org/projects/ada-security/badge/?version=latest)](https://ada-security.readthedocs.io/en/latest/?badge=latest)
[![Download](https://img.shields.io/badge/download-1.5.0-brightgreen.svg)](http://download.vacs.fr/ada-security/ada-security-1.5.0.tar.gz)
[![License](https://img.shields.io/badge/license-APACHE2-blue.svg)](LICENSE)
[![GitLab](https://img.shields.io/badge/repo-GitLab-6C488A.svg)](https://gitlab.com/stcarrez/ada-security)
[![Commits](https://img.shields.io/github/commits-since/stcarrez/ada-security/1.5.0.svg)](Commits)

Ada Security provides a security framework which allows applications to define
and enforce security policies. This framework allows users to authenticate by using
[OpenID Authentication 2.0](https://openid.net/specs/openid-authentication-2_0.html)
as well as [OAuth 2.0](https://oauth.net/2/) protocol.
It allows a web application to integrate easily with Yahoo!, Gitlab, Github, Facebook and
Google+ authentication systems.
The Ada05 library includes:

* An OpenID client authentication,
* An OAuth 2.0 client authentication,
* An OpenID Connect authentication framework,
* An OAuth 2.0 server authentication framework,
* A policy based security framework to protect the resources

![Ada Security Overview](https://gitlab.com/stcarrez/ada-security/wiki/images/AdaSecurity.jpg)

The Ada Security library is used by the
[Ada Web Application](https://gitlab.com/stcarrez/ada-awa)
to provide authentication and access control to users within the web applications.

## Version 1.5.1  - Under development
  - Cleanup build environment to drop configure

## Version 1.5.0   - Jul 2023
  - Add Create function for API key grant types

[List all versions](https://gitlab.com/stcarrez/ada-security/blob/master/NEWS.md)

## Build with Alire

```
alr with security
```

## Build with configure

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
authentication.  Because OAuth2 relies exclusively on HTTPS, you must use an AWS
server that has the SSL support.  Build it as follows:
```
   gprbuild -Psamples
```
Before launching the demo server, you must update the 'samples.properties' file
and change the lines that contain PUT-HERE-YOUR-FACEBOOK-xxx with your client ID
and client secrets.  This change
is required by the OAuth and OpenID Connect framework only.
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

- [Ada Security Programmer's Guide](https://ada-security.readthedocs.io/en/latest/)
- [Overview](https://gitlab.com/stcarrez/ada-security/wiki)
- [Security Overview](https://gitlab.com/stcarrez/ada-security/wiki/Security)


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
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
