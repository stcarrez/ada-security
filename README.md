# Ada Security Library

[![Build Status](https://img.shields.io/jenkins/s/http/jenkins.vacs.fr/Bionic-Ada-Security.svg)](https://jenkins.vacs.fr/job/Bionic-Ada-Security/)
[![Test Status](https://img.shields.io/jenkins/t/http/jenkins.vacs.fr/Bionic-Ada-Security.svg)](https://jenkins.vacs.fr/job/Bionic-Ada-Security/)
[![codecov](https://codecov.io/gh/stcarrez/ada-security/branch/master/graph/badge.svg)](https://codecov.io/gh/stcarrez/ada-security)
[![Documentation Status](https://readthedocs.org/projects/ada-security/badge/?version=latest)](https://ada-security.readthedocs.io/en/latest/?badge=latest)
[![Download](https://img.shields.io/badge/download-1.4.1-brightgreen.svg)](http://download.vacs.fr/ada-security/ada-security-1.4.1.tar.gz)
[![License](https://img.shields.io/badge/license-APACHE2-blue.svg)](LICENSE)
[![GitLab](https://img.shields.io/badge/repo-GitLab-6C488A.svg)](https://gitlab.com/stcarrez/ada-security)
![Commits](https://img.shields.io/github/commits-since/stcarrez/ada-security/1.4.1.svg)

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

![Ada Security Overview](https://github.com/stcarrez/ada-security/wiki/images/AdaSecurity.jpg)

The Ada Security library is used by the
[Ada Web Application](https://github.com/stcarrez/ada-awa)
to provide authentication and access control to users within the web applications.

## Version 1.4.1   - Aug 2022
- Fix Alire GNAT project to build in debug mode
- Fix Security.Random that generates shorter random string

[List all versions](https://github.com/stcarrez/ada-security/blob/master/NEWS.md)

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
- [Overview](https://github.com/stcarrez/ada-security/wiki)
- [Security Overview](https://github.com/stcarrez/ada-security/wiki/Security)


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
