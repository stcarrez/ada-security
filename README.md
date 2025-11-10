# Ada Security Library

[![Alire](https://img.shields.io/endpoint?url=https://alire.ada.dev/badges/security.json)](https://alire.ada.dev/crates/security)
[![Ada 2012](https://img.shields.io/badge/2012-inside-green?logo=ada&logoColor=white&logoSize=auto)](https://adaic.org/ada-resources/standards/ada12)
[![Build Status](https://img.shields.io/endpoint?url=https://porion.vacs.fr/porion/api/v1/projects/ada-security/badges/build.json)](https://porion.vacs.fr/porion/projects/view/ada-security/summary)
[![Test Status](https://img.shields.io/endpoint?url=https://porion.vacs.fr/porion/api/v1/projects/ada-security/badges/tests.json)](https://porion.vacs.fr/porion/projects/view/ada-securit/xunits)
[![Coverage](https://img.shields.io/endpoint?url=https://porion.vacs.fr/porion/api/v1/projects/ada-security/badges/coverage.json)](https://porion.vacs.fr/porion/projects/view/ada-security/summary)
[![Documentation Status](https://readthedocs.org/projects/ada-security/badge/?version=latest)](https://ada-security.readthedocs.io/en/latest/?badge=latest)
[![Download](https://img.shields.io/badge/download-1.5.1-brightgreen.svg)](http://download.vacs.fr/ada-security/ada-security-1.5.1.tar.gz)
[![License](https://img.shields.io/badge/license-APACHE2-blue.svg)](LICENSE)
[![GitLab](https://img.shields.io/badge/repo-GitLab-6C488A.svg)](https://gitlab.com/stcarrez/ada-security)
[![Commits](https://img.shields.io/github/commits-since/stcarrez/ada-security/1.5.1.svg)](Commits)

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
[Ada Web Application](https://gitlab.com/stcarrez/ada-awa)
and the [OpenAPI Ada library](https://github.com/stcarrez/swagger-ada)
to provide authentication and access control to users within the web applications.

## Version 1.5.2  - Under development
  - Fix #11: Ada.Calendar.Conversions.To_Struct_Timespec is deprecated

## Version 1.5.1  - Aug 2024
  - Cleanup build environment to drop configure

[List all versions](https://gitlab.com/stcarrez/ada-security/blob/master/NEWS.md)

## Using with Alire

If you are using [Alire](https://alire.ada.dev/) in your project, run the following command
within your [Alire](https://alire.ada.dev/) project to use the library:

```
alr with security
```

## Using without Alire

If you don't have [Alire](https://alire.ada.dev/) or want to build and install the library
on a specific place, run a `setup` command to configure the build as well as installation
directory.
For a detailed description on how you can configure, build and install the library
refer to the [Installation](https://ada-security.readthedocs.io/en/latest/Installation/) guide.
Otherwise, you can easily configure and build the library with the steps described below.

The `HAVE_ALIRE` configuration allows you to disable the build with [Alire](https://alire.ada.dev/):

```
make setup BUILD=debug PREFIX=/build/install HAVE_ALIRE=no
```

Since this build method does not verify that all dependencies are met, make sure that you
have already built and install the following components and they are available to `gprbuild`
through `ADA_PROJECT_PATH` if needed:

* [Ada Utility Library](https://gitlab.com/stcarrez/ada-util/)

Then build, run the unit tests and install by using:

```
make
make test
make install
```

To use the installed libraries, make sure your `ADA_PROJECT_PATH` contains the directory
where you installed the libraries (configured by the `PREFIX=<path>` option in the setup phase).
The installed GNAT projects are the same as those used when using [Alire](https://alire.ada.dev/).


## Running the tests

The unit tests are built and executed with:

```
make test
```

## Samples

The package provides a simple AWS server that illustrates the OpenID and OpenConnect
authentication.  Because OAuth2 relies exclusively on HTTPS, you must use an AWS
server that has the SSL support.  Build it as follows:

```
cd samples
alr build
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

# Sites Using Ada Security

* [Java 2 Ada](https://blog.vacs.fr/)
* [Ada France](https://www.ada-france.org/adafr/index.html)
* [Atlas](https://demo.vacs.fr/atlas/index.html)
* [Jason Project Manager](https://vdo.vacs.fr/vdo/index.html)
* [Porion Build Manager](https://porion.vacs.fr/porion/index.html)
