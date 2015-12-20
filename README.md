# Ada Security Library

[![Build Status](https://img.shields.io/jenkins/s/http/jenkins.vacs.fr/Ada-Security.svg)](http://jenkins.vacs.fr/job/Ada-Security/)
[![Test Status](https://img.shields.io/jenkins/t/http/jenkins.vacs.fr/Ada-Security.svg)](http://jenkins.vacs.fr/job/Ada-Security/)
[![License](http://img.shields.io/badge/license-APACHE2-blue.svg)](LICENSE)
[![Download](https://img.shields.io/badge/download-1.1.0-brightgreen.svg)](http://download.vacs.fr/ada-security/ada-security-1.1.0.tar.gz)
![Download](https://img.shields.io/github/commits-since/stcarrez/ada-security/v1.1.1.svg)

This Ada05 library provides some security frameworks needed by some Web applications.
It allows a web application to integrate easily with Google, Yahoo!, Facebook and
Google+ authentication systems.
The library includes:

* An OpenID client authentication,
* An OAuth 2.0 client authentication,
* An OpenID Connect authentication framework,
* A policy based security framework to protect the resources

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

   https://github.com/stcarrez/ada-security
