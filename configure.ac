dnl Autoconf configure script for Ada Security
dnl Copyright (C) 2012, 2013, 2015, 2016, 2018, 2019, 2020 Stephane Carrez
dnl Written by Stephane Carrez (Stephane.Carrez@gmail.com)
dnl
dnl  Licensed under the Apache License, Version 2.0 (the "License");
dnl  you may not use this file except in compliance with the License.
dnl  You may obtain a copy of the License at
dnl
dnl     http://www.apache.org/licenses/LICENSE-2.0
dnl
dnl  Unless required by applicable law or agreed to in writing, software
dnl  distributed under the License is distributed on an "AS IS" BASIS,
dnl  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
dnl  See the License for the specific language governing permissions and
dnl  limitations under the License.
dnl 
dnl Process this file with autoconf to produce a configure script.

AC_INIT(src/security.ads)

# Current release settings
SECURITY_MAJOR_VERSION=1
SECURITY_MINOR_VERSION=3
SECURITY_MICRO_VERSION=0
SECURITY_VERSION=$SECURITY_MAJOR_VERSION.$SECURITY_MINOR_VERSION.$SECURITY_MICRO_VERSION

# Set the version number of Ada Server Faces
AC_SUBST(SECURITY_VERSION)
AC_SUBST(SECURITY_MAJOR_VERSION)
AC_SUBST(SECURITY_MINOR_VERSION)
AC_SUBST(SECURITY_MICRO_VERSION)

AM_GNAT_LIBRARY_PROJECT(security)

AC_CHECK_PROG(HAVE_PANDOC,pandoc,yes)
AC_CHECK_PROG(HAVE_DYNAMO,dynamo,yes)

AM_GNAT_FIND_ADA_UTIL([Ada Security])

AC_OUTPUT(
Makefile.conf
security.gpr
security_tests.gpr
samples.gpr
)
