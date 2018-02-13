# Installation

This chapter explains how to build and install the library.

## Before Building

Before building the library, you will need:

* [Ada Utility Library](https://github.com/stcarrez/ada-util).

First get, build and install the [Ada Utility Library](https://github.com/stcarrez/ada-util).

## Configuration

The library uses the `configure` script to detect the build environment,
check for [Ada Utility Library](https://github.com/stcarrez/ada-util) library.
The `configure` script provides several standard options
and you may use:

  * `--prefix=DIR` to control the installation directory,
  * `--enable-shared` to enable the build of shared libraries,
  * `--disable-static` to disable the build of static libraries,
  * `--with-ada-util=PATH` to control the installation path of [Ada Utility Library](https://github.com/stcarrez/ada-util),
  * `--help` to get a detailed list of supported options.

In most cases you will configure with the following command:
```
./configure
```

## Build

After configuration is successful, you can build the library by running:
```
make
```

After building, it is good practice to run the unit tests before installing the library.
The unit tests are built and executed using:
```
make test
```
And unit tests are executed by running the `bin/util_harness` test program.

## Installation
The installation is done by running the `install` target:

```
make install
```

If you want to install on a specific place, you can change the `prefix` and indicate the installation
direction as follows:

```
make install prefix=/opt
```
