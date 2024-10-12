# Installation

This chapter explains how to build and install the library.

## Using Alire

To use Ada Security in your project, run the following command to add the dependency
for your project:

```
alr index --update-all
alr with security
```

## Without Alire

If you don't have [Alire](https://alire.ada.dev/) or want to build and install the library
on a specific place, run a `setup` command to configure the build as well as installation
directory.

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

If you want to install on a specific place, you can change the `prefix` and indicate the installation
direction as follows:

```
make install prefix=/opt
```

## Using

To use the library in an Ada project, add the following line at the beginning of your GNAT project file:

```
with "security";
```
