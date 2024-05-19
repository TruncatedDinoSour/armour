# Libarmour

> C library for pDB (Password Database) and pKf (pDB Keyfile) formats, as well as the SNAPI protocol

## Requirements

-   A C compiler that supports C89 (for compiling binaries, objects, and shared objects).
-   Make utility (for the build system).
-   Basic userland utilities (A shell, `find`, `rm`, `basename`) (for compilation and testing).
-   OpenSSL library and headers (The library for cryptographic operations Libarmour uses. LibreSSL is planned for the future).
-   A Linux system (at least until Libarmour supports other OSes).

## Compilation

```sh
make -j$(nproc --all)
```

This will compile all code and generate a `libarmour.so` file, as well as generating
the `obj/` directory with the object files.

## Testing

```sh
make test -j$(nproc --all)
```

This will compile and run all tests, testing every feature and check of Libarmour.

### Requirements

Besides the requirements of Libarmour, you also need these to run the tests:

-   Python 3 (for `pretest.py` scripts).

## Format support

This section lists all supported versions of pDB and pKf formats, as well as SNAPI protocol
versions.

-   pDB
    -   v1
-   pKf
    -   v0
-   SNAPI
    -   v0

To include them and use them include `armour/<version>/<format>/...`. For example: `armour/v1/pdb/...`.

## Environment support

This section lists all supported environments that Libarmour can possibly work on.

-   Architecture: Any/All.
-   Compiler: Any/All.
-   LibSSL: OpenSSL.
-   Endianess: Little and Big endian.
-   Operating system: Linux.
