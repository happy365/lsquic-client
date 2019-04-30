[![Build Status](https://travis-ci.org/litespeedtech/lsquic-client.svg?branch=master)](https://travis-ci.org/litespeedtech/lsquic-client)
[![Build Status](https://api.cirrus-ci.com/github/litespeedtech/lsquic-client.svg)](https://cirrus-ci.com/github/litespeedtech/lsquic-client)
[![Build status](https://ci.appveyor.com/api/projects/status/kei9649t9leoqicr?svg=true)](https://ci.appveyor.com/project/litespeedtech/lsquic-client)

LiteSpeed QUIC (LSQUIC) Client Library README
=============================================

Description
-----------

LiteSpeed QUIC (LSQUIC) Client Library is an open-source implementation
of QUIC functionality for clients.  It is released in the hope to speed
the adoption of QUIC.  Most of the code in this distribution is used in
our own products: LiteSpeed Web Server and ADC.  We think it is free of
major problems.  Nevertheless, do not hesitate to report bugs back to us.
Even better, send us fixes and improvements!

Currently supported QUIC versions are Q035, Q039, Q043, and Q044.  Support
for newer versions will be added soon after they are released.  The
version(s) specified by IETF QUIC WG are being developed on
[one or more branches](https://github.com/litespeedtech/lsquic-client/branches).
When deemed stable, the IETF QUIC support will be added to the master branch.

Documentation
-------------

The documentation for this module is admittedly sparse.  The API is
documented in include/lsquic.h.  If you have doxygen, you can run
`doxygen dox.cfg` or `make docs`.  The example program is
test/http_client.c: a bare-bones, but working, QUIC client.  Have a look
in EXAMPLES.txt to see how it can be used.

Requirements
------------

To build LSQUIC, you need CMake, zlib, and BoringSSL.  The example program
uses libevent to provide the event loop.

Building BoringSSL
------------------

BoringSSL is not packaged; you have to build it yourself.  The process is
straightforward.  You will need `go` installed.

1. Clone BoringSSL by issuing the following command:

```
git clone https://boringssl.googlesource.com/boringssl
cd boringssl
```

2. Compile the library

```
cmake . &&  make
```

Remember where BoringSSL sources are:
```
BORINGSSL=$PWD
```

If you want to turn on optimizations, do

```
cmake -DCMAKE_BUILD_TYPE=Release . && make
```

Building LSQUIC Client Library
------------------------------

LSQUIC's `http_client` and the tests link BoringSSL libraries statically.
Following previous section, you can build LSQUIC as follows:

1. Get the source code

```
git clone https://github.com/litespeedtech/lsquic-client.git
cd lsquic-client
```

2. Compile the library


```
# $BORINGSSL is the top-level BoringSSL directory from the previous step
cmake -DBORINGSSL_DIR=$BORINGSSL .
make
```

3. Run tests

```
make test
```

Building with Docker
---------
The library and http_client example can be built with Docker.
```
docker build -t lsquic-client .
```

Then you can use the http_client example from the command line.
```
docker run -it --rm lsquic-client http_client -H www.google.com -s 74.125.22.106:443 -p /
```

Platforms
---------

The client library has been tested on the following platforms:
- Linux
  - i386
  - x86_64
  - ARM (Raspberry Pi 3)
- FreeBSD
  - i386
- Windows
  - x86_64
- MacOS
  - x86_64

Have fun,

LiteSpeed QUIC Team.

Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc
