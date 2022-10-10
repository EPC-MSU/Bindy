Bindy
=====

https://github.com/EPC-MSU/Bindy

About
-----

Bindy is a lightweight cross-platform framework for cloud service written in C++ language. We haven't found any lightweight solutions to create stable peer-to-peer networks with encryption. A lot of great and big projects aim at either distributed cloud calculation, file sharing, or messaging. We do not aim to solve any of these tasks, but to provide easy-to-use, cross-platform, and well documented C++ library to **bind** computers into a cloud network, that can keep and synchronize arbitrary data, manage access rules, and encrypt connections with symmetrical AES algorithm.

Each node is either active node (server-cloud), or passive node(client). Both nodes uses databases files as parameters to keep all authorized node names, link data, and other relevant cloud information. The active node starts listening on all available network interfaces for incoming connections. The passive node tries to establish connection to an arbitrary active node of the cloud, finding it using the information in its database. After handshake we have a working encrypted tunnel. Both nodes can transmit messages now.
You can also use low level "predefined IP" mode to establish connection to the specific node.

This project is developed in EPC-MSU by professional developers for internal purposes. The project was created originally free, since we earn money from other products. Let this code be used for good.

Using Bindy
-----------
The project includes a tiny client-server example to test that Bindy works properly and to show how it might be used. The server accepts a "keyfile" parameter which lists all authorized client keys and starts listening on all available network interfaces for incoming connections. The client needs an "IP", a "message" and a "keyfile" parameters; it then tries to establish connection to the chosen IP address, identify itself using chosen keyfile and transmit the message. The server outputs the messages it receives from clients to standard output.

Requirements
------------

Bindy is based on several open-source solutions.

* TinyThread++. Cross-platform solution for multithreading. Included in source code.

* Crypto++. It manages encryption and cross-platform sockets. External dependency.

CryptoPP can be used in two modes:

1. As a shared library. To use shared library invoke cmake with a `-DCRYPTOPP_SHARED_LIBRARY=TRUE` flag

2. As a static library with PIC support. Please note that packaged static cryptopp is never compiled with `-fPIC` so you must compile it yourself.

Special cryptopp location can be specified with `CRYPTOPP_PATH` (for library) and `CRYPTOPP_PATH_INCLUDE` (for headers) cmake variables.

Cloning the project
--------------------------------

```
   git clone https://github.com/EPC-MSU/Bindy
```

The project uses  submodules and has several dev-branches, so:

```
   git submodule update 
   git switch <branch>
   git submodule update --init --recursive
   git submodule update --recursive
```

Building the library and example
--------------------------------

    cmake .
    make

History
-------

* v0.3 - 2015.02.12
 - CMake build
 - dropped cryptopp from source code
 - a lot of fixes

* v0.2 - 2014.10.28
 - Second release

* v0.1 - 2014.10.15
 - Initial release.


License
-------

Copyright (c) 2014-2015 EPC-MSU

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
