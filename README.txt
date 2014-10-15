Bindy v0.1
==========
https://github.com/EPC-MSU/Bindy


About
-----
Bindy is a lightweight cross-platform framework for cloud service written in C++ language. We haven't found any lightweight solutions to create stable peer-to-peer networks with encryption. A lot of great and big projects aim at either distributed cloud calculation, file sharing, or messaging. We do not aim to solve any of these tasks, but to provide easy-to-use, cross-platform, and well documented C++ library to bind computers into a cloud network, that can keep and synchronize arbitrary data, manage access rules, and encrypt connections.


Using Bindy
-----------
The project includes a tiny client-server example to test that Bindy works properly and to show how it might be used. The server accepts a "keyfile" parameter which lists all authorized client keys and starts listening on all available network interfaces for incoming connections. The client needs an "IP", a "message" and a "keyfile" parameters; it then tries to establish connection to the chosen IP address, identify itself using chosen keyfile and transmit the message. The server outputs the messages it receives from clients to standard output.


Building the example
--------------------
Linux and Mac OS X:
  ensure you have g++ and make installed
  run "make" in the project directory

Windows with MS Visual Studio:
  open Bindy.sln (solution)
  choose "Debug" or "Release" configuration
  click "Build"


History
-------
v0.1 - 2014.10.15
 * Initial release.


License
-------
Copyright (c) 2014 EPC-MSU

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
