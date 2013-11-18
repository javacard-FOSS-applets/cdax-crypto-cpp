cdax-crypto-cpp
===============

Basic model/simulation of the C-DAX security functionalities in C++.

C++ dependencies:

* Boost (for threading, tcp connections and serialization, see http://www.boost.org/)
* Crypto++ (for cryptographic functions, see http://www.cryptopp.com/)
  
To install the dependencies on OSX install MacPorts (http://www.macports.org/) and run:

```bash
sudo port install boost libcryptopp
```

You can compile the code using cmake and run one of the executables 'test' (unit test of message class) or 'simulation':

```bash
cd build
cmake ..
make
./simulation
```
