# Shick Crypto Library
This library shows how to use [NaCl][NaCl] in form of [libsodium][libsodium] to securely encrypt a message with asymmetrical encryption.

You can find Shick Crypto Library

* on [GitHub](https://github.com/lukaspustina/shick_crypto)
* on [Travis CI](https://travis-ci.org/lukaspustina/shick_crypto)

Please feel free to clone and adapt to your needs. If you find any bugs or have enhancements, please share it. I will react on pull requests promptly.

## Prerequisites

1. Crypto library [NaCl][NaCl] in form of [libsodium][libsodium]
2. C unit testing library [Check][check]

Check is usually available on all Linux distributions and in [Homebrew][brew]. libsodium might be available, but please make sure you use a recent version. It is easy to install from source -- see their [Readme](https://github.com/jedisct1/libsodium/blob/master/README.markdown).

## Compile

1. `autoreconf --install`
1. `./configure`
1. `make`

## Run Tests

1. `make check` 
1. `./configure --enable-gcov && make clean && make && make check` for coverage test


[NaCl]:http://nacl.cace-project.eu
[libsodium]:https://github.com/jedisct1/libsodium
[check]: http://check.sourceforge.net
[brew]: http://brew.sh

