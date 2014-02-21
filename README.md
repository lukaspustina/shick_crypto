# Shick OpenSSL Crypto Library

* On [GitHub](https://github.com/lukaspustina/shick_crypto)
* On [Travis CI](https://travis-ci.org/lukaspustina/shick_crypto)

## Prerequisites

1. [NaCl](http://nacl.cace-project.eu) in form of [libsodium](https://github.com/jedisct1/libsodium)

## Compile

1. `autoreconf --install`
1. `./configure`
1. `make`

## Run Tests

1. `make check` 
1. `./configure --enable-gcov && make clean && make && make check` for coverage test



