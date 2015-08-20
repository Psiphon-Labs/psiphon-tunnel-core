#!/bin/bash

# Based on: https://wiki.openssl.org/index.php/Android

rm -rf ./openssl-1.0.1p
tar xvf openssl-1.0.1p.tar.gz
source ./setenv-android.sh
cd openssl-1.0.1p
perl -pi -e 's/install: all install_docs install_sw/install: install_docs install_sw/g' Makefile.org
# TODO: strip out more unnecessary components
./config no-shared no-ssl2 no-ssl3 no-comp no-hw no-md2 no-md4 no-rc2 no-rc5 no-krb5 no-ripemd160 no-idea no-gost no-camellia no-seed no-3des no-heartbeats --openssldir=../ssl
perl -pi -e 's/-O3/-Os -mfloat-abi=softfp/g' Makefile
make depend
make all
cd ..
