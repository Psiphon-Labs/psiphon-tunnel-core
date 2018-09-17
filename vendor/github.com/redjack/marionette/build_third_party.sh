#!/bin/sh
set -ex

# This script will build the third party libraries and put in the correct file
# paths to make it possible to build the binary without installing the
# dependencies system wide.
PKG_TOPDIR=$(cd $(dirname $0) && pwd -P)

cd $PKG_TOPDIR/third_party/openfst && ./configure --enable-static=yes && make
cd $PKG_TOPDIR/third_party/re2 && make

cd $PKG_TOPDIR/third_party
curl -LsO https://gmplib.org/download/gmp/gmp-6.1.2.tar.bz2
PKG_CHECKSUM="5275bb04f4863a13516b2f39392ac5e272f5e1bb8057b18aec1c9b79d73d8fb2"
REAL_CHECKSUM=$(shasum -a 256 gmp-6.1.2.tar.bz2 | awk '{print $1}')
[ $PKG_CHECKSUM = "$REAL_CHECKSUM" ]
tar -xvjf $PKG_TOPDIR/third_party/gmp-6.1.2.tar.bz2
cd $PKG_TOPDIR/third_party/gmp-6.1.2 && ./configure --enable-cxx && make

mkdir -p $PKG_TOPDIR/third_party/libs/

cp $PKG_TOPDIR/third_party/gmp-6.1.2/.libs/libgmp.a $PKG_TOPDIR/third_party/libs/
cp $PKG_TOPDIR/third_party/re2/obj/libre2.a $PKG_TOPDIR/third_party/libs/
cp $PKG_TOPDIR/third_party/openfst/src/lib/.libs/libfst.a $PKG_TOPDIR/third_party/libs/
cp $PKG_TOPDIR/third_party/openfst/src/script/.libs/libfstscript.a $PKG_TOPDIR/third_party/libs/
