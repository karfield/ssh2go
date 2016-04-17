#!/bin/bash

#set -ex

CGO_LDFLAGS=""
CGO_CFLAGS=""

ZLIB_DIR=$PWD/vendor/zlib
pushd $ZLIB_DIR
test ! -e Makefile && ./configure
make
popd
CGO_LDFLAGS="$ZLIB_DIR/libz.a -L$ZLIB_DIR $CGO_LDFLAGS"
CGO_CFLAGS="-I$ZLIB_DIR $CGO_CFLAGS"

LIBGPG_ERROR_DIR=$PWD/vendor/libgpg-error
pushd $LIBGPG_ERROR_DIR
test ! -e configure && ./autogen.sh
test ! -e Makefile && ./configure \
    --disable-dependency-tracking \
    --disable-silent-rules \
    --disable-nls \
    --disable-doc \
    --enable-static
make
popd
LIBGPG_ERROR_LIBDIR="$LIBGPG_ERROR_DIR/src/.libs/"
CGO_LDFLAGS="$LIBGPG_ERROR_LIBDIR/libgpg-error.a -L$LIBGPG_ERROR_LIBDIR $CGO_LDFLAGS"
CGO_CFLAGS="-I$LIBGPG_ERROR_DIR/src $CGO_CFLAGS"

LIBGCRYPT_DIR=$PWD/vendor/libgcrypt
pushd $LIBGCRYPT_DIR
test ! -e Makefile && ./configure \
    --enable-static \
    --disable-dependency-tracking \
    --disable-silent-rules \
    --disable-doc \
    --disable-asm
make
popd
LIBGCRYPT_LIBDIR=$LIBGCRYPT_DIR/src/.libs/
CGO_LDFLAGS="$LIBGCRYPT_LIBDIR/libgcrypt.a -L$LIBGCRYPT_LIBDIR $CGO_LDFLAGS"
CGO_CFLAGS="-I$LIBSSH_DIR/src $CGO_CFLAGS"

LIBSSH_DIR=$PWD/vendor/libssh
LIBSSH_BUILDDIR=$LIBSSH_DIR/build
mkdir -p $LIBSSH_BUILDDIR
pushd $LIBSSH_BUILDDIR
cmake \
    -DWITH_STATIC_LIB=ON \
    -DWITH_GSSAPI=OFF \
    -DWITH_GCRYPT=ON \
    ..
make
popd
CGO_LDFLAGS="$LIBSSH_BUILDDIR/src/libssh.a -L$LIBSSH_BUILDDIR/src $CGO_LDFLAGS"
CGO_CFLAGS="-I$LIBSSH_DIR/include $CGO_CFLAGS"

#FLAGS=`pkg-config --static --libs $LIBSSH_BUILDDIR/libssh.pc`

export CGO_LDFLAGS="$CGO_LDFLAGS $LDFLAGS"
export CGO_CFLAGS="$CGO_CFLAGS $CFLAGS"

