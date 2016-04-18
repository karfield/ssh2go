#!/bin/bash

INSTALLDIR=$PWD/vendor/install
mkdir -p $INSTALLDIR

ZLIB_DIR=$PWD/vendor/zlib
pushd $ZLIB_DIR
./configure --prefix=$INSTALLDIR
make
make install
popd

LIBGPG_ERROR_DIR=$PWD/vendor/libgpg-error
pushd $LIBGPG_ERROR_DIR
./autogen.sh
./configure \
    --prefix=$INSTALLDIR \
    --disable-dependency-tracking \
    --disable-silent-rules \
    --disable-nls \
    --disable-doc \
    --enable-static
make
make install
popd

LIBGCRYPT_DIR=$PWD/vendor/libgcrypt
pushd $LIBGCRYPT_DIR
./autogen.sh
./configure \
    --prefix=$INSTALLDIR \
    --enable-static \
    --disable-dependency-tracking \
    --disable-silent-rules \
    --disable-doc \
    --disable-asm
make
make install
popd

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
make DESTDIR=$INSTALLDIR install
popd

export CGO_LDFLAGS="-L$INSTALLDIR/lib -L$INSTALLDIR/usr/local/lib -lssh -lgcrypt -lgpg-error -lz"
export CGO_CFLAGS="-I$INSTALLDIR/include -I$INSTALLDIR/usr/local/include"

