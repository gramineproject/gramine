#!/bin/sh

set -x
set -e

CURRENT_SOURCE_DIR="$1"
VENDOR_SOURCE_DIR="$2"
CURRENT_BUILD_DIR="$3"
PRIVATE_DIR="$4"
SUBPROJ_ROOT="$5"
shift 5

OUTPUTS=""
while test "$#" -gt 0 && ! test "$1" = --
do
    OUTPUTS="$OUTPUTS $1"
    shift
done
if test "$1" = --
then
    shift
fi

rm -rf "$PRIVATE_DIR"

cp -ar "$VENDOR_SOURCE_DIR" "$PRIVATE_DIR"
cp "$CURRENT_SOURCE_DIR"/include/mbedtls/*.h "$PRIVATE_DIR"/include/mbedtls/
patch -p1 --directory "$PRIVATE_DIR" <"$CURRENT_SOURCE_DIR"/gramine.patch
patch -p1 --directory "$PRIVATE_DIR" <"$CURRENT_SOURCE_DIR"/fcntl.patch

make -C "$PRIVATE_DIR" lib "$@" install DESTDIR="$SUBPROJ_ROOT"/mbedtls-curl
touch mbedtls-curl-dummy.h
