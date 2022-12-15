#!/bin/sh

set -ex

CURRENT_SOURCE_DIR="$1"
VENDOR_SOURCE_DIR="$2"
CURRENT_BUILD_DIR="$3"
PRIVATE_DIR="$4"
SUBPROJ_ROOT="$5"
shift 5

rm -rf "$PRIVATE_DIR"

cp -ar "$VENDOR_SOURCE_DIR" "$PRIVATE_DIR"
cp "$CURRENT_SOURCE_DIR"/include/mbedtls/*.h "$PRIVATE_DIR"/include/mbedtls/
patch -p1 --directory "$PRIVATE_DIR" <"$CURRENT_SOURCE_DIR"/gramine.patch
patch -p1 --directory "$PRIVATE_DIR" <"$CURRENT_SOURCE_DIR"/fcntl.patch
patch -p1 --directory "$PRIVATE_DIR" <"$CURRENT_SOURCE_DIR"/enforce-aes-ni.patch

make -C "$PRIVATE_DIR" lib SUFFIX="''" install DESTDIR="$SUBPROJ_ROOT"/mbedtls-curl

for output in $@
do
    cp -a "$PRIVATE_DIR"/library/"$(basename "$output")" "$output"
done
