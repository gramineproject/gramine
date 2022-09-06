#!/bin/sh

set -x
set -e

CURRENT_SOURCE_DIR="$1"
VENDOR_SOURCE_DIR="$2"
CURRENT_BUILD_DIR="$3"
PRIVATE_DIR="$4"
SUBPROJ_ROOT="$5"
shift 5

MBEDTLS_CURL_DIR="$SUBPROJ_ROOT"/mbedtls-curl

rm -rf "$PRIVATE_DIR"

cp -ar "$VENDOR_SOURCE_DIR" "$PRIVATE_DIR"
cp "$CURRENT_SOURCE_DIR"/include/mbedtls/*.h "$PRIVATE_DIR"/include/mbedtls/
patch -p1 --directory "$PRIVATE_DIR" <"$CURRENT_SOURCE_DIR"/gramine.patch
patch -p1 --directory "$PRIVATE_DIR" <"$CURRENT_SOURCE_DIR"/fcntl.patch

make -C "$PRIVATE_DIR" lib SUFFIX="''" install DESTDIR="$MBEDTLS_CURL_DIR"
touch "$MBEDTLS_CURL_DIR"/mbedtls-curl-dummy.h
