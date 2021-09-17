#!/bin/sh

set -xe

CPU_FAMILY="$1"
CURRENT_SOURCE_DIR="$2"
CURRENT_BUILD_DIR="$3"
PRIVATE_DIR="$4"
PREFIX="$5"
LIBDIR="$6"
shift 6

CC=gcc
CXX=g++
AS=gcc
CFLAGS="-O2 -Wno-unused-values"
CPPFLAGS="\
    -I$(realpath "$CURRENT_SOURCE_DIR")/../../LibOS/shim/include \
    -I$(realpath "$CURRENT_SOURCE_DIR")/../../LibOS/shim/include/arch/$CPU_FAMILY \
"
export CC CXX AS CFLAGS CPPFLAGS

rm -rf "$PRIVATE_DIR"
cp -ar "$CURRENT_SOURCE_DIR" "$PRIVATE_DIR"

for patch in "$CURRENT_SOURCE_DIR"/*.patch
do
    patch -p1 --directory "$PRIVATE_DIR" <"$patch"
done

BUILDDIR="$PRIVATE_DIR"/build

mkdir -p "$BUILDDIR"

(
    cd "$BUILDDIR"

    ../configure \
        --prefix="$PREFIX" \
        --libdir="$PREFIX"/"$LIBDIR"/graphene/runtime/glibc \
        --with-tls \
        --without-gd \
        --without-selinux \
        --disable-test \
        --disable-nscd

    make -j"$(nproc)"
)

for output in "$@"
do
    cp -aP "$BUILDDIR/$output" "$CURRENT_BUILD_DIR"/
done
