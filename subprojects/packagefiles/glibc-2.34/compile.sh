#!/bin/sh

set -xe

CPU_FAMILY="$1"
CURRENT_SOURCE_DIR="$2"
CURRENT_BUILD_DIR="$3"
PRIVATE_DIR="$4"
PREFIX="$5"
LIBDIR="$6"
EXTRA_CFLAGS="$7"
shift 7

CC=gcc
CXX=g++
AS=gcc
CFLAGS="-O2 -Wno-unused-values $EXTRA_CFLAGS"
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

    # if Gramine is built with the default prefix `/usr/local`, Glibc requires the option
    # `--disable-sanity-checks` otherwise it complains like this: "On GNU/Linux systems the GNU C
    # Library should not be installed into /usr/local since this might make your system totally
    # unusable. We strongly advise to use a different prefix." Note that `--disable-sanity-checks`
    # simply silences this warning -- we actually install Glibc under `gramine/runtime/glibc`.
    ../configure \
        --prefix="$PREFIX" \
        --libdir="$PREFIX"/"$LIBDIR"/gramine/runtime/glibc \
        --with-tls \
        --without-gd \
        --without-selinux \
        --disable-sanity-checks \
        --disable-test \
        --disable-nscd

    make -j"$(nproc)"
)

for output in "$@"
do
    cp -aP "$BUILDDIR/$output" "$CURRENT_BUILD_DIR"/
done
