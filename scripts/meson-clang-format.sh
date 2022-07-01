#!/bin/sh

set -e

if test x"$1" = x-d
then
    # debug mode: just print, and developer is responsible for running in source root
    FINDACTION="-print"
else
    test -n "$MESON_SOURCE_ROOT"
    cd "$MESON_SOURCE_ROOT"
    FINDACTION="-exec clang-format -i {} +"
fi

find pal libos tools \
    -path common/src/crypto/mbedtls -prune -o \
    -path tools/sgx/common/cJSON.c -prune -o \
    -path tools/sgx/common/cJSON.h -prune -o \
    -path tools/sgx/common/cJSON-\*/cJSON.c -prune -o \
    -path tools/sgx/common/cJSON-\*/cJSON.h -prune -o \
    -path libos/test/ltp -prune -o \
    -path libos/glibc\* -prune -o \
    \( -name \*.c -o -name \*.h \) \
    $FINDACTION
