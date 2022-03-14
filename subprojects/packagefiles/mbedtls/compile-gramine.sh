#!/bin/sh

CFLAGS='-O2 -DMBEDTLS_CONFIG_FILE=\"mbedtls/config-gramine.h\"'

# Generate position-independent code even for a static library, so that it can be used in
# Gramine-provided shared libraries
CFLAGS="$CFLAGS -fPIC"

export CFLAGS
exec "$(dirname "$0")"/compile.sh "$@"
