#!/bin/sh

CFLAGS='-O2 -DMBEDTLS_CONFIG_FILE=\"mbedtls/config-pal.h\"'

# Gramine's stack protector options (TODO: pass from Meson?)
CFLAGS="$CFLAGS -fstack-protector-strong -mstack-protector-guard=tls \
    -mstack-protector-guard-reg=%gs -mstack-protector-guard-offset=8"

# Generate position-independent code even for a static library, so that it can be used in PAL and
# LibOS
CFLAGS="$CFLAGS -fPIC"

# Don't assume existence of builtins (currently Clang emits references to `bcmp`)
CFLAGS="$CFLAGS -fno-builtin"

export CFLAGS
exec "$(dirname "$0")"/compile.sh "$@"
