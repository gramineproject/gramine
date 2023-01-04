#!/bin/sh

CFLAGS='-O2'

export CFLAGS
exec "$(dirname "$0")"/compile.sh "$@"
