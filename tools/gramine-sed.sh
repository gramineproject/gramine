#!/bin/sh

set -e

INPUT="$1"
OUTPUT="$2"

SGX="$3"
CONFIG_SGX_DRIVER="$4"
PREFIX="$5"
BINDIR="$6"
HOST_PAL_PATH="$7"
LIBPAL_PATH="$8"
PAL_CMD="$9"

sed -e "s|@SGX@|$SGX|g" \
    -e "s|@CONFIG_SGX_DRIVER@|\"$CONFIG_SGX_DRIVER\"|g" \
    -e "s|@PREFIX@|\"$PREFIX\"|g" \
    -e "s|@BINDIR@|\"$BINDIR\"|g" \
    -e "s|@HOST_PAL_PATH@|\"$HOST_PAL_PATH\"|g" \
    -e "s|@LIBPAL_PATH@|\"$LIBPAL_PATH\"|g" \
    -e "s|@PAL_CMD@|\"$PAL_CMD\"|g" \
    "$INPUT" > "$OUTPUT"

chmod +x "$OUTPUT"
