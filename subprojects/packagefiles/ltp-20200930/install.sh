#!/bin/sh

set -e

TARBALL="$1"
DEST="$MESON_INSTALL_DESTDIR_PREFIX"/"$2"

mkdir -p "$DEST"
tar xzf "$TARBALL" -C "$DEST" --strip-components 1
