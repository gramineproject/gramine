#!/bin/sh

set -e

log() {
    echo "libcbor (static): $*"
}

if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <source dir> <build dir> <private dir>" >&2
    exit 2
fi

SOURCE_DIR="$1"
BUILD_DIR="$2"
PRIVATE_DIR="$3"

BUILD_LOG=$(realpath "$BUILD_DIR/libcbor-build.log")
rm -f "$BUILD_LOG"

log "see $BUILD_LOG for full build log"

log "preparing sources..."

rm -rf "$PRIVATE_DIR"
cp -ar "$SOURCE_DIR" "$PRIVATE_DIR"

(
    cd "$PRIVATE_DIR"

    log "running cmake..."
    cmake \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        -DCMAKE_INSTALL_LIBDIR=lib \
        -DCMAKE_INSTALL_PREFIX="$BUILD_DIR" \
        . >>"$BUILD_LOG" 2>&1

    log "running make..."
    make -j"$(nproc)" >>"$BUILD_LOG" 2>&1
    make install >>"$BUILD_LOG" 2>&1
)

cp -ar "$BUILD_DIR"/include/. "$BUILD_DIR"
cp -ar "$BUILD_DIR"/lib/. "$BUILD_DIR"

log "done"
