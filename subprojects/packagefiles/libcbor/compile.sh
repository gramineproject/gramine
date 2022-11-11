#!/bin/sh

set -e

log() {
    echo "libcbor (static): $*"
}

CURRENT_SOURCE_DIR="$1"
CURRENT_BUILD_DIR="$2"
PRIVATE_DIR="$3"

BUILD_LOG=$(realpath "$CURRENT_BUILD_DIR/libcbor-build.log")
rm -f "$BUILD_LOG"

log "see $BUILD_LOG for full build log"

log "preparing sources..."

rm -rf "$PRIVATE_DIR"
cp -ar "$CURRENT_SOURCE_DIR" "$PRIVATE_DIR"

(
    cd "$PRIVATE_DIR"

    log "running cmake..."
    cmake \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        -DCMAKE_INSTALL_PREFIX="$CURRENT_BUILD_DIR" \
        . >>"$BUILD_LOG" 2>&1

    log "running make..."
    make -j"$(nproc)" >>"$BUILD_LOG" 2>&1
    make install >>"$BUILD_LOG" 2>&1
)

cp -ar "$CURRENT_BUILD_DIR"/include/. "$CURRENT_BUILD_DIR"
cp -ar "$CURRENT_BUILD_DIR"/lib/. "$CURRENT_BUILD_DIR"

log "ls -la $CURRENT_BUILD_DIR"
ls -la $CURRENT_BUILD_DIR

log "done"
