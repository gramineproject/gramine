#!/bin/sh

set -e

log() {
    echo "ltp: $*"
}

CURRENT_SOURCE_DIR="$1"
CURRENT_BUILD_DIR="$2"
PRIVATE_DIR="$3"
OUTPUT="$4"

BUILD_LOG=$(realpath "$CURRENT_BUILD_DIR/ltp-build.log")
rm -f "$BUILD_LOG"

log "see $BUILD_LOG for full build log"

log "preparing sources..."

rm -rf "$PRIVATE_DIR"
cp -ar "$CURRENT_SOURCE_DIR" "$PRIVATE_DIR"

INSTALLDIR=$(realpath "$PRIVATE_DIR"/install)

(
    cd "$PRIVATE_DIR"

    MAKEFLAGS="$MAKEFLAGS -j$(nproc)"

    log "running make autotools..."
    make autotools >>"$BUILD_LOG" 2>&1

    # `--without-modules`: kernel module tests are not meaningful for our LibOS, and building them
    # causes troubles on incompatible host kernels
    log "running configure..."
    ./configure --without-modules --prefix "$INSTALLDIR" >>"$BUILD_LOG" 2>&1

    log "running make..."
    make >>"$BUILD_LOG" 2>&1

    # `SKIP_IDCHECK=1`: do not modify `/etc/{group,passwd}` on target system's sysroot
    log "running make install..."
    make SKIP_IDCHECK=1 install >>"$BUILD_LOG" 2>&1

    log "creating a tarball..."
    tar czf "$CURRENT_BUILD_DIR"/"$OUTPUT" install/
)

log "done"
