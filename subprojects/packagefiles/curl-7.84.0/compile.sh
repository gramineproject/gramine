#!/bin/sh

set -e

log() {
    echo "curl: $*"
}

CURRENT_SOURCE_DIR="$1"
CURRENT_BUILD_DIR="$2"
PRIVATE_DIR="$3"
shift 3

BUILD_LOG=$(realpath "$CURRENT_BUILD_DIR/curl-build.log")
rm -f "$BUILD_LOG"

log "see $BUILD_LOG for full build log"

log "preparing sources..."

rm -rf "$PRIVATE_DIR"
cp -ar "$CURRENT_SOURCE_DIR" "$PRIVATE_DIR"

BUILDDIR="$PRIVATE_DIR/lib/.libs"

(
    cd "$PRIVATE_DIR"

    log "running configure..."
    ./configure                     \
        --disable-shared            \
        --disable-alt-svc           \
        --disable-ares              \
        --disable-cookies           \
        --disable-crypto-auth       \
        --disable-dateparse         \
        --disable-dnsshuffle        \
        --disable-doh               \
        --disable-get-easy-options  \
        --disable-hsts              \
        --disable-http-auth         \
        --disable-ipv6              \
        --disable-libcurl-option    \
        --disable-manual            \
        --disable-netrc             \
        --disable-ntlm-wb           \
        --disable-progress-meter    \
        --disable-proxy             \
        --disable-pthreads          \
        --disable-socketpair        \
        --disable-threaded-resolver \
        --disable-tls-srp           \
        --disable-unix-sockets      \
        --disable-verbose           \
        --disable-versioned-symbols \
        --without-brotli            \
        --without-libpsl            \
        --without-nghttp2           \
        --without-ngtcp2            \
        --without-zstd              \
        --without-libidn2           \
        --without-librtmp           \
        --without-zlib              \
        --with-mbedtls              \
        >>"$BUILD_LOG" 2>&1

    log "running make..."
    make -j"$(nproc)" >>"$BUILD_LOG" 2>&1
)

cp -r "$BUILDDIR"/* "$CURRENT_BUILD_DIR"/

log "done"
