#!/bin/sh

set -e

log() {
    echo "curl: $*"
}

CURRENT_SOURCE_DIR="$1"
CURRENT_BUILD_DIR="$2"
PRIVATE_DIR="$3"
MBEDTLS_INC="$4"
shift 4

BUILD_LOG=$(realpath "$CURRENT_BUILD_DIR/curl-build.log")
rm -f "$BUILD_LOG"

log "see $BUILD_LOG for full build log"

log "preparing sources..."

rm -rf "$PRIVATE_DIR"
cp -ar "$CURRENT_SOURCE_DIR" "$PRIVATE_DIR"

(
    cd "$PRIVATE_DIR"

    # HACK: We need to configure libcurl with mbedTLS (even if curl does not detect it). Thus
    # patching the configure file here so that it forces the mbedTLS check to always pass.
    sed -i "s|mbedtls_havege_init=no|mbedtls_havege_init=yes|" configure
    sed -i "s|      LIBS=\"-lmbedtls -lmbedx509 -lmbedcrypto \$LIBS\"||" configure

    log "running configure..."
    # The list of configure options is selected based on:
    # https://github.com/curl/curl/blob/curl-7_84_0/docs/INSTALL.md#reducing-size
    CPPFLAGS=-I"$MBEDTLS_INC"       \
        ./configure                 \
        --disable-alt-svc           \
        --disable-ares              \
        --disable-cookies           \
        --disable-crypto-auth       \
        --disable-dateparse         \
        --disable-dict              \
        --disable-dnsshuffle        \
        --disable-doh               \
        --disable-file              \
        --disable-ftp               \
        --disable-get-easy-options  \
        --disable-gopher            \
        --disable-hsts              \
        --disable-http-auth         \
        --disable-imap              \
        --disable-ldap              \
        --disable-ldaps             \
        --disable-libcurl-option    \
        --disable-manual            \
        --disable-mqtt              \
        --disable-netrc             \
        --disable-ntlm-wb           \
        --disable-pop3              \
        --disable-progress-meter    \
        --disable-proxy             \
        --disable-pthreads          \
        --disable-rtsp              \
        --disable-shared            \
        --disable-smb               \
        --disable-smtp              \
        --disable-socketpair        \
        --disable-telnet            \
        --disable-tftp              \
        --disable-threaded-resolver \
        --disable-tls-srp           \
        --disable-unix-sockets      \
        --disable-verbose           \
        --disable-versioned-symbols \
        --with-mbedtls              \
        --without-brotli            \
        --without-libidn2           \
        --without-libpsl            \
        --without-librtmp           \
        --without-nghttp2           \
        --without-ngtcp2            \
        --without-zlib              \
        --without-zstd              \
        >>"$BUILD_LOG" 2>&1

    # Only build libcurl since building the curl executable requires a linking stage which will fail
    # if there is no mbedTLS installed on the host.
    log "running make..."
    cd lib; make -j"$(nproc)" >>"$BUILD_LOG" 2>&1
)

cp -r "$PRIVATE_DIR"/lib/.libs/* "$CURRENT_BUILD_DIR"/

log "done"
