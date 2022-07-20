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

    log "running configure..."
    # The list of configure options is selected based on:
    # https://github.com/curl/curl/blob/curl-7_84_0/docs/INSTALL.md#reducing-size
    CPPFLAGS=-I"$MBEDTLS_INC"       \
        ./configure                 \
        --disable-shared            \
        --disable-ftp               \
        --disable-file              \
        --disable-ldap              \
        --disable-ldaps             \
        --disable-rtsp              \
        --disable-proxy             \
        --disable-dict              \
        --disable-telnet            \
        --disable-tftp              \
        --disable-pop3              \
        --disable-imap              \
        --disable-smb               \
        --disable-smtp              \
        --disable-gopher            \
        --disable-mqtt              \
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

    # HACK: We need to configure libcurl with mbedTLS and should not build the curl executable to
    # avoid it being linked with the mbedTLS library.
    # To achieve this, overriding the curl config to force using mbedTLS (even if curl does not
    # detects it) and disabling in Makefile (which is not supported by curl autotools) the building
    # of the curl executable.
    BDL_PATH='\"\/etc\/ssl\/certs\/ca-certificates\.crt\"'
    sed -i "s|/\* #undef USE_MBEDTLS \*/|#define USE_MBEDTLS 1|" lib/curl_config.h
    sed -i "s|/\* #undef CURL_CA_BUNDLE \*/|#define CURL_CA_BUNDLE $BDL_PATH|" lib/curl_config.h
    sed -i "s/SUBDIRS = lib src/SUBDIRS = lib # src/" Makefile

    log "running make..."
    make -j"$(nproc)" >>"$BUILD_LOG" 2>&1
)

cp -r "$PRIVATE_DIR"/lib/.libs/* "$CURRENT_BUILD_DIR"/

log "done"
