FROM alpine:3.17

RUN apk add \
    alpine-sdk \
    doas \
    jq \
    meson \
    nasm

COPY packaging/alpine/APKBUILD /APKBUILD
RUN abuild -F -r builddeps
RUN rm -f /APKBUILD
