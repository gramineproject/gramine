FROM alpine:3.17

RUN apk add \
    alpine-sdk \
    doas \
    jq \
    meson \
    nasm

COPY packaging/alpine/APKBUILD /APKBUILD
RUN adduser -u 1000 --disabled-password abuilder && \
    echo "permit nopass 1000 as root" >> /etc/doas.d/doas.conf
RUN abuild -F -r builddeps
RUN rm -f /APKBUILD
