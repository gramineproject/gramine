FROM alpine:3.17

RUN apk add \
    alpine-sdk \
    doas \
    jq \
    meson \
    nasm

COPY packaging/alpine/APKBUILD /APKBUILD

# When Jenkins runs a pipeline, it uses UID 1000 and GID 1001.
RUN adduser -u 1000 --disabled-password abuilder && \
    echo "permit nopass 1000 as root" >> /etc/doas.d/doas.conf
# But sometimes it also uses UID 1001.
RUN adduser -u 1001 --disabled-password abuilder1 && \
    echo "permit nopass 1001 as root" >> /etc/doas.d/doas.conf

RUN abuild -F -r builddeps
RUN rm -f /APKBUILD
