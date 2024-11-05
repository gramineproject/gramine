#!/usr/bin/env bash

usage() {
    echo "Usage: build.sh [ubuntu22,ubuntu24]"
    exit 1
}

if [ $# -ne 1 ]; then
    usage
fi

image=""
codename=""

case "$1" in
    ubuntu22)
        image="ubuntu:22.04"
        codename="jammy"
        ;;
    ubuntu24)
        image="ubuntu:24.04"
        codename="noble"
        ;;
    *)
        usage
        ;;
esac

docker build \
    --build-arg UBUNTU_IMAGE="${image}" \
    --build-arg UBUNTU_CODENAME="${codename}" \
    -t gramineproject/gramine:stable-"${codename}" \
    .
