#!/usr/bin/env bash

usage() {
    echo "Usage: build.sh [ubuntu20,ubuntu22]"
    exit 1
}

if [ $# -ne 1 ]; then
    usage
fi

image=""
codename=""

case "$1" in
    ubuntu20)
        image="ubuntu:20.04"
        codename="focal"
        ;;
    ubuntu22)
        image="ubuntu:22.04"
        codename="jammy"
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
