#!/usr/bin/env bash

usage() {
    echo "Usage: test.sh [ubuntu20,ubuntu22]"
    exit 1
}

if [ $# -ne 1 ]; then
    usage
fi

image=""
codename=""

case "$1" in
    ubuntu20)
        codename="focal"
        ;;
    ubuntu22)
        codename="jammy"
        ;;
    *)
        usage
        ;;
esac

EXTRA_ARGS=""
if [ -n "${GRAMINE_URL}" ]; then
    EXTRA_ARGS="--build-arg GRAMINE_URL=${GRAMINE_URL}"
fi

tag="gramineproject/gramine:testing-stable-${codename}"
docker build \
    --build-arg GRAMINE_IMAGE="gramineproject/gramine:stable-${codename}" \
    ${EXTRA_ARGS} \
    -t "${tag}" \
    -f Dockerfile.test \
    . || exit 1

docker run \
    --rm \
    -ti \
    --device /dev/sgx_enclave \
    --volume /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket \
    --cap-add SYS_ADMIN \
    --cap-add SYS_PTRACE \
    --security-opt seccomp=unconfined \
    "${tag}" \
    -C /root/gramine/libos/test/regression pytest

docker run \
    --rm \
    -ti \
    --device /dev/sgx_enclave \
    --volume /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket \
    "${tag}" \
    -C /root/gramine/libos/test/regression --sgx pytest
