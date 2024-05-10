FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y ca-certificates

# Intel's RSA-2048 key signing the intel-sgx/sgx_repo repository. Expires 2027-03-20.
# https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key
COPY .ci/intel-sgx-deb.key /etc/apt/keyrings/intel-sgx-deb.asc
RUN echo deb [arch=amd64 signed-by=/etc/apt/keyrings/intel-sgx-deb.asc] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main > /etc/apt/sources.list.d/intel-sgx.list

# Dependencies for actual build.
# NOTE: COPY invalidates docker cache when source file changes,
# so `apt-get build-dep` will rerun if dependencies change, despite no change
# in dockerfile.
RUN mkdir /debian
COPY debian/control /debian
RUN apt-get update && apt-get -y build-dep --no-install-recommends --no-install-suggests /
RUN rm -rf /debian

# runtime dependencies of Gramine, for running tests
# keep this synced with debian/control
RUN apt-get update && apt-get satisfy -y \
    'libcurl4 (>= 7.58)' \
    'libprotobuf-c1' \
    'python3' \
    'python3 (>= 3.10) | python3-pkg-resources' \
    'python3-click (>= 6.7)' \
    'python3-cryptography' \
    'python3-jinja2' \
    'python3-pyelftools' \
    'python3-tomli (>= 1.1.0)' \
    'python3-tomli-w (>= 0.4.0)' \
    'python3-voluptuous'

# dependencies for various tests, CI-Examples, etc.
# git: scripts/gitignore-test (among others)
# libunwind8: libos/test/regression/bootstrap_cpp.manifest.template
# nginx: CI-Examples/ra-tls-nginx
# shellcheck: .ci/run-shellcheck
# cargo: CI-Examples/rust
# clang: asan and ubsan builds
# jq: used in jenkinsfiles
# cpio dwarves gcc/g++-12 kmod qemu-kvm: for building kernel modules and running VMs
# wget: scripts/download
RUN apt-get update && apt-get install -y \
    cargo \
    clang \
    cpio \
    dwarves \
    g++-12 \
    gcc-12 \
    git \
    jq \
    kmod \
    libunwind8 \
    nginx \
    python3-pytest \
    qemu-kvm \
    shellcheck \
    wget

# Kernel on the host machine is built with GCC-12, so we need to set it as default in Docker
RUN update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-12 10 && \
    update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-12 10 && \
    update-alternatives --set gcc /usr/bin/gcc-12 && \
    update-alternatives --set g++ /usr/bin/g++-12

CMD ["bash"]
