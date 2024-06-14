FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y ca-certificates

# Intel's RSA-2048 key signing the intel-sgx/sgx_repo repository. Expires 2027-03-20.
# https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key
# TODO after Intel releases for noble: fix mantic to noble
COPY .ci/intel-sgx-deb.key /etc/apt/keyrings/intel-sgx-deb.asc
RUN echo deb [arch=amd64 signed-by=/etc/apt/keyrings/intel-sgx-deb.asc] https://download.01.org/intel-sgx/sgx_repo/ubuntu mantic main > /etc/apt/sources.list.d/intel-sgx.list

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
# musl-tools: for compilation with musl (not done in deb/rpm)
# nginx: CI-Examples/ra-tls-nginx
# shellcheck: .ci/run-shellcheck
# busybox: CI-Examples/busybox
# cargo: CI-Examples/rust
# clang: asan and ubsan builds
# jq: used in jenkinsfiles
# cpio dwarves kmod qemu-kvm: for building kernel modules and running VMs
# wget: scripts/download
# python3-pytest: for running tests
# python3-pytest-xdist: for pytest -n option, to run in parallel
# python3-numpy python3-scipy: imported by script in CI-Examples/python
# gdb: tested in libos suite
# ncat: used in scripts/wait_for_server
# linux-libc-dev: among others, needed to compile busybox (CI-Examples/busybox)
# libomp-dev: needed for libos/test/regression/openmp.c
# libevent-dev: CI-Examples/memcached
# libmemcached-tools: CI-Examples/memcache
# zlib1g-dev: CI-Examples/lighttpd
# wrk: used by CI-Examples/common_tools/benchmark-http.sh
# libssl-dev: CI-Examples/nginx
# sqlite3: CI-Examples/sqlite
# libsgx-*: CI-Examples/ra-tls-*
RUN apt-get update && apt-get install -y \
    busybox \
    cargo \
    clang \
    cmake \
    cpio \
    dwarves \
    gdb \
    git \
    jq \
    kmod \
    libevent-dev \
    libmemcached-tools \
    libomp-dev \
    libsgx-dcap-default-qpl \
    libsgx-dcap-quote-verify-dev \
    libsgx-urts \
    libssl-dev \
    libunwind8 \
    linux-libc-dev \
    musl-tools \
    ncat \
    nginx \
    python3-numpy \
    python3-pytest \
    python3-pytest-xdist \
    python3-scipy \
    qemu-kvm \
    shellcheck \
    sqlite3 \
    wget \
    wrk \
    zlib1g-dev

CMD ["bash"]
