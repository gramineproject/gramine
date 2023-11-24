FROM ubuntu:22.04

RUN apt-get update && env DEBIAN_FRONTEND=noninteractive apt-get install -y \
    autoconf \
    bc \
    bison \
    build-essential \
    cargo \
    clang \
    curl \
    flex \
    gawk \
    gdb \
    gettext \
    git \
    jq \
    libapr1-dev \
    libaprutil1-dev \
    libcjson-dev \
    libelf-dev \
    libevent-dev \
    libexpat1 \
    libexpat1-dev \
    libmemcached-tools \
    libnss-mdns \
    libnuma1 \
    libomp-dev \
    libpcre2-dev \
    libpcre3-dev \
    libprotobuf-c-dev \
    libssl-dev \
    libunwind8 \
    libxfixes3 \
    libxi6 \
    libxml2-dev \
    libxrender1 \
    libxxf86vm1 \
    linux-headers-generic \
    musl \
    musl-tools \
    nasm \
    net-tools \
    netcat-openbsd \
    nginx \
    ninja-build \
    pkg-config \
    protobuf-c-compiler \
    protobuf-compiler \
    python3 \
    python3-apport \
    python3-apt \
    python3-breathe \
    python3-click \
    python3-cryptography \
    python3-jinja2 \
    python3-lxml \
    python3-numpy \
    python3-pip \
    python3-pkg-resources \
    python3-protobuf \
    python3-pyelftools \
    python3-pytest \
    python3-pytest-xdist \
    python3-scipy \
    python3-sphinx-rtd-theme \
    shellcheck \
    sphinx-doc \
    sqlite3 \
    texinfo \
    uthash-dev \
    wget \
    zlib1g \
    zlib1g-dev

# NOTE about meson version: we support "0.56 or newer", so in CI we pin to latest patch version of
# the earliest supported minor version (pip implicitly installs latest version satisfying the
# specification)
RUN python3 -m pip install -U \
    'tomli>=1.1.0' \
    'tomli-w>=0.4.0' \
    'meson>=0.56,<0.57' \
    'recommonmark>=0.5.0,<=0.7.1' \
    'docutils>=0.17,<0.18'

# Dependencies required for building kernel modules and running VMs
RUN apt-get update && env DEBIAN_FRONTEND=noninteractive apt-get install -y \
    cpio \
    dwarves \
    g++-12 \
    gcc-12 \
    kmod \
    qemu-kvm

# Kernel on the host machine is built with GCC-12, so we need to set it as default in Docker
RUN update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-12 10 && \
    update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-12 10 && \
    update-alternatives --set gcc /usr/bin/gcc-12 && \
    update-alternatives --set g++ /usr/bin/g++-12

CMD ["bash"]
