FROM ubuntu:18.04

RUN apt-get update && env DEBIAN_FRONTEND=noninteractive apt-get install -y \
    autoconf \
    bc \
    bison \
    build-essential \
    cargo \
    curl \
    flex \
    gawk \
    gdb \
    gettext \
    git \
    jq \
    libapr1-dev \
    libaprutil1-dev \
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
    linux-headers-4.15.0-20-generic \
    musl \
    musl-tools \
    nasm \
    net-tools \
    netcat-openbsd \
    ninja-build \
    pkg-config \
    protobuf-c-compiler \
    protobuf-compiler \
    pylint3 \
    python \
    python3-apport \
    python3-apt \
    python3-breathe \
    python3-click \
    python3-cryptography \
    python3-jinja2 \
    python3-lxml \
    python3-numpy \
    python3-pip \
    python3-protobuf \
    python3-pyelftools \
    python3-pytest \
    python3-pytest-xdist \
    python3-scipy \
    shellcheck \
    sqlite3 \
    texinfo \
    uthash-dev \
    wget \
    zlib1g \
    zlib1g-dev

# Install wrk2 benchmark. This benchmark is used in `benchmark-http.sh`.
RUN git clone https://github.com/giltene/wrk2.git \
    && cd wrk2 \
    && git checkout 44a94c17d8e6a0bac8559b53da76848e430cb7a7 \
    && make \
    && cp wrk /usr/local/bin \
    && cd .. \
    && rm -rf wrk2


# NOTE about meson version: we support "0.56 or newer", so in CI we pin to latest patch version of
# the earliest supported minor version (pip implicitly installs latest version satisfying the
# specification)
RUN python3 -m pip install -U \
    'Sphinx==1.8' \
    'sphinx_rtd_theme<1' \
    'tomli>=1.1.0' \
    'tomli-w>=0.4.0' \
    'meson>=0.56,<0.57' \
    'docutils>=0.17,<0.18'

CMD ["bash"]
