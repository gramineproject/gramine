FROM debian:bullseye-backports

ENV DEBIAN_FRONTEND=noninteractive

# ca-certificates needed for update over https
# and auxiliary tools
RUN apt-get update && apt-get install -y \
    ca-certificates \
    git \
    jq \
    pbuilder

# Intel's RSA-1024 key signing intel-sgx/sgx_repo below. Expires 2023-05-24.
# https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key
COPY .ci/intel-sgx-deb.key /etc/apt/trusted.gpg.d/intel-sgx-deb.asc
RUN echo deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main > /etc/apt/sources.list.d/intel-sgx.list

# dependencies for actual build (cf. debian/control)
RUN apt-get update && apt-get install -y -t bullseye-backports \
    build-essential \
    autoconf \
    bison \
    gawk \
    libcjson-dev \
    libcurl4-openssl-dev \
    libprotobuf-c-dev \
    libsgx-dcap-quote-verify-dev \
    linux-headers-amd64 \
    meson \
    nasm \
    ninja-build \
    pkg-config \
    protobuf-compiler \
    protobuf-c-compiler \
    python3-breathe \
    python3-sphinx \
    python3-sphinx-rtd-theme \
    python3-tomli \
    python3-tomli-w

# Define default command.
CMD ["bash"]
