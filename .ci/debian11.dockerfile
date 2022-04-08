FROM debian:bullseye-backports

ENV DEBIAN_FRONTEND=noninteractive

# needed for update over https and apt-key add
RUN apt-get update
RUN apt-get install -y ca-certificates gnupg

# Intel's RSA-1024 key signing intel-sgx/sgx_repo below. Expires 2023-05-24.
# https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key
COPY .ci/intel-sgx-deb.key /root/intel-sgx-deb.key
RUN apt-key add /root/intel-sgx-deb.key

RUN echo deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main > /etc/apt/sources.list.d/intel-sgx.list
RUN apt-get update

RUN apt-get install -y -t bullseye-backports \
    build-essential \
    autoconf \
    bison \
    ca-certificates \
    gawk \
    libcurl4-openssl-dev \
    libprotobuf-c-dev \
    libsgx-dcap-quote-verify-dev \
    linux-headers-amd64 \
    meson \
    ninja-build \
    pkg-config \
    protobuf-c-compiler \
    python3-breathe \
    python3-sphinx \
    python3-sphinx-rtd-theme

# Define default command.
CMD ["bash"]
