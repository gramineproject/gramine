FROM debian:11

ENV DEBIAN_FRONTEND=noninteractive

# Intel's RSA-1024 key signing intel-sgx/sgx_repo below. Expires 2023-05-24.
RUN <<EOF
cat <<EOF2 | apt-key add -
-----BEGIN PGP PUBLIC KEY BLOCK-----

mI0EXOdU7AEEAOZzO9x8v0xGlnScmcRyRYGNrVqEsvoku18wH/5iCxuq3p/6HRMy
BpQmM9R6qbYk2B2y0aotxAlr1A6xLiqNvAzYTrw9b8GWvGNLMsfh+R1SGhjTHPcV
ulB7EPeEGTMAYkywGht2FwPQ4xbiKrkPrB9Ystbv9DtHIKkFSAwPheF/ABEBAAG0
FlNHWF9EQ0FQX3JlcG9fc2lnbl9rZXmIvgQTAQgAKAUCXOdU7AIbAwUJB4YfgAYL
CQgHAwIGFQgCCQoLBBYCAwECHgECF4AACgkQqmWtJiYbMgs8PQQAlaZuIv7G/GPN
Dc0VxXbyl2pKBFaGqol96QyiXcBU1atjcwh5W0ErpypOaS4eqHTt92/JsD5wH0+Q
7wqd2pnhbKRvwSM2N3w5qsjcjEuACkxrboZBHNk0c8pkepawFhQFkv7OXo6EowFg
XYrsUoYJ5PHswaihtdjNBFluU4pqrMk=
=xhcP
-----END PGP PUBLIC KEY BLOCK-----
EOF2
EOF

RUN echo deb https://deb.debian.org/debian bullseye-backports main > /etc/apt/sources.list.d/bullseye-backports.list
RUN echo deb https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main > /etc/apt/sources.list.d/intel-sgx.list
RUN apt-get update

# keep this list synced with Build-Depends: in debian/control
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
