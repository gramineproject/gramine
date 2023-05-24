FROM debian:bullseye-backports

ENV DEBIAN_FRONTEND=noninteractive

# ca-certificates needed for update over https
# devscripts is `debuild`
# git, jq are needed for `meson dist` and the script
RUN apt-get update && apt-get install -y \
    ca-certificates \
    devscripts \
    git \
    jq

# Intel's RSA-2048 key signing the intel-sgx/sgx_repo repository. Expires 2027-03-20.
# https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key
COPY .ci/intel-sgx-deb.key /etc/apt/trusted.gpg.d/intel-sgx-deb.asc
RUN echo deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main > /etc/apt/sources.list.d/intel-sgx.list

# Dependencies for actual build.
# NOTE: COPY invalidates docker cache when source file changes,
# so `apt-get build-dep` will rerun if dependencies change, despite no change
# in dockerfile.
RUN mkdir /debian
COPY debian/control /debian
RUN apt-get update && apt-get -y build-dep -t bullseye-backports --no-install-recommends --no-install-suggests /

CMD ["bash"]
