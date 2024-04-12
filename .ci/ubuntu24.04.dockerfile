FROM ubuntu:noble

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y ca-certificates

# Intel's RSA-2048 key signing the intel-sgx/sgx_repo repository. Expires 2027-03-20.
# https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key
# TODO after Intel releases for noble: fix mantic to noble
COPY .ci/intel-sgx-deb.key /etc/apt/trusted.gpg.d/intel-sgx-deb.asc
RUN echo deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu mantic main > /etc/apt/sources.list.d/intel-sgx.list

# Dependencies for actual build.
# NOTE: COPY invalidates docker cache when source file changes,
# so `apt-get build-dep` will rerun if dependencies change, despite no change
# in dockerfile.
RUN mkdir /debian
COPY debian/control /debian
RUN apt-get update && apt-get -y build-dep --no-install-recommends --no-install-suggests /
RUN rm -rf /debian

# dependencies for various tests, CI-Examples, etc.
RUN apt-get update && apt-get install -y \
    nginx

CMD ["bash"]
