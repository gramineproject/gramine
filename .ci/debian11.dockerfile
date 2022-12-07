FROM debian:bullseye-backports

ENV DEBIAN_FRONTEND=noninteractive

# ca-certificates needed for update over https
# devscripts is `debuild`
# git, jq, meson are needed for `meson dist` and the script
# sudo is for `apt-get` and `unshare`
RUN apt-get update && apt-get install -y \
    ca-certificates \
    devscripts \
    git \
    jq \
    sudo

RUN groupadd user -g 1001 && useradd -u 1001 -g user -m -d /home/user user
RUN echo 'ALL ALL=(ALL) ROLE=unconfined_r TYPE=unconfined_t NOPASSWD: ALL' > /etc/sudoers.d/jenkins

# Intel's RSA-1024 key signing intel-sgx/sgx_repo below. Expires 2023-05-24.
# https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key

COPY .ci/intel-sgx-deb.key /etc/apt/trusted.gpg.d/intel-sgx-deb.asc
RUN echo deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main > /etc/apt/sources.list.d/intel-sgx.list

RUN apt-get update

# Define default command.
CMD ["bash"]
