ARG UBUNTU_IMAGE=ubuntu:20.04

FROM ${UBUNTU_IMAGE}

# ARGs cannot be grouped since each FROM in a Dockerfile initiates a new build
# stage, resulting in the loss of ARG values from earlier stages.
ARG UBUNTU_CODENAME=focal

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y curl gnupg2 binutils

RUN curl -fsSLo /usr/share/keyrings/gramine-keyring.gpg https://packages.gramineproject.io/gramine-keyring.gpg && \
    echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg] https://packages.gramineproject.io/ '${UBUNTU_CODENAME}' main' > /etc/apt/sources.list.d/gramine.list

RUN curl -fsSLo /usr/share/keyrings/intel-sgx-deb.key https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key && \
    echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx-deb.key] https://download.01.org/intel-sgx/sgx_repo/ubuntu '${UBUNTU_CODENAME}' main' > /etc/apt/sources.list.d/intel-sgx.list

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y gramine \
    sgx-aesm-service \
    libsgx-aesm-launch-plugin \
    libsgx-aesm-epid-plugin \
    libsgx-aesm-quote-ex-plugin \
    libsgx-aesm-ecdsa-plugin \
    libsgx-dcap-quote-verify \
    psmisc && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/run/aesmd/

COPY restart_aesm.sh /restart_aesm.sh

ENTRYPOINT ["/bin/sh", "-c"]
CMD ["/restart_aesm.sh ; exec /bin/bash"]
