# Steps to create ra-tls-secret-prov min client GSC image for AKS:
#
# STEP 1: Make sure RA-TLS DCAP libraries are built in Gramine via:
#         $ cd gramine/Pal/src/host/Linux-SGX/tools/ra-tls && make dcap
#
# STEP 2: Create base ra-tls-secret-prov min client image
#         $ cd gramine
#         $ docker build -t <base-secret-prov-client-img> \
#           -f Tools/gsc/images/gramine-aks-attestation/aks-secret-prov-client.dockerfile .
#
# STEP 3: Prepare client to connect with remote ra-tls-secret-prov server hosted inside AKS cluster
#         3.1 Provide server dns name <AKS-DNS-NAME> as loader.env.SECRET_PROVISION_SERVERS value
#             inside Tools/gsc/images/gramine-aks-attestation/aks-secret-prov-client.manifest file.
#
# STEP 4: Create gsc image for ra-tls-secret-prov min client
#         $ cd gramine/Tools/gsc
#         $ openssl genrsa -3 -out enclave-key.pem 3072
#         $ ./gsc build <base-secret-prov-client-img> \
#           images/gramine-aks-attestation/aks-secret-prov-client.manifest
#         $ ./gsc sign-image <base-secret-prov-client-img> enclave-key.pem
#
# STEP 5: Push resulting image to Docker Hub or your preferred registry
#         $ docker tag <gsc-base-secret-prov-client-img> \
#           <dockerhubusername>/<aks-gsc-secret-prov-client-img>
#         $ docker push <dockerhubusername>/<aks-gsc-secret-prov-client-img>
#
# STEP 6: Deploy <aks-gsc-secret-prov-client-img> in AKS confidential compute cluster
#         Reference deployment file:
#         gsc/images/gramine-aks-attestation/aks-secret-prov-client-deployment.yaml

FROM ubuntu:18.04

RUN apt-get update \
    && env DEBIAN_FRONTEND=noninteractive apt-get install -y wget \
    build-essential \
    gnupg2 \
    libcurl3-gnutls \
    python3

# Installing DCAP libraries

RUN echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' \
    > /etc/apt/sources.list.d/intel-sgx.list \
    && wget https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key \
    && apt-key add intel-sgx-deb.key

RUN apt-get update \
    && apt-get install -y libsgx-urts \
    libsgx-dcap-ql \
    libsgx-quote-ex

# Build environment of this Dockerfile should point to the root of Gramine directory

RUN mkdir -p /gramine/Scripts \
    && mkdir -p /gramine/Pal/src/host/Linux-SGX/tools/pf_crypt \
    && mkdir -p /gramine/Pal/src/host/Linux-SGX/tools/common \
    && mkdir -p /gramine/Pal/src/host/Linux-SGX/tools/ra-tls \
    && mkdir -p /gramine/Examples/ra-tls-secret-prov

# The below files are copied to satisfy Makefile dependencies of gramine/Examples/ra-tls-secret-prov

COPY Scripts/Makefile.configs  /gramine/Scripts/
COPY Scripts/Makefile.Host  /gramine/Scripts/
COPY Scripts/download  /gramine/Scripts/

COPY Pal/src/host/Linux-SGX/tools/pf_crypt/pf_crypt /gramine/Pal/src/host/Linux-SGX/tools/pf_crypt/
COPY Pal/src/host/Linux-SGX/tools/common/libsgx_util.so /gramine/Pal/src/host/Linux-SGX/tools/common/

# make sure RA-TLS DCAP libraries are built in host Gramine via:
# cd gramine/Pal/src/host/Linux-SGX/tools/ra-tls && make dcap

COPY Pal/src/host/Linux-SGX/tools/ra-tls/libsecret_prov_attest.so /gramine/Pal/src/host/Linux-SGX/tools/ra-tls/
COPY Pal/src/host/Linux-SGX/tools/ra-tls/libsecret_prov_verify_dcap.so /gramine/Pal/src/host/Linux-SGX/tools/ra-tls/
COPY Pal/src/host/Linux-SGX/tools/ra-tls/secret_prov.h /gramine/Pal/src/host/Linux-SGX/tools/ra-tls/

# If user doesn't want to copy above files, then she can build the ra-tls-secret-prov sample locally
# and copy the entire directory with executables

COPY Examples/ra-tls-secret-prov /gramine/Examples/ra-tls-secret-prov

WORKDIR /gramine/Examples/ra-tls-secret-prov

RUN make clean \
    && make clients dcap

ENV LD_LIBRARY_PATH = "${LD_LIBRARY_PATH}:./libs"

ENV PATH = "${PATH}:/gramine/Examples/ra-tls-secret-prov"

ENTRYPOINT ["/gramine/Examples/ra-tls-secret-prov/secret_prov_min_client"]
