# Steps to create ra-tls-secret-prov server image for AKS:
#
# STEP 1: Prepare server certificate
#         1.1 Create server certificate signed by your trusted root CA. Ensure Common Name
#             field in the server certificate corresponds to <AKS-DNS-NAME> used in STEP 5.
#         1.2 Put trusted root CA certificate, server certificate, and server key in
#             gramine/Examples/ra-tls-secret-prov/certs directory with existing naming convention.
#
# STEP 2: Make sure RA-TLS DCAP libraries are built in Gramine via:
#         $ cd gramine/Pal/src/host/Linux-SGX/tools/ra-tls && make dcap
#
# STEP 3: Create base ra-tls-secret-prov server image
#         $ cd gramine
#         $ docker build -t <aks-secret-prov-server-img> \
#           -f Tools/gsc/images/gramine-aks-attestation/aks-secret-prov-server.dockerfile .
#
# STEP 4: Push resulting image to Docker Hub or your preferred registry
#         $ docker tag <aks-secret-prov-server-img> \
#           <dockerhubusername>/<aks-secret-prov-server-img>
#         $ docker push <dockerhubusername>/<aks-secret-prov-server-img>
#
# STEP 5: Deploy <aks-secret-prov-server-img> in AKS confidential compute cluster
#         Reference deployment file:
#         gsc/images/gramine-aks-attestation/aks-secret-prov-server-deployment.yaml
#
# NOTE:  Server can be deployed at a non-confidential compute node as well. However, in that case
#        QVE-based dcap verification will fail.

FROM ubuntu:18.04

RUN apt-get update \
    && env DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential \
    gnupg2 \
    libcurl3-gnutls \
    libcurl4-openssl-dev \
    python3 \
    wget

# Installing Azure DCAP Quote Provider Library (az-dcap-client).
# Here, the version of az-dcap-client should be in sync with the
# az-dcap-client version used for quote generation.
# User can replace the below package with the latest package.

RUN wget https://github.com/microsoft/Azure-DCAP-Client/releases/download/1.8/az-dcap-client_1.8_amd64_18.04.deb \
    && dpkg -i az-dcap-client_1.8_amd64_18.04.deb

# Installing DCAP Quote Verification Library
RUN echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' \
    > /etc/apt/sources.list.d/intel-sgx.list \
    && wget https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key \
    && apt-key add intel-sgx-deb.key

RUN apt-get update && apt-get install -y libsgx-dcap-quote-verify

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
    && make dcap files/input.txt

ENV LD_LIBRARY_PATH = "${LD_LIBRARY_PATH}:./libs"

ENV PATH = "${PATH}:/gramine/Examples/ra-tls-secret-prov"

ENTRYPOINT ["/gramine/Examples/ra-tls-secret-prov/secret_prov_server_dcap"]
