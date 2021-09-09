Cloud Deployment
================

.. highlight:: sh

Graphene without Intel SGX can be deployed on arbitrary cloud VMs. Please see
our :doc:`quickstart` guide for the details.

To deploy Graphene with Intel SGX, the cloud VM has to support Intel SGX. Please
see the installation and usage guide for each cloud VM offering individually
below (currently only for Microsoft Azure).

Azure confidential computing VMs
--------------------------------

`Azure confidential computing services
<https://azure.microsoft.com/en-us/solutions/confidential-compute/>`__ are
generally available and provide access to VMs with Intel SGX enabled in `DCsv2
VM instances
<https://docs.microsoft.com/en-us/azure/virtual-machines/dcv2-series>`__. The
description below uses a VM running Ubuntu 18.04.

Prerequisites
^^^^^^^^^^^^^

Update and install the required packages for Graphene::

   sudo apt-get update
   sudo apt-get install -y autoconf bison build-essential gawk \
       libcurl4-openssl-dev libprotobuf-c-dev meson protobuf-c-compiler \
       python3 python3-click python3-jinja2 python3-pip python3-protobuf \
       wget
   python3 -m pip install toml>=0.10

Graphene requires the kernel to support FSGSBASE x86 instructions. Older Azure
Confidential Compute VMs may not contain the required kernel patches and need to
be updated.

To be able to run all tests also install::

    sudo apt-get install -y libunwind8 python3-pyelftools python3-pytest

Building
^^^^^^^^

#. Clone Graphene::

       git clone https://github.com/oscarlab/graphene.git
       cd graphene

#. Prepare the signing keys::

       openssl genrsa -3 -out Pal/src/host/Linux-SGX/signer/enclave-key.pem 3072

#. Build Graphene::

       make ISGX_DRIVER_PATH=/usr/src/linux-headers-`uname -r`/arch/x86/ SGX=1
       meson setup build/ --buildtype=release -Dsgx=enabled -Ddirect=disabled
       ninja -C build/
       sudo ninja -C build/ install

#. Build and run :program:`helloworld`::

       cd LibOS/shim/test/regression
       make SGX=1
       make SGX=1 sgx-tokens
       graphene-sgx helloworld
