Cloud Deployment
================

.. highlight:: sh

Gramine without Intel SGX can be deployed on arbitrary cloud VMs. Please see
our :doc:`quickstart` guide for the details.

To deploy Gramine with Intel SGX, the cloud VM has to support Intel SGX. Please
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

.. NOTE to anyone who will be sorting this list: build-essential should not be
   sorted together with others, because it is implicit when specifying package
   dependecies, so when copying to debian/control, it should be omitted

Update and install the required packages for Gramine::

   sudo apt-get update
   sudo apt-get install -y build-essential \
       autoconf bison gawk libcurl4-openssl-dev libprotobuf-c-dev ninja-build \
       protobuf-c-compiler python3 python3-click python3-jinja2 python3-pip \
       python3-protobuf wget
   sudo python3 -m pip install 'meson>=0.55' 'toml>=0.10'

Gramine requires the kernel to support FSGSBASE x86 instructions. Older Azure
Confidential Compute VMs may not contain the required kernel patches and need to
be updated.

To be able to run all tests also install::

    sudo apt-get install -y libunwind8 python3-pyelftools python3-pytest

Building
^^^^^^^^

#. Clone Gramine::

       git clone https://github.com/gramineproject/gramine.git
       cd gramine

#. Prepare the signing keys::

       openssl genrsa -3 -out Pal/src/host/Linux-SGX/signer/enclave-key.pem 3072

#. Build Gramine::

       meson setup build/ --buildtype=release -Dsgx=enabled -Ddirect=disabled
       ninja -C build/
       sudo ninja -C build/ install

#. Build and run :program:`helloworld`::

       cd CI-Examples/helloworld
       make SGX=1
       gramine-sgx helloworld
