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
available and provide access to VMs with Intel SGX enabled in `DCsv2
<https://docs.microsoft.com/en-us/azure/virtual-machines/dcv2-series>`__ and
`DCsv3 <https://docs.microsoft.com/en-us/azure/virtual-machines/dcv3-series>`__
VM instances. The description below uses a *DCsv3 VM* running Ubuntu 20.04.

Prerequisites
^^^^^^^^^^^^^

Gramine requires the kernel to support FSGSBASE x86 instructions. Older Azure
Confidential Compute VMs may not contain the required kernel patches and need to
be updated.

Installing
^^^^^^^^^^

#. Add repository::

      sudo curl -fsSLo /usr/share/keyrings/gramine-keyring.gpg https://packages.gramineproject.io/gramine-keyring.gpg
      echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg] https://packages.gramineproject.io/ stable main' | sudo tee /etc/apt/sources.list.d/gramine.list
      sudo apt-get update

#. Install Gramine::

      sudo apt-get install gramine

#. Prepare the signing keys::

      openssl genrsa -3 -out "$HOME"/.config/gramine/enclave-key.pem 3072

#. To check if everything works, clone gramine and build and run
   :program:`helloworld`::

      git clone https://github.com/gramineproject/gramine.git
      cd gramine/CI-Examples/helloworld
      make SGX=1 SGX_SIGNER_KEY="$HOME"/.config/gramine/enclave-key.pem
      gramine-sgx helloworld
