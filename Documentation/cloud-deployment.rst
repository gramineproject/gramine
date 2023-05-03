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
VM instances. The description below uses a *DCsv3 VM* running Ubuntu
18.04/20.04.

Install Gramine
^^^^^^^^^^^^^^^

On Ubuntu 20.04 LTS and 18.04 LTS::

   sudo curl -fsSLo /usr/share/keyrings/gramine-keyring.gpg https://packages.gramineproject.io/gramine-keyring.gpg
   echo "deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg] https://packages.gramineproject.io/ $(lsb_release -sc) main" \
   | sudo tee /etc/apt/sources.list.d/gramine.list

   sudo curl -fsSLo /usr/share/keyrings/intel-sgx-deb.asc https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key
   echo "deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx-deb.asc] https://download.01.org/intel-sgx/sgx_repo/ubuntu $(lsb_release -sc) main" \
   | sudo tee /etc/apt/sources.list.d/intel-sgx.list

   sudo apt-get update
   sudo apt-get install gramine

Prepare a signing key
^^^^^^^^^^^^^^^^^^^^^

Only prepare a signing key if you haven't already done so.

The following command generates an |~| RSA 3072 key suitable for signing SGX
enclaves and stores it in :file:`{HOME}/.config/gramine/enclave-key.pem`.
Protect this key and do not disclose it to anyone::

   gramine-sgx-gen-private-key

Run sample application
^^^^^^^^^^^^^^^^^^^^^^

Core Gramine repository contains several sample applications. Thus, to test
Gramine installation, we clone the Gramine repo and use the HelloWorld example
from there:

.. parsed-literal::

   git clone --depth 1 |stable-checkout| \https://github.com/gramineproject/gramine.git

To build the HelloWorld application, we need the ``gcc`` compiler and the
``make`` build system::

   sudo apt-get install gcc make

Run the HelloWorld example with SGX::

   cd gramine/CI-Examples/helloworld
   make SGX=1
   gramine-sgx helloworld
