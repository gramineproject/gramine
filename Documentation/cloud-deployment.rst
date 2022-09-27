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

On Ubuntu 20.04::

   sudo curl -fsSLo /usr/share/keyrings/gramine-keyring.gpg https://packages.gramineproject.io/gramine-keyring.gpg
   echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg] https://packages.gramineproject.io/ focal main' | sudo tee /etc/apt/sources.list.d/gramine.list

   curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -
   echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list

   sudo apt-get update
   sudo apt-get install gramine

On Ubuntu 18.04::

   sudo curl -fsSLo /usr/share/keyrings/gramine-keyring.gpg https://packages.gramineproject.io/gramine-keyring.gpg
   echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg] https://packages.gramineproject.io/ bionic main' | sudo tee /etc/apt/sources.list.d/gramine.list

   curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -
   echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list

   sudo apt-get update
   sudo apt-get install gramine-dcap

Prepare a signing key
^^^^^^^^^^^^^^^^^^^^^

Only if you haven't already::

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
