.. _environment_setup

Set up the Gramine environment
-------------------------------
Gramine without SGX has no special requirements.

Gramine with SGX support requires several features from your system:

- The FSGSBASE feature of recent processors must be enabled in the Linux kernel;

- The Intel SGX driver must be built in the Linux kernel;

- Intel SGX SDK/PSW and (optionally) Intel DCAP must be installed.

If your system doesn’t meet these requirements, please refer to more detailed descriptions in :doc:`devel/building`.

Check for SGX compatibility
==============================

We supply a tool, `is-sgx-available <https://deb-intel.github.io/GramineTest/manpages/is-sgx-available.html>`_ that checks the environment for SGX compatibility. Use this tool to check your hardware and system. It’s installed together with the respective gramine package you previously installed.


Prepare a signing key  
==========================

Only for SGX, and if you haven’t already, enter the following:

.. parsed-literal::

gramine-sgx-gen-private-key


This command generates an RSA 3072 key suitable for signing SGX enclaves and stores it in HOME/.config/gramine/enclave-key.pem. Protect this key and do not disclose it to anyone.