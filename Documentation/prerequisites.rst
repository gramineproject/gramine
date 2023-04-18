.. _prerequisites

Prerequisites
-------------

Gramine without Intel® SGX support has no special requirements.

Gramine with Intel® SGX support has the following requirements:

- Linux kernel version at least 5.11 (with Intel® SGX driver enabled);
- Intel SGX PSW and (optionally) Intel® DCAP must be installed and configured.

If your system doesn't meet these requirements, please refer to the
:doc:`devel/building` section for instructions on how to install these
requirements.

Check for Intel® SGX compatibility
---------------

To check your hardware and system for Intel® SGX compatibility, use the supplied
tool, :doc:`manpages/is-sgx-available`. It's installed together with the
respective Gramine package you install from the options below.
