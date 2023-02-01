Quick start
===========

.. highlight:: sh

Prerequisites
-------------

Gramine without SGX has no special requirements.

Gramine with SGX support requires several features from your system:

- Linux kernel version at least 5.11 (with SGX driver enabled);
- Intel SGX PSW and (optionally) Intel DCAP must be installed and configured.

If your system doesn't meet these requirements, please refer to more detailed
descriptions in :doc:`devel/building`.

We supply a tool :doc:`manpages/is-sgx-available`, which you can use to check
your hardware and system. It's installed together with the respective gramine
package (see below).

Install Gramine
---------------

Debian 11
^^^^^^^^^

::

   # if you don't already have backports repo enabled:
   echo "deb http://deb.debian.org/debian $(lsb_release -sc)-backports main" \
   | sudo tee /etc/apt/sources.list.d/backports.list

   sudo curl -fsSLo /usr/share/keyrings/gramine-keyring.gpg https://packages.gramineproject.io/gramine-keyring.gpg
   echo "deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg] https://packages.gramineproject.io/ $(lsb_release -sc) main" \
   | sudo tee /etc/apt/sources.list.d/gramine.list

   sudo curl -fsSLo /usr/share/keyrings/intel-sgx-deb.asc https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key
   echo "deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx-deb.asc] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main" \
   | sudo tee /etc/apt/sources.list.d/intel-sgx.list

   sudo apt-get update
   sudo apt-get install gramine

Ubuntu 22.04 LTS, 20.04 LTS or 18.04 LTS
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

   sudo curl -fsSLo /usr/share/keyrings/gramine-keyring.gpg https://packages.gramineproject.io/gramine-keyring.gpg
   echo "deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg] https://packages.gramineproject.io/ $(lsb_release -sc) main" \
   | sudo tee /etc/apt/sources.list.d/gramine.list

   sudo curl -fsSLo /usr/share/keyrings/intel-sgx-deb.asc https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key
   echo "deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx-deb.asc] https://download.01.org/intel-sgx/sgx_repo/ubuntu $(lsb_release -sc) main" \
   | sudo tee /etc/apt/sources.list.d/intel-sgx.list

   sudo apt-get update
   sudo apt-get install gramine

RHEL-like distributions version 8 (and experimentally also version 9)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

(like AlmaLinux, Rocky Linux, ...)

1. Install EPEL repository as described here:
   https://docs.fedoraproject.org/en-US/epel/

2. Install Gramine::

      sudo curl -fsSLo /etc/yum.repos.d/gramine.repo https://packages.gramineproject.io/rpm/gramine.repo
      sudo dnf install gramine

Prepare a signing key
---------------------

Only for SGX, and if you haven't already::

   gramine-sgx-gen-private-key

This command generates an |~| RSA 3072 key suitable for signing SGX enclaves and
stores it in :file:`{HOME}/.config/gramine/enclave-key.pem`. This key needs to
be protected and should not be disclosed to anyone.

Run sample application
----------------------

Core Gramine repository contains several sample applications. Thus, to test
Gramine installation, we clone the Gramine repo:

.. parsed-literal::

   git clone --depth 1 |stable-checkout| \https://github.com/gramineproject/gramine.git

We don't want to build Gramine (it is already installed on the system). Instead,
we want to build and run the HelloWorld example. To build the HelloWorld
application, we need the ``gcc`` compiler and the ``make`` build system::

   sudo apt-get install gcc make  # for Ubuntu distribution
   sudo dnf install gcc make      # for RHEL-like distribution

Go to the HelloWorld example directory::

   cd gramine/CI-Examples/helloworld

Build and run without SGX::

   make
   gramine-direct helloworld

Build and run with SGX::

   make SGX=1
   gramine-sgx helloworld

Other sample applications
-------------------------

We prepared and tested several applications to demonstrate Gramine usability.
These applications can be found in the :file:`CI-Examples` directory in the
repository, each containing a short README with instructions how to test it. We
recommend starting with a simpler, thoroughly documented example of Redis, to
understand manifest options and features of Gramine.

Additional sample configurations for applications enabled in Gramine can be
found in a separate repository https://github.com/gramineproject/examples.

Please note that these sample applications are tested on Ubuntu. Most of these
applications are also known to run correctly on Fedora/RHEL/AlmaLinux/Rocky
Linux, but with caveats. One caveat is that Makefiles should be invoked with
``ARCH_LIBDIR=/lib64 make``. Another caveat is that applications that rely on
specific versions/builds of Glibc may break (our GCC example is known to work
only on Ubuntu).

glibc vs musl
-------------

Most of the examples we provide use GNU C Library (glibc). If your application
is built against musl libc, you can pass ``'musl'`` to
:py:func:`gramine.runtimedir()` when generating the manifest from a template,
which will mount musl libc (instead of the default glibc).
