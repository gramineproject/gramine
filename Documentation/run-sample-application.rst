Run a sample application
========================

.. highlight:: sh

The core Gramine repository contains sample applications to test the Gramine
installation. To clone the Gramine repo, use the following command:

.. parsed-literal::

   git clone --depth 1 |stable-checkout| \https://github.com/gramineproject/gramine.git

Don't build Gramine if it is already installed on the system.

Build and run HelloWorld sample app
-----------------------------------

To build the HelloWorld application, install the ``gcc`` compiler and the
``make`` build system by entering the following::

   sudo apt-get install gcc make  # for Ubuntu distribution
   sudo dnf install gcc make      # for RHEL-like distribution
   sudo apk add build-base make   # for Alpine distribution

Go to the HelloWorld example directory::

   cd gramine/CI-Examples/helloworld

Build and run without SGX::

   make
   gramine-direct helloworld

Build and run with SGX::

   make SGX=1
   gramine-sgx helloworld

If you want to run this example on Alpine, then before building, modify the
:file:`helloworld.manifest.template` file: replace ``gramine.runtimedir()`` with
``gramine.runtimedir('musl')``. For details, see the section "glibc vs musl"
below.

Other sample applications
-------------------------

Several applications that demonstrate Gramine usability are available in the
:file:`CI-Examples` directory in the repository. Each application contains a
short README file with instructions how to test it. We recommend starting with a
thoroughly documented example of Redis to understand manifest options and
Gramine features.

Additional sample Gramine configurations for applications are available in a
separate repository: https://github.com/gramineproject/examples.

Please note that these sample applications are tested on Debian/Ubuntu. Most of
these applications are also known to run correctly on Alpine and RHEL-like
distributions (Fedora, CentOS Stream, AlmaLinux, Rocky Linux) but with caveats:

- On RHEL-like distributions, Makefiles should be invoked with
  ``ARCH_LIBDIR=/lib64 make``.
- On Alpine, manifest files must use ``gramine.runtimedir('musl')`` instead of
  ``gramine.runtimedir()``, and Makefiles should be invoked with
  ``ARCH_LIBDIR=/lib make``.
- Applications that rely on specific versions/builds of Glibc may break (our GCC
  example is known to work only on Ubuntu).

glibc vs musl
-------------

Most of the examples we provide use GNU C Library (glibc). If your application
is built against musl libc, you can pass ``'musl'`` to
:py:func:`gramine.runtimedir()` when generating the manifest from a template,
which will mount musl libc (instead of the default glibc).
