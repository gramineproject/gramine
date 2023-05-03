.. _run_sample_application


Run a sample application
========================

The core Gramine repository contains sample applications to test the Gramine
installation. To clone the Gramine repo, use the following command:

.. parsed-literal::

   git clone --depth 1 |stable-checkout| \https://github.com/gramineproject/gramine.git

Don't build Gramine as it is already installed on the system. Instead,
build and run the HelloWorld example. To build the HelloWorld application,
access the ``gcc`` compiler and the ``make`` build system by entering the
following::

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

Several applications that demonstrate Gramine usability are available in the
:file:`CI-Examples` directory in the repository. Each application contains a
short README file with instructions how to test it. We recommend starting
with a simpler, thoroughly documented example of Redis to
understand manifest options and Gramine features.

Additional sample configurations for applications enabled in Gramine are
available in a separate repository https://github.com/gramineproject/examples.

Please note that these sample applications are tested on Ubuntu. Most of these
applications are also known to run correctly on Fedora/RHEL/AlmaLinux/Rocky
Linux, but with caveats. One caveat is that Makefiles should be invoked with
``ARCH_LIBDIR=/lib64 make``. Another caveat is that applications that rely on
specific versions/builds of Glibc may break (our GCC example is known to work
only on Ubuntu).

glibc vs musl
-------------

Most of the examples we provide use GNU C Library (glibc).
If your application is built against musl libc, you can pass ''musl'' to
''gramine.runtimedir()'' when generating the manifest from a template;
this will mount musl libc (instead of the default glibc).
