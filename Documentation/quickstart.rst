Quick start
===========

.. highlight:: sh

The following guide assumes you're using Ubuntu 18.04 or 20.04.

Quick start without SGX support
-------------------------------

#. Clone the Gramine repository::

      git clone https://github.com/gramineproject/gramine.git

#. Build Gramine:

   .. NOTE if you're about to sort the apt-get invocation below, see note in
      building.rst

   .. code-block:: sh

      sudo apt-get install -y build-essential \
          autoconf bison gawk ninja-build python3 python3-click python3-jinja2 \
          wget
      sudo python3 -m pip install 'meson>=0.55' 'toml>=0.10'
      cd gramine
      meson setup build/ --buildtype=release -Ddirect=enabled -Dsgx=disabled
      ninja -C build/
      sudo ninja -C build/ install

#. Build and run :program:`helloworld`::

      cd CI-Examples/helloworld
      make
      gramine-direct helloworld

#. For more complex examples, see :file:`CI-Examples` directory.

Quick start with SGX support
----------------------------

Gramine requires several features from your system:

- the FSGSBASE feature of recent processors must be enabled in the Linux kernel,
- the Intel SGX driver must be built in the Linux kernel, and Linux headers for
  your kernel (``linux-headers-*`` package) must be installed,
- Intel SGX SDK/PSW and (optionally) Intel DCAP must be installed.

If your system doesn't meet these requirements, please refer to more detailed
descriptions in :doc:`building`.

#. Ensure that Intel SGX is enabled on your platform using
   :program:`is_sgx_available`.

#. Clone the Gramine repository::

      git clone https://github.com/gramineproject/gramine.git
      cd gramine

#. Prepare a signing key::

      openssl genrsa -3 -out Pal/src/host/Linux-SGX/signer/enclave-key.pem 3072

#. Build Gramine with SGX support:

   .. NOTE if you're about to sort the apt-get invocation below, see note in
      building.rst

   .. code-block:: sh

      sudo apt-get install -y build-essential \
          autoconf bison gawk libcurl4-openssl-dev libprotobuf-c-dev \
          ninja-build protobuf-c-compiler python3 python3-click python3-jinja2 \
          python3-pip python3-protobuf wget
      sudo python3 -m pip install 'meson>=0.55' 'toml>=0.10'
      # this assumes Linux 5.11+
      meson setup build/ --buildtype=release -Ddirect=enabled -Dsgx=enabled
      ninja -C build/
      sudo ninja -C build/ install

   In case of a non-standard SGX driver configuration (different SGX driver, or
   different kernel headers path) you might need to also pass ``-Dsgx_driver``
   and ``-Dsgx_driver_include_path`` options to Meson. See :doc:`building` for
   details.

#. Set ``vm.mmap_min_addr=0`` in the system (*only required for the legacy SGX
   driver and not needed for newer DCAP/in-kernel drivers*)::

      sudo sysctl vm.mmap_min_addr=0

   Note that this is an inadvisable configuration for production systems.

#. Build and run :program:`helloworld`::

      cd CI-Examples/helloworld
      make SGX=1
      gramine-sgx helloworld

Troubleshooting
---------------

- When installing from sources, Gramine executables are placed under
  ``/usr/local/bin``. Some Linux distributions (notably CentOS) do not search
  for executables under this path. If your system reports that Gramine programs
  can not be found, you might need to edit your configuration files so that
  ``/usr/local/bin`` is in your path (in ``PATH`` environment variable).

- If you invoked ``meson setup`` once, the next invocation of this command will
  *not* have any effect. Instead, to change the build configuration, use ``meson
  configure``. For example, if you built with ``meson setup build/
  -Dsgx=disabled`` first and now want to enable SGX, type ``meson configure
  build/ -Dsgx=enabled``.

Running sample applications
---------------------------

We prepared and tested several applications to demonstrate Gramine usability.
These applications can be found in the :file:`CI-Examples` folder in the
repository, each containing a short README with instructions how to test it. We
recommend starting with a simpler, thoroughly documented example of Redis, to
understand manifest options and features of Gramine.

Additional sample configurations for applications enabled in Gramine can be
found in a separate repository https://github.com/gramineproject/examples.

Please note that these sample applications are tested on Ubuntu 18.04 and 20.04.
Most of these applications are also known to run correctly on
Fedora/RHEL/CentOS, but with caveats. One caveat is that Makefiles should be
invoked with ``ARCH_LIBDIR=/lib64 make``. Another caveat is that applications
that rely on specific versions/builds of Glibc may break (our GCC example is
known to work only on Ubuntu).
