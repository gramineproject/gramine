Building
========

.. highlight:: sh

.. todo::

   This page really belongs to :file:`devel/`, move it there after a |~| proper
   release. Instead, for all users, there should be documentation for installing
   without full compilation.

Gramine consists of several components:

- The Library OS itself (a shared library named ``libsysdb.so``, called the
  "shim" in our source code)
- The Platform Adaptation Layer, or PAL (a shared library named ``libpal.so``)
- A patched GNU C Library (a set of shared libraries ``libc.so``,
  ``libpthread.so``, ``libm.so``, etc.)

The build of Gramine implies building at least the first two components. The
build of the patched C library is optional but highly recommended for
performance reasons. The patched C library is built by default.

Gramine currently only works on the x86_64 architecture. Gramine is currently
tested on Ubuntu 18.04/20.04, along with Linux kernel version 5.x. We recommend
building and installing Gramine on Ubuntu with Linux kernel version 5.11 or
higher. If you find problems with Gramine on other Linux distributions, please
contact us with a |~| detailed `bug report
<https://github.com/gramineproject/gramine/issues/new>`__.

Installing dependencies
-----------------------

Common dependencies
^^^^^^^^^^^^^^^^^^^

.. NOTE to anyone who will be sorting this list: build-essential should not be
   sorted together with others, because it is implicit when specifying package
   dependecies, so when copying to debian/control, it should be omitted

Run the following command on Ubuntu LTS to install dependencies::

    sudo apt-get install -y build-essential \
        autoconf bison gawk ninja-build python3 python3-click python3-jinja2 \
        wget
    sudo python3 -m pip install 'meson>=0.55' 'toml>=0.10'

You can also install Meson and python3-toml from apt instead of pip, but only if
your distro is new enough to have Meson >= 0.55 and python3-toml >= 0.10 (Debian
11, Ubuntu 20.10).

For GDB support and to run all tests locally you also need to install::

    sudo apt-get install -y libunwind8 python3-pyelftools python3-pytest

Dependencies for SGX
^^^^^^^^^^^^^^^^^^^^

The build of Gramine with SGX support requires the corresponding SGX software
infrastructure to be installed on the system. In particular, the FSGSBASE
functionality must be enabled in the Linux kernel, the Intel SGX driver must be
running, and Intel SGX SDK/PSW/DCAP must be installed.

.. note::

   We recommend to use Linux kernel version 5.11 or higher: starting from this
   version, Linux has the FSGSBASE functionality as well as the Intel SGX driver
   built-in. If you have Linux 5.11+, skip steps 2 and 3.

1. Required packages
""""""""""""""""""""
Run the following commands on Ubuntu to install SGX-related dependencies::

    sudo apt-get install -y libcurl4-openssl-dev libprotobuf-c-dev \
        protobuf-c-compiler python3-pip python3-protobuf

2. Upgrade to the Linux kernel patched with FSGSBASE
""""""""""""""""""""""""""""""""""""""""""""""""""""

FSGSBASE is a feature in recent processors which allows direct access to the FS
and GS segment base addresses. For more information about FSGSBASE and its
benefits, see `this discussion <https://lwn.net/Articles/821719>`__. Note that
if your kernel version is 5.9 or higher, then the FSGSBASE feature is already
supported and you can skip this step.

If your current kernel version is lower than 5.9, then you have two options:

- Update the Linux kernel to at least 5.9 in your OS distro. If you use Ubuntu,
  you can follow e.g. `this tutorial
  <https://itsfoss.com/upgrade-linux-kernel-ubuntu/>`__.

- Use our provided patches to the Linux kernel version 5.4. See section
  :ref:`FSGSBASE` for the exact steps.

3. Install the Intel SGX driver
"""""""""""""""""""""""""""""""

This step depends on your hardware and kernel version. Note that if your kernel
version is 5.11 or higher, then the Intel SGX driver is already installed and
you can skip this step.

If you have an older CPU without :term:`FLC` support, you need to download and
install the the following Intel SGX driver:

- https://github.com/intel/linux-sgx-driver

Alternatively, if your CPU supports :term:`FLC`, you can choose to install the
DCAP version of the Intel SGX driver from:

- https://github.com/intel/SGXDataCenterAttestationPrimitives

4. Install Intel SGX SDK/PSW
""""""""""""""""""""""""""""

Follow the installation instructions from:

- https://github.com/intel/linux-sgx

5. Generate signing keys
""""""""""""""""""""""""

A 3072-bit RSA private key (PEM format) is required for signing the manifest.
If you don't have a private key, create it with the following command::

   openssl genrsa -3 -out enclave-key.pem 3072

You can either place the generated enclave key in the default path,
:file:`Pal/src/host/Linux-SGX/signer/enclave-key.pem`, or specify the key's
location through the environment variable ``SGX_SIGNER_KEY``.

After signing the application's manifest, users may ship the application and
Gramine binaries, along with an SGX-specific manifest (``.manifest.sgx``
extension), the SIGSTRUCT signature file (``.sig`` extension), and the
EINITTOKEN file (``.token`` extension) to execute on another SGX-enabled host.

Building
--------

In order to build Gramine, you need to first set up the build directory. In the
root directory of Gramine repo, run the following command (recall that "direct"
means non-SGX version)::

   meson setup build/ --buildtype=release -Ddirect=enabled -Dsgx=enabled \
       -Dsgx_driver=<driver> -Dsgx_driver_path=<path-to-sgx-driver-sources>

Then, build and install Gramine by running the following::

   ninja -C build/
   sudo ninja -C build/ install

Set ``-Ddirect=`` and ``-Dsgx=`` options to ``enabled`` or ``disabled``
according to whether you built the corresponding PAL (the snippet assumes you
built both).

The ``-Dsgx_driver`` parameter controls which SGX driver to use:

* ``upstream`` (default) for upstreamed in-kernel driver (mainline Linux kernel
  5.11+),
* ``dcap1.6`` for Intel DCAP version 1.6 or higher,  but below 1.10,
* ``dcap1.10`` for Intel DCAP version 1.10 or higher,
* ``oot`` for non-DCAP, out-of-tree version of the driver.

The ``-Dsgx_driver_include_path`` parameter must point to the absolute path
where the SGX driver was downloaded or installed in the previous step. For
example, for the DCAP version 1.41 of the SGX driver, you must specify
``-Dsgx_driver_include_path="/usr/src/sgx-1.41/include/"``. If this parameter is
omitted, Gramine's build system will try to determine the right path.

.. note::

   When installing from sources, Gramine executables are placed under
   ``/usr/local/bin``. Some Linux distributions (notably CentOS) do not search
   for executables under this path. If your system reports that Gramine
   programs can not be found, you might need to edit your configuration files so
   that ``/usr/local/bin`` is in your path (in ``PATH`` environment variable).

Additional build options
^^^^^^^^^^^^^^^^^^^^^^^^

- To create a debug build, run :command:`meson --buildtype=debug`. This adds
  debug symbols in all Gramine components, builds them without optimizations,
  and enables detailed debug logs in Gramine.

  .. warning::
     Debug builds are not suitable for production.

- To create a debug build that does not disable optimizations, run
  :command:`meson --buildtype=debugoptimized`.

  .. warning::
     Debug builds are not suitable for production.

  .. note::
     This is generally *not* recommended, because optimized builds lose some
     debugging information, and may cause GDB to display confusing tracebacks or
     garbage data. You should use ``DEBUGOPT=1`` only if you have a good reason
     (e.g. for profiling).

- To compile with undefined behavior sanitization (UBSan), run
  :command:`meson -Dubsan=enabled`. This causes Gramine to abort when undefined
  behavior is detected (and display information about source line). UBSan can be
  enabled for both debug and non-debug builds.

  .. warning::
     UBSan builds (even non-debug) are not suitable for production.

- To compile with address sanitization (ASan), run
  :command:`meson -Dasan=enabled`. In this mode, Gramine will attempt to detect
  invalid memory accesses. ASan can be enabled for both debug and non-debug
  builds.

  ASan is supported only when compiling with Clang (before building, set the
  appropriate environment variables with :command:`export CC=clang CXX=clang++
  AS=clang`).

  .. warning::
     ASan builds (even non-debug) are not suitable for production.

- To build with ``-Werror``, run :command:`meson --werror`.

- To install into some other place than :file:`/usr/local`, use
  :command:`meson --prefix=<prefix>`. Note that if you chose something else than
  :file:`/usr` then for things to work, you probably need to adjust several
  environment variables:

  =========================== ================================================== ========================
  Variable                    What to add                                        Read more
  =========================== ================================================== ========================
  ``$PATH``                   :file:`<prefix>/bin`                               `POSIX.1-2018 8.3`_
  ``$PYTHONPATH``             :file:`<prefix>/lib/python<version>/site-packages` :manpage:`python3(1)`
  ``$PKG_CONFIG_PATH``        :file:`<prefix>/<libdir>/pkgconfig`                :manpage:`pkg-config(1)`
  =========================== ================================================== ========================

  .. _POSIX.1-2018 8.3: https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap08.html#tag_08_03

  This very much depends on particular distribution, so please consult relevant
  documentation provided by your distro.

.. _FSGSBASE:

Advanced: installing Linux kernel with FSGSBASE patches
-------------------------------------------------------

FSGSBASE patchset was merged in Linux kernel version 5.9. For older kernels it
is available as `separate patches
<https://github.com/oscarlab/graphene-sgx-driver/tree/master/fsgsbase_patches>`__.
(Note that Gramine was prevously called *Graphene* and was hosted under a
different organization, hence the name of the linked repository.)

The following instructions to patch and compile a Linux kernel with FSGSBASE
support below are written around Ubuntu 18.04 LTS (Bionic Beaver) with a Linux
5.4 LTS stable kernel but can be adapted for other distros as necessary. These
instructions ensure that the resulting kernel has FSGSBASE support.

#. Clone the repository with patches::

       git clone https://github.com/oscarlab/graphene-sgx-driver

#. Setup a build environment for kernel development following `the instructions
   in the Ubuntu wiki <https://wiki.ubuntu.com/KernelTeam/GitKernelBuild>`__.
   Clone Linux version 5.4 via::

       git clone --single-branch --branch linux-5.4.y \
           https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git
       cd linux

#. Apply the provided FSGSBASE patches to the kernel source tree::

       git am <graphene-sgx-driver>/fsgsbase_patches/*.patch

   The conversation regarding this patchset can be found in the kernel mailing
   list archives `here
   <https://lore.kernel.org/lkml/20200528201402.1708239-1-sashal@kernel.org>`__.

#. Build and install the kernel following `the instructions in the Ubuntu wiki
   <https://wiki.ubuntu.com/KernelTeam/GitKernelBuild>`__.

#. After rebooting, verify the patched kernel is the one that has been booted
   and is running::

       uname -r

#. Also verify that the patched kernel supports FSGSBASE (the below command
   must return that bit 2 is set)::

       LD_SHOW_AUXV=1 /bin/true | grep AT_HWCAP2

After the patched Linux kernel is installed, you may proceed with installations
of other SGX software infrastructure: the Intel SGX Linux driver, the Intel SGX
SDK/PSW, and Gramine itself.
