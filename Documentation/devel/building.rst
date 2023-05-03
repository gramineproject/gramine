Build and install Gramine from source
=====================================

.. highlight:: sh

Gramine consists of several components:

- The Library OS itself (a shared library named ``libsysdb.so``)
- The Platform Adaptation Layer, or PAL (a shared library named ``libpal.so``)
- A patched C Library (shared library ``libc.so`` and possibly others).
  Currently there are two options: musl and GNU C Library (glibc).

Building Gramine implies building at least the first two components. The
build of the patched C library is optional but highly recommended for
performance reasons. Both patched glibc and patched musl are built by default.

Gramine currently only works on the x86_64 architecture. Gramine is currently
tested on Ubuntu 18.04/20.04, along with Linux kernel version 5.x. We recommend
building and installing Gramine on Ubuntu with Linux kernel version 5.11 or
higher. If you find problems with Gramine on other Linux distributions,
contact us with a |~| detailed `bug report
<https://github.com/gramineproject/gramine/issues/new>`__.

Install dependencies
--------------------

.. _common-dependencies:

Common dependencies
^^^^^^^^^^^^^^^^^^^

.. NOTE to anyone who will be sorting this list: build-essential should not be
   sorted together with others, because it is implicit when specifying package
   dependecies, so when copying to debian/control, it should be omitted

Run the following command on Ubuntu LTS to install dependencies::

    sudo apt-get install -y build-essential \
        autoconf bison gawk nasm ninja-build pkg-config python3 python3-click \
        python3-jinja2 python3-pip python3-pyelftools wget
    sudo python3 -m pip install 'meson>=0.56' 'tomli>=1.1.0' 'tomli-w>=0.4.0'

You can also install Meson, python3-tomli and python3-tomli-w from apt instead
of pip, but only if your distro is new enough to have Meson >= 0.56,
python3-tomli >= 1.1.0 and python3-tomli-w >= 0.4.0 (e.g. Ubuntu 22.04 or Debian
11 with ``bullseye-backports`` repo enabled).

For GDB support and to run all tests locally you also need to install::

    sudo apt-get install -y libunwind8 musl-tools python3-pytest

If you want to build the patched ``libgomp`` library, you also need to install
GCC's build dependencies::

    sudo apt-get install -y libgmp-dev libmpfr-dev libmpc-dev libisl-dev

Dependencies for SGX
^^^^^^^^^^^^^^^^^^^^

The build of Gramine with SGX support requires the corresponding SGX software
infrastructure to be installed on the system. We require Linux kernel with SGX
driver built in (``CONFIG_X86_SGX=y``, which is the case for most of available
distribution kernels), which is available since version 5.11 (and also as
backported patches to older kernels in certain distros). Note this requires CPU
with :term:`FLC`.

Kernel version can be checked using the following command::

       uname -r

If your current kernel version is lower than 5.11, then you have two options:

- Update the Linux kernel to at least 5.11 in your OS distro. If you use Ubuntu,
  you can follow e.g., `this tutorial
  <https://itsfoss.com/upgrade-linux-kernel-ubuntu/>`__.

- Install out-of-tree driver and use our provided patches to the Linux kernel
  version 5.4. See section :ref:`legacy-kernel-and-hardware` for the exact
  steps.

1. Required packages
""""""""""""""""""""
Run the following commands on Ubuntu to install SGX-related dependencies::

    sudo apt-get install -y libprotobuf-c-dev protobuf-c-compiler \
        protobuf-compiler python3-cryptography python3-pip python3-protobuf

2. Install Intel SGX SDK/PSW
""""""""""""""""""""""""""""

Follow the installation instructions from the latest version of "Intel SGX
Software Installation Guide":

- https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_SW_Installation_Guide_for_Linux.pdf

In general, various documentation for Intel SGX SDK/PSW can be found here:

- https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/
- https://download.01.org/intel-sgx/latest/linux-latest/docs/

Additional information, package descriptions, etc. can be found in the official
"Intel SGX for Linux" GitHub repo:

- https://github.com/intel/linux-sgx

3. Install dependencies for DCAP
""""""""""""""""""""""""""""""""

If you plan on enabling ``-Ddcap`` option, you need to install
``libsgx-dcap-quote-verify`` package (and it's development counterpart)::

   curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -
   echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
   # (if you're on Ubuntu 18.04, write "bionic" instead of "focal" above)

   sudo apt-get update
   sudo apt-get install libsgx-dcap-quote-verify-dev

Build Gramine
-------------

To build Gramine, you need to first set up the build directory. In the
root directory of Gramine repo, run the following command (recall that "direct"
means non-SGX version)::

   meson setup build/ --buildtype=release -Ddirect=enabled -Dsgx=enabled \
       -Dsgx_driver=<driver> -Dsgx_driver_include_path=<path-to-sgx-driver-sources>

.. note::

   If you plan to contribute changes to Gramine, then you should always build it
   with ``--werror`` added to the invocation above.

.. note::

   If you invoked ``meson setup`` once, the next invocation of this command will
   *not* have any effect. Instead, to change the build configuration, use
   ``meson configure``. For example, if you built with ``meson setup build/
   -Dsgx=disabled`` first and now want to enable SGX, type ``meson configure
   build/ -Dsgx=enabled``.

Then, build and install Gramine by running the following::

   ninja -C build/
   sudo ninja -C build/ install

Set ``-Ddirect=`` and ``-Dsgx=`` options to ``enabled`` or ``disabled``
according to whether you built the corresponding PAL (the snippet assumes you
built both).

The ``-Dsgx_driver`` parameter controls which SGX driver to use:

* ``upstream`` (default) for upstreamed in-kernel driver (mainline Linux kernel
  5.11+),
* ``oot`` for non-DCAP, out-of-tree version of the driver.

The ``-Dsgx_driver_include_path`` parameter must point to the absolute path
where the SGX driver was downloaded or installed in the previous step. For
example, for the OOT driver installed at the default path, you can specify
``-Dsgx_driver_include_path="/opt/intel/linux-sgx-driver"``. If this parameter
is omitted, Gramine's build system will try to determine the right path, so,
it's usually not needed.

.. note::

   If you have a DCAP driver installed on the system (e.g. on 18.04 Azure),
   then you can still use the upstream driver and specify the `upstream header
   file <https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/plain/arch/x86/include/uapi/asm/sgx.h?h=v5.11>`__.
   This is because the DCAP and the upstream drivers have compatible APIs.

.. note::

   When installing from sources, Gramine executables are placed under
   ``/usr/local/bin``. Some Linux distributions (notably CentOS) do not search
   for executables under this path. If your system reports that Gramine
   programs can not be found, you might need to edit your configuration files so
   that ``/usr/local/bin`` is in your path (in ``PATH`` environment variable).

Set ``-Dglibc=`` or ``-Dmusl=`` options to ``disabled`` if you wish not to build
the support for any (they are both built by default).

Additional build options
^^^^^^^^^^^^^^^^^^^^^^^^

- To build test binaries, run :command:`meson -Dtests=enabled`. This is
  necessary if you will be running regression tests. See
  :doc:`contributing` for details.

- In order to run SGX tools with DCAP version of RA-TLS library
  (``ra_tls_verify_dcap.so``), build with :command:`meson -Ddcap=enabled` option.
  See `RA-TLS example's README <https://github.com/gramineproject/gramine/blob/master/CI-Examples/ra-tls-mbedtls/README.md>`__.

  .. note::
     EPID version of RA-TLS library (``ra_tls_verify_epid.so``) is built by
     default.

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
     garbage data. You should use ``--buildtype=debugoptimized`` only if you
     have a good reason (e.g. for profiling).

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

  This very much depends on a particular distribution, so please consult relevant
  documentation provided by your distro.

- To compile a patched version of GCC's OpenMP library (``libgomp``), install
  GCC's build prerequisites (see :ref:`common-dependencies`), and use
  :command:`meson -Dlibgomp=enabled`.

  The patched version has significantly better performance under SGX
  (``libgomp`` uses inline ``SYSCALL`` instructions for futex calls; our patch
  replaces them with a jump to Gramine LibOS, same as for ``glibc``).

  Building the patched ``libgomp`` library is disabled by default because it can
  take a long time: unfortunately, the only supported way of building
  ``libgomp`` is as part of a complete GCC build.

Prepare a signing key
---------------------

These instructions are only required for systems using Intel® SGX that have not
already created a signing key.

The following command generates an |~| RSA 3072 key suitable for signing SGX
enclaves and stores it in :file:`{HOME}/.config/gramine/enclave-key.pem`.
Protect this key and do not disclose it to anyone::

   gramine-sgx-gen-private-key

After signing the application's manifest, users may ship the application and
Gramine binaries, along with an SGX-specific manifest (``.manifest.sgx``
extension), the SIGSTRUCT signature file (``.sig`` extension), and the
EINITTOKEN file (``.token`` extension) to execute on another SGX-enabled host.

Advanced: building without network access
-----------------------------------------

First, before you cut your network access, you need to download (or otherwise
obtain) a |~| checkout of Gramine repository and all wrapped subprojects'
distfiles. The files :file:`subprojects/{*}.wrap` describe those downloads and
their respective SHA-256 checksums. You can use :command:`meson subprojects
download` to download and check them automatically. Otherwise, you should put
all those distfiles into :file:`subprojects/packagecache` directory. Pay
attention to expected filenames as specified in wrap files. (You don't need to
checksum them separately, Meson will do that for you later if they're mismatched
or corrupted).

Alternatively, you can prepare a |~| "dist" tarball using :command:`meson dist`
command, which apart from Gramine code will contain all wrapped subprojects and
also git submodules. For this you need to create a |~| dummy builddir using
:command:`meson setup` command::

    meson setup build-dist/ \
        -Ddirect=disabled -Dsgx=disabled -Dskeleton=enabled \
        -Dglibc=enabled -Dmusl=enabled -Dlibgomp-enabled
    meson dist -C build-dist/ --no-tests --include-subprojects --formats=gztar

The options specified with ``-D`` (especially ``-Dglibc``, ``-Dmusl`` and
``-Dlibgomp``) are important, because without them some subprojects will not be
included in the tarball (if in doubt, you can consult
:file:`scripts/makedist.sh` script). The command :command:`meson dist` still
needs network access, because it downloads subprojects and checks out git
submodules. The tarballs are located in :file:`build-dist/meson-dist`. You can
adjust ``--formats`` option to your needs.

You can now sever your network connection::

    sudo unshare -n su "$USER"

If you build from dist tarball, unpack it and :command:`cd` to the main
directory. If not, go to the repository checkout where you've downloaded
:file:`subproject/packagecache`. In either case, you can now :command:`meson
setup` your build directory with the switch ``--wrap-mode=nodownload``, which
prevents Meson from downloading subprojects. Those subprojects should already be
downloaded and if you didn't :command:`unshare -n`, it prevents a |~| mistake.
Proceed with compiling and installing as usual.

::

    meson setup build/ --prefix=/usr --wrap-mode=nodownload \
        -Ddirect=enabled -Dsgx=enabled -Dsgx_driver=upstream
    meson compile -C build/
    meson install -C build/


.. _legacy-kernel-and-hardware:

Legacy kernel and hardware
--------------------------

Although we recommend kernel version 5.11 or later, Gramine can be run on older
kernels with out-of-tree SGX driver. OOT driver is also the only possibility to
run Gramine on non-FLC hardware. In this configuration, we require kernel at
least 5.4, and for kernels between 5.4 (inclusive) and 5.9 (exclusive) we
additionally require FSGSBASE patchset (see below).

Beware that some enterprise distributions provide kernels that report some old
version, but actually provide upstream SGX driver that has been backported (like
RHEL and derivatives since version 8, which has nominally kernel 4.18). If you
have one of those enterprise kernels, this section does not apply. If in doubt,
check kernel's ``.config`` and consult your distro documentation.

1. Install Linux kernel with patched FSGSBASE
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

FSGSBASE is a feature in recent processors which allows direct access to the FS
and GS segment base addresses. For more information about FSGSBASE and its
benefits, see `this discussion <https://lwn.net/Articles/821719>`__.

FSGSBASE patchset was merged in Linux kernel version 5.9, so if your kernel
version is 5.9 or higher, then the FSGSBASE feature is already supported and you
can skip this step. For older kernels it is available as `separate patches
<https://github.com/oscarlab/graphene-sgx-driver/tree/master/fsgsbase_patches>`__.

(Note that Gramine was prevously called *Graphene* and was hosted under
a different organization, hence the name of the linked repository.)

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
   must return that bit 1 is set)::

       # Linux kernel doesn't support FSGSBASE: patch or use higher version!
       $ LD_SHOW_AUXV=1 /bin/true | grep AT_HWCAP2
       AT_HWCAP2:       0x0

       # Linux kernel supports FSGSBASE (example where only bit 1 is set)
       $ LD_SHOW_AUXV=1 /bin/true | grep AT_HWCAP2
       AT_HWCAP2:       0x2

After the patched Linux kernel is installed, you may proceed with installations
of other SGX software infrastructure: the Intel SGX Linux driver, the Intel SGX
SDK/PSW, and Gramine itself.

2. Install the Intel SGX driver
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This step depends on your hardware and kernel version. Note that if your kernel
version is 5.11 or higher, then the Intel SGX driver is already installed and
you can skip this step.

If you have an older CPU without :term:`FLC` support, you need to download and
install the following out-of-tree (OOT) Intel SGX driver:

- https://github.com/intel/linux-sgx-driver

For this driver, you need to set ``vm.mmap_min_addr=0`` in the system (*only
required for the legacy SGX driver and not needed for newer DCAP/in-kernel
drivers*)::

   sudo sysctl vm.mmap_min_addr=0

Note that this is an inadvisable configuration for production systems.

Alternatively, if your CPU supports :term:`FLC`, you can choose to install the
DCAP version of the Intel SGX driver from:

- https://github.com/intel/SGXDataCenterAttestationPrimitives
