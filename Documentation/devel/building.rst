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
performance reasons. You can choose at most one of the libcs available. By
default glibc is built.

Gramine currently only works on the x86_64 architecture. Gramine is currently
tested on Ubuntu 24.04/22.04, along with Linux kernel version 5.x. We recommend
building and installing Gramine on Ubuntu with Linux kernel version 5.11 or
higher. If you find problems with Gramine on other Linux distributions, contact
us with a |~| detailed `bug report
<https://github.com/gramineproject/gramine/issues/new/choose>`__.

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
        autoconf bison gawk meson nasm pkg-config python3 python3-click \
        python3-jinja2 python3-pyelftools python3-tomli python3-tomli-w \
        python3-voluptuous wget

.. TODO after deprecating Debian 11 (bullseye): remove the following paragraph

On Debian 11, ``python3-tomli`` and ``python3-tomli-w`` come from
``bullseye-backports`` repository, so you need to enable this repo and add
``-t bullseye-backports`` to ``apt-get install`` invocation above. Please refer
to `Debian's documentation <https://backports.debian.org/Instructions/>`__ for
detailed instructions.

For GDB support and to run all tests locally you also need to install::

    sudo apt-get install -y libunwind8 musl-tools python3-pytest

If you want to build the patched ``libgomp`` library, you also need to install
GCC's build dependencies::

    sudo apt-get install -y libgmp-dev libmpfr-dev libmpc-dev libisl-dev

Dependencies for SGX
^^^^^^^^^^^^^^^^^^^^

The build of Gramine with SGX support requires CPU with :term:`Flexible Launch
Control (FLC)<FLC>` feature and the corresponding SGX software infrastructure to
be installed on the system. We require Linux kernel with SGX driver built in
(``CONFIG_X86_SGX=y``, which is the case for most of available distribution
kernels), which is available since version 5.11 (and also as backported patches
to older kernels in certain distros).

Kernel version can be checked using the following command::

    uname -r

If your current kernel version is 5.11 or higher, you have a built-in SGX
support. The driver is accessible through :file:`/dev/sgx_enclave`
and :file:`/dev/sgx_provision`.

Beware that some enterprise distributions provide kernels that report some old
version, but actually provide upstream SGX driver that has been backported (like
RHEL and derivatives since version 8, which has nominally kernel 4.18). If you
have one of those enterprise kernels, this point does not apply. If in doubt,
check kernel's ``.config`` and consult your distro documentation.

If your current kernel version is lower than 5.11, then you need to upgrade the
whole distribution. This is because ``linux-libc-dev`` package, which supplies
``<asm/sgx.h>`` header that we use, is typically tied to distro's stable kernel.
Just installing newer kernel image and rebooting might not be sufficient, unless
you set up ``CFLAGS="-I ..."`` pointing to a |~| directory containing uapi
(userspace API) headers matching that newer kernel. This approach is unsupported
and outside of the scope in this guide.

1. Required packages
""""""""""""""""""""
Run the following commands on Ubuntu to install SGX-related dependencies::

    sudo apt-get install -y cmake libprotobuf-c-dev protobuf-c-compiler \
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
``libsgx-dcap-quote-verify`` package (and its development counterpart)::

   # Below commands work on Ubuntu 24.04 LTS and 22.04 LTS
   sudo curl -fsSLo /usr/share/keyrings/intel-sgx-deb.asc https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key
   echo "deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx-deb.asc] https://download.01.org/intel-sgx/sgx_repo/ubuntu $(lsb_release -sc) main" \
   | sudo tee /etc/apt/sources.list.d/intel-sgx.list

   sudo apt-get update
   sudo apt-get install libsgx-dcap-quote-verify-dev

Build Gramine
-------------

To build Gramine, you need to first set up the build directory. In the root
directory of Gramine repo, run the following command (recall that "direct" means
non-SGX version)::

   meson setup build/ --buildtype=release -Ddirect=enabled -Dsgx=enabled

.. note::

   If you plan to contribute changes to Gramine, then you should always build it
   with ``--werror`` added to the invocation above.

.. note::

   If you invoked ``meson setup`` once, the next invocation of this command will
   *not* have any effect. Instead, to change the build configuration, use
   ``meson configure``. For example, if you built with ``meson setup build/
   -Dsgx=disabled`` first and now want to enable SGX, type ``meson configure
   build/ -Dsgx=enabled``.

Set ``-Ddirect=`` and ``-Dsgx=`` options to ``enabled`` or ``disabled``
according to whether you built the corresponding PAL (the snippet assumes you
built both).

Since Gramine v1.9, we only support upstream, in-kernel driver and the
``-Dsgx_driver`` option, as well as associated ``-Dsgx_driver_include_path`` and
``-Dsgx_driver_device`` options, are gone.

Set ``-Dlibc`` option to ``musl`` if you wish to build musl instead of glibc
(which is built by default), or to ``none`` if you do not want to build any
libc.

Then, build and install Gramine by running the following::

   meson compile -C build/
   sudo meson compile -C build/ install

Installation prefix
^^^^^^^^^^^^^^^^^^^

By default, Meson uses installation prefix :file:`/usr/local`.

- When installing from sources, Gramine executables are placed under
  :file:`/usr/local/bin`. Some Linux distributions (notably CentOS) do not
  search for executables under this path. If your system reports that Gramine
  programs can not be found, you might need to edit your configuration files so
  that :file:`/usr/local/bin` is in your path (in ``$PATH`` environment
  variable). Alternatively, you can modify the installation prefix (e.g. to
  :file:`/usr`) or the executable directory (e.g. :command:`meson
  --bindir=/usr/bin`).

- When installing from sources, Gramine Python modules are placed under
  :file:`/usr/local/lib/python3.xyz/site-packages` (or under
  :file:`/usr/local/lib/python3.xyz/dist-packages` on Debian-like distros). Some
  Linux distributions (notably Alpine) do not search for Python modules under
  this path. If your system fails to find Gramine Python modules, you might need
  to adjust ``PYTHONPATH`` environment variable. Alternatively, you can modify
  the installation prefix, e.g. to :file:`/usr`.

To install into some other place than :file:`/usr/local`, use :command:`meson
--prefix=<prefix>`. Note that if you chose something else than :file:`/usr`
then for things to work, you probably need to adjust several environment
variables:

=========================== ================================================== ========================
Variable                    What to add                                        Read more
=========================== ================================================== ========================
``$PATH``                   :file:`<prefix>/bin`                               `POSIX.1-2018 8.3`_
``$PYTHONPATH``             :file:`<prefix>/lib/python<version>/site-packages` :manpage:`python3(1)`
``$PKG_CONFIG_PATH``        :file:`<prefix>/<libdir>/pkgconfig`                :manpage:`pkg-config(1)`
=========================== ================================================== ========================

.. _POSIX.1-2018 8.3: https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap08.html#tag_08_03

This very much depends on a particular distribution, so please consult
relevant documentation provided by your distro.

Additional build options
^^^^^^^^^^^^^^^^^^^^^^^^

- To build test binaries, run :command:`meson -Dtests=enabled`. This is
  necessary if you will be running regression tests. See
  :doc:`contributing` for details.

- In order to run SGX tools with DCAP version of RA-TLS library
  (``ra_tls_verify_dcap.so``), build with :command:`meson -Ddcap=enabled` option.
  See `RA-TLS example's README <https://github.com/gramineproject/gramine/blob/master/CI-Examples/ra-tls-mbedtls/README.md>`__.

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

These instructions are only required for systems using Intel SGX that have not
already created a signing key.

The following command generates an |~| RSA 3072 key suitable for signing SGX
enclaves and stores it in :file:`{HOME}/.config/gramine/enclave-key.pem`.
Protect this key and do not disclose it to anyone::

   gramine-sgx-gen-private-key

After signing the application's manifest, users may ship the application and
Gramine binaries, along with an SGX-specific manifest (``.manifest.sgx``
extension), the SIGSTRUCT signature file (``.sig`` extension) to execute on
another SGX-enabled host.

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
        -Dlibc=glibc -Dlibgomp=enabled
    meson dist -C build-dist/ --no-tests --include-subprojects --formats=gztar

The options specified with ``-D`` (especially ``-Dlibc`` and ``-Dlibgomp``) are
important, because they determine which subprojects will be included in the
tarball. They need to match what you intend to build. The command
:command:`meson dist` still needs network access, because it downloads
subprojects and checks out git submodules. The tarballs are located in
:file:`build-dist/meson-dist`. You can adjust ``--formats`` option to your
needs.

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
        -Ddirect=enabled -Dsgx=enabled
    meson compile -C build/
    meson install -C build/

.. _legacy-kernel-and-hardware:

Legacy kernel and hardware
--------------------------

Gramine v1.9 and later no longer supports non-FLC hardware, nor kernels older
than 5.11.
