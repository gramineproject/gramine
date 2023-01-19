Packaging and distributing
==========================

Gramine project aims to support two most recent releases of the long-lived
distributions (e.g. Debian, Ubuntu LTS, AlmaLinux and other CentOS replacements,
...).

Currently officially supported distributions:

- Ubuntu (22.04 LTS, 20.04 LTS, 18.04 LTS);
- RHEL-8-like distributions (like AlmaLinux 8, Rocky Linux 8, ...);
- experimentally, RHEL-9-like distros (packages are not fully validated).

Exceptions
----------

Linux kernel
^^^^^^^^^^^^
Because upstream support for SGX was only merged relatively recently and in
non-longterm release, together with the fact that EPID attestation is
unsupported in upstream driver, **it is acceptable to require the user to use
kernel other that provided by distro**.

.. _glibc:

glibc
^^^^^
Glibc is a special case, because we need to provide the version supported by the
distribution **or a later version**, which is inverse from the usual dependency
relation that we need to support the version from distro or earlier. Therefore
we will provide some reasonably new version under the assumption that older
software will be able to run against new glibc version.

musl
^^^^
See :ref:`glibc`. Same thing applies to musl.

varia
^^^^^
Maintainer tools, examples, etc. need not run on all distros.

Packaging guide
---------------

TBD

Acknowledgements
----------------

Distro support policy was inspired by `Libvirt's policy
<https://libvirt.org/platforms.html>`__.
