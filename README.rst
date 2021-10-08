*****************************************
Gramine Library OS with Intel SGX Support
*****************************************

.. image:: https://readthedocs.org/projects/gramine/badge/?version=latest
   :target: http://gramine.readthedocs.io/en/latest/?badge=latest
   :alt: Documentation Status

*A Linux-compatible Library OS for Multi-Process Applications*

.. This is not |~|, because that is in rst_prolog in conf.py, which GitHub cannot parse.
   GitHub doesn't appear to use it correctly anyway...
.. |nbsp| unicode:: 0xa0
   :trim:

.. highlight:: sh

**NOTE:** We recently transitioned our buildsystem to Meson, and
the build procedures were changed. See `Building instructions
<https://gramine.readthedocs.io/en/latest/building.html>`__ for an up-to-date
build tutorial.

What is Gramine?
================

Gramine (formerly called *Graphene*) is a |nbsp| lightweight library OS,
designed to run a single application with minimal host requirements. Gramine can
run applications in an isolated environment with benefits comparable to running
a |nbsp| complete OS in a |nbsp| virtual machine -- including guest
customization, ease of porting to different OSes, and process migration.

Gramine supports native, unmodified Linux binaries on any platform. Currently,
Gramine runs on Linux and Intel SGX enclaves on Linux platforms.

In untrusted cloud and edge deployments, there is a |nbsp| strong desire to
shield the whole application from rest of the infrastructure. Gramine supports
this “lift and shift” paradigm for bringing unmodified applications into
Confidential Computing with Intel SGX. Gramine can protect applications from a
|nbsp| malicious system stack with minimal porting effort.

Gramine is a growing project and we have a growing contributor and maintainer
community. The code and overall direction of the project are determined by a
diverse group of contributors, from universities, small and large companies, as
well as individuals. Our goal is to continue this growth in both contributions
and community adoption.

Note that the Gramine project was formerly known as Graphene. However, the name
"Graphene" was deemed too common, could be impossible to trademark, and collided
with several other software projects. Thus, a new name "Gramine" was chosen.

Gramine 1.0 release
===================

Gramine has evolved a |nbsp| lot since our last major release. Over the last
few months, we have made significant updates to provide a |nbsp| stable version
that supports deploying key workloads with Intel SGX. We’ve rewritten major
subsystems, done a |nbsp| significant update to the build and packaging
scripts, extended test coverage, and improved the CI/CD process. We’ve reviewed
and hardened specific security aspects of Gramine, and increased stability for
long-running and heavy workloads.

We recently published our first production-ready release - Gramine 1.0. This
version was tested on various configurations and heavy workloads, we also
ensured that all risky configurations are clearly warned about to prevent
insecure deployments. More details (including a list of all breaking changes)
are available on the `v1.0 release page
<https://github.com/gramineproject/gramine/releases/tag/v1.0>`__.

Gramine documentation
=====================

The official Gramine documentation can be found at
https://gramine.readthedocs.io. Below are quick links to some of the most
important pages:

- `Quick start and how to run applications
  <https://gramine.readthedocs.io/en/latest/quickstart.html>`__
- `Complete building instructions
  <https://gramine.readthedocs.io/en/latest/building.html>`__
- `Gramine manifest file syntax
  <https://gramine.readthedocs.io/en/latest/manifest-syntax.html>`__
- `Performance tuning & analysis of SGX applications in Gramine
  <https://gramine.readthedocs.io/en/latest/devel/performance.html>`__
- `Remote attestation in Gramine
  <https://gramine.readthedocs.io/en/latest/attestation.html>`__


Getting help
============

For any questions, please send an email to gramine-users@googlegroups.com
(`public archive <https://groups.google.com/g/gramine-users>`__).

For bug reports, post an issue on our GitHub repository:
https://github.com/gramineproject/gramine/issues.


Reporting security issues
=========================

Please report security issues to gramine-security@googlegroups.com.


Acknowledgments
===============

Gramine Project benefits from generous help of `fosshost.org
<https://fosshost.org>`__: they lend us a VPS, which we use as toolserver and
package hosting.
