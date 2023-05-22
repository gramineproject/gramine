*********************
Gramine documentation
*********************

Gramine is a lightweight guest OS that's designed to run a single Linux
application with minimal host requirements. Gramine can run applications in an
isolated environment with benefits comparable to running a complete OS in a
virtual machine, including guest customization, ease of porting to different
host OSes, and process migration.

Gramine supports running Linux applications using the :term:`Intel SGX <SGX>`
(Software Guard Extensions) technology. Gramine is able to run unmodified
applications inside SGX enclaves, without the toll of manually porting the
application to the SGX environment. For more information, refer to the
:doc:`sgx-intro` article.

This page provides an overview of this documentation. Each section is outlined
below with a brief explanation and links to specific sub-sections. This page
mimics the table of contents in the left-side menu.

Gramine deployment options
--------------------------

There are two deployment options for Gramine: protect your container and protect
your application. Each option has a dedicated section in the menu, and an
introduction is provided below.

Protect your container
======================

In this section, we describe how you can protect your Docker container using
Gramine Shielded Containers (GSC) and how you can use ready-made SGX images for
popular open source projects.

- **Gramine Shielded Containers**

  Docker images are used to run applications in the cloud. The Gramine Shielded
  Containers (GSC) tool transforms a regular Docker image into a graminized
  Docker image that includes the Gramine Library OS and the Gramine-specific app
  configuration. It enables you to run an application in a Docker container and
  keep it protected. See the :doc:`gsc-installation` article for more information.

- **Ready-made SGX images**

  Users can create ready-made SGX Docker images with the help of the
  `Confidential Compute for X
  <https://github.com/gramineproject/contrib/tree/master/Intel-Confidential-Compute-for-X>`_
  project. This project provides an interactive script to transform regular
  Docker images to Gramine-protected Docker images. See the
  :doc:`curated-installation` article for more information.

  .. note ::
     "Confidential Compute for X" project is not an official part of Gramine.

Protect your application
========================

Use this option to protect an existing application with Gramine. Little to no
additional modification of your application is usually needed.

The following steps can be performed to protect your application with Gramine:

- :doc:`Install Gramine<installation>` - Install official Gramine packages from
  the repository of your Linux distribution.
- :doc:`Set up the SGX environment<sgx-setup>` - Set up the SGX environment and
  prepare a signing key.
- :doc:`Run a sample application<run-sample-application>` - Run a sample
  application to ensure your environment is configured correctly.
- :doc:`Provide an application-specific configuration file<manifest-syntax>` -
  Gramine requires a so-called manifest file for each application.
- :doc:`Set up attestation<attestation>` -- If you intend to use remote
  attestation, you should set up attestation infrastructure.
- :doc:`Tune performance of application<performance>` - You may want to tune the
  performance of your application under Gramine.

You can also check :doc:`Gramine tutorials<tutorials-index>`.

Develop Gramine
---------------

This section describes how to develop Gramine. It contains instructions on how
to build and install Gramine from source, install dependencies, set up
debugging and other processes necessary for Gramine development.

- :doc:`Build Gramine from source files<devel/building>` - Build Gramine and
  ensure all the dependencies are installed.
- :doc:`Set up debugging<devel/debugging>` - Run Gramine with GDB.
- :doc:`Learn about packaging<devel/packaging>` - Package and distribute Gramine
  on different Linux distributions.
- :doc:`Use Python API<python/api>` - Use Python API provided by Gramine.

We also provide :doc:`manual pages for Gramine tools<manpages/index>`.

Contribute to Gramine
---------------------

We encourage anyone who is interested to contribute to Gramine. The below
articles contain helpful material for prospective contributors:

- :doc:`devel/contributing` - The Contributing to Gramine page outlines the
  procedures for performing pull requests, reviews, and regression tests.
- :doc:`devel/onboarding` - This page describes the knowledge needed to
  efficiently contribute high-quality PRs to the Gramine project. This page
  also describes typical flows that Gramine developers should follow to make
  the process of PR review consistent for everyone involved.
- :doc:`devel/setup` - Learn the Emacs and Vim configurations used for Gramine.
- :doc:`devel/coding-style` - This document describes coding conventions and
  formatting styles we use in Gramine. All newly committed code must conform
  to them to pass a review.
- :doc:`devel/howto-doc` - This section describes how the Gramine documentation
  is constructed and provides directions on how to contribute to it.
- :doc:`devel/DCO/index` - Affirm that the source code you will submit was
  originated by you and/or that you have permission to submit it to the Gramine
  project.
- `Gramine Users mailing list <https://groups.google.com/g/gramine-users>`_ - If
  you prefer emails, send them to the Gramine Users mailing list.

Resources
---------

The Gramine project provides resources to help you understand and develop it.
The resources page contains a list of maintainers, users of Gramine, and a
glossary to help you with any questions you may have.

- :doc:`management-team` - This page lists maintainers of Gramine.
- :doc:`gramine-users` - See what companies use Gramine for their confidential
  computing needs.
- :doc:`sgx-intro` - Learn about the Intel SGX technology and software stack.
- :doc:`glossary` - Become familiar with the terms used in Gramine.
- :doc:`devel/features` -- This page has a comprehensive description of
  implemented and unimplemented features of Gramine, including the lists of
  available system calls and pseudo-files.

Getting help
------------

For any questions, please send an email to users@gramineproject.io or join us on
our `Gitter chat <https://gitter.im/gramineproject/community>`__.  For bug
reports, post an issue on our GitHub repository:
https://github.com/gramineproject/gramine/issues.

Indices and tables
------------------

- :ref:`genindex`
- :ref:`search`

.. toctree::
   :hidden:
   :caption: Protect your container
   :maxdepth: 1

   gsc-installation
   curated-installation

.. toctree::
   :hidden:
   :caption: Protect your application
   :maxdepth: 1

   installation
   sgx-setup
   run-sample-application
   manifest-syntax
   attestation
   performance
   tutorials-index

.. toctree::
   :hidden:
   :caption: Develop Gramine
   :maxdepth: 1

   devel/building
   devel/debugging
   devel/packaging
   python/api
   devel/new-syscall
   libos/libos-init
   pal/host-abi
   manpages/index

.. toctree::
   :hidden:
   :caption: Contribute to Gramine
   :maxdepth: 1

   devel/contributing
   devel/onboarding
   devel/setup
   devel/coding-style
   devel/howto-doc
   devel/DCO/index

.. toctree::
   :hidden:
   :caption: Resources
   :maxdepth: 1

   management-team
   gramine-users
   sgx-intro
   glossary
   devel/features
