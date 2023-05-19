*********************
Gramine Documentation
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

This page provides an overview of this site. Each section is outlined below with
a brief explanation and links to specific sub-sections. This page mimics the
table of contents in the left-side menu.

Gramine deployment options
--------------------------

There are two deployment options for Gramine: protect your container and protect
your application. Each option has a dedicated section in the menu, and an
introduction is provided below.

Protect your container
======================

In this section, we describe how you can protect your Docker container using
Gramine Shielded Containers (GSC) and how you can use ready-made solutions for
popular open source projects.

Gramine Shielded Containers
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Docker images are used to run applications in the cloud. The Gramine Shielded
Containers (GSC) tool transforms an original Docker image into a graminized
Docker image that includes the Gramine Library OS and the Gramine-specific app
configuration. It enables you to run an application in a Docker container and
keep it protected.

- :doc:`gsc-installation` - Get an overview of the GSC installation process.
- `Read GSC documentation <https://gramine.readthedocs.io/projects/gsc/>`_.
- `Download GSC <https://github.com/gramineproject/gsc>`_.

Ready-made confidential compute images
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Confidential compute images are ready-made solutions for popular open source
projects such as PyTorch and Redis. These images enable you to customize your
environment through interactive scripts. The result is an image that includes
your specific application, common dependencies, and a manifest file.

See the :doc:`curated-installation` article for more information.

.. note ::
   Confidential compute images is not an official part of Gramine.

Protect your application
========================

Use this option to protect an existing application with Gramine. Little to no
additional modification of your application is needed.

The following steps can be performed to protect your application with Gramine:

- :doc:`Install Gramine<quickstart>` - Install the official Gramine packages
  from the repository of your operating system.
- :doc:`Set up the environment<environment-setup>` - Set up the Gramine
  environment to work with or without SGX and prepare a signing key (only for
  SGX).
- :doc:`Run a sample application<run-sample-application>` - Run a sample
  application to ensure your environment is running correctly.

You can also check :doc:`Gramine tutorials<tutorials-index>`.

Configure your application
--------------------------

To protect an existing application, you should configure your application
correctly:

- :doc:`Provide an application-specific configuration file<manifest-syntax>` -
  Gramine requires a so-called manifest file for each application.
- :doc:`Provide attestation configuration<attestation>` -- If you intend to use
  remote attestation, you should also provide attestation parameters.
- :doc:`Tune performance of application<performance>` - You may want to tune the
  performance of your application under Gramine.

Develop Gramine
---------------

This section describes how to develop Gramine. It contains instructions on how
to build and install Gramine from source, install dependencies, set up
debugging and other processes necessary for Gramine development.

- :doc:`Build Gramine from source files<devel/building>` - Build Gramine and
  ensure all the dependencies are installed.
- :doc:`Set up debugging<devel/debugging>` - Run Gramine with GNU Debugger
  (GDB).
- :doc:`Learn about packaging<devel/packaging>` - Package and distribute Gramine
  on different OS distributions.
- :doc:`Use Python API<python/api>` - Use Python API provided by Gramine.

We also provide :doc:`manual pages for Gramine tools<manpages/index>`.

Contribute to Gramine
---------------------

We encourage anyone who is interested to contribute to Gramine. We offer
procedures and user groups that help you getting started.

These articles contain helpful material for users who want to contribute to
Gramine development.

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
- `Gramine User Groups <https://groups.google.com/g/gramine-users>`_ - The
  Gramine user-groups page lists the user groups you can join to help you get up
  to speed with developing Gramine.

Gramine design and features
---------------------------

The Gramine Library OS is a complex software. The below articles provide an
overview of Gramine design and implemented/unimplemented features.

- :doc:`devel/features` -- This page has a comprehensive description of
  implemented and unimplemented features of Gramine, including the lists of
  available system calls and pseudo-files.

Resources
---------

The Gramine project provides resources to help you understand and develop it.
The resources page contains a list of maintainers, users of Gramine, and a
glossary to help you with any questions you may have.

- :doc:`management-team` - This page lists maintainers of Gramine.
- :doc:`gramine-users` - See what companies are using Gramine for their
  confidential computing needs.
- :doc:`docker-image-installation` - Use the official Gramine Docker image.
- :doc:`sgx-intro` - Learn about the Intel SGX technology and software stack.
- :doc:`glossary` - Become familiar with the terms used for Gramine.

Getting help
------------

For any questions, please send an email to users@gramineproject.io
or join us on our `Gitter chat <https://gitter.im/gramineproject/community>`__.

For bug reports, post an issue on our GitHub repository:
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

   quickstart
   environment-setup
   run-sample-application
   tutorials-index

.. toctree::
   :hidden:
   :caption: Configure application
   :maxdepth: 1

   manifest-syntax
   attestation
   performance

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
   :caption: Gramine design and concepts
   :maxdepth: 1

   devel/features

.. toctree::
   :hidden:
   :caption: Resources
   :maxdepth: 1

   management-team
   gramine-users
   docker-image-installation
   sgx-intro
   glossary
