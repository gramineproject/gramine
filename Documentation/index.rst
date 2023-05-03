*********************
Gramine Documentation
*********************

Gramine is a lightweight guest OS that's designed to run a single Linux
application with minimal host requirements.
Gramine can run applications in an isolated environment with benefits comparable
to running a complete OS in a virtual machine, including guest customization,
ease of porting to different host OSs, and process migration.

Gramine supports running Linux applications using the Intel Software Guard
Extensions, or Intel SGX. For mor information, refer to the :doc:`sgx-intro`
article.

This page provides an overview of this site.
Each section is outlined below with a brief explanation and links to specific
sections.
This page mimics the table of contents in the left column.

Gramine deployment options
--------------------------

There are three deployment options for Gramine -- each option has a dedicated
section in the menu and an introduction is provided below.

Ready-made protected applications
=================================

Confidential compute images are ready-made solutions for popular open source
projects such as `PyTorch <https://github.com/gramineproject/contrib/tree/master/Curated-Apps/workloads/pytorch>`_
and `Redis <https://github.com/gramineproject/contrib/tree/master/Curated-Apps/workloads/redis>`_.
These images enable you to customize your environment through interactive
scripts. The result is an image that includes your specific machine-learning
application, common dependencies, and a manifest file.

.. note::  These confidential compute images only run on machines that support
   Intel SGX.

See the :doc:`curated-installation` article for more information.

Protect your container
======================

Docker images are used to run applications in the cloud.
The Gramine Shielded Container tool transforms a Docker image into a graminized
image that includes the Gramine Library OS and Intel SGX related information.
It enables you to run an application on a Docker image and keep it protected.

- :doc:`gsc-installation` - Get an overview of the installation process of a
  Gramine Shielded Container.
- `Build a Gramine Docker image <https://gramine.readthedocs.io/projects/gsc/en/latest/>`_ -
  Build a Docker image that contains the Gramine functionality.
- `Download the Gramine Shielded Container tool <https://github.com/gramineproject/gsc>`_ -
  Protect the Docker image containing the application you want to protect.

Protect your application
========================

Use this option to protect an exiting application with Gramine.
Little to no addition modification of your application is needed.

The following steps can be performed to protect your application with
Gramine:

- :doc:`Install Gramine<quickstart>` - Install Gramine using binaries from the
  repository of your operating system.
- :doc:`Set up the environment<environment-setup>` - Set up the Gramine
  environment to work with or without SGX and prepare a signing key.
- :doc:`Run a sample application<run-sample-application>` - Run a sample
  application to ensure your environment is running correctly.

Develop Gramine
---------------

This section describes how to develop Gramine.
It contains instructions on how to install Gramine from binaries, install
dependencies, set up debugging and other processes necessary for Gramine
development.

- :doc:`Build Gramine from source files<devel/building>` - Build Gramine and
  ensure all the dependencies installed with proper drivers.
  This option requires more work but allows you to choose build options.
- :doc:`Set up debugging<devel/debugging>` - Run Gramine with GNU Debugger
  (GDB) and setup compiling optimizations.
- :doc:`Implement a new system call<devel/new-syscall>` - Define the interface
  of the system call, add, import, and implement new PAL calls if needed.

Contribute to Gramine
---------------------

We encourage anyone who is interested to contribute to Gramine.
We offer procedures and user groups that help you getting started.

These articles contain helpful material for users who want to contribute to
Gramine development.

- :doc:`devel/contributing` - The Contributing to Gramine page outlines the
  procedures for performing pull requests, reviews, and regression tests.

- :doc:`devel/onboarding` - This page describes the knowledge needed to
  efficiently contribute high-quality PRs to the Gramine project.
  This page also describes typical flows that Gramine developers should follow
  to make the process of PR review consistent for everyone involved.

- :doc:`devel/DCO/index` - Affirm that the source code you will submit was
  originated by you and/or that you have permission to submit it to the Gramine
  project.

- :doc:`devel/setup` - Learn the Emacs and Vim configurations used for Gramine.

- :doc:`devel/coding-style` - This document describes coding conventions and
  formatting styles we use in Gramine.
  All newly committed code must conform to them to pass a review.

- :doc:`devel/howto-doc` - This section describes how the Gramine documentation
  is constructed and provides directions on how to contribute to it.

- `Gramine User Groups <https://groups.google.com/g/gramine-users>`_ - The
  Gramine user-groups page lists the user groups you can join to help you get up
  to speed with developing Gramine.

Resources
---------

The Gramine project provides resources to help you understand and develop it.
The resources page contains a list of maintainers, users, and a glossary to help
you with any questions you may have.

- :doc:`management-team` - This page lists maintainers of Gramine.
- :doc:`gramine-users` - See what companies are using Gramine for their
  confidential computing needs.
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
   :caption: Ready-made protected applications
   :maxdepth: 1

   curated-installation


.. toctree::
   :hidden:
   :caption: Protect your container
   :maxdepth: 1

   gsc-installation


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
   :caption: Develop Gramine
   :maxdepth: 1

   devel/building
   devel/debugging
   devel/new-syscall
   devel/packaging
   devel/features
   pal/host-abi
   python/api
   manpages/manpages-index
   concepts-index


.. toctree::
   :hidden:
   :caption: Contribute to Gramine
   :maxdepth: 1

   devel/contributing
   devel/onboarding
   devel/DCO/index
   devel/setup
   devel/coding-style
   devel/howto-doc


.. toctree::
   :hidden:
   :caption: Resources
   :maxdepth: 1

   management-team
   gramine-users
   glossary
