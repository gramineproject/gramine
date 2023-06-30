Gramine installation options
============================

.. highlight:: sh

There are three options to choose from when using Gramine to protect your
application. The option you choose depends on how you are running your
application. The first two options are explained on this page and the third
option on a dedicated page.

- :ref:`install-gramine-packages` - This option installs the official Gramine
  packages from the repository of your operating system.

- :ref:`use-gramine-docker-image` - With this option, you protect your
  application using a Docker image that provides a minimal distribution of
  Gramine.

- :doc:`devel/building` - This option is mainly used for assisting in Gramine
  development. This option is recommended for advanced users who want to get all
  current bugfixes and improvements without waiting for a next release. This
  option is much more involved than the other two options.

.. _install-gramine-packages:

Install Gramine packages
------------------------

Debian 12
^^^^^^^^^

::

   sudo curl -fsSLo /usr/share/keyrings/gramine-keyring.gpg https://packages.gramineproject.io/gramine-keyring.gpg
   echo "deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg] https://packages.gramineproject.io/ $(lsb_release -sc) main" \
   | sudo tee /etc/apt/sources.list.d/gramine.list

   sudo curl -fsSLo /usr/share/keyrings/intel-sgx-deb.asc https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key
   echo "deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx-deb.asc] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main" \
   | sudo tee /etc/apt/sources.list.d/intel-sgx.list

   sudo apt-get update
   sudo apt-get install gramine

Debian 11
^^^^^^^^^

::

   # if you don't already have backports repo enabled:
   echo "deb http://deb.debian.org/debian $(lsb_release -sc)-backports main" \
   | sudo tee /etc/apt/sources.list.d/backports.list

   sudo curl -fsSLo /usr/share/keyrings/gramine-keyring.gpg https://packages.gramineproject.io/gramine-keyring.gpg
   echo "deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg] https://packages.gramineproject.io/ $(lsb_release -sc) main" \
   | sudo tee /etc/apt/sources.list.d/gramine.list

   sudo curl -fsSLo /usr/share/keyrings/intel-sgx-deb.asc https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key
   echo "deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx-deb.asc] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main" \
   | sudo tee /etc/apt/sources.list.d/intel-sgx.list

   sudo apt-get update
   sudo apt-get install gramine

Ubuntu 22.04 LTS or 20.04 LTS
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

   sudo curl -fsSLo /usr/share/keyrings/gramine-keyring.gpg https://packages.gramineproject.io/gramine-keyring.gpg
   echo "deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg] https://packages.gramineproject.io/ $(lsb_release -sc) main" \
   | sudo tee /etc/apt/sources.list.d/gramine.list

   sudo curl -fsSLo /usr/share/keyrings/intel-sgx-deb.asc https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key
   echo "deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx-deb.asc] https://download.01.org/intel-sgx/sgx_repo/ubuntu $(lsb_release -sc) main" \
   | sudo tee /etc/apt/sources.list.d/intel-sgx.list

   sudo apt-get update
   sudo apt-get install gramine

AlmaLinux and compatible distributions, versions 9 and 8
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

These are distributions like AlmaLinux, Rocky Linux, etc.

1. Install EPEL repository as described here:
   https://docs.fedoraproject.org/en-US/epel/

2. Install Gramine::

      sudo curl -fsSLo /etc/yum.repos.d/gramine.repo https://packages.gramineproject.io/rpm/gramine.repo
      sudo dnf install gramine

.. _use-gramine-docker-image:

Use Gramine Docker image
------------------------

The Gramine team publishes a base Gramine Docker image at
https://hub.docker.com/r/gramineproject/gramine.

This Gramine image is a minimal distribution of Gramine: it contains only
Gramine binaries and tools, as well as the pre-requisite packages to run
applications under Gramine. The only currently available Gramine image is based
on Ubuntu 20.04. The only requirement on the host system is a Linux kernel with
in-kernel SGX driver (available from version 5.11 onward).

This Gramine image can be used as a disposable playground environment, to
quickly test Gramine with your applications and workloads. This image can also
be used as a base for your workflows to produce production-ready Docker images
for your SGX applications.

To run the Gramine image via Docker, the recommended command is::

    docker run --device /dev/sgx_enclave -it gramineproject/gramine

If you want to run :program:`gramine-direct` in addition to
:program:`gramine-sgx`, then you should run Docker with our custom seccomp
profile using::

    --security-opt seccomp=<profile_file>

You can download the profile file from
https://github.com/gramineproject/gramine/blob/master/scripts. Two profile files
are available: ``docker_seccomp_mar_2021.json`` (for older Docker versions) and
``docker_seccomp_aug_2022.json`` (for newer Docker versions).
