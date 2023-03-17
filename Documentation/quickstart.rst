.. _quickstart_installation

Gramine installation options
----------------------------

There are three options to choose from when using Gramine to protect your application. The option you choose depends on how you are running your application. 

:ref:`Install Gramine` - This option provides instructions for installing Gramine on various versions of Ubuntu or Red Hat Enterprise Linux 8. 

:ref:`Gramine Docker Image` - This option provides instructions for installing a prepared Docker image with Gramine and running the container. This option enables you to protect an application running in the cloud. 

:doc:`devel/building` - This option is mainly used for assisting in helping the development of Gramine. This option is much more involved. The instructions for this option are listed on another page.

..role:: h1Install Gramine 
 

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

   sudo apt-get install gramine

Ubuntu 22.04 LTS, 20.04 LTS or 18.04 LTS
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
::

   sudo curl -fsSLo /usr/share/keyrings/gramine-keyring.gpg https://packages.gramineproject.io/gramine-keyring.gpg
   echo "deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg] https://packages.gramineproject.io/ $(lsb_release -sc) main" \
   | sudo tee /etc/apt/sources.list.d/gramine.list

   sudo curl -fsSLo /usr/share/keyrings/intel-sgx-deb.asc https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key
   echo "deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx-deb.asc] https://download.01.org/intel-sgx/sgx_repo/ubuntu $(lsb_release -sc) main" \
   | sudo tee /etc/apt/sources.list.d/intel-sgx.list

   sudo apt-get install gramine

RHEL-like distributions version 8 (and experimentally also version 9)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

(like AlmaLinux, Rocky Linux, ...)

1. Install EPEL repository as described here:
   https://docs.fedoraproject.org/en-US/epel/


2. Install Gramine::

      sudo curl -fsSLo /etc/yum.repos.d/gramine.repo https://packages.gramineproject.io/rpm/gramine.repo
      sudo dnf install gramine

Gramine Docker image
========================

This Gramine image is a minimal distribution of Gramine. It contains only Gramine binaries and tools, as well as the pre-requisite packages to run applications under Gramine. The only currently available Gramine image is based on Ubuntu 20.04. The only requirement on the host system is a Linux kernel with in-kernel SGX driver (available from version 5.11 onward). This Gramine image can be used as a disposable playground environment, to quickly test Gramine with your applications and workloads. This image can also be used as a base for your workflows to produce production-ready Docker images for your SGX applications. 

The Gramine team publishes a base Gramine Docker image at: `DockerHub <https://hub.docker.com/r/gramineproject/gramine>`_.

The recommended command to run the Gramine image via Docker is::

``docker run --device /dev/sgx_enclave -it gramineproject/gramine``

If you want to run :program:`gramine-direct` in addition to
command:`gramine-sgx`, then you should run Docker with our custom seccomp
profile using:

 ``--security-opt seccomp=<profile_file>``  

You can download the profile file from:

https://github.com/gramineproject/gramine/blob/master/scripts/docker_seccomp.json.

Alternatively you can disable seccomp completely using this command:

``--security-optseccomp=unconfined``