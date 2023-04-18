.. _quickstart_installation

Gramine installation options
----------------------------

There are three options to choose from when using Gramine to protect your
application.
The option you choose depends on how you are running your application.

:ref:`Install Gramine` - This option provides instructions for installing
Gramine on various versions of Ubuntu or Red Hat Enterprise Linux 8.

:doc:`docker-image-installation` - This option provides instructions for
installing a prepared Docker image with Gramine and running the container.
This option enables you to protect an application running in the cloud.

:doc:`devel/building` - This option is mainly used for assisting in helping the
development of Gramine.
This option is much more involved.
The instructions for this option are listed on another page.

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

Ubuntu 22.04 LTS, 20.04 LTS or 18.04 LTS
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

   sudo curl -fsSLo /usr/share/keyrings/gramine-keyring.gpg https://packages.gramineproject.io/gramine-keyring.gpg
   echo "deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg] https://packages.gramineproject.io/ $(lsb_release -sc) main" \
   | sudo tee /etc/apt/sources.list.d/gramine.list

   sudo curl -fsSLo /usr/share/keyrings/intel-sgx-deb.asc https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key
   echo "deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx-deb.asc] https://download.01.org/intel-sgx/sgx_repo/ubuntu $(lsb_release -sc) main" \
   | sudo tee /etc/apt/sources.list.d/intel-sgx.list

   sudo apt-get update
   sudo apt-get install gramine

RHEL-like distributions version 8 (and experimentally also version 9)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

(like AlmaLinux, Rocky Linux, ...)

1. Install EPEL repository as described here:
   https://docs.fedoraproject.org/en-US/epel/

2. Install Gramine::

      sudo curl -fsSLo /etc/yum.repos.d/gramine.repo https://packages.gramineproject.io/rpm/gramine.repo
      sudo dnf install gramine
