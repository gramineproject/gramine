Container integration
=====================

.. highlight:: sh

Container technologies such as Docker are widely used to deploy applications in
the cloud. Gramine has several tools to ease integration with different
container technologies, described below.

Gramine Docker image
--------------------

The Gramine team publishes a base Gramine Docker image at DockerHub:
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
command:`gramine-sgx`, then you should run Docker with our custom seccomp
profile using ``--security-opt seccomp=<profile_file>``. You can download the
profile file from
https://github.com/gramineproject/gramine/blob/master/scripts/docker_seccomp.json.
Alternatively you can disable seccomp completely (``--security-opt
seccomp=unconfined``).

GSC (Gramine Shielded Containers)
---------------------------------

The GSC tool transforms an original Docker image into a new, "graminized" image
which includes the Gramine Library OS, manifest files, Intel SGX related
information, and executes the application inside an Intel SGX enclave using
Gramine. It follows the common Docker approach to first build an image and
subsequently run this image inside of a container. At first a Docker image has
to be graminized via the ``gsc build`` command. When the graminized image should
run within an Intel SGX enclave, the image has to be signed via a ``gsc
sign-image`` command.  Subsequently, the image can be run using ``docker run``.

Note that GSC (Gramine Shielded Containers) tool is split from the core Gramine
repository and can be found here: https://github.com/gramineproject/gsc.

Similarly, GSC documentation is split from the core Gramine documentation and is
hosted here: https://gramine.readthedocs.io/projects/gsc.
