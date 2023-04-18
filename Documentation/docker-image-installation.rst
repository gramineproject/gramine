Gramine docker image
====================

This Gramine image is a minimal distribution of Gramine: it contains only
Gramine binaries and tools, as well as the pre-requisite packages to run
applications under Gramine. The only currently available Gramine image is based
on Ubuntu 20.04. The only requirement on the host system is a Linux kernel with
in-kernel SGX driver (available from version 5.11 onward).

This Gramine image can be used as a disposable playground environment, to
quickly test Gramine with your applications and workloads. This image can also
be used as a base for your workflows to produce production-ready Docker images
for your SGX applications.

The Gramine team publishes a base Gramine Docker image at:
`DockerHub <https://hub.docker.com/r/gramineproject/gramine>`_.

To run the Gramine image via Docker, the recommended command is::

``docker run --device /dev/sgx_enclave -it gramineproject/gramine``

If you want to run :program:`gramine-direct` in addition to
command:`gramine-sgx`, then you should run Docker with our custom seccomp
profile using:

 ``--security-opt seccomp=<profile_file>``

You can download the profile file from:

https://github.com/gramineproject/gramine/blob/master/scripts/docker_seccomp.json.

Alternatively you can disable seccomp completely

``--security-optseccomp=unconfined``
