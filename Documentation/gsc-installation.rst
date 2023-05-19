Gramine Shielded Containers
===========================

The Gramine Shielded Containers (GSC) tool transforms an original Docker image
into a new, "graminized" image which includes the Gramine Library OS and the
Gramine-specific app configuration. It uses Gramine to execute the application
inside an Intel SGX enclave. It follows the common Docker approach to first
build a Docker image and subsequently run this image inside a Docker container.

At first an original Docker image has to be graminized via the ``gsc build``
command. In a second step, the image must be signed via a ``gsc sign-image``
command. Subsequently, the image can be run using ``docker run``.

Note that the GSC tool is split from core Gramine and is hosted here:

- https://github.com/gramineproject/gsc -- GitHub repository.
- https://gramine.readthedocs.io/projects/gsc -- documentation.
