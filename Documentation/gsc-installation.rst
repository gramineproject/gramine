Gramine Shielded Containers
===========================

The Gramine Shielded Container (GSC) tool transforms an original Docker image
into a new, "graminized" image which includes the Gramine Library OS, manifest
files, and Intel SGX related information.
It uses Gramine to execute the application inside an Intel SGX enclave.
It follows the common Docker approach to first build an image and subsequently
run this image inside a container.

At first a Docker image has to be graminized via the ``gsc build`` command.
When the graminized image is run within an Intel SGX enclave, the image must be
signed via a ``gsc sign-image`` command.
Subsequently, the image can be run using ``docker run``.

Note the GSC documentation is split from the core Gramine documentation
and is hosted here: https://gramine.readthedocs.io/projects/gsc.

Similarly, the GSC tool is split from the core Gramine repository and can be
found here: https://github.com/gramineproject/gsc.
