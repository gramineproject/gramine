Ready-made SGX images
=====================

.. note ::
   This is not an official part of Gramine. The offering mentioned here wasn't
   thoroughly reviewed by the Gramine maintainers. Use at your own risk!

Users can create ready-made SGX Docker images with the help of the `Confidential
Compute for X
<https://github.com/gramineproject/contrib/tree/master/Intel-Confidential-Compute-for-X>`_
project. This project provides an interactive script to transform base Docker
images to Gramine-protected Docker images. The transformation adds important
features, e.g., attestation, to the base Docker image to enable secure
end-to-end use cases. The interactive script asks users for necessary
configurations, and provides these inputs to the :doc:`GSC<gsc-installation>`
tool for the actual transformation. The result is a curated image that includes
your specific application, common dependencies, and a Gramine manifest file that
specifies security policies to enforce for your workload.

Current list of solutions and installation instructions:

- `Redis <https://github.com/gramineproject/contrib/tree/master/Intel-Confidential-Compute-for-X/workloads/redis>`_
- `PyTorch <https://github.com/gramineproject/contrib/tree/master/Intel-Confidential-Compute-for-X/workloads/pytorch>`_
