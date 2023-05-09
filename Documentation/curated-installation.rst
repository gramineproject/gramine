.. _curated_index

Ready-made confidential protected images
========================================

.. note::
    This is not an official part of Gramine.
    The offering mentioned here wasn't thoroughly reviewed by the Gramine
    maintainers.
    Use at your own risk!

Confidential Compute images with Gramine are ready-made solutions for popular
open-source projects, such as PyTorch and Redis.
Customize your environment through interactive scripts.
The result is a curated, confidentially-protected Gramine image that includes
your specific machine-learning application, common dependencies, and a manifest
file that specifies security policies to enforce for your workload.

.. note::
    These confidential compute images only run on machines that support Intel
    SGX.

Current list of solutions and installation instructions:

- `Redis <https://github.com/gramineproject/contrib/tree/master/Intel-Confidential-Compute-for-X/workloads/redis>`_
- `PyTorch <https://github.com/gramineproject/contrib/tree/master/Intel-Confidential-Compute-for-X/workloads/pytorch>`_
