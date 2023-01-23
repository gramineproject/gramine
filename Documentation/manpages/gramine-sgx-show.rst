.. program:: gramine-sgx-show
.. _gramine-sgx-show:

===========================================================
:program:`gramine-sgx-show` -- Show metadata of SGX enclave
===========================================================

Synopsis
========

:command:`gramine-sgx-show` [*SIGSTRUCT-FILE*]

Description
===========

:program:`gramine-sgx-show` is used to show metadata of the SGX enclave,
extracted from the SIGSTRUCT (``.sig``) file (MRENCLAVE, MRSIGNER, etc.).

Example
=======

.. code-block:: sh

   gramine-sgx-show helloworld.sig
