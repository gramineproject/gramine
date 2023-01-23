.. program:: gramine-sgx-sigstruct-view
.. _gramine-sgx-sigstruct-view:

==============================================================
:program:`gramine-sgx-sigstruct-view` -- Display SGX SIGSTRUCT
==============================================================

Synopsis
========

:command:`gramine-sgx-sigstruct-view` [*SIGSTRUCT-FILE*]

Description
===========

:program:`gramine-sgx-sigstruct-view` is used to display SIGSTRUCT fields of the
SGX enclave (MRENCLAVE, MRSIGNER, etc.), extracted from the ``.sig`` file.

Example
=======

.. code-block:: sh

   gramine-sgx-sigstruct-show helloworld.sig
