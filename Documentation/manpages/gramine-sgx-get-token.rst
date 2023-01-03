.. program:: gramine-sgx-get-token
.. _gramine-sgx-get-token:

===============================================================
:program:`gramine-sgx-get-token` -- Gramine SGX token generator
===============================================================

Synopsis
========

:command:`gramine-sgx-get-token` [*OPTION*]... --sig sigstruct_file
--output token_file

Description
===========

:program:`gramine-sgx-get-token` is used to generate the SGX token file for
given SIGSTRUCT (".sig" file).

Using this command is not necessary (it was previously), since the token is
fetched automatically if needed during the first enclave start.

On upstream/DCAP driver this command does nothing and is deprecated. In
the future, it will be removed altogether.

Command line arguments
======================

.. option:: --sig sigstruct_file, -s sigstruct_file

    Path to the input file containing SIGSTRUCT.

.. option:: --output token_file, -o token_file

   Path to the output token file.

.. option:: --verbose, -v

    Print details to standard output. This is the default.

.. option:: --quiet, -q

    Don't print details to standard output.
