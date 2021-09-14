.. program:: gramine-sgx-sign
.. _gramine-sgx-sign:

==========================================================
:program:`gramine-sgx-sign` -- Gramine SIGSTRUCT generator
==========================================================

Synopsis
========

:command:`gramine-sgx-sign` [*OPTION*]... --output output_manifest
--key key_file --manifest manifest_file

Description
===========

:program:`gramine-sgx-sign` is used to expand Trusted Files and generate
signature file for given input manifest and libpal file (main Gramine binary).

Command line arguments
======================

.. option:: --output output_manifest, -o output_manifest

   Path to the output manifest file (with Trusted Files expanded).

.. option:: --key key_file, -k key_file

    Path to the private key used for signing.

.. option:: --manifest manifest_file, -m manifest_file

    Input manifest file.

.. option:: --libpal libpal_path, -l libpal_path

    Path to libpal file (main Gramine binary).

.. option:: --sigfile sigfile, -s sigfile

    Path to the output file containing SIGSTRUCT. If not provided,
    `manifest_file` will be used with ".manifest" (if present) removed from
    the end and with ".sig" appended.
