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

.. option:: --keytype key_type, -t key_type

    Type of signing key: `pem` for a local private key in .pem format or
    `akv` for Azure Key Vault Managed HSM.

.. option:: --key key_path, -k key_path

    Path to .pem file for a local private key or
    `vault_url:key_name` for Azure Key Vault Managed HSM. For example, if
    we have a key named sgx_sign_key available in the Managed HSM with
    URL  https://myakv-mhsm.managedhsm.azure.net, the key path will be
    `https://myakv-mhsm.managedhsm.azure.net:sgx_sign_key`

.. option:: --manifest manifest_file, -m manifest_file

    Input manifest file.

.. option:: --libpal libpal_path, -l libpal_path

    Path to libpal file (main Gramine binary).

.. option:: --sigfile sigfile, -s sigfile

    Path to the output file containing SIGSTRUCT. If not provided,
    `manifest_file` will be used with ".manifest" (if present) removed from
    the end and with ".sig" appended.

.. option:: --depfile depfile

    Generate a file that describes the dependencies for the output manifest and
    SIGSTRUCT, i.e. files that should trigger rebuilding if they're modified.
    The dependency file is in Makefile format, and is suitable for using in
    build systems (Make, Ninja).

.. option:: --verbose, -v

    Print details to standard output. This is the default.

.. option:: --quiet, -q

    Don't print details to standard output.
